#include "aegis/vault_service.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace aegis
{
    namespace
    {
        // SecureText byte view

        std::span<const unsigned char> text_bytes(const SecureText& text)
        {
            return std::span<const unsigned char>(text.data(),text.size());
        }

        // Compare credential names

        bool names_equal(std::span<const unsigned char> first, std::span<const unsigned char> second)
        {
            if (first.size() != second.size())
            {
                return false;
            }

            if (first.empty())
            {
                return true;
            }

            return sodium_memcmp(first.data(), second.data(), first.size()) == 0;
        }

        // Locate encrypted credential by ID

        const EncryptedCredentialRecord& find_record(const std::vector<EncryptedCredentialRecord>& records, const CredentialId& id)
        {
            const auto it = std::find_if(records.begin(), records.end(),

                [&](const EncryptedCredentialRecord& record)
                {
                    return record.id == id;
                }
            );

            if (it == records.end())
            {
                throw std::runtime_error(
                    "Vault record inventory is inconsistent.");
            }

            return *it;
        }
    }

    // Constructor

    VaultService::VaultService(std::filesystem::path path, UnlockedVault vault) : path_(std::move(path)), vault_(std::move(vault)) {}

    // Open existing vault

    VaultService VaultService::open(const std::filesystem::path& path, const SecureText& master_password)
    {
        UnlockedVault unlocked = open_vault(path, master_password);

        return VaultService(path, std::move(unlocked));
    }

    // Credential name lookup

    std::optional<std::size_t> VaultService::find_index(const SecureText& name) const
    {
        const auto requested_name = text_bytes(name);

        for (std::size_t i = 0; i < vault_.catalog.size(); ++i)
        {
            const auto existing_name = vault_.catalog.name_at(i);

            if (names_equal(requested_name, existing_name))
            {
                return i;
            }
        }

        return std::nullopt;
    }

    // Prevent writes after an uncertain save

    void VaultService::ensure_writable() const
    {
        if (!writable_)
        {
            throw std::runtime_error("Previous save failed. Reopen the vault before making additional changes.");
        }
    }

    // Rebuild authenticated catalog

    void VaultService::rebuild_catalog(VaultImage& proposed, const SecureText* added_name, const CredentialId* added_id, const CredentialId* removed_id) const
    {
        std::vector<CatalogViewInput> entries;

        entries.reserve(vault_.catalog.size() + (added_name != nullptr ? 1 : 0));

        // Preserve existing entries

        for (std::size_t i = 0; i < vault_.catalog.size(); ++i)
        {
            const CredentialId& id = vault_.catalog.id_at(i);

            // Skip the credential being removed
            if (removed_id != nullptr && id == *removed_id)
            {
                continue;
            }

            const auto& record = find_record(proposed.records,id);

            // Reuse the existing secure catalog name buffer
            entries.push_back(CatalogViewInput{vault_.catalog.name_at(i), record});
        }

        if (added_name != nullptr && added_id != nullptr)
        {
            const auto& record = find_record(proposed.records, *added_id);

            entries.push_back(CatalogViewInput{text_bytes(*added_name), record});
        }

        proposed.catalog = encrypt_catalog_views(proposed.header, vault_.key, std::span<const CatalogViewInput>(entries));
    }

    // Commit updated vault

    void VaultService::commit(VaultImage&& proposed)
    {
        DecryptedCatalog new_catalog = decrypt_catalog(proposed.header, vault_.key, proposed.catalog);

        new_catalog.verify_records(proposed.records);

        try
        {
            save_vault(path_, proposed, vault_.key);
        }
        catch (...)
        {
            // Filesystem replacement failures can leave the
            // destination state uncertain. Do not allow another
            // write using potentially stale session state.
            writable_ = false;

            throw;
        }

        vault_.image = std::move(proposed);

        vault_.catalog = std::move(new_catalog);
    }

    // Add credential

    void VaultService::add( const SecureText& name, const SecureText& username, const SecureText& password, const SecureText& notes)
    {
        ensure_writable();

        // Prevent duplicate names.
        if (find_index(name).has_value())
        {
            throw std::invalid_argument("Credential name already exists.");
        }

        if (vault_.image.records.size() >= MAX_CATALOG_ENTRIES)
        {
            throw std::invalid_argument("Vault has reached its credential limit.");
        }

        VaultImage proposed = vault_.image;

        // Generate a new random credential identifier
        const CredentialId id = generate_credential_id();

        // Encrypt the new credential independently
        EncryptedCredentialRecord record = encrypt_credential(proposed.header, vault_.key, id, username, password, notes);

        proposed.records.push_back(std::move(record));

        // Rebuild the authenticated catalog
        rebuild_catalog(proposed, &name, &id, nullptr);

        commit(std::move(proposed));
    }
 
    // Get credential

    DecryptedCredential VaultService::get(const SecureText& name) const
    {
        const auto index = find_index(name);

        if (!index.has_value())
        {
            throw std::out_of_range("Credential not found.");
        }

        const CredentialId& id = vault_.catalog.id_at(*index);

        const auto& record = find_record(vault_.image.records, id);

        return decrypt_credential(vault_.image.header, vault_.key, record);
    }
 
    // Update Credential

    void VaultService::update(const SecureText& name, const SecureText& username, const SecureText& password, const SecureText& notes)
    {
        ensure_writable();

        const auto index = find_index(name);

        if (!index.has_value())
        {
            throw std::out_of_range("Credential not found.");
        }

        const CredentialId id = vault_.catalog.id_at(*index);

        VaultImage proposed = vault_.image;

        // Locate the existing encrypted record
        auto it = std::find_if(proposed.records.begin(), proposed.records.end(),

            [&](const EncryptedCredentialRecord& record)
            {
                return record.id == id;
            }
        );

        if (it == proposed.records.end())
        {
            throw std::runtime_error("Vault record inventory is inconsistent.");
        }

        EncryptedCredentialRecord replacement = encrypt_credential(proposed.header, vault_.key, id, username, password, notes);

        *it = std::move(replacement);

        rebuild_catalog(proposed, nullptr, nullptr, nullptr);

        commit(std::move(proposed));
    }

    // Remove credential

    void VaultService::remove(const SecureText& name)
    {
        ensure_writable();

        const auto index = find_index(name);

        if (!index.has_value())
        {
            throw std::out_of_range("Credential not found.");
        }

        const CredentialId id = vault_.catalog.id_at(*index);

        VaultImage proposed = vault_.image;

        const auto it = std::remove_if(proposed.records.begin(), proposed.records.end(),

            [&](const EncryptedCredentialRecord& record)
            {
                return record.id == id;
            }
        );

        proposed.records.erase(it, proposed.records.end());

        // Rebuild the catalog without the deleted entry
        rebuild_catalog(proposed, nullptr, nullptr, &id);

        commit(std::move(proposed));
    }

    // List Credential Names

    std::size_t VaultService::size() const noexcept
    {
        return vault_.catalog.size();
    }


    std::span<const unsigned char> VaultService::name_at(std::size_t index) const
    {
        return vault_.catalog.name_at(index);
    }
}