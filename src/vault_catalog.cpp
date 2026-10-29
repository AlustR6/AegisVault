#pragma once

#include "aegis/crypto.hpp"
#include "aegis/secure_text.hpp"
#include "aegis/vault_credential.hpp"
#include "aegis/vault_format.hpp"
#include "aegis/vault_catalog.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>
#include <stdexcept>


namespace aegis
{
	namespace
	{
		// Internal constants

		constexpr unsigned char CATALOG_RECORD_TYPE = 0x02;

		constexpr std::size_t CATALOG_AAD_SIZE = VAULT_HEADER_SIZE + 1;

		constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

		constexpr std::size_t TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

		constexpr std::size_t CATALOG_PREFIX_SIZE = NONCE_SIZE + 4;

		constexpr std::size_t MIN_CATALOG_PLAINTEXT_SIZE = 6;

		using CatalogAad = std::array<unsigned char, CATALOG_AAD_SIZE>;

		// Bounds checking

		void require_bytes(std::span<const unsigned char> source, std::size_t offset, std::size_t count)
		{
			if (offset > source.size() || count > source.size() - offset)
			{
				throw std::runtime_error("Invalid or truncated catalog");
			}
		}

		// LE writing

		void write_u16(unsigned char* destination, std::size_t& offset, std::uint16_t value)
		{
			for (std::size_t i = 0; i < 2; ++i)
			{
				destination[offset++] = static_cast<unsigned char>((value >> (i * 8)) & 0xFF);
			}
		}

		void write_u32(unsigned char* destination, std::size_t& offset, std::uint32_t value)
		{
			for (std::size_t i = 0; i < 4; ++i)
			{
				destination[offset++] = static_cast<unsigned char>((value >> (i * 8)) & 0xFF);
			}
		}

		// LE reading

		std::uint16_t read_u16(std::span<const unsigned char> source, std::size_t& offset)
		{
			require_bytes(source, offset, 2);

			std::uint16_t value = 0;

			for (std::size_t i = 0; i < 2; ++i)
			{
				value |= static_cast<std::uint16_t>(source[offset++]) << (i * 8);
			}

			return value;
		}

		std::uint32_t read_u32(std::span<const unsigned char> source, std::size_t& offset)
		{
			require_bytes(source, offset, 4);

			std::uint32_t value = 0;

			for (std::size_t i = 0; i < 4; ++i)
			{
				value |= static_cast<std::uint32_t>(source[offset++]) << (i * 8);
			}

			return value;
		}

		// UTF-8 name validation

		bool valid_name(std::span<const unsigned char> bytes)
		{
			if (bytes.empty() || bytes.size() > MAX_ENTRY_NAME_BYTES)
			{
				return false;
			}

			std::size_t i = 0;

			while (i < bytes.size())
			{
				const unsigned char first = bytes[i];

				std::uint32_t codepoint = 0;
				std::uint32_t minimum = 0;

				std::size_t count = 0;

				if (first <= 0x7F)
				{
					codepoint = first;
					count = 1;
				}
				else if (first >= 0xC2 && first <= 0xDF)
				{
					codepoint = first & 0x1F;
					minimum = 0x80;
					count = 2;
				}
				else if (first >= 0xE0 && first <= 0xEF)
				{
					codepoint = first & 0x0F;
					minimum = 0x800;
					count = 3;
				}
				else if (first >= 0xF0 && first <= 0xF4)
				{
					codepoint = first & 0x07;
					minimum = 0x10000;
					count = 4;
				}
				else
				{
					return false;
				}

				if (count > bytes.size() - i)
				{
					return false;
				}

				for (std::size_t j = 1; j < count; ++j)
				{
					const unsigned char next = bytes[i + j];

					if ((next & 0xC0) != 0x80)
					{
						return false;
					}

					codepoint = (codepoint << 6) | (next & 0x3F);
				}

				// Reject overlong encodings, control chars, surrogate codepoints, and invalid unicode

				if (codepoint < minimum || codepoint < 0x20 || codepoint >= 0x7F && codepoint < 0xA0 || codepoint >= 0xD800 && codepoint <= 0xDFFF || codepoint > 0x10FFFF)
				{
					return false;
				}

				i += count;
			}

			return true;
		}

		// Compare names without making copies

		bool names_equal(std::span<const unsigned char> first, std::span<const unsigned char> second)
		{
			if (first.size() != second.size())
			{
				return false;
			}

			return sodium_memcmp(first.data(), second.data(), first.size()) == 0;
		}

		// Catalog associated data

		CatalogAad build_catalog_aad(const VaultHeader& header)
		{
			const VaultHeaderBytes serialized = serialize_header(header);

			CatalogAad aad{};

			std::copy(serialized.begin(), serialized.end(), aad.begin());

			aad[VAULT_HEADER_SIZE] = CATALOG_RECORD_TYPE;

			return aad;
		}

		// Validate catalog length

		void validate_encrypted_size(std::size_t size)
		{
			if (size < MIN_CATALOG_PLAINTEXT_SIZE + TAG_SIZE || size > MAX_CREDENTIAL_PLAINTEXT_BYTES + TAG_SIZE)
			{
				throw std::runtime_error("Invalid encrypted catalog size.");
			}
		}
	}

	// Calculate credential hash

	RecordHash hash_credential_record(const EncryptedCredentialRecord& record)
	{
		const std::vector<unsigned char> bytes = serialize_credential_record(record);

		RecordHash hash{};

		const int result = crypto_generichash(hash.data(), hash.size(), bytes.data(), static_cast<unsigned long long>(bytes.size()), nullptr, 0);

		if (result != 0)
		{
			throw std::runtime_error("Credential record hashing failed.");
		}

		return hash;
	}

	// Ecnrypt catalog

	EncryptedCatalog encrypt_catalog(const VaultHeader& header, const SecureBuffer& key, std::span<const CatalogInput> entries)
	{
		if (entries.size() > MAX_CATALOG_ENTRIES)
		{
			throw std::invalid_argument("Catalog contains too many entries.");
		}

		// Start with schema version and entry count

		std::size_t plaintext_size = 6;

		for (std::size_t i = 0; i < entries.size(); ++i)
		{
			const CatalogInput& entry = entries[i];

			const std::span<const unsigned char> name(entry.name.data(), entry.name.size());

			if (!valid_name(name))
			{
				throw std::invalid_argument("Invalid catalog entry name.");
			}

			// Reject duplicate ids and duplicate names

			for (std::size_t j = 0; j < i; ++j)
			{
				if (entry.record.id == entries[j].record.id)
				{
					throw std::invalid_argument("Duplicate credential identifier.");
				}

				const std::span<const unsigned char> other_name(entries[j].name.data(), entries[j].name.size());

				if (names_equal(name, other_name))
				{
					throw std::invalid_argument("Duplicate catalog entry name.");
				}
			}

			plaintext_size += 16 + 2 + name.size() + CATALOG_HASH_SIZE;
		}

		// Protects against accidental layout mistakes

		if (plaintext_size > MAX_CATALOG_PLAINTEXT_BYTES)
		{
			throw std::invalid_argument("Catalog exceeds maximum size.");
		}

		// Keep decrypted names and hashes in protected memory

		SecureBuffer plaintext(plaintext_size);

		std::size_t offset = 0;

		write_u16(plaintext.data(), offset, CATALOG_SCHEMA_VERSION);

		write_u32(plaintext.data(), offset, static_cast<std::uint32_t>(entries.size()));

		for (const CatalogInput& entry : entries)
		{
			// Write credential identifier

			std::copy(entry.record.id.begin(), entry.record.id.end(), plaintext.data() + offset);

			offset += entry.record.id.size();

			// Write name length

			write_u16(plaintext.data(), offset, static_cast<std::uint16_t>(entry.name.size()));

			// Write encrypted catalog only name plaintext

			std::copy_n(entry.name.data(), entry.name.size(), plaintext.data() + offset);

			offset += entry.name.size();

			// Hash the corresponding record

			const RecordHash hash = hash_credential_record(entry.record);

			std::copy(hash.begin(), hash.end(), plaintext.data() + offset);

			offset += hash.size();
		}

		// Authenticate the header and catalog record type

		const CatalogAad aad = build_catalog_aad(header);

		EncryptedCatalog catalog;

		catalog.encrypted = encrypt_record(key, plaintext, std::span<const unsigned char>(aad));

		return catalog;
	}

	// DecryptedCatalog constructor

	DecryptedCatalog::DecryptedCatalog(SecureBuffer plaintext, std::vector<IndexEntry> entries) noexcept
		: plaintext_(std::move(plaintext)), entries_(std::move(entries)) {}

	// Parse catalog

	DecryptedCatalog DecryptedCatalog::from_plaintext(SecureBuffer plaintext)
	{
		if (plaintext.size() < MIN_CATALOG_PLAINTEXT_SIZE || plaintext.size() > MAX_CATALOG_PLAINTEXT_BYTES)
		{
			throw std::runtime_error("Invalid catalog plaintext size.");
		}

		const std::span<const unsigned char> bytes(plaintext.data(), plaintext.size());

		std::size_t offset = 0;

		const std::uint16_t version = read_u16(bytes, offset);

		if (version != CATALOG_SCHEMA_VERSION)
		{
			throw std::runtime_error("Catalog entry count exceeds limit.");
		}

		const std::uint32_t count = read_u32(bytes, offset);

		std::vector<IndexEntry> entries;

		entries.reserve(count);

		for (std::uint32_t i = 0; i < count; ++i)
		{
			IndexEntry entry;

			// Read credential id

			require_bytes(bytes, offset, entry.id.size());

			std::copy_n(bytes.begin() + offset, entry.id.size(), entry.id.begin());

			offset += entry.id.size();

			// Read name length

			const std::uint16_t name_length = read_u16(bytes, offset);

			if (name_length == 0 || name_length > MAX_ENTRY_NAME_BYTES)
			{
				throw std::runtime_error("Invalid catalog name length.");
			}

			require_bytes(bytes, offset, name_length);

			const std::span<const unsigned char> name(bytes.data() + offset, name_length);

			if (!valid_name(name))
			{
				throw std::runtime_error("Invalid UTF-8 catalog name.");
			}

			entry.name_offset = offset;
			entry.name_length = name_length;

			offset += name_length;

			// Read the authenticated record fingerprint

			require_bytes(bytes, offset, entry.hash.size());

			std::copy_n(bytes.begin() + offset, entry.hash.size(), entry.hash.begin());

			offset += entry.hash.size();

			// Reject duplicated identifiers and names

			for (const IndexEntry& previous : entries)
			{
				if (previous.id == entry.id)
				{
					throw std::runtime_error("Duplicate catalog identifier.");
				}

				const std::span<const unsigned char> previous_name(bytes.data() + previous.name_offset, previous.name_length);

				if (names_equal(name, previous_name))
				{
					throw std::runtime_error("Duplicate catalog name.");
				}
			}

			entries.push_back(entry);
		}

		if (offset != bytes.size())
		{
			throw std::runtime_error("Unexpected trailing catalog data.");
		}

		return DecryptedCatalog(std::move(plaintext), std::move(entries));
	}

	// Catalog Accessors

	std::size_t DecryptedCatalog::size() const noexcept
	{
		return entries_.size();
	}

	std::span<const unsigned char> DecryptedCatalog::name_at(std::size_t index) const
	{
		if (plaintext_.empty())
		{
			throw std::runtime_error("Catalog no longer owns plaintext.");
		}

		const IndexEntry& entry = entries_.at(index);

		return std::span<const unsigned char>(plaintext_.data() + entry.name_offset, entry.name_length);
	}

	const CredentialId& DecryptedCatalog::id_at(std::size_t index) const
	{
		return entries_.at(index).id;
	}

	// Verify the entire record collection

	void DecryptedCatalog::verify_records(std::span<const EncryptedCredentialRecord> records) const
	{
		if (records.size() != entries_.size())
		{
			throw std::runtime_error("Vault corrupted or tampered.");
		}

		// Detect duplicate ids in the actual record collection

		for (std::size_t i = 0; i < records.size(); ++i)
		{
			for (std::size_t j = 0; j < i; ++j)
			{
				if (records[i].id == records[j].id)
				{
					throw std::runtime_error("Vault corrupted or tampered.");
				}
			}
		}

		for (const IndexEntry& expected : entries_)
		{
			const EncryptedCredentialRecord* found = nullptr;

			for (const EncryptedCredentialRecord& record : records)
			{
				if (record.id == expected.id)
				{
					found = &record;
					break;
				}
			}

			if (found == nullptr)
			{
				throw std::runtime_error("Vault corrupted or tampered.");
			}

			const RecordHash actual_hash = hash_credential_record(*found);

			if (sodium_memcmp(expected.hash.data(), actual_hash.data(), expected.hash.size()) != 0)
			{
				throw std::runtime_error("Vault corrupted or tampered.");
			}
		}
	}

	DecryptedCatalog decrypt_catalog(const VaultHeader& header, const SecureBuffer& key, const EncryptedCatalog& catalog)
	{
		validate_encrypted_size(catalog.encrypted.ciphertext.size());

		const CatalogAad aad = build_catalog_aad(header);

		SecureBuffer plaintext = decrypt_record(key, catalog.encrypted, std::span<const unsigned char>(aad));

		return DecryptedCatalog::from_plaintext(std::move(plaintext));
	}

	// Serialize catalog

	std::vector<unsigned char> serialize_catalog_record(const EncryptedCatalog& catalog)
	{
		const std::size_t ciphertext_size = catalog.encrypted.ciphertext.size();

		validate_encrypted_size(ciphertext_size);

		std::vector<unsigned char> bytes(CATALOG_PREFIX_SIZE + ciphertext_size);

		std::size_t offset = 0;

		// Write nonce

		std::copy(catalog.encrypted.nonce.begin(), catalog.encrypted.nonce.end(), bytes.begin());

		offset += NONCE_SIZE;

		// Write ciphertext length including authentication tag

		write_u32(bytes.data(), offset, static_cast<std::uint32_t>(ciphertext_size));

		// Write cipher text and the authentication tag

		std::copy(catalog.encrypted.ciphertext.begin(), catalog.encrypted.ciphertext.end(), bytes.begin() + offset);

		return bytes;
	}

	// Deserialize catalog

	EncryptedCatalog deserialize_catalog_record(std::span<const unsigned char> bytes)
	{
		if (bytes.size() < CATALOG_PREFIX_SIZE)
		{
			throw std::runtime_error("Trucated encrypted catalog.");
		}

		EncryptedCatalog catalog;

		std::size_t offset = 0;

		std::copy_n(bytes.begin(), NONCE_SIZE, catalog.encrypted.nonce.begin());

		offset += NONCE_SIZE;

		const std::uint32_t ciphertext_size = read_u32(bytes, offset);

		validate_encrypted_size(ciphertext_size);

		if (bytes.size() - offset != ciphertext_size)
		{
			throw std::runtime_error("Encrypted catalog length mismatch.");
		}

		catalog.encrypted.ciphertext.assign(bytes.begin() + offset, bytes.end());

		return catalog;
	}
}