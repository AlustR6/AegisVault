#pragma once

#include "aegis/vault_catalog.hpp"
#include "aegis/vault_credential.hpp"
#include "aegis/vault_format.hpp"
#include "aegis/vault_verification.hpp"

#include <cstddef>
#include <filesystem>
#include <span>
#include <vector>

namespace aegis
{
	// Vault file size limits

	inline constexpr std::size_t MAX_CATALOG_DISK_BYTES = 24 + 4 + MAX_CATALOG_PLAINTEXT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;

	inline constexpr std::size_t MAX_CREDENTIAL_DISK_BYTES = 16 + 24 + 4 + MAX_CREDENTIAL_PLAINTEXT_BYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES;

	inline constexpr std::size_t MAX_VAULT_FILE_BYTES = VAULT_HEADER_SIZE + VAULT_VERIFICATION_RECORD_SIZE + MAX_CATALOG_DISK_BYTES + 4 + MAX_CATALOG_ENTRIES + MAX_CREDENTIAL_DISK_BYTES;

	// Encrypted vault image

	struct VaultImage
	{
		VaultHeader header{};

		VaultVerificationRecord verification{};

		EncryptedCatalog catalog{};

		std::vector<EncryptedCredentialRecord> records;
	};

	// Authenticated unlocked vault

	struct UnlockedVault
	{
		VaultImage image;

		SecureBuffer key;

		DecryptedCatalog catalog;
	};

	// Binary Encoding

	[[nodiscard]] std::vector<unsigned char> serialize_vault_image(const VaultImage& image);

	// Binary decoding

	[[nodiscard]] VaultImage deserialize_vault_image(std::span<const unsigned char> bytes);

	// Read untrusted encrypted file

	[[nodiscard]] VaultImage read_vault_file(const std::filesystem::path& path);

	// Create new vault

	void create_new_vault(const std::filesystem::path& path, const SecureText& password, const KdfParameters& parameters = {});

	// Open and authenticate the existing vault

	[[nodiscard]] UnlockedVault open_vault(const std::filesystem::path& path, const SecureText& password);

	// Save updated vault

	void save_vault(const std::filesystem::path& path, const VaultImage& image, const SecureBuffer& key);
}