#pragma once

#include "aegis/crypto.hpp"
#include "aegis/secure_text.hpp"
#include "aegis/vault_credential.hpp"
#include "aegis/vault_format.hpp"

#include <sodium.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace aegis
{
	// Catalog constants

	inline constexpr std::uint16_t CATALOG_SCHEMA_VERSION = 1;
	inline constexpr std::size_t MAX_CATALOG_ENTRIES = 256;
	inline constexpr std::size_t MAX_ENTRY_NAME_BYTES = 128;
	inline constexpr std::size_t CATALOG_HASH_SIZE = crypto_generichash_BYTES;
	inline constexpr std::size_t MAX_CATALOG_PLAINTEXT_BYTES = 6 + MAX_CATALOG_ENTRIES * (16 + 2 + MAX_ENTRY_NAME_BYTES + CATALOG_HASH_SIZE);

	// Catalog types

	using RecordHash = std::array<unsigned char, CATALOG_HASH_SIZE>;

	struct CatalogInput
	{
		const SecureText& name;
		const EncryptedCredentialRecord& record;
	};

	struct EncryptedCatalog
	{
		EncryptedBlob encrypted;
	};

	// Decrypted catalog

	class DecryptedCatalog
	{
	public:

		DecryptedCatalog(const DecryptedCatalog&) = delete;

		DecryptedCatalog& operator=(const DecryptedCatalog&) = delete;

		DecryptedCatalog(DecryptedCatalog&&) noexcept = default;

		DecryptedCatalog& operator=(DecryptedCatalog&&) noexcept = default;

		[[nodiscard]] static DecryptedCatalog from_plaintext(SecureBuffer plaintext);

		[[nodiscard]] std::size_t size() const noexcept;

		[[nodiscard]] std::span<const unsigned char> name_at(std::size_t index) const;

		[[nodiscard]] const CredentialId& id_at(std::size_t index) const;

		// Validate the collection of records

		void verify_records(std::span<const EncryptedCredentialRecord> records) const;

	private:

		struct IndexEntry
		{
			CredentialId id{};

			RecordHash hash{};

			std::size_t name_offset = 0;

			std::size_t name_length = 0;
		};

		DecryptedCatalog(SecureBuffer plaintext, std::vector<IndexEntry> entries) noexcept;

		SecureBuffer plaintext_;

		std::vector<IndexEntry> entries_;
	};

	// Record hashing

	[[nodiscard]] RecordHash hash_credential_record(const EncryptedCredentialRecord& record);

	// Catalog encryption

	[[nodiscard]] EncryptedCatalog encrypt_catalog(const VaultHeader& header, const SecureBuffer& key, std::span<const CatalogInput> entries);

	// Catalog decryption

	[[nodiscard]] DecryptedCatalog decrypt_catalog(const VaultHeader& header, const SecureBuffer& key, const EncryptedCatalog& catalog);

	// Binary serialization

	[[nodiscard]] std::vector<unsigned char> serialize_catalog_record(const EncryptedCatalog& catalog);

	[[nodiscard]] EncryptedCatalog deserialize_catalog_record(std::span<const unsigned char> bytes);
}