#pragma once

#include "aegis/crypto.hpp"
#include "aegis/secure_text.hpp"
#include "aegis/vault_format.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace aegis
{
	// Credential format constants

	inline constexpr std::uint16_t CREDENTIAL_SCHEMA_VERSION = 1;

	inline constexpr std::size_t MAX_USERNAME_BYTES = 4096;
	inline constexpr std::size_t MAX_PASSWORD_BYTES = 4096;
	inline constexpr std::size_t MAX_NOTES_BYTES = 65536;

	inline constexpr std::size_t MAX_CREDENTIAL_PLAINTEXT_BYTES = 2 + 12 + MAX_USERNAME_BYTES + MAX_PASSWORD_BYTES + MAX_NOTES_BYTES;

	// Credential identifier

	using CredentialId = std::array<unsigned char, 16>;

	// Encrypted credential

	struct EncryptedCredentialRecord
	{
		CredentialId id{};
		EncryptedBlob encrypted;
	};

	// Decrypted credential

	class DecryptedCredential
	{
	public:

		DecryptedCredential(const DecryptedCredential&) = delete;

		DecryptedCredential& operator=(const DecryptedCredential&) = delete;

		DecryptedCredential(DecryptedCredential&&) noexcept = default;

		DecryptedCredential& operator=(DecryptedCredential&&) noexcept = default;

		// Parse an existing protected plaintext buffer
		[[nodiscard]] static DecryptedCredential from_plaintext(SecureBuffer plaintext);

		// Read only views into the protected allocation
		[[nodiscard]] std::span<const unsigned char> username() const noexcept;

		[[nodiscard]] std::span<const unsigned char> password() const noexcept;

		[[nodiscard]] std::span<const unsigned char> notes() const noexcept;

	private:

		struct FieldRange
		{
			std::size_t offset = 0;
			std::size_t length = 0;
		};

		DecryptedCredential(SecureBuffer plaintext, FieldRange username, FieldRange password, FieldRange notes) noexcept;

		[[nodiscard]] std::span<const unsigned char> slice(FieldRange range) const noexcept;

		SecureBuffer plaintext_;

		FieldRange username_;
		FieldRange password_;
		FieldRange notes_;
	};

	// Credential ID generation

	[[nodiscard]] CredentialId generate_credential_id();

	// Credential encryption

	[[nodiscard]] EncryptedCredentialRecord encrypt_credential(const VaultHeader& header, const SecureBuffer& key, const CredentialId& id, const SecureText& usernname, const SecureText& password, const SecureText& notes);

	// Credential decryption

	[[nodiscard]] DecryptedCredential decrypt_credential(const VaultHeader& header, const SecureBuffer& key, const EncryptedCredentialRecord& record);

	// Encrypted record serialization

	[[nodiscard]] std::vector<unsigned char> serialize_credential_record(const EncryptedCredentialRecord& record);

	// Enrypted record deserialization

	[[nodiscard]] EncryptedCredentialRecord deserialize_credential_record(std::span<const unsigned char> bytes);
}