#pragma once

#include "aegis/crypto.hpp"
#include "aegis/vault_format.hpp"

#include <array>
#include <cstddef>
#include <span>

namespace aegis
{
	// Verification record constants
	inline constexpr std::size_t VAULT_VERIFICATION_MARKER_SIZE = 16;

	inline constexpr std::size_t VAULT_VERIFICATION_CIPHERTEXT_SIZE = VAULT_VERIFICATION_MARKER_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES;

	inline constexpr std::size_t VAULT_VERIFICATION_RECORD_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + VAULT_VERIFICATION_CIPHERTEXT_SIZE;

	// Verification record types

	using VaultVerificationBytes = std::array<unsigned char, VAULT_VERIFICATION_RECORD_SIZE>;

	struct VaultVerificationRecord
	{
		AeadNonce nonce{};

		std::array<unsigned char, VAULT_VERIFICATION_CIPHERTEXT_SIZE> ciphertext{};
	};

	// Verification record creation

	[[nodiscard]] VaultVerificationRecord create_verification_record(const VaultHeader& header, const SecureBuffer& key);

	// Master key verification

	void verify_master_key(const VaultHeader& header, const SecureBuffer& key, const VaultVerificationRecord& record);

	// Verification record serialization

	[[nodiscard]] VaultVerificationBytes serialize_verification_record(const VaultVerificationRecord& record);

	// Verification record deserialization

	[[nodiscard]] VaultVerificationRecord deserialize_verification_record(std::span<const unsigned char> bytes);

	// Password unlocking

	[[nodiscard]] SecureBuffer unlock_master_key(const VaultHeader& header, const SecureText& password, const VaultVerificationRecord& record);
}