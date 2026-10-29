#pragma once

#include "aegis/secure_buffer.hpp"
#include "aegis/secure_text.hpp"

#include <sodium.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace aegis
{
	//Fixed salt size used for Argon2id
	using VaultSalt = std::array<unsigned char, crypto_pwhash_SALTBYTES>;

	// Params controlling the computational cost of Argon
	struct KdfParameters
	{
		std::uint64_t opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE;

		std::uint64_t memlimit_bytes = crypto_pwhash_MEMLIMIT_SENSITIVE;
	};

	//Generate a cryptographically random salt
	[[nodiscard]] VaultSalt generate_salt();

	//Derive a 256 bit key from a master password
	[[nodiscard]] SecureBuffer derive_master_key(const SecureText& password, const VaultSalt& salt, const KdfParameters& parameters = {});

	using AeadNonce = std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

	struct EncryptedBlob
	{
		AeadNonce nonce{};

		//Contains encrypted data followed by the auth tag.
		std::vector<unsigned char> ciphertext;
	};

	// Authenticated encryption functions

	[[nodiscard]] EncryptedBlob encrypt_record(const SecureBuffer& key, const SecureBuffer& plaintext, std::span<const unsigned char> associiated_data);

	[[nodiscard]] SecureBuffer decrypt_record(const SecureBuffer& key, const EncryptedBlob& encrypted, std::span<const unsigned char> associated_data);
}