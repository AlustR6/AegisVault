#include "aegis/vault_verification.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <stdexcept>

namespace aegis
{
	namespace
	{
		// Internal constants
		constexpr std::array<unsigned char, VAULT_VERIFICATION_MARKER_SIZE> VERIFICATION_MARKER = { 'A', 'E', 'G', 'I', 'S', '-', 'V', 'E', 'R', 'I', 'F', 'Y', '-', '0', '0', '1' };

		constexpr unsigned char VERIFICATION_RECORD_TYPE = 0x01;

		constexpr std::size_t VERIFICATION_AAD_SIZE = VAULT_HEADER_SIZE + 1;

		constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

		using VerificationAad = std::array<unsigned char, VERIFICATION_AAD_SIZE>;

		static_assert(VAULT_VERIFICATION_RECORD_SIZE == 56);

		// Build associated authenticated data

		VerificationAad build_verification_aad(const VaultHeader& header)
		{
			const VaultHeaderBytes serialized_header = serialize_header(header);

			VerificationAad aad{};

			// Copy the serialized header
			std::copy(serialized_header.begin(), serialized_header.end(), aad.begin());

			// Bind the ciphertext to its record type
			aad[VAULT_HEADER_SIZE] = VERIFICATION_RECORD_TYPE;

			return aad;
		}

		// Convert verification record to EncryptedBlob

		EncryptedBlob make_encrypted_blob(const VaultVerificationRecord& record)
		{
			EncryptedBlob encrypted;

			encrypted.nonce = record.nonce;

			encrypted.ciphertext.assign(record.ciphertext.begin(), record.ciphertext.end());

			return encrypted;
		}
	}

	// Create verification record

	VaultVerificationRecord create_verification_record(const VaultHeader& header, const SecureBuffer& key)
	{
		// Construct authenticated metadata
		const VerificationAad aad = build_verification_aad(header);

		// Allocate protected memory for the verification marker
		SecureBuffer plaintext(VAULT_VERIFICATION_MARKER_SIZE);

		// Copy the marker into protected memory
		std::copy(VERIFICATION_MARKER.begin(), VERIFICATION_MARKER.end(), plaintext.data());

		// Encrypt
		EncryptedBlob encrypted = encrypt_record(key, plaintext, std::span<const unsigned char>(aad));

		// Make sure the output matches the file format
		if (encrypted.ciphertext.size() != VAULT_VERIFICATION_CIPHERTEXT_SIZE)
		{
			throw std::runtime_error("Unexpected verification record size.");
		}

		VaultVerificationRecord record;

		record.nonce = encrypted.nonce;

		std::copy(encrypted.ciphertext.begin(), encrypted.ciphertext.end(), record.ciphertext.begin());

		return record;
	}

	// Verify key

	void verify_master_key(const VaultHeader& header, const SecureBuffer& key, const VaultVerificationRecord& record)
	{
		const VerificationAad aad = build_verification_aad(header);
		const EncryptedBlob encrypted = make_encrypted_blob(record);

		// Attempt decryption using the same public error for auth failures
		try
		{
			SecureBuffer plaintext = decrypt_record(key, encrypted, std::span<const unsigned char>(aad));

			if (plaintext.size() != VERIFICATION_MARKER.size())
			{
				throw std::runtime_error("Incorrect password or corrupted vault.");
			}

			// Compare the marker using libsodium
			const int comparison = sodium_memcmp(plaintext.data(), VERIFICATION_MARKER.data(), VERIFICATION_MARKER.size());

			if (comparison != 0)
			{
				throw std::runtime_error("Incorrect password or corrupted vault.");
			}
		}
		catch (const std::runtime_error&)
		{
			throw std::runtime_error("Incorrect password or corrupted vault.");
		}
	}

	// Serialize verification record
	
	VaultVerificationBytes serialize_verification_record(const VaultVerificationRecord& record)
	{
		VaultVerificationBytes bytes{};

		// First 24 bytes contain the nonce
		std::copy(record.nonce.begin(), record.nonce.end(), bytes.begin());

		// Remaining contain the ciphertext + auth key
		std::copy(record.ciphertext.begin(), record.ciphertext.end(), bytes.begin() + NONCE_SIZE);

		return bytes;
	}

	// Deserialize verification record

	VaultVerificationRecord deserialize_verification_record(std::span<const unsigned char> bytes)
	{
		// The record must contain exactly 16 bytes

		if (bytes.size() != VAULT_VERIFICATION_RECORD_SIZE)
		{
			throw std::runtime_error("Invalid vault verification record length.");
		}

		VaultVerificationRecord record;

		// Read the 24 byte nonce

		std::copy_n(bytes.begin(), record.nonce.size(), record.nonce.begin());

		// Read the ciphertext and auth key

		std::copy_n(bytes.begin() + NONCE_SIZE, record.ciphertext.size(), record.ciphertext.begin());

		return record;
	}

	// Unlock master key

	SecureBuffer unlock_master_key(const VaultHeader& header, const SecureText& password, const VaultVerificationRecord& record)
	{
		// Reproduce the key using the params stored in the header
		
		SecureBuffer key = derive_master_key(password, header.salt, header.kdf);

		// Reject the key if it cant authenticate the record
		verify_master_key(header, key, record);

		// Return the verified encryption key
		return key;
	}
}