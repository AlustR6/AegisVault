#include "aegis/crypto.hpp"

#include <sodium.h>

#include <cstddef>
#include <limits>
#include <stdexcept>

namespace aegis
{
	namespace
	{
		//Validate KDF params before passing them to libsodium
		void validate_kdf_parameters(const KdfParameters& parameters)
		{
			if (parameters.opslimit < crypto_pwhash_OPSLIMIT_INTERACTIVE || parameters.opslimit > crypto_pwhash_OPSLIMIT_SENSITIVE)
			{
				throw std::invalid_argument("Argon2id operations limit is outside the supported range.");
			}

			if (parameters.memlimit_bytes < crypto_pwhash_MEMLIMIT_INTERACTIVE || parameters.memlimit_bytes > crypto_pwhash_MEMLIMIT_SENSITIVE)
			{
				throw std::invalid_argument("Argon2id memory limit is outside the supported range.");
			}

			if (parameters.memlimit_bytes > std::numeric_limits<std::size_t>::max())
			{
				throw std::invalid_argument("Argon2id memory limit exceeds platfrom capabilities.");
			}
		}
	}

	VaultSalt generate_salt()
	{
		VaultSalt salt{};

		//Fill the salt with secure random bytes
		randombytes_buf(salt.data(), salt.size());

		return salt;
	}

	SecureBuffer derive_master_key(const SecureText& password, const VaultSalt& salt, const KdfParameters& parameters)
	{
		validate_kdf_parameters(parameters);

		// Reject empty master passwords
		if (password.empty())
		{
			throw std::invalid_argument("Master password cannot be empty.");
		}

		// Enforce our application's maximum password size
		SecureBuffer key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

		//Derive the encryption using Argon2id
		const int result = crypto_pwhash(
			key.data(),
			static_cast<unsigned long long>(key.size()),

			reinterpret_cast<const char*>(password.data()),
			static_cast<unsigned long long>(password.size()),

			salt.data(),

			static_cast<unsigned long long>(parameters.opslimit),
			static_cast<std::size_t>(parameters.memlimit_bytes),

			crypto_pwhash_ALG_ARGON2ID13);

		// Don't use key if derivation failed
		if (result != 0)
		{
			throw std::runtime_error("Argon2id key derivation failed.");
		}

		return key;
	}
}

namespace aegis
{
	namespace
	{
		// Max plaintext size supported
		constexpr std::size_t MAX_RECORD_SIZE = 1024 * 1024;

		// Maximum associated data size
		constexpr std::size_t MAX_AAD_SIZE = 4096;

		constexpr std::size_t AUTH_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

		void validate_encryption_key(const SecureBuffer& key)
		{
			constexpr std::size_t REQUIRED_KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
			
			if (key.size() != REQUIRED_KEY_SIZE)
			{
				throw std::invalid_argument("Invalid enxryption key size.");
			}
		}

		void validate_associated_data(std::span<const unsigned char> associated_data)
		{
			if (associated_data.empty() || associated_data.size() > MAX_AAD_SIZE)
			{
				throw std::invalid_argument("Invalid associated data.");
			}
		}
	}

	EncryptedBlob encrypt_record(const SecureBuffer& key, const SecureBuffer& plaintext, std::span<const unsigned char> associated_data)
	{
		//Validate the encryption key
		validate_encryption_key(key);

		//Every encrypted record must be bound to metadata
		validate_associated_data(associated_data);

		//Reject empty or exessively large plaintext records.
		if (plaintext.empty() || plaintext.size() > MAX_RECORD_SIZE)
		{
			throw std::invalid_argument("Invalid plaintext size.");
		}

		EncryptedBlob encrypted;

		//Generate a fresh 24 byte nonce
		randombytes_buf(encrypted.nonce.data(), encrypted.nonce.size());

		//Allocate space for ciphertext and the auth tag
		encrypted.ciphertext.resize(plaintext.size() + AUTH_TAG_SIZE);

		unsigned long long ciphertext_length = 0;

		// Perfrom authenticated encryption

		const int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
			encrypted.ciphertext.data(),
			&ciphertext_length,

			plaintext.data(),
			static_cast<unsigned long long>(plaintext.size()),

			associated_data.data(),
			static_cast<unsigned long long>(associated_data.size()),

			nullptr,
			encrypted.nonce.data(),
			key.data()
		);

		// Reject any failure
		if (result != 0)
		{
			throw std::runtime_error("Authenticated encryption failed.");
		}

		if (ciphertext_length != static_cast<unsigned long long>(encrypted.ciphertext.size()))
		{
			throw std::runtime_error("Unexpected encrypted record length.");
		}

		return encrypted;
	}

	SecureBuffer decrypt_record(const SecureBuffer& key, const EncryptedBlob& encrypted, std::span<const unsigned char> associated_data)
	{
		validate_encryption_key(key);

		validate_associated_data(associated_data);

		if (encrypted.ciphertext.size() <= AUTH_TAG_SIZE || encrypted.ciphertext.size() > MAX_RECORD_SIZE + AUTH_TAG_SIZE)
		{
			throw std::invalid_argument("Invalid enrypted record size.");
		}

		// Determine the max possible plaintext length
		const std::size_t plaintext_size = encrypted.ciphertext.size() - AUTH_TAG_SIZE;

		// Allocate protected memory for decrypted data
		SecureBuffer plaintext(plaintext_size);

		unsigned long long decrypted_length = 0;

		// Authenticate and decrypt the record
		const int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
			plaintext.data(),
			&decrypted_length,

			nullptr,

			encrypted.ciphertext.data(),
			static_cast<unsigned long long>(encrypted.ciphertext.size()),

			associated_data.data(),
			static_cast<unsigned long long>(associated_data.size()),

			encrypted.nonce.data(),
			key.data()
		);

		// Auth failue means the data cant be trusted
		if (result != 0)
		{
			throw std::runtime_error("Incorrect key or corrupted/tampered data.");
		}

		// Validate the decrypted output length
		if (decrypted_length != static_cast<unsigned long long>(plaintext_size))
		{
			throw std::runtime_error("Incorrect key or corrupted/tampered data.");
		}

		return plaintext;
	}
}