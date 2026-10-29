#include "aegis/vault_credential.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace aegis
{
	namespace
	{
		// Internal constants
		constexpr unsigned char CREDENTIAL_RECORD_TYPE = 0x03;

		constexpr std::size_t CREDENTIAL_AAD_SIZE = VAULT_HEADER_SIZE + 1 + 16;

		constexpr std::size_t ENTRY_ID_SIZE = 16;

		constexpr std::size_t NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

		constexpr std::size_t AUTH_TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES;

		// Entry ID + Nonce + ciphertext length
		constexpr std::size_t ENCRYPTED_RECORD_PREFIX_SIZE = ENTRY_ID_SIZE + NONCE_SIZE + 4;

		using CredentialAad = std::array<unsigned char, CREDENTIAL_AAD_SIZE>;

		// Write LE integers
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

		// Read LE
		std::uint16_t read_u16(std::span<const unsigned char> source, std::size_t& offset)
		{
			if (offset > source.size() || source.size() - offset < 2)
			{
				throw std::runtime_error("Invalid decrypted credential layout.");
			}

			std::uint16_t value = 0;

			for (std::size_t i = 0; i < 2; ++i)
			{
				value |= static_cast<std::uint16_t>(source[offset++]) << (i * 8);
			}

			return value;
		}

		std::uint32_t read_u32(std::span<const unsigned char> source, std::size_t& offset)
		{
			if (offset > source.size() || source.size() - offset < 4)
			{
				throw std::runtime_error("Invalid decrypted credential layout.");
			}

			std::uint32_t value = 0;

			for (std::size_t i = 0; i < 4; ++i)
			{
				value |= static_cast<std::uint32_t>(source[offset++]) << (i * 8);
			}

			return value;
		}

		// Validate credential fields

		void validate_fields(const SecureText& username, const SecureText& password, const SecureText& notes)
		{
			if (username.size() > MAX_USERNAME_BYTES)
			{
				throw std::invalid_argument("Username exceeds maximum length.");
			}

			if (password.empty() || password.size() > MAX_PASSWORD_BYTES)
			{
				throw std::invalid_argument("Invalid password length.");
			}

			if (notes.size() > MAX_NOTES_BYTES)
			{
				throw std::invalid_argument("Notes exceed maximum length.");
			}
		}

		// Append protected text to a protected buffer

		void append_text(unsigned char* destination, std::size_t& offset, const SecureText& text)
		{
			write_u32(destination, offset, static_cast<std::uint32_t>(text.size()));

			if (!text.empty())
			{
				std::copy_n(text.data(), text.size(), destination + offset);
			}

			offset += text.size();
		}

		// Serialize plaintext credential

		SecureBuffer serialize_plaintext(const SecureText& username, const SecureText& password, const SecureText& notes)
		{
			validate_fields(username, password, notes);

			const std::size_t total_size = 2 + 12 + username.size() + password.size() + notes.size();

			// Allocated protected memory for the whole credential

			SecureBuffer plaintext(total_size);

			std::size_t offset = 0;

			// Credential schema version

			write_u16(plaintext.data(), offset, CREDENTIAL_SCHEMA_VERSION);

			// Length prefixed credential fields

			append_text(plaintext.data(), offset, username);
			append_text(plaintext.data(), offset, password);
			append_text(plaintext.data(), offset, notes);

			return plaintext;
		}

		// Build authenticated credential metadata

		CredentialAad build_credential_aad(const VaultHeader& header, const CredentialId& id)
		{
			const VaultHeaderBytes serialized_header = serialize_header(header);

			CredentialAad aad{};

			// Authenticate the complete header
			std::copy(serialized_header.begin(), serialized_header.end(), aad.begin());

			// Authenticate record type
			aad[VAULT_HEADER_SIZE] = CREDENTIAL_RECORD_TYPE;

			// Authenticate the credential identifier
			std::copy(id.begin(), id.end(), aad.begin() + VAULT_HEADER_SIZE + 1);

			return aad;
		}

		// Validate record size

		void validate_enrypted_size(std::size_t size)
		{
			if (size <= AUTH_TAG_SIZE || size > MAX_CREDENTIAL_PLAINTEXT_BYTES + AUTH_TAG_SIZE)
			{
				throw std::runtime_error("Invalid encrypted credential size.");
			}
		}
	}

	// Generate credential ID

	CredentialId generate_credential_id()
	{
		CredentialId id{};

		randombytes_buf(id.data(), id.size());

		return id;
	}

	// DecryptedCredential constructor

	DecryptedCredential::DecryptedCredential(SecureBuffer plaintext, FieldRange username, FieldRange password, FieldRange notes) noexcept :
		plaintext_(std::move(plaintext)), username_(username), password_(password), notes_(notes) { }

	// Parse Decrypted credential

	DecryptedCredential DecryptedCredential::from_plaintext(SecureBuffer plaintext)
	{
		if (plaintext.empty() || plaintext.size() > MAX_CREDENTIAL_PLAINTEXT_BYTES)
		{
			throw std::runtime_error("Invalid decrypted credential size.");
		}

		const std::span<const unsigned char> bytes(plaintext.data(), plaintext.size());

		std::size_t offset = 0;

		// Read schema version

		const std::uint16_t version = read_u16(bytes, offset);

		if (version != CREDENTIAL_SCHEMA_VERSION)
		{
			throw std::runtime_error("Unsupported credential schema version.");
		}

		// Parse one length prefixed field

		auto read_field = [&](std::size_t maximum, bool require_nonempty) -> FieldRange
			{
				const std::uint32_t length = read_u32(bytes, offset);

				if (length > maximum || require_nonempty && length == 0)
				{
					throw std::runtime_error("Invalid decrypted credential field length.");
				}

				if (offset > bytes.size() || length > bytes.size() - offset)
				{
					throw std::runtime_error("Truncated decrypted credential.");
				}

				FieldRange range{ offset, static_cast<std::size_t>(length) };

				offset += length;

				return range;
			};

		// Parse all fields

		const FieldRange username = read_field(MAX_USERNAME_BYTES, false);

		const FieldRange password = read_field(MAX_PASSWORD_BYTES, true);

		const FieldRange notes = read_field(MAX_NOTES_BYTES, false);

		// Reject unexpected trailing data

		if (offset != bytes.size())
		{
			throw std::runtime_error("Unexpected trailing credential data.");
		}

		return DecryptedCredential(std::move(plaintext), username, password, notes);
	}

	// Return read only field view

	std::span<const unsigned char> DecryptedCredential::slice(FieldRange range) const noexcept
	{
		if (plaintext_.empty())
		{
			return {};
		}

		return std::span<const unsigned char>(plaintext_.data() + range.offset, range.length);
	}

	std::span<const unsigned char> DecryptedCredential::username() const noexcept
	{
		return slice(username_);
	}

	std::span<const unsigned char> DecryptedCredential::password() const noexcept
	{
		return slice(password_);
	}

	std::span<const unsigned char> DecryptedCredential::notes() const noexcept
	{
		return slice(notes_);
	}

	// Encrypt credential

	EncryptedCredentialRecord encrypt_credential(const VaultHeader& header, const SecureBuffer& key,
		const CredentialId& id, const SecureText& username, const SecureText& password, const SecureText& notes)
	{
		// Serialize sensitive fields directly into protected memory

		SecureBuffer plaintext = serialize_plaintext(username, password, notes);

		// Construct authenticated metadata
		
		const CredentialAad aad = build_credential_aad(header, id);

		// Encrypt 

		EncryptedBlob encrypted = encrypt_record(key, plaintext, std::span<const unsigned char>(aad));

		EncryptedCredentialRecord record;

		record.id = id;
		record.encrypted = std::move(encrypted);

		return record;
	}

	// Decrypt 

	DecryptedCredential decrypt_credential(const VaultHeader& header, const SecureBuffer& key, const EncryptedCredentialRecord& record)
	{
		// Reconstruct metadata

		const CredentialAad aad = build_credential_aad(header, record.id);

		// Authenticated decryption into protected memory
		
		SecureBuffer plaintext = decrypt_record(key, record.encrypted, std::span<const unsigned char>(aad));

		// Parse without copying

		return DecryptedCredential::from_plaintext(std::move(plaintext));
	}

	// Serialize

	std::vector<unsigned char> serialize_credential_record(const EncryptedCredentialRecord& record)
	{
		const std::size_t ciphertext_size = record.encrypted.ciphertext.size();

		validate_enrypted_size(ciphertext_size);

		// Cipher text is public encrypted data

		std::vector<unsigned char> bytes(ENCRYPTED_RECORD_PREFIX_SIZE + ciphertext_size);

		std::size_t offset = 0;

		// Write entry identifier
		
		std::copy(record.id.begin(), record.id.end(), bytes.begin());

		offset += ENTRY_ID_SIZE;

		// Write nonce

		std::copy(record.encrypted.nonce.begin(), record.encrypted.nonce.end(), bytes.begin() + offset);

		offset += NONCE_SIZE;

		// Write ciphertext length as int32 LE

		write_u32(bytes.data(), offset, static_cast<std::uint32_t>(ciphertext_size));

		// write authenticated ciphertext

		std::copy(record.encrypted.ciphertext.begin(), record.encrypted.ciphertext.end(), bytes.begin() + offset);

		return bytes;
	}

	// Deserialize

	EncryptedCredentialRecord deserialize_credential_record(std::span<const unsigned char> bytes)
	{
		// Check the fixed size prefix before reading

		if (bytes.size() < ENCRYPTED_RECORD_PREFIX_SIZE)
		{
			throw std::runtime_error("Truncated encrypted credential record.");
		}

		EncryptedCredentialRecord record;

		std::size_t offset = 0;

		// Read credential identifier

		std::copy_n(bytes.begin(), ENTRY_ID_SIZE, record.id.begin());

		offset += ENTRY_ID_SIZE;

		// Read nonce
		std::copy_n(bytes.begin() + offset, NONCE_SIZE, record.encrypted.nonce.begin());

		offset += NONCE_SIZE;

		// Read declard ciphertext length

		const std::uint32_t ciphertext_length = read_u32(bytes, offset);

		validate_enrypted_size(ciphertext_length);

		// The length must match remaining bytes exactly

		if (bytes.size() - offset != ciphertext_length)
		{
			throw std::runtime_error("Encrypted credential length mismatch.");
		}

		// Cipher text can be stored in ordinary memory

		record.encrypted.ciphertext.assign(bytes.begin() + offset, bytes.end());

		return record;
	}
}