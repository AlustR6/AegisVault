#include "aegis/vault_format.hpp"

#include <sodium.h>

#include <algorithm>
#include <climits>
#include <limits>
#include <stdexcept>

namespace aegis
{
	namespace
	{
		// Compile time validation
		static_assert(CHAR_BIT == 8);
		static_assert(crypto_pwhash_SALTBYTES == 16);

		// Binary format constants

		constexpr std::array<unsigned char, 8> MAGIC = { 'A', 'E', 'G', 'I', 'S', 'V', 'L', 'T' };

		constexpr std::size_t VERSION_OFFSET = 8;
		constexpr std::size_t FLAGS_OFFSET = 10;

		constexpr std::size_t SALT_OFFSET = 12;
		constexpr std::size_t VAULT_ID_OFFSET = 28;

		constexpr std::size_t OPSLIMIT_OFFSET = 44;
		constexpr std::size_t MEMLIMIT_OFFSET = 52;

		constexpr std::size_t ALGORITHM_OFFSET = 60;

		// KDF param validation
		void validate_kdf(const KdfParameters& parameters)
		{
			if (parameters.opslimit < crypto_pwhash_OPSLIMIT_INTERACTIVE)
			{
				throw std::invalid_argument("Argon2id operations limit is too low.");
			}

			if (parameters.opslimit > crypto_pwhash_OPSLIMIT_SENSITIVE)
			{
				throw std::invalid_argument("Argon2id operations limit is too high.");
			}

			if (parameters.memlimit_bytes < crypto_pwhash_MEMLIMIT_INTERACTIVE)
			{
				throw std::invalid_argument("Argon2id memory limit is too low.");
			}

			if (parameters.memlimit_bytes > crypto_pwhash_MEMLIMIT_SENSITIVE)
			{
				throw std::invalid_argument("Argon2id memory limit is too high.");
			}

			if (parameters.memlimit_bytes > std::numeric_limits<std::size_t>::max())
			{
				throw std::invalid_argument("Argon2id memory limit is unsupported.");
			}
		}

		// Little Endian integer writing
		void write_le(VaultHeaderBytes& destination, std::size_t offset, std::uint64_t value, std::size_t byte_count)
		{
			for (std::size_t i = 0; i < byte_count; ++i)
			{
				destination[offset + i] = static_cast<unsigned char>((value >> (i * 8)) & 0xFF);
			}
		}

		// Little Endian integer reading
		std::uint64_t read_le(std::span<const unsigned char> source, std::size_t offset, std::size_t byte_count)
		{
			std::uint64_t value = 0;

			for (std::size_t i = 0; i < byte_count; ++i)
			{
				value |= static_cast<std::uint64_t>(source[offset + i]) << (i * 8);
			}

			return value;
		}
	}

	// Create Vault Header
	VaultHeader create_vault_header(const KdfParameters& parameters)
	{
		validate_kdf(parameters);

		VaultHeader header;

		// Generate a random Argon2id salt
		header.salt = generate_salt();

		// Generate a random vault identifier
		randombytes_buf(header.vault_id.data(), header.vault_id.size());

		// Preserve the selected KDF params
		header.kdf = parameters;

		return header;
	}

	// Serialize Vault Header

	VaultHeaderBytes serialize_header(const VaultHeader& header)
	{
		validate_kdf(header.kdf);

		VaultHeaderBytes bytes{};

		// Write the magic bytes
		std::copy(MAGIC.begin(), MAGIC.end(), bytes.begin());

		//Write format version
		write_le(bytes, VERSION_OFFSET, VAULT_FORMAT_VERSION, 2);

		// Reserved falgs must be zero for v1
		write_le(bytes, FLAGS_OFFSET, 0, 2);

		// Write Argon2id salt
		std::copy(header.salt.begin(), header.salt.end(), bytes.begin() + SALT_OFFSET);

		// Write the vault identifier
		std::copy(header.vault_id.begin(), header.vault_id.end(), bytes.begin() + VAULT_ID_OFFSET);

		// Write Argon2id operations limit
		write_le(bytes, OPSLIMIT_OFFSET, header.kdf.opslimit, 8);

		// Write Argon2id momory limit
		write_le(bytes, MEMLIMIT_OFFSET, header.kdf.memlimit_bytes, 8);

		// Write fixed Argon2id13 algorithm identifier
		write_le(bytes, ALGORITHM_OFFSET, VAULT_KDF_ARGON2ID13, 4);

		return bytes;
	}

	// Deserialize Vault Header

	VaultHeader deserialize_header(std::span<const unsigned char> bytes)
	{
		// Reject incomplete or incorrect sized headers
		if (bytes.size() != VAULT_HEADER_SIZE)
		{
			throw std::runtime_error("Invalid vault header length.");
		}

		// Validate the file magic
		if (!std::equal(MAGIC.begin(), MAGIC.end(), bytes.begin()))
		{
			throw std::runtime_error("Invalid Aegis Vault file signature.");
		}

		// Read and validate the format version
		const std::int64_t version = read_le(bytes, VERSION_OFFSET, 2);

		if (version != VAULT_FORMAT_VERSION)
		{
			throw std::runtime_error("Unsupported vault format version.");
		}

		const std::uint64_t flags = read_le(bytes, FLAGS_OFFSET, 2);

		if (flags != 0)
		{
			throw std::runtime_error("Unsupported vault header flags.");
		}

		// Validate the KDF algorithm identifier
		const std::uint64_t algorithm = read_le(bytes, ALGORITHM_OFFSET, 4);

		if (algorithm != VAULT_KDF_ARGON2ID13)
		{
			throw std::runtime_error("Unsupported vault KDF algorithm.");
		}

		VaultHeader header;

		// Read the salt
		std::copy_n(bytes.begin() + SALT_OFFSET, header.salt.size(), header.salt.begin());

		// Read the vault identifier
		std::copy_n(bytes.begin() + VAULT_ID_OFFSET, header.vault_id.size(), header.vault_id.begin());

		// Read the Argon params
		header.kdf.opslimit = read_le(bytes, OPSLIMIT_OFFSET, 8);
		header.kdf.memlimit_bytes = read_le(bytes, MEMLIMIT_OFFSET, 8);

		// Reject unsafe or unsupported KDF values
		try
		{
			validate_kdf(header.kdf);
		}
		catch (const std::invalid_argument&)
		{
			throw std::runtime_error("Invalid vault header KDF parameters.");
		}

		return header;
	}
}