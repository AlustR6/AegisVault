#pragma once

#include "aegis/crypto.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>


namespace aegis
{
	// Vault format constants

	inline constexpr std::size_t VAULT_HEADER_SIZE = 64;
	inline constexpr std::uint16_t VAULT_FORMAT_VERSION = 1;
	inline constexpr std::uint32_t VAULT_KDF_ARGON2ID13 = 1;

	// Vault types

	using VaultId = std::array<unsigned char, 16>;

	using VaultHeaderBytes = std::array<unsigned char, VAULT_HEADER_SIZE>;

	// Vault header

	struct VaultHeader
	{
		VaultSalt salt{};

		VaultId vault_id{};

		KdfParameters kdf{};
	};

	// Header creation

	[[nodiscard]] VaultHeader create_vault_header(const KdfParameters& parameters = {});

	// Serialization

	[[nodiscard]] VaultHeaderBytes serialize_header(const VaultHeader& header);

	// Deserialization

	[[nodiscard]] VaultHeader deserialize_header(std::span<const unsigned char> bytes);
}