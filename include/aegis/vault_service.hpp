#pragma once

#include "aegis/vault_repository.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>

namespace aegis
{
	class VaultService
	{
	public:

		VaultService(const VaultService&) = delete;

		VaultService& operator=(const VaultService&) = delete;

		VaultService(VaultService&&) noexcept = default;

		VaultService& operator=(VaultService&&) noexcept = default;

		[[nodiscard]] static VaultService open(const std::filesystem::path& path, const SecureText& master_password);

		void add(const SecureText& name, const SecureText& username, const SecureText& password, const SecureText& notes);

		[[nodiscard]] DecryptedCredential get(const SecureText& name) const;

		void update(const SecureText& name, const SecureText& username, const SecureText& password, const SecureText& notes);

		void remove(const SecureText& name);

		[[nodiscard]] std::size_t size() const noexcept;

		[[nodiscard]] std::span<const unsigned char> name_at(std::size_t index) const;

	private:

		VaultService(std::filesystem::path path, UnlockedVault vault);

		[[nodiscard]] std::optional<std::size_t> find_index(const SecureText& name) const;

		void rebuild_catalog(VaultImage& proposed, const SecureText* added_name, const CredentialId* added_id, const CredentialId* removed_id) const;

		void commit(VaultImage&& proposed);

		void ensure_writable() const;

		std::filesystem::path path_;

		UnlockedVault vault_;

		bool writable_ = true;
	};
}