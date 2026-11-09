#include "aegis/vault_service.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstddef>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>


namespace
{
    // ========================================================
    // Test Helpers
    // ========================================================

    aegis::KdfParameters test_parameters()
    {
        return {
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        };
    }


    aegis::SecureText make_text(std::u32string_view value)
    {
        aegis::SecureText text(256);

        for (char32_t character : value)
        {
            text.append_codepoint(character);
        }

        return text;
    }


    aegis::SecureText make_password()
    {
        return make_text(U"test-master-password");
    }


    // ========================================================
    // Protected Text Comparison
    // ========================================================

    void expect_text_equal(
        std::span<const unsigned char> actual,
        const aegis::SecureText& expected)
    {
        ASSERT_EQ(actual.size(), expected.size());

        if (!actual.empty())
        {
            EXPECT_EQ(
                sodium_memcmp(
                    actual.data(),
                    expected.data(),
                    actual.size()
                ),
                0
            );
        }
    }


    // ========================================================
    // Temporary Directory
    // ========================================================

    class TestDirectory
    {
    public:

        TestDirectory()
        {
            std::array<unsigned char, 16> random{};

            randombytes_buf(
                random.data(),
                random.size()
            );

            constexpr char HEX[] =
                "0123456789abcdef";

            std::string suffix;

            for (unsigned char byte : random)
            {
                suffix.push_back(HEX[byte >> 4]);
                suffix.push_back(HEX[byte & 0x0F]);
            }

            path_ =
                std::filesystem::temp_directory_path() /
                ("aegis-service-test-" + suffix);

            std::filesystem::create_directory(path_);
        }


        ~TestDirectory() noexcept
        {
            std::error_code error;

            std::filesystem::remove_all(path_, error);
        }


        TestDirectory(const TestDirectory&) = delete;

        TestDirectory& operator=(
            const TestDirectory&) = delete;


        [[nodiscard]] std::filesystem::path vault_path() const
        {
            return path_ / "test.avlt";
        }


        void initialize() const
        {
            auto password = make_password();

            aegis::create_new_vault(
                vault_path(),
                password,
                test_parameters()
            );
        }


    private:

        std::filesystem::path path_;
    };


    // ========================================================
    // Add Disposable Test Credential
    // ========================================================

    void add_test_credential(
        aegis::VaultService& vault,
        std::u32string_view name_value)
    {
        auto name = make_text(name_value);
        auto username = make_text(U"test-user");
        auto password = make_text(U"test-password");
        auto notes = make_text(U"test-notes");

        vault.add(
            name,
            username,
            password,
            notes
        );
    }
}


// ============================================================
// Test 1: Open Empty Vault
// ============================================================

TEST(VaultServiceTests, OpensEmptyVault)
{
    TestDirectory directory;

    directory.initialize();

    auto password = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        password
    );

    EXPECT_EQ(vault.size(), 0u);
}


// ============================================================
// Test 2: Add and Retrieve Credential
// ============================================================

TEST(VaultServiceTests, AddsAndRetrievesCredential)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    auto name = make_text(U"GitHub");
    auto username = make_text(U"example-user");
    auto password = make_text(U"example-password");
    auto notes = make_text(U"Personal account");

    vault.add(
        name,
        username,
        password,
        notes
    );

    ASSERT_EQ(vault.size(), 1u);

    auto credential = vault.get(name);

    expect_text_equal(
        credential.username(),
        username
    );

    expect_text_equal(
        credential.password(),
        password
    );

    expect_text_equal(
        credential.notes(),
        notes
    );
}


// ============================================================
// Test 3: Changes Persist Across Reopening
// ============================================================

TEST(VaultServiceTests, PersistsChanges)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    {
        auto vault = aegis::VaultService::open(
            directory.vault_path(),
            master
        );

        add_test_credential(vault, U"GitHub");
    }

    // Open a completely new authenticated session.
    auto reopened = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    ASSERT_EQ(reopened.size(), 1u);

    auto name = make_text(U"GitHub");

    auto credential = reopened.get(name);

    auto expected_password = make_text(U"test-password");

    expect_text_equal(
        credential.password(),
        expected_password
    );
}


// ============================================================
// Test 4: List Credential Names
// ============================================================

TEST(VaultServiceTests, ListsCredentialNames)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    add_test_credential(vault, U"GitHub");
    add_test_credential(vault, U"Discord");

    ASSERT_EQ(vault.size(), 2u);

    auto first = make_text(U"GitHub");
    auto second = make_text(U"Discord");

    expect_text_equal(
        vault.name_at(0),
        first
    );

    expect_text_equal(
        vault.name_at(1),
        second
    );
}


// ============================================================
// Test 5: Reject Duplicate Credential Names
// ============================================================

TEST(VaultServiceTests, RejectsDuplicateNames)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    add_test_credential(vault, U"GitHub");

    EXPECT_THROW(
        add_test_credential(vault, U"GitHub"),
        std::invalid_argument
    );

    EXPECT_EQ(vault.size(), 1u);

    auto reopened = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    EXPECT_EQ(reopened.size(), 1u);
}


// ============================================================
// Test 6: Remove Credential
// ============================================================

TEST(VaultServiceTests, RemovesCredential)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    add_test_credential(vault, U"GitHub");
    add_test_credential(vault, U"Discord");

    auto github = make_text(U"GitHub");

    vault.remove(github);

    ASSERT_EQ(vault.size(), 1u);

    auto discord = make_text(U"Discord");

    expect_text_equal(
        vault.name_at(0),
        discord
    );

    EXPECT_THROW(
        static_cast<void>(
            vault.get(github)
            ),
        std::out_of_range
    );

    // Verify the change persisted.
    auto reopened = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    ASSERT_EQ(reopened.size(), 1u);

    expect_text_equal(
        reopened.name_at(0),
        discord
    );
}


// ============================================================
// Test 7: Reject Missing Credential
// ============================================================

TEST(VaultServiceTests, RejectsMissingCredential)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    auto missing = make_text(U"Nonexistent");

    EXPECT_THROW(
        static_cast<void>(
            vault.get(missing)
            ),
        std::out_of_range
    );

    EXPECT_THROW(
        vault.remove(missing),
        std::out_of_range
    );
}


// ============================================================
// Test 8: Update Credential
// ============================================================

TEST(VaultServiceTests, UpdatesCredential)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    add_test_credential(vault, U"GitHub");

    auto name = make_text(U"GitHub");

    auto new_username = make_text(U"new-user");
    auto new_password = make_text(U"new-password");
    auto new_notes = make_text(U"Updated credentials");

    vault.update(
        name,
        new_username,
        new_password,
        new_notes
    );

    auto credential = vault.get(name);

    expect_text_equal(
        credential.username(),
        new_username
    );

    expect_text_equal(
        credential.password(),
        new_password
    );

    expect_text_equal(
        credential.notes(),
        new_notes
    );

    // Verify the updated values survive reopening.
    auto reopened = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    auto restored = reopened.get(name);

    expect_text_equal(
        restored.password(),
        new_password
    );
}


// ============================================================
// Test 9: Updating One Entry Preserves Other Ciphertext
// ============================================================

TEST(VaultServiceTests, UpdatePreservesOtherRecords)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    add_test_credential(vault, U"GitHub");
    add_test_credential(vault, U"Discord");

    // Capture the encrypted file contents before updating.
    auto before = aegis::read_vault_file(
        directory.vault_path()
    );

    ASSERT_EQ(before.records.size(), 2u);

    auto github = make_text(U"GitHub");

    auto username = make_text(U"updated-user");
    auto password = make_text(U"updated-password");
    auto notes = make_text(U"updated-notes");

    vault.update(
        github,
        username,
        password,
        notes
    );

    auto after = aegis::read_vault_file(
        directory.vault_path()
    );

    ASSERT_EQ(after.records.size(), 2u);

    // GitHub keeps the same identifier.
    EXPECT_EQ(
        before.records[0].id,
        after.records[0].id
    );

    // GitHub receives fresh encryption.
    EXPECT_NE(
        before.records[0].encrypted.nonce,
        after.records[0].encrypted.nonce
    );

    // Discord's identifier remains unchanged.
    EXPECT_EQ(
        before.records[1].id,
        after.records[1].id
    );

    // Discord's nonce remains unchanged.
    EXPECT_EQ(
        before.records[1].encrypted.nonce,
        after.records[1].encrypted.nonce
    );

    // Discord's ciphertext remains unchanged.
    EXPECT_EQ(
        before.records[1].encrypted.ciphertext,
        after.records[1].encrypted.ciphertext
    );
}


// ============================================================
// Test 10: Reject Invalid Credential Without Saving
// ============================================================

TEST(VaultServiceTests, RejectsInvalidCredentialWithoutSaving)
{
    TestDirectory directory;

    directory.initialize();

    auto master = make_password();

    auto vault = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    auto name = make_text(U"GitHub");
    auto username = make_text(U"test-user");

    // Empty passwords are rejected by our credential format.
    aegis::SecureText empty_password(64);

    auto notes = make_text(U"test-notes");

    EXPECT_THROW(
        vault.add(
            name,
            username,
            empty_password,
            notes
        ),
        std::invalid_argument
    );

    EXPECT_EQ(vault.size(), 0u);

    // The existing file should remain unchanged.
    auto reopened = aegis::VaultService::open(
        directory.vault_path(),
        master
    );

    EXPECT_EQ(reopened.size(), 0u);
}