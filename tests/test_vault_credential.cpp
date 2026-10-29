#include "aegis/vault_credential.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>


namespace
{
    // ========================================================
    // Test Helpers
    // ========================================================

    aegis::VaultHeader make_header()
    {
        aegis::KdfParameters parameters{
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        };

        return aegis::create_vault_header(parameters);
    }


    aegis::SecureBuffer make_key()
    {
        aegis::SecureBuffer key(
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES
        );

        randombytes_buf(key.data(), key.size());

        return key;
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


    aegis::EncryptedCredentialRecord make_record(
        const aegis::VaultHeader& header,
        const aegis::SecureBuffer& key)
    {
        auto username = make_text(U"example@gmail.com");
        auto password = make_text(U"test-password-123");
        auto notes = make_text(U"Test credential");

        auto id = aegis::generate_credential_id();

        return aegis::encrypt_credential(
            header,
            key,
            id,
            username,
            password,
            notes
        );
    }


    void expect_equal(
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
}


// ============================================================
// Test 1: Credential Encryption Round Trip
// ============================================================

TEST(VaultCredentialTests, EncryptDecryptRoundTrip)
{
    auto header = make_header();
    auto key = make_key();

    auto username = make_text(U"example@gmail.com");
    auto password = make_text(U"test-password-123");
    auto notes = make_text(U"Personal account");

    auto id = aegis::generate_credential_id();

    auto encrypted = aegis::encrypt_credential(
        header,
        key,
        id,
        username,
        password,
        notes
    );

    auto decrypted = aegis::decrypt_credential(
        header,
        key,
        encrypted
    );

    expect_equal(decrypted.username(), username);
    expect_equal(decrypted.password(), password);
    expect_equal(decrypted.notes(), notes);
}


// ============================================================
// Test 2: Binary Record Round Trip
// ============================================================

TEST(VaultCredentialTests, BinaryRecordRoundTrip)
{
    auto header = make_header();
    auto key = make_key();

    auto original = make_record(header, key);

    auto bytes = aegis::serialize_credential_record(
        original
    );

    auto restored = aegis::deserialize_credential_record(
        bytes
    );

    EXPECT_EQ(original.id, restored.id);

    EXPECT_EQ(
        original.encrypted.nonce,
        restored.encrypted.nonce
    );

    EXPECT_EQ(
        original.encrypted.ciphertext,
        restored.encrypted.ciphertext
    );

    EXPECT_NO_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header,
                key,
                restored
            )
            )
    );
}


// ============================================================
// Test 3: Random Credential Identifiers
// ============================================================

TEST(VaultCredentialTests, GeneratesDistinctIds)
{
    auto first = aegis::generate_credential_id();
    auto second = aegis::generate_credential_id();

    EXPECT_NE(first, second);
}


// ============================================================
// Test 4: Fresh Encryption Nonces
// ============================================================

TEST(VaultCredentialTests, GeneratesFreshNonces)
{
    auto header = make_header();
    auto key = make_key();

    auto username = make_text(U"user");
    auto password = make_text(U"password");
    auto notes = make_text(U"notes");

    auto id = aegis::generate_credential_id();

    auto first = aegis::encrypt_credential(
        header, key, id, username, password, notes
    );

    auto second = aegis::encrypt_credential(
        header, key, id, username, password, notes
    );

    EXPECT_NE(
        first.encrypted.nonce,
        second.encrypted.nonce
    );

    EXPECT_NE(
        first.encrypted.ciphertext,
        second.encrypted.ciphertext
    );
}


// ============================================================
// Test 5: Wrong Encryption Key
// ============================================================

TEST(VaultCredentialTests, RejectsIncorrectKey)
{
    auto header = make_header();

    auto correct_key = make_key();
    auto wrong_key = make_key();

    auto record = make_record(header, correct_key);

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header,
                wrong_key,
                record
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 6: Ciphertext Tampering
// ============================================================

TEST(VaultCredentialTests, RejectsModifiedCiphertext)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    record.encrypted.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header, key, record
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 7: Authentication Tag Tampering
// ============================================================

TEST(VaultCredentialTests, RejectsModifiedTag)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    record.encrypted.ciphertext.back() ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header, key, record
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 8: Nonce Tampering
// ============================================================

TEST(VaultCredentialTests, RejectsModifiedNonce)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    record.encrypted.nonce[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header, key, record
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 9: Credential ID Tampering
// ============================================================

TEST(VaultCredentialTests, RejectsModifiedId)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    record.id[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header, key, record
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 10: Vault Header Tampering
// ============================================================

TEST(VaultCredentialTests, RejectsModifiedHeader)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    header.vault_id[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_credential(
                header, key, record
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 11: Truncated Binary Record
// ============================================================

TEST(VaultCredentialTests, RejectsTruncatedRecord)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    auto bytes = aegis::serialize_credential_record(
        record
    );

    bytes.pop_back();

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_credential_record(bytes)
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 12: Incorrect Ciphertext Length
// ============================================================

TEST(VaultCredentialTests, RejectsIncorrectLength)
{
    auto header = make_header();
    auto key = make_key();

    auto record = make_record(header, key);

    auto bytes = aegis::serialize_credential_record(
        record
    );

    // The ciphertext length begins at offset 40.
    bytes[40] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_credential_record(bytes)
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 13: Empty Credential Password
// ============================================================

TEST(VaultCredentialTests, RejectsEmptyPassword)
{
    auto header = make_header();
    auto key = make_key();

    auto id = aegis::generate_credential_id();

    auto username = make_text(U"user");
    aegis::SecureText password(64);
    auto notes = make_text(U"notes");

    EXPECT_THROW(
        static_cast<void>(
            aegis::encrypt_credential(
                header,
                key,
                id,
                username,
                password,
                notes
            )
            ),
        std::invalid_argument
    );
}


// ============================================================
// Test 14: Unsupported Plaintext Schema
// ============================================================

TEST(VaultCredentialTests, RejectsUnsupportedSchema)
{
    aegis::SecureBuffer plaintext(2);

    // Schema version 2, which is currently unsupported.
    plaintext.data()[0] = 2;
    plaintext.data()[1] = 0;

    EXPECT_THROW(
        static_cast<void>(
            aegis::DecryptedCredential::from_plaintext(
                std::move(plaintext)
            )
            ),
        std::runtime_error
    );
}