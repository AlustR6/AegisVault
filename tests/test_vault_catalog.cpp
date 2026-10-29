#include "aegis/vault_catalog.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>


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

        randombytes_buf(
            key.data(),
            key.size()
        );

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


    // Reusable fixture containing two encrypted credentials.
    struct CatalogSample
    {
        aegis::VaultHeader header = make_header();

        aegis::SecureBuffer key = make_key();

        aegis::SecureText name_a = make_text(U"GitHub");

        aegis::SecureText name_b = make_text(U"Discord");

        std::vector<aegis::EncryptedCredentialRecord> records;


        CatalogSample()
        {
            auto username = make_text(U"test-user");
            auto password = make_text(U"test-password");
            auto notes = make_text(U"test-notes");

            records.push_back(
                aegis::encrypt_credential(
                    header,
                    key,
                    aegis::generate_credential_id(),
                    username,
                    password,
                    notes
                )
            );

            records.push_back(
                aegis::encrypt_credential(
                    header,
                    key,
                    aegis::generate_credential_id(),
                    username,
                    password,
                    notes
                )
            );
        }
    };


    aegis::EncryptedCatalog make_catalog(
        const CatalogSample& sample)
    {
        const std::array<aegis::CatalogInput, 2> entries{ {
            { sample.name_a, sample.records[0] },
            { sample.name_b, sample.records[1] }
        } };

        return aegis::encrypt_catalog(
            sample.header,
            sample.key,
            entries
        );
    }
}


// ============================================================
// Test 1: Encryption and Decryption
// ============================================================

TEST(VaultCatalogTests, EncryptDecryptRoundTrip)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto decrypted = aegis::decrypt_catalog(
        sample.header,
        sample.key,
        encrypted
    );

    EXPECT_EQ(decrypted.size(), 2u);

    EXPECT_EQ(
        decrypted.id_at(0),
        sample.records[0].id
    );

    EXPECT_EQ(
        decrypted.id_at(1),
        sample.records[1].id
    );

    const auto first_name = decrypted.name_at(0);

    ASSERT_EQ(first_name.size(), sample.name_a.size());

    EXPECT_EQ(
        sodium_memcmp(
            first_name.data(),
            sample.name_a.data(),
            first_name.size()
        ),
        0
    );

    EXPECT_NO_THROW(
        decrypted.verify_records(sample.records)
    );
}


// ============================================================
// Test 2: Empty Catalog
// ============================================================

TEST(VaultCatalogTests, SupportsEmptyCatalog)
{
    auto header = make_header();
    auto key = make_key();

    const std::span<const aegis::CatalogInput> empty_entries;

    auto encrypted = aegis::encrypt_catalog(
        header,
        key,
        empty_entries
    );

    auto decrypted = aegis::decrypt_catalog(
        header,
        key,
        encrypted
    );

    EXPECT_EQ(decrypted.size(), 0u);

    const std::span<const aegis::EncryptedCredentialRecord>
        empty_records;

    EXPECT_NO_THROW(
        decrypted.verify_records(empty_records)
    );
}


// ============================================================
// Test 3: Binary Serialization
// ============================================================

TEST(VaultCatalogTests, BinaryRecordRoundTrip)
{
    CatalogSample sample;

    auto original = make_catalog(sample);

    auto bytes = aegis::serialize_catalog_record(
        original
    );

    auto restored = aegis::deserialize_catalog_record(
        bytes
    );

    EXPECT_EQ(
        original.encrypted.nonce,
        restored.encrypted.nonce
    );

    EXPECT_EQ(
        original.encrypted.ciphertext,
        restored.encrypted.ciphertext
    );

    auto decrypted = aegis::decrypt_catalog(
        sample.header,
        sample.key,
        restored
    );

    EXPECT_EQ(decrypted.size(), 2u);
}


// ============================================================
// Test 4: Modified Credential Detection
// ============================================================

TEST(VaultCatalogTests, RejectsModifiedCredential)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto catalog = aegis::decrypt_catalog(
        sample.header,
        sample.key,
        encrypted
    );

    auto modified = sample.records;

    modified[0].encrypted.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        catalog.verify_records(modified),
        std::runtime_error
    );
}


// ============================================================
// Test 5: Missing Credential Detection
// ============================================================

TEST(VaultCatalogTests, RejectsMissingCredential)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto catalog = aegis::decrypt_catalog(
        sample.header,
        sample.key,
        encrypted
    );

    auto modified = sample.records;

    modified.pop_back();

    EXPECT_THROW(
        catalog.verify_records(modified),
        std::runtime_error
    );
}


// ============================================================
// Test 6: Unexpected Credential Detection
// ============================================================

TEST(VaultCatalogTests, RejectsUnexpectedCredential)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto catalog = aegis::decrypt_catalog(
        sample.header,
        sample.key,
        encrypted
    );

    auto modified = sample.records;

    auto extra = modified[0];

    extra.id = aegis::generate_credential_id();

    modified.push_back(extra);

    EXPECT_THROW(
        catalog.verify_records(modified),
        std::runtime_error
    );
}


// ============================================================
// Test 7: Incorrect Encryption Key
// ============================================================

TEST(VaultCatalogTests, RejectsIncorrectKey)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto wrong_key = make_key();

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_catalog(
                sample.header,
                wrong_key,
                encrypted
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 8: Modified Vault Header
// ============================================================

TEST(VaultCatalogTests, RejectsModifiedHeader)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto modified_header = sample.header;

    modified_header.vault_id[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_catalog(
                modified_header,
                sample.key,
                encrypted
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 9: Modified Encrypted Catalog
// ============================================================

TEST(VaultCatalogTests, RejectsModifiedCatalog)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    encrypted.encrypted.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_catalog(
                sample.header,
                sample.key,
                encrypted
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 10: Duplicate Catalog Names
// ============================================================

TEST(VaultCatalogTests, RejectsDuplicateNames)
{
    CatalogSample sample;

    auto duplicate_name = make_text(U"GitHub");

    const std::array<aegis::CatalogInput, 2> entries{ {
        { sample.name_a, sample.records[0] },
        { duplicate_name, sample.records[1] }
    } };

    EXPECT_THROW(
        static_cast<void>(
            aegis::encrypt_catalog(
                sample.header,
                sample.key,
                entries
            )
            ),
        std::invalid_argument
    );
}


// ============================================================
// Test 11: Duplicate Credential IDs
// ============================================================

TEST(VaultCatalogTests, RejectsDuplicateIds)
{
    CatalogSample sample;

    auto duplicate_record = sample.records[1];

    duplicate_record.id = sample.records[0].id;

    const std::array<aegis::CatalogInput, 2> entries{ {
        { sample.name_a, sample.records[0] },
        { sample.name_b, duplicate_record }
    } };

    EXPECT_THROW(
        static_cast<void>(
            aegis::encrypt_catalog(
                sample.header,
                sample.key,
                entries
            )
            ),
        std::invalid_argument
    );
}


// ============================================================
// Test 12: Truncated Binary Catalog
// ============================================================

TEST(VaultCatalogTests, RejectsTruncatedRecord)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto bytes = aegis::serialize_catalog_record(
        encrypted
    );

    bytes.pop_back();

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_catalog_record(bytes)
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 13: Invalid Ciphertext Length
// ============================================================

TEST(VaultCatalogTests, RejectsIncorrectLength)
{
    CatalogSample sample;

    auto encrypted = make_catalog(sample);

    auto bytes = aegis::serialize_catalog_record(
        encrypted
    );

    // The ciphertext length starts immediately after the nonce.
    bytes[24] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_catalog_record(bytes)
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 14: Reject Invalid Name
// ============================================================

TEST(VaultCatalogTests, RejectsEmptyName)
{
    CatalogSample sample;

    aegis::SecureText empty_name(32);

    const std::array<aegis::CatalogInput, 1> entries{ {
        { empty_name, sample.records[0] }
    } };

    EXPECT_THROW(
        static_cast<void>(
            aegis::encrypt_catalog(
                sample.header,
                sample.key,
                entries
            )
            ),
        std::invalid_argument
    );
}


// ============================================================
// Test 15: Reject Invalid UTF-8
// ============================================================

TEST(VaultCatalogTests, RejectsMalformedUtf8)
{
    // Construct a malformed but structurally complete
    // decrypted catalog.

    constexpr std::size_t size =
        6 + 16 + 2 + 1 + aegis::CATALOG_HASH_SIZE;

    aegis::SecureBuffer plaintext(size);

    // Schema version 1.
    plaintext.data()[0] = 1;

    // Entry count 1.
    plaintext.data()[2] = 1;

    // Credential ID occupies bytes 6 through 21.

    // Name length = 1.
    plaintext.data()[22] = 1;

    // 0xFF is not a valid standalone UTF-8 character.
    plaintext.data()[24] = 0xFF;

    EXPECT_THROW(
        static_cast<void>(
            aegis::DecryptedCatalog::from_plaintext(
                std::move(plaintext)
            )
            ),
        std::runtime_error
    );
}