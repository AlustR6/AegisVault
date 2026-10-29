#include "aegis/vault_verification.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>


namespace
{
    // ========================================================
    // Test Helpers
    // ========================================================

    aegis::KdfParameters test_parameters()
    {
        return
        {
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        };
    }


    aegis::VaultHeader make_test_header()
    {
        return aegis::create_vault_header(
            test_parameters()
        );
    }


    aegis::SecureBuffer make_test_key()
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


    aegis::SecureText make_test_password()
    {
        aegis::SecureText password(64);

        constexpr char32_t value[] = U"test-master-password";

        for (char32_t character : value)
        {
            if (character == U'\0')
            {
                break;
            }

            password.append_codepoint(character);
        }

        return password;
    }
}


// ============================================================
// Test 1: Verification Record Serialization
// ============================================================

TEST(VaultVerificationTests, RecordRoundTrip)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto original = aegis::create_verification_record(
        header,
        key
    );

    auto bytes = aegis::serialize_verification_record(
        original
    );

    auto restored = aegis::deserialize_verification_record(
        bytes
    );

    EXPECT_EQ(
        bytes.size(),
        aegis::VAULT_VERIFICATION_RECORD_SIZE
    );

    EXPECT_EQ(
        original.nonce,
        restored.nonce
    );

    EXPECT_EQ(
        original.ciphertext,
        restored.ciphertext
    );
}


// ============================================================
// Test 2: Correct Key Verification
// ============================================================

TEST(VaultVerificationTests, AcceptsCorrectKey)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        key
    );

    EXPECT_NO_THROW(
        aegis::verify_master_key(
            header,
            key,
            record
        )
    );
}


// ============================================================
// Test 3: Incorrect Key Rejection
// ============================================================

TEST(VaultVerificationTests, RejectsIncorrectKey)
{
    auto header = make_test_header();

    auto correct_key = make_test_key();
    auto incorrect_key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        correct_key
    );

    EXPECT_THROW(
        aegis::verify_master_key(
            header,
            incorrect_key,
            record
        ),
        std::runtime_error
    );
}


// ============================================================
// Test 4: Ciphertext Tampering
// ============================================================

TEST(VaultVerificationTests, RejectsModifiedCiphertext)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        key
    );

    // Modify one encrypted byte.
    record.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        aegis::verify_master_key(
            header,
            key,
            record
        ),
        std::runtime_error
    );
}


// ============================================================
// Test 5: Authentication Tag Tampering
// ============================================================

TEST(VaultVerificationTests, RejectsModifiedTag)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        key
    );

    // Modify the final byte of the authentication tag.
    record.ciphertext.back() ^= 0x01;

    EXPECT_THROW(
        aegis::verify_master_key(
            header,
            key,
            record
        ),
        std::runtime_error
    );
}


// ============================================================
// Test 6: Nonce Tampering
// ============================================================

TEST(VaultVerificationTests, RejectsModifiedNonce)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        key
    );

    record.nonce[0] ^= 0x01;

    EXPECT_THROW(
        aegis::verify_master_key(
            header,
            key,
            record
        ),
        std::runtime_error
    );
}


// ============================================================
// Test 7: Header Tampering
// ============================================================

TEST(VaultVerificationTests, RejectsModifiedHeader)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        key
    );

    // Change the vault identifier after encryption.
    header.vault_id[0] ^= 0x01;

    EXPECT_THROW(
        aegis::verify_master_key(
            header,
            key,
            record
        ),
        std::runtime_error
    );
}


// ============================================================
// Test 8: Truncated Record Rejection
// ============================================================

TEST(VaultVerificationTests, RejectsTruncatedRecord)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto record = aegis::create_verification_record(
        header,
        key
    );

    auto bytes = aegis::serialize_verification_record(
        record
    );

    std::vector<unsigned char> truncated(
        bytes.begin(),
        bytes.end() - 1
    );

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_verification_record(
                truncated
            )
            ),
        std::runtime_error
    );
}


// ============================================================
// Test 9: Fresh Verification Nonces
// ============================================================

TEST(VaultVerificationTests, GeneratesFreshNonces)
{
    auto header = make_test_header();
    auto key = make_test_key();

    auto first = aegis::create_verification_record(
        header,
        key
    );

    auto second = aegis::create_verification_record(
        header,
        key
    );

    EXPECT_NE(
        first.nonce,
        second.nonce
    );

    EXPECT_NE(
        first.ciphertext,
        second.ciphertext
    );
}


// ============================================================
// Test 10: Complete Password Unlock
// ============================================================

TEST(VaultVerificationTests, UnlocksWithCorrectPassword)
{
    auto header = make_test_header();
    auto password = make_test_password();

    // Derive the original key.
    auto original_key = aegis::derive_master_key(
        password,
        header.salt,
        header.kdf
    );

    // Create the verification record.
    auto record = aegis::create_verification_record(
        header,
        original_key
    );

    // Attempt unlocking using the same password.
    auto unlocked_key = aegis::unlock_master_key(
        header,
        password,
        record
    );

    ASSERT_EQ(
        original_key.size(),
        unlocked_key.size()
    );

    EXPECT_EQ(
        sodium_memcmp(
            original_key.data(),
            unlocked_key.data(),
            original_key.size()
        ),
        0
    );
}


// ============================================================
// Test 11: Incorrect Master Password
// ============================================================

TEST(VaultVerificationTests, RejectsWrongMasterPassword)
{
    auto header = make_test_header();

    auto correct_password = make_test_password();

    auto original_key = aegis::derive_master_key(
        correct_password,
        header.salt,
        header.kdf
    );

    auto record = aegis::create_verification_record(
        header,
        original_key
    );

    // Create an incorrect password.
    auto wrong_password = make_test_password();

    wrong_password.backspace();
    wrong_password.append_codepoint(U'!');

    EXPECT_THROW(
        static_cast<void>(
            aegis::unlock_master_key(
                header,
                wrong_password,
                record
            )
            ),
        std::runtime_error
    );
}