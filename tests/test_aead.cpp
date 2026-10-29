#include "aegis/crypto.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <utility>


namespace
{
    constexpr std::array<unsigned char, 6> TEST_AAD =
    {
        'e', 'n', 't', 'r', 'y', '1'
    };


    std::span<const unsigned char> test_aad()
    {
        return std::span<const unsigned char>(TEST_AAD);
    }


    aegis::SecureBuffer make_test_key()
    {
        aegis::SecureBuffer key(
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES
        );

        randombytes_buf(key.data(), key.size());

        return key;
    }


    aegis::SecureBuffer make_test_plaintext()
    {
        aegis::SecureBuffer plaintext(16);

        for (std::size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext.data()[i] =
                static_cast<unsigned char>(i + 1);
        }

        return plaintext;
    }
}

TEST(AeadTests, EncryptionDecryptionRoundTrip)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    // Encrypt the original data.
    auto encrypted = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    // Decrypt the resulting ciphertext.
    auto decrypted = aegis::decrypt_record(
        key,
        encrypted,
        test_aad()
    );

    // The decrypted data should have the original size.
    ASSERT_EQ(decrypted.size(), plaintext.size());

    // Compare the recovered plaintext with the original.
    EXPECT_EQ(
        sodium_memcmp(
            decrypted.data(),
            plaintext.data(),
            plaintext.size()
        ),
        0
    );
}

TEST(AeadTests, EncryptionGeneratesFreshNonce)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    auto first = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    auto second = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    // Independent encryption operations should use different nonces.
    EXPECT_NE(first.nonce, second.nonce);

    // Consequently, their ciphertexts should differ.
    EXPECT_NE(first.ciphertext, second.ciphertext);
}

TEST(AeadTests, RejectsModifiedCiphertext)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    auto encrypted = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    // Simulate an attacker modifying one encrypted byte.
    encrypted.ciphertext[0] ^= 0x01;

    // Authentication must fail.
    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_record(
                key,
                encrypted,
                test_aad()
            )
            ),
        std::runtime_error
    );
}

TEST(AeadTests, RejectsModifiedAuthenticationTag)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    auto encrypted = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    // The authentication tag is appended to the ciphertext.
    encrypted.ciphertext.back() ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_record(
                key,
                encrypted,
                test_aad()
            )
            ),
        std::runtime_error
    );
}

TEST(AeadTests, RejectsModifiedNonce)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    auto encrypted = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    // Modify the stored nonce.
    encrypted.nonce[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_record(
                key,
                encrypted,
                test_aad()
            )
            ),
        std::runtime_error
    );
}

TEST(AeadTests, RejectsIncorrectKey)
{
    auto correct_key = make_test_key();
    auto incorrect_key = make_test_key();

    auto plaintext = make_test_plaintext();

    auto encrypted = aegis::encrypt_record(
        correct_key,
        plaintext,
        test_aad()
    );

    // Attempt decryption using a different key.
    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_record(
                incorrect_key,
                encrypted,
                test_aad()
            )
            ),
        std::runtime_error
    );
}

TEST(AeadTests, RejectsModifiedAssociatedData)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    auto encrypted = aegis::encrypt_record(
        key,
        plaintext,
        test_aad()
    );

    // Create a modified copy of our public metadata.
    auto modified_aad = TEST_AAD;

    modified_aad[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_record(
                key,
                encrypted,
                std::span<const unsigned char>(modified_aad)
            )
            ),
        std::runtime_error
    );
}

TEST(AeadTests, RejectsTruncatedCiphertext)
{
    auto key = make_test_key();

    aegis::EncryptedBlob encrypted;

    // Too short to contain a valid encrypted record.
    encrypted.ciphertext.resize(8);

    EXPECT_THROW(
        static_cast<void>(
            aegis::decrypt_record(
                key,
                encrypted,
                test_aad()
            )
            ),
        std::invalid_argument
    );
}

TEST(AeadTests, RejectsInvalidKeySize)
{
    aegis::SecureBuffer invalid_key(16);

    auto plaintext = make_test_plaintext();

    EXPECT_THROW(
        static_cast<void>(
            aegis::encrypt_record(
                invalid_key,
                plaintext,
                test_aad()
            )
            ),
        std::invalid_argument
    );
}

TEST(AeadTests, RejectsEmptyAssociatedData)
{
    auto key = make_test_key();
    auto plaintext = make_test_plaintext();

    std::span<const unsigned char> empty_aad;

    EXPECT_THROW(
        static_cast<void>(
            aegis::encrypt_record(
                key,
                plaintext,
                empty_aad
            )
            ),
        std::invalid_argument
    );
}