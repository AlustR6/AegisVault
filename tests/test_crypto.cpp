#include "aegis/crypto.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstddef>
#include <stdexcept>


namespace
{
    aegis::SecureText make_test_password()
    {
        aegis::SecureText password(64);

        // Disposable password used only for automated testing.
        constexpr char32_t test_value[] = U"test-password-123";

        for (char32_t character : test_value)
        {
            if (character == U'\0')
            {
                break;
            }

            password.append_codepoint(character);
        }

        return password;
    }


    aegis::KdfParameters test_parameters()
    {
        return
        {
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        };
    }
}


// ---------------------------------------
// Test 1: Correct Key Size
// ---------------------------------------

TEST(CryptoTests, DerivesCorrectKeySize)
{
    auto password = make_test_password();

    aegis::VaultSalt salt{};
    salt.fill(0x11);

    auto key = aegis::derive_master_key(
        password,
        salt,
        test_parameters()
    );

    EXPECT_EQ(
        key.size(),
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    );

    EXPECT_NE(key.data(), nullptr);
}


// ---------------------------------------
// Test 2: Deterministic Derivation
// ---------------------------------------

TEST(CryptoTests, SameInputsProduceSameKey)
{
    auto password = make_test_password();

    aegis::VaultSalt salt{};
    salt.fill(0x22);

    auto first = aegis::derive_master_key(
        password,
        salt,
        test_parameters()
    );

    auto second = aegis::derive_master_key(
        password,
        salt,
        test_parameters()
    );

    EXPECT_EQ(first.size(), second.size());

    EXPECT_EQ(
        sodium_memcmp(
            first.data(),
            second.data(),
            first.size()
        ),
        0
    );
}


// ---------------------------------------
// Test 3: Different Salts
// ---------------------------------------

TEST(CryptoTests, DifferentSaltsProduceDifferentKeys)
{
    auto password = make_test_password();

    aegis::VaultSalt first_salt{};
    aegis::VaultSalt second_salt{};

    first_salt.fill(0x33);
    second_salt.fill(0x44);

    auto first = aegis::derive_master_key(
        password,
        first_salt,
        test_parameters()
    );

    auto second = aegis::derive_master_key(
        password,
        second_salt,
        test_parameters()
    );

    EXPECT_NE(
        sodium_memcmp(
            first.data(),
            second.data(),
            first.size()
        ),
        0
    );
}


// ---------------------------------------
// Test 4: Different Passwords
// ---------------------------------------

TEST(CryptoTests, DifferentPasswordsProduceDifferentKeys)
{
    auto first_password = make_test_password();
    auto second_password = make_test_password();

    // Modify the final character of the second password.
    second_password.backspace();
    second_password.append_codepoint(U'!');

    aegis::VaultSalt salt{};
    salt.fill(0x55);

    auto first = aegis::derive_master_key(
        first_password,
        salt,
        test_parameters()
    );

    auto second = aegis::derive_master_key(
        second_password,
        salt,
        test_parameters()
    );

    EXPECT_NE(
        sodium_memcmp(
            first.data(),
            second.data(),
            first.size()
        ),
        0
    );
}


// ---------------------------------------
// Test 5: Empty Password Rejection
// ---------------------------------------

TEST(CryptoTests, RejectsEmptyPassword)
{
    aegis::SecureText password(64);

    aegis::VaultSalt salt{};
    salt.fill(0x66);

    EXPECT_THROW(
        aegis::derive_master_key(
            password,
            salt,
            test_parameters()
        ),
        std::invalid_argument
    );
}


// ---------------------------------------
// Test 6: Invalid Parameters
// ---------------------------------------

TEST(CryptoTests, RejectsInvalidParameters)
{
    auto password = make_test_password();

    aegis::VaultSalt salt{};
    salt.fill(0x77);

    aegis::KdfParameters invalid_parameters
    {
        0,
        1
    };

    EXPECT_THROW(
        aegis::derive_master_key(
            password,
            salt,
            invalid_parameters
        ),
        std::invalid_argument
    );
}