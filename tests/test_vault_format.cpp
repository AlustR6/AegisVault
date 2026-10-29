#include "aegis/vault_format.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>


namespace
{
    aegis::VaultHeader make_test_header()
    {
        aegis::VaultHeader header;

        header.salt.fill(0xAA);
        header.vault_id.fill(0xBB);

        header.kdf =
        {
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        };

        return header;
    }
}


// ---------------------------------------------------------
// Test 1: Header Round Trip
// ---------------------------------------------------------

TEST(VaultFormatTests, HeaderRoundTrip)
{
    auto original = make_test_header();

    auto serialized =
        aegis::serialize_header(original);

    auto restored =
        aegis::deserialize_header(serialized);

    EXPECT_EQ(restored.salt, original.salt);

    EXPECT_EQ(restored.vault_id, original.vault_id);

    EXPECT_EQ(
        restored.kdf.opslimit,
        original.kdf.opslimit
    );

    EXPECT_EQ(
        restored.kdf.memlimit_bytes,
        original.kdf.memlimit_bytes
    );
}


// ---------------------------------------------------------
// Test 2: Header Size and Magic
// ---------------------------------------------------------

TEST(VaultFormatTests, HeaderHasCorrectLayout)
{
    auto header = make_test_header();

    auto bytes = aegis::serialize_header(header);

    ASSERT_EQ(bytes.size(), 64u);

    constexpr unsigned char expected_magic[] =
    {
        'A', 'E', 'G', 'I', 'S', 'V', 'L', 'T'
    };

    EXPECT_TRUE(std::equal(
        std::begin(expected_magic),
        std::end(expected_magic),
        bytes.begin()
    ));

    // Version 1, stored as a 16-bit little-endian value.
    EXPECT_EQ(bytes[8], 1);
    EXPECT_EQ(bytes[9], 0);

    // Reserved flags.
    EXPECT_EQ(bytes[10], 0);
    EXPECT_EQ(bytes[11], 0);

    // KDF algorithm ID = 1.
    EXPECT_EQ(bytes[60], 1);
    EXPECT_EQ(bytes[61], 0);
    EXPECT_EQ(bytes[62], 0);
    EXPECT_EQ(bytes[63], 0);
}


// ---------------------------------------------------------
// Test 3: Little-Endian KDF Encoding
// ---------------------------------------------------------

TEST(VaultFormatTests, UsesLittleEndianEncoding)
{
    auto header = make_test_header();

    auto bytes = aegis::serialize_header(header);

    for (std::size_t i = 0; i < 8; ++i)
    {
        auto expected_operations =
            static_cast<unsigned char>(
                (header.kdf.opslimit >> (i * 8)) & 0xFF
                );

        auto expected_memory =
            static_cast<unsigned char>(
                (header.kdf.memlimit_bytes >> (i * 8)) & 0xFF
                );

        EXPECT_EQ(bytes[44 + i], expected_operations);
        EXPECT_EQ(bytes[52 + i], expected_memory);
    }
}


// ---------------------------------------------------------
// Test 4: Reject Incorrect Magic
// ---------------------------------------------------------

TEST(VaultFormatTests, RejectsInvalidMagic)
{
    auto bytes =
        aegis::serialize_header(make_test_header());

    bytes[0] ^= 0x01;

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(bytes)
            ),
        std::runtime_error
    );
}


// ---------------------------------------------------------
// Test 5: Reject Unsupported Version
// ---------------------------------------------------------

TEST(VaultFormatTests, RejectsUnsupportedVersion)
{
    auto bytes =
        aegis::serialize_header(make_test_header());

    bytes[8] = 2;

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(bytes)
            ),
        std::runtime_error
    );
}


// ---------------------------------------------------------
// Test 6: Reject Unknown Flags
// ---------------------------------------------------------

TEST(VaultFormatTests, RejectsUnknownFlags)
{
    auto bytes =
        aegis::serialize_header(make_test_header());

    bytes[10] = 1;

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(bytes)
            ),
        std::runtime_error
    );
}


// ---------------------------------------------------------
// Test 7: Reject Unsupported KDF
// ---------------------------------------------------------

TEST(VaultFormatTests, RejectsUnsupportedKdf)
{
    auto bytes =
        aegis::serialize_header(make_test_header());

    bytes[60] = 99;

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(bytes)
            ),
        std::runtime_error
    );
}


// ---------------------------------------------------------
// Test 8: Reject Incorrect Header Length
// ---------------------------------------------------------

TEST(VaultFormatTests, RejectsIncorrectHeaderLength)
{
    auto bytes =
        aegis::serialize_header(make_test_header());

    std::vector<unsigned char> truncated(
        bytes.begin(),
        bytes.end() - 1
    );

    std::vector<unsigned char> oversized(
        bytes.begin(),
        bytes.end()
    );

    oversized.push_back(0);

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(truncated)
            ),
        std::runtime_error
    );

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(oversized)
            ),
        std::runtime_error
    );
}


// ---------------------------------------------------------
// Test 9: Reject Excessive Memory Requirements
// ---------------------------------------------------------

TEST(VaultFormatTests, RejectsUnsafeKdfParameters)
{
    auto bytes =
        aegis::serialize_header(make_test_header());

    // Replace the eight-byte memory limit with UINT64_MAX.
    for (std::size_t i = 52; i < 60; ++i)
    {
        bytes[i] = 0xFF;
    }

    EXPECT_THROW(
        static_cast<void>(
            aegis::deserialize_header(bytes)
            ),
        std::runtime_error
    );
}


// ---------------------------------------------------------
// Test 10: Random Header Generation
// ---------------------------------------------------------

TEST(VaultFormatTests, CreatesDistinctRandomHeaders)
{
    aegis::KdfParameters parameters
    {
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE
    };

    auto first =
        aegis::create_vault_header(parameters);

    auto second =
        aegis::create_vault_header(parameters);

    EXPECT_NE(first.salt, second.salt);

    EXPECT_NE(first.vault_id, second.vault_id);
}