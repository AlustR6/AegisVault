#include "aegis/secure_text.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <type_traits>
#include <utility>


static_assert(!std::is_copy_constructible_v<aegis::SecureText>);
static_assert(!std::is_copy_assignable_v<aegis::SecureText>);

static_assert(std::is_move_constructible_v<aegis::SecureText>);
static_assert(std::is_move_assignable_v<aegis::SecureText>);


TEST(SecureTextTests, StartsEmpty)
{
    aegis::SecureText text(64);

    EXPECT_TRUE(text.empty());
    EXPECT_EQ(text.size(), 0u);
    EXPECT_EQ(text.capacity(), 64u);
}


TEST(SecureTextTests, AppendsASCII)
{
    aegis::SecureText text(64);

    text.append_codepoint(U'A');
    text.append_codepoint(U'B');
    text.append_codepoint(U'C');

    EXPECT_EQ(text.size(), 3u);

    EXPECT_EQ(text.data()[0], 'A');
    EXPECT_EQ(text.data()[1], 'B');
    EXPECT_EQ(text.data()[2], 'C');
}


TEST(SecureTextTests, AppendsUnicode)
{
    aegis::SecureText text(64);

    text.append_codepoint(U'\u00E9');

    EXPECT_EQ(text.size(), 2u);

    EXPECT_EQ(text.data()[0], 0xC3);
    EXPECT_EQ(text.data()[1], 0xA9);
}


TEST(SecureTextTests, BackspaceErasesBytes)
{
    aegis::SecureText text(64);

    text.append_codepoint(U'A');
    text.append_codepoint(U'B');

    text.backspace();

    EXPECT_EQ(text.size(), 1u);
    EXPECT_EQ(text.data()[0], 'A');
    EXPECT_EQ(text.data()[1], 0);
}


TEST(SecureTextTests, BackspaceRemovesUnicodeCharacter)
{
    aegis::SecureText text(64);

    text.append_codepoint(U'A');
    text.append_codepoint(U'\U0001F512');

    EXPECT_EQ(text.size(), 5u);

    text.backspace();

    EXPECT_EQ(text.size(), 1u);

    for (std::size_t i = 1; i < 5; ++i)
    {
        EXPECT_EQ(text.data()[i], 0);
    }
}


TEST(SecureTextTests, RejectsExcessiveLength)
{
    aegis::SecureText text(2);

    text.append_codepoint(U'A');

    EXPECT_THROW(
        text.append_codepoint(U'\u00E9'),
        std::length_error
    );

    EXPECT_EQ(text.size(), 1u);
}


TEST(SecureTextTests, RejectsInvalidUnicode)
{
    aegis::SecureText text(64);

    EXPECT_THROW(
        text.append_codepoint(static_cast<char32_t>(0xD800)),
        std::invalid_argument
    );
}


TEST(SecureTextTests, ClearsContents)
{
    aegis::SecureText text(64);

    text.append_codepoint(U'S');
    text.append_codepoint(U'E');
    text.append_codepoint(U'C');

    text.clear();

    EXPECT_TRUE(text.empty());

    for (std::size_t i = 0; i < text.capacity(); ++i)
    {
        EXPECT_EQ(text.data()[i], 0);
    }
}


TEST(SecureTextTests, MoveTransfersOwnership)
{
    aegis::SecureText original(64);

    original.append_codepoint(U'A');

    const unsigned char* original_address = original.data();

    aegis::SecureText moved(std::move(original));

    EXPECT_EQ(moved.data(), original_address);
    EXPECT_EQ(moved.size(), 1u);

    EXPECT_TRUE(original.empty());
    EXPECT_EQ(original.data(), nullptr);
}