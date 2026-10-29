#include "aegis/secure_buffer.hpp"

#include <gtest/gtest.h>

#include <type_traits>
#include <utility>


// SecureBuffer must never be copyable.
static_assert(!std::is_copy_constructible_v<aegis::SecureBuffer>);
static_assert(!std::is_copy_assignable_v<aegis::SecureBuffer>);

// SecureBuffer must support move operations.
static_assert(std::is_move_constructible_v<aegis::SecureBuffer>);
static_assert(std::is_move_assignable_v<aegis::SecureBuffer>);


// ---------------------------------------
// Test 1: Default Construction
// ---------------------------------------

TEST(SecureBufferTests, DefaultConstruction)
{
    aegis::SecureBuffer buffer;

    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0u);
    EXPECT_EQ(buffer.data(), nullptr);
}


// ---------------------------------------
// Test 2: Memory Allocation
// ---------------------------------------

TEST(SecureBufferTests, AllocatesMemory)
{
    aegis::SecureBuffer buffer(32);

    EXPECT_FALSE(buffer.empty());
    EXPECT_EQ(buffer.size(), 32u);
    ASSERT_NE(buffer.data(), nullptr);

    for (std::size_t i = 0; i < buffer.size(); ++i)
    {
        EXPECT_EQ(buffer.data()[i], 0);
    }
}


// ---------------------------------------
// Test 3: Secure Memory Clearing
// ---------------------------------------

TEST(SecureBufferTests, ClearsMemory)
{
    aegis::SecureBuffer buffer(16);

    ASSERT_NE(buffer.data(), nullptr);

    // Write example sensitive data.
    for (std::size_t i = 0; i < buffer.size(); ++i)
    {
        buffer.data()[i] = 0xAB;
    }

    // Securely erase the contents.
    buffer.clear();

    // Verify every byte was overwritten.
    for (std::size_t i = 0; i < buffer.size(); ++i)
    {
        EXPECT_EQ(buffer.data()[i], 0);
    }
}


// ---------------------------------------
// Test 4: Move Construction
// ---------------------------------------

TEST(SecureBufferTests, MoveConstruction)
{
    aegis::SecureBuffer original(32);

    unsigned char* originalAddress = original.data();

    aegis::SecureBuffer moved(std::move(original));

    EXPECT_EQ(moved.data(), originalAddress);
    EXPECT_EQ(moved.size(), 32u);

    EXPECT_EQ(original.data(), nullptr);
    EXPECT_EQ(original.size(), 0u);
}


// ---------------------------------------
// Test 5: Move Assignment
// ---------------------------------------

TEST(SecureBufferTests, MoveAssignment)
{
    aegis::SecureBuffer source(32);
    aegis::SecureBuffer destination(16);

    unsigned char* originalAddress = source.data();

    destination = std::move(source);

    EXPECT_EQ(destination.data(), originalAddress);
    EXPECT_EQ(destination.size(), 32u);

    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.data(), nullptr);
}


// ---------------------------------------
// Test 6: Self Move Assignment
// ---------------------------------------

TEST(SecureBufferTests, SelfMoveAssignment)
{
    aegis::SecureBuffer buffer(32);

    unsigned char* originalAddress = buffer.data();

    auto& reference = buffer;

    buffer = std::move(reference);

    EXPECT_EQ(buffer.data(), originalAddress);
    EXPECT_EQ(buffer.size(), 32u);
}