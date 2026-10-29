#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv)
{
    if (sodium_init() < 0)
    {
        std::cerr << "[ERROR] Failed to initialize libsodium.\n";

        return EXIT_FAILURE;
    }

    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}