#include <gtest/gtest.h>
#include <sodium.h>

TEST(SodiumIntegration, InitializesSuccessfully)
{
	EXPECT_GE(sodium_init(), 0);
}

TEST(SodiumIntegration, UsesExpectedNonceSize)
{
	EXPECT_EQ(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 24u);
}

TEST(SodiumIntegration, UsesExpectedSaltSize)
{
	EXPECT_EQ(crypto_pwhash_SALTBYTES, 16u);
}