#include "aegis/vault_repository.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <span>
#include <stdexcept>

namespace
{
    aegis::SecureBuffer make_key()
    {
        aegis::SecureBuffer key(
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES
        );

        randombytes_buf(key.data(), key.size());

        return key;
    }

    aegis::VaultImage make_image()
    {
        aegis::VaultImage image;
        const aegis::KdfParameters parameters{
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        };

        image.header = aegis::create_vault_header(parameters);

        auto key = make_key();
        image.verification = aegis::create_verification_record(
            image.header,
            key
        );

        const std::span<const aegis::CatalogInput> empty_entries;
        image.catalog = aegis::encrypt_catalog(
            image.header,
            key,
            empty_entries
        );

        return image;
    }
}

TEST(VaultRepositoryTests, SerializesAndDeserializesVaultImage)
{
    const auto original = make_image();

    const auto bytes = aegis::serialize_vault_image(original);
    const auto restored = aegis::deserialize_vault_image(bytes);

    EXPECT_EQ(restored.header.salt, original.header.salt);
    EXPECT_EQ(restored.header.vault_id, original.header.vault_id);
    EXPECT_EQ(restored.header.kdf.opslimit, original.header.kdf.opslimit);
    EXPECT_EQ(
        restored.header.kdf.memlimit_bytes,
        original.header.kdf.memlimit_bytes
    );
    EXPECT_EQ(restored.verification.nonce, original.verification.nonce);
    EXPECT_EQ(
        restored.verification.ciphertext,
        original.verification.ciphertext
    );
    EXPECT_EQ(
        aegis::serialize_catalog_record(restored.catalog),
        aegis::serialize_catalog_record(original.catalog)
    );
    EXPECT_TRUE(restored.records.empty());
}

TEST(VaultRepositoryTests, RejectsTrailingData)
{
    const auto image = make_image();
    auto bytes = aegis::serialize_vault_image(image);

    bytes.push_back(0);

    EXPECT_THROW(
        static_cast<void>(aegis::deserialize_vault_image(bytes)),
        std::runtime_error
    );
}
