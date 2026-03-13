#include "aes256gcm/pbkdf2.hpp"
#include <gtest/gtest.h>

TEST(pbsdf2, derive_key)
{
    auto const key = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "sha256", 2048);
    ASSERT_EQ(32, key.size());
}

TEST(pbsdf2, derive_key_fails_with_invalid_digest)
{
    ASSERT_ANY_THROW({
        aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "invalid-digest", 2048);
    });
}

TEST(pbsdf2, generates_different_keys_for_different_passwords)
{
    auto const key1 = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "sha256", 2048);
    auto const key2 = aes256gcm::pbkdf2("SECRET", {1,2,3,4,5,6,7,8}, "sha256", 2048);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbsdf2, generates_different_keys_for_different_nonces)
{
    auto const key1 = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "sha256", 2048);
    auto const key2 = aes256gcm::pbkdf2("secret", {0,1,2,3,4,5,6,7}, "sha256", 2048);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbsdf2, generates_different_keys_for_different_iterations)
{
    auto const key1 = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "sha256", 2048);
    auto const key2 = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "sha256", 1024);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

TEST(pbsdf2, generates_different_keys_for_different_digests)
{
    auto const key1 = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "sha256", 2048);
    auto const key2 = aes256gcm::pbkdf2("secret", {1,2,3,4,5,6,7,8}, "md5"   , 2048);

    ASSERT_EQ(32, key1.size());
    ASSERT_EQ(32, key2.size());
    ASSERT_NE(key1, key2);
}

