#include "aes256gcm/pbkdf2.hpp"
#include "aes256gcm/rand.hpp"
#include "aes256gcm/constants.hpp"
#include "aes256gcm/openssl_error.hpp"

#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include <memory>

namespace aes256gcm
{

std::string pbkdf2(
    std::string const & password,
    std::string const & salt,
    std::string const & digest,
    unsigned int iterations)
{
    EVP_KDF * raw_kdf = EVP_KDF_fetch(nullptr, pbkdf2_algorithm, nullptr);
    if (nullptr == raw_kdf)
    {
        throw openssl_error();
    }
    auto kdf = std::unique_ptr<EVP_KDF, void (*) (EVP_KDF*)>(raw_kdf, EVP_KDF_free);

    EVP_KDF_CTX * raw_ctx = EVP_KDF_CTX_new(kdf.get());
    if (nullptr == raw_ctx)
    {
        throw openssl_error();
    }
    auto ctx = std::unique_ptr<EVP_KDF_CTX, void (*) (EVP_KDF_CTX*)>(raw_ctx, EVP_KDF_CTX_free);

    OSSL_PARAM const params[] =
    {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(password.data()), password.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<char*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest.data()), digest.size()),
        OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations),
        OSSL_PARAM_construct_end()
    };

    char key[key_size];
    int const rc = EVP_KDF_derive(ctx.get(), reinterpret_cast<unsigned char*>(key), key_size, params);
    if (rc != 1)
    {
        throw openssl_error();
    }

    return std::string(key, key_size);
}

void pbkdf2_generate_params(
    std::string & salt,
    std::string & digest,
    unsigned int & iterations)
{
    salt = rand(kdf_salt_size);
    digest = kdf_digest;
    iterations = kdf_iterations;
}


}