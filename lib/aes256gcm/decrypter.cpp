#include "aes256gcm/decrypter.hpp"
#include "aes256gcm/rand.hpp"
#include "aes256gcm/pbkdf2.hpp"
#include "aes256gcm/openssl_error.hpp"
#include "aes256gcm/constants.hpp"

namespace aes256gcm
{

decrypter::decrypter(
    std::string const & key,
    std::string const & nonce,
    std::string const & tag,
    std::string const & additional_data)
: m_ctx(nullptr, EVP_CIPHER_CTX_free)
{
    if (key.size() != key_size)
    {
        throw std::logic_error("invalid key size");
    }

    if (nonce.size() != nonce_size)
    {
        throw std::logic_error("invalid nonce size");
    }

    if (tag.size() != tag_size)
    {
        throw std::logic_error("invalid tag size");
    }

    EVP_CIPHER_CTX * raw_ctx = EVP_CIPHER_CTX_new();
    if (nullptr == raw_ctx)
    {
        throw openssl_error();
    }
    m_ctx.reset(raw_ctx);

    int rc = EVP_DecryptInit_ex(m_ctx.get(), EVP_aes_256_gcm(), nullptr, 
        reinterpret_cast<unsigned char const*>(key.data()), 
        reinterpret_cast<unsigned char const *>(nonce.data()));
    if (rc != 1)
    {
        throw openssl_error();
    }

    rc = EVP_CIPHER_CTX_ctrl(m_ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), 
        const_cast<char*>(tag.data()));
    if (rc != 1)
    {
        throw openssl_error();
    }

    if (!additional_data.empty())
    {
        rc = EVP_DecryptUpdate(m_ctx.get(), nullptr, 0, 
            reinterpret_cast<unsigned char const*>(additional_data.data()),
            additional_data.size());
        if (rc != 1)
        {
            throw openssl_error();
        }
    }
}

void decrypter::update(char const * in, char * out, size_t size)
{
    int out_size = static_cast<int>(size);

    int const rc = EVP_DecryptUpdate(m_ctx.get(), 
        reinterpret_cast<unsigned char*>(out), &out_size, 
        reinterpret_cast<unsigned char const*>(in), size);
    if (rc != 1)
    {
        throw openssl_error();
    }

    if (size != out_size)
    {
        throw std::runtime_error("output buffer size mismatch");
    }
}

void decrypter::update_inplace(char * buffer, size_t buffer_size)
{
    int out_size = buffer_size;

    int const rc = EVP_DecryptUpdate(m_ctx.get(), 
        reinterpret_cast<unsigned char*>(buffer), &out_size, 
        reinterpret_cast<unsigned char const*>(buffer), buffer_size);
    if (rc != 1)
    {
        throw openssl_error();
    }

    if (buffer_size != out_size)
    {
        throw std::runtime_error("output buffer size mismatch");
    }
}

bool decrypter::finalize()
{
    int out_size = 0;
    int const rc = EVP_DecryptFinal_ex(m_ctx.get(), nullptr, &out_size);
    return (rc == 1);
}


}