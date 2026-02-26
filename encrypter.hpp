#ifndef AES256GCM_ENCRYPTER_HPP
#define AES256GCM_ENCRYPTER_HPP

#include <openssl/evp.h>

#include <string>
#include <memory>

namespace aes256gcm
{

/// @brief AES256-GCM encryption context.
class encrypter
{
public:
    /// @brief Creates a new AES256-GCM encryption context.
    ///
    /// @param key Key used for encryption.
    /// @param additional_data Optional additional authenticated data.
    /// @throws A logic error is thrown on invalid key size.
    ///         An openssl_error is thrown on error of underlying OpenSSL function calls.
    encrypter(
        std::string const & key,
        std::string const & additional_data = "");
    
    /// @brief Cleans up the encryption context.
    ~encrypter() = default;

    /// @brief Encrypts some data.
    ///
    /// @note input and output buffer are of equal size.
    ///
    /// @param in buffer of the unencrypted data.
    /// @param out buffer to store the encrypted data.
    /// @param size size of input and output buffers.
    /// @throws An openssl_error is thrown on error of underlying OpenSSL function call.
    ///         A runtime_error is thrown on mismatch of output buffer size.
    void update(char const * in, char * out, size_t size);

    /// @brief Encrypts some data inplace.
    /// @param buffer buffer to encrypt.
    /// @param buffer_size Size of the buffer.
    /// @throws An openssl_error is thrown on error of underlying OpenSSL function call.
    ///         A runtime_error is thrown on mismatch of output buffer size.
    void update_inplace(char * buffer, size_t buffer_size);

    /// @brief Finalizes the encryption and returns the encryption tag.
    /// @return Encryption tag.
    /// @throws An openssl_error is thrown on error of underlying OpenSSL function calls.
    std::string finalize();

    /// @brief Returns the Nonce / Initialization Vector of the encryption.
    /// @return Nonce / Initialization Vector of the encryption.
    std::string const & nonce() const noexcept;

private:
    std::unique_ptr<EVP_CIPHER_CTX, void (*) (EVP_CIPHER_CTX*)> m_ctx;
    std::string m_nonce;
};
    

}

#endif
