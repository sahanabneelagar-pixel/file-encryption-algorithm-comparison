#ifndef AES256GCM_OPENSSL_ERROR_HPP
#define AES256GCM_OPENSSL_ERROR_HPP

#include <stdexcept>
#include <string>

namespace aes256gcm
{

/// @brief Exception to encapsulate OpenSSL errors.
class openssl_error: public std::exception
{
public:
    /// @brief Creates a new openssl_error.
    ///
    /// Uses OpenSSL functions to retrieve error code
    // and error message of the currently active 
    /// OpenSSL error.
    openssl_error();

    /// @brief Cleans up the openssl error.
    ~openssl_error() override = default;

    /// @brief Return the error message.
    /// @return error message
    char const * what() const noexcept override;

    /// @brief Returns the OpenSSL error code.
    ///
    /// The error code might be used as input of
    /// various OpenSSL functions to retrieve
    /// further error information-
    ///
    /// @return OpenSSL error code.
    unsigned long error_code() const noexcept;
private:
    unsigned long m_error_code;
    std::string m_error_message;
};

}

#endif
