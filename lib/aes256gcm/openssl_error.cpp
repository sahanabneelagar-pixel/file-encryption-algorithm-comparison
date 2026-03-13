#include "aes256gcm/openssl_error.hpp"
#include <openssl/err.h>

namespace aes256gcm
{

openssl_error::openssl_error()
{
    m_error_code = ERR_get_error();
    
    constexpr size_t const buffer_size = 256;
    char buffer[buffer_size];
    ERR_error_string_n(m_error_code, buffer, buffer_size);

    m_error_message = buffer;
}

char const * openssl_error::what() const noexcept
{
    return m_error_message.c_str();
}

unsigned long openssl_error::error_code() const noexcept
{
    return m_error_code;
}

}