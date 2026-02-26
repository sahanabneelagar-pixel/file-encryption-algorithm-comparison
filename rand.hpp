#ifndef AES256GCM_RAND_HPP
#define AES256GCM_RAND_HPP

#include <string>

namespace aes256gcm
{

/// @brief Returns a string of random data of the given size.
/// @param size Amount of random data to return.
/// @return String of random data of the given size.
/// @throws An openssl_error is thrown on error of underlying OpenSSL function call.
std::string rand(size_t size);

}

#endif