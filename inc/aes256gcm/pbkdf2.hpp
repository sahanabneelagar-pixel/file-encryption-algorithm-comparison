#ifndef AES256GCM_PBKDF2_HPP
#define AES256GCM_PBKDF2_HPP

#include <string>

namespace aes256gcm
{

/// @brief Derives a key from a password using PBKDF2 method.
///
/// @note The key size is 32 bytes, which is needed for
///       AES256-GCM, but might be insufficient for other
///       algorithms.
///
/// @param password   password to derive key from
/// @param salt       salt of password; should be at least 8 bytes
/// @param digest     name of the alorith used to hash the password
/// @param iterations number of iterations to derive key
/// @return derived key
/// @throws An openssl_error is thrown on error of underlying OpenSSL function calls.
std::string pbkdf2(
    std::string const & password,
    std::string const & salt,
    std::string const & digest,
    unsigned int iterations);

/// @brief Generates parameters for key derivation
/// @param salt random salt to generate
/// @param digest store digest
/// @param iterations store iterations
/// @throws An openssl_error is thrown on error creating random salt.
void pbkdf2_generate_params(
    std::string & salt,
    std::string & digest,
    unsigned int & iterations);

}

#endif