#ifndef AES256GCM_CONSTANTS_HPP
#define AES256GCM_CONSTANTS_HPP

#include <cstddef>

namespace aes256gcm
{

constexpr size_t const kdf_salt_size = 8;
constexpr size_t const nonce_size = 12;
constexpr size_t const key_size = 32;
constexpr size_t const tag_size = 16;
constexpr unsigned int const kdf_iterations = 2048;
constexpr char const kdf_digest[] = "sha256";
constexpr char const pbkdf2_algorithm[] = "PBKDF2";
constexpr char const encryption_method[] = "AES256-GCM";
    
}

#endif
