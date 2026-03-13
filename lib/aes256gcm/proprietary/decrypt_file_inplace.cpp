#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/proprietary/memmapped_file.hpp"

#include "aes256gcm/decrypter.hpp"
#include "aes256gcm/pbkdf2.hpp"

#include <iostream>
#include <filesystem>


namespace aes256gcm::proprietary
{

int decrypt_file_inplace(
    std::string const & filename,
    std::string const & password)
{
    encryption_info info;
    if (!get_encryption_info(filename, info))
    {
        return EXIT_FAILURE;
    }

    auto const key = pbkdf2(password, info.kdf.salt, info.kdf.digest, info.kdf.iterations);
    decrypter dec(key, info.nonce, info.tag, info.additional_data);

    auto const file_size = std::filesystem::file_size(filename);
    auto const data_size = file_size - info.size;
    std::filesystem::resize_file(filename, data_size);

    {
        memmapped_file file(filename);
        dec.update_inplace(file.address(), file.size());
    }

    if (!dec.finalize())
    {
        std::cerr << "error: failed to decrypt file (file data corrupted)" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
    
}
