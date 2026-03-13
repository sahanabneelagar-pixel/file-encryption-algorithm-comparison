#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/proprietary/memmapped_file.hpp"

#include "aes256gcm/encrypter.hpp"
#include "aes256gcm/pbkdf2.hpp"

#include <filesystem>
#include <fstream>

namespace aes256gcm::proprietary
{

void encrypt_file_inplace(
    std::string const & filename,
    std::string const & password,
    std::string const & additional_data)
{
    std::string salt;
    std::string digest;
    unsigned int iterations;
    pbkdf2_generate_params(salt, digest, iterations);
    auto const key = pbkdf2(password, salt, digest, iterations);

    encrypter enc(key, additional_data);

    {
        memmapped_file file(filename);
        enc.update_inplace(file.address(), file.size());
    }

    auto const tag = enc.finalize();
    auto const & nonce = enc.nonce();

    std::ofstream file(filename, std::ios_base::binary | std::ios_base::app);

    std::vector<char> info;
    create_encryption_info(info, salt, digest, iterations, nonce, tag, additional_data);
    file.write(info.data(), info.size());

    if (file.fail())
    {
        throw std::runtime_error("failed to write to file");
    }
}
    

}