#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/decrypter.hpp"
#include "aes256gcm/pbkdf2.hpp"

#include <fstream>
#include <stdexcept>
#include <filesystem>

#include <iostream>

namespace aes256gcm::proprietary
{

    
int decrypt_file(
    std::string const & input_filename,
    std::string const & output_filename,
    std::string const & password)
{
    encryption_info info;
    if (!get_encryption_info(input_filename, info))
    {
        return EXIT_FAILURE;
    }

    auto const key = pbkdf2(password, info.kdf.salt, info.kdf.digest, info.kdf.iterations);
    decrypter dec(key, info.nonce, info.tag, info.additional_data);

    auto const file_size = std::filesystem::file_size(input_filename);
    auto remaining = file_size - info.size;

    {
        std::ifstream in(input_filename);
        std::ofstream out(output_filename);

        constexpr size_t const buffer_size = 100 * 1024;
        std::vector<char> in_buffer(buffer_size);
        std::vector<char> out_buffer(buffer_size);

        while ((in) && (out) && (remaining > 0))
        {
            auto const chunk_size = std::min(remaining, buffer_size);
            in.read(in_buffer.data(), chunk_size);
            auto const bytes_read = in.gcount();

            if (bytes_read > 0)
            {
                dec.update(in_buffer.data(), out_buffer.data(), bytes_read);
                out.write(out_buffer.data(), bytes_read);
                remaining -= bytes_read;
            }
        }

        if (in.bad())
        {
            throw std::runtime_error("failed to read from file");        
        }

        if (out.bad())
        {
            throw std::runtime_error("failed to write to file");
        }
    }

    if (!dec.finalize())
    {
        std::filesystem::remove(output_filename);
        std::cerr << "error: failed to decrypt file" << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}


}