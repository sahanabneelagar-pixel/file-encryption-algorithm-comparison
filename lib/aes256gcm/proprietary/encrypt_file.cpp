#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/encrypter.hpp"
#include "aes256gcm/pbkdf2.hpp"

#include <vector>
#include <fstream>
#include <filesystem>

namespace aes256gcm::proprietary
{

void encrypt_file(
    std::string const & input_filename,
    std::string const & output_filename,
    std::string const & password,
    std::string const & additional_data)
{
    try
    {
        std::string salt;
        std::string digest;
        unsigned int iterations;
        pbkdf2_generate_params(salt, digest, iterations);

        auto const key = pbkdf2(password, salt, digest, iterations);

        encrypter enc(key, additional_data);

        std::ifstream in(input_filename);    
        std::ofstream out(output_filename);

        std::vector<char> in_buffer;
        std::vector<char> out_buffer;

        while (in)
        {
            constexpr size_t const buffer_size = 100 * 1024;
            in_buffer.resize(buffer_size);
            in.read(in_buffer.data(), in_buffer.size());
            in_buffer.resize(in.gcount());

            if (!in_buffer.empty())
            {
                out_buffer.resize(in_buffer.size());
                enc.update(in_buffer.data(), out_buffer.data(), in_buffer.size());
                out.write(out_buffer.data(), out_buffer.size());
            }
        }

        if (in.bad())
        {
            throw std::runtime_error("failed to read from file");
        }

        auto const tag = enc.finalize();
        auto const & nonce = enc.nonce();

        std::vector<char> info;
        create_encryption_info(info, salt, digest, iterations, nonce, tag, additional_data);
        out.write(info.data(), info.size());

        if (out.fail())
        {
            throw std::runtime_error("failed to write to file");
        }
    }
    catch (...)
    {
        std::filesystem::remove(output_filename);
        throw;
    }
}
    

}