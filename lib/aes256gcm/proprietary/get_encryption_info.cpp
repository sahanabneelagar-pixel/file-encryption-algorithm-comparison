#include "aes256gcm/proprietary.hpp"
#include "aes256gcm/proprietary/encryption_info.hpp"

#include <cstring>

#include <fstream>
#include <filesystem>
#include <iostream>

namespace aes256gcm::proprietary
{

bool get_encryption_info(
    std::string const & filename,
    encryption_info & info)
{
    auto const file_size = std::filesystem::file_size(filename);
    if (file_size < end_of_info_size)
    {
        std::cerr << "error: file too small" << std::endl;
        return false;
    }

    auto const end_of_info_pos = file_size - end_of_info_size;
    std::ifstream file(filename);
    file.seekg(end_of_info_pos);

    char end_of_info[end_of_info_size];
    file.read(end_of_info, end_of_info_size);

    if (end_of_info_size != file.gcount())
    {
        std::cerr << "error: failed to read encryption info" << std::endl;
        return false;
    }

    if (0 != strncmp(&end_of_info[4], signature, sizeof(signature)))
    {
        std::cerr << "error: invalid signature " << std::endl;
        return false;
    }

    uint32_t info_size = 0;
    for (size_t i = 0; i < 4; i++)
    {
        info_size <<= 8;
        info_size += ((uint32_t) end_of_info[i]) & 0xff;
    }

    if ((info_size > file_size) || (info_size > max_info_size))
    {
        std::cerr << "error: invalid info size" << info_size << std::endl;
        return false;
    }

    auto const info_pos = file_size - info_size;
    std::vector<char> raw_info(info_size);
    file.seekg(info_pos);
    file.read(raw_info.data(), raw_info.size());

    if (file.gcount() != info_size)
    {
        std::cerr << "error: failed to read encryption info" << std::endl;
        return false;
    }

    return parse_encryption_info(raw_info, info);
}
    

}