#ifndef AES256GCM_PROPRIETARY_ENCRYPTION_INFO_HPP
#define AES256GCM_PROPRIETARY_ENCRYPTION_INFO_HPP

#include "aes256gcm/proprietary.hpp"
#include <vector>

namespace aes256gcm::proprietary
{

constexpr char const signature[8] = {'E', 'N','C','-','I','N','F','O'};
constexpr size_t const end_of_info_size = 4 + sizeof(signature);
constexpr size_t const max_info_size = 1 * 1024 * 1024;

void create_encryption_info(
    std::vector<char> & data,
    std::string const & salt,
    std::string const & digest,
    unsigned int iterations,
    std::string const & nonce,
    std::string const & tag,
    std::string const & additional_data);


bool parse_encryption_info(
    std::vector<char> const & data,
    encryption_info & info);


}


#endif
