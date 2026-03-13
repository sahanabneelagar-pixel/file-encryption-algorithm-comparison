#include "aes256gcm/proprietary/encryption_info.hpp"
#include "aes256gcm/constants.hpp"

#include <cstring>
#include <stdexcept>
#include <vector>

#include <iostream>

namespace aes256gcm::proprietary
{

constexpr char const kdf_algorithm_id = 'k';
constexpr char const kdf_salt_id = 's';
constexpr char const kdf_digest_id = 'd';
constexpr char const kdf_interations_id = 'i';

constexpr char const encryption_method_id = 'm';
constexpr char const nonce_id = 'n';
constexpr char const tag_id = 't';
constexpr char const additional_data_id = 'a';

constexpr char const end_of_info_id = 0x0;
constexpr char const invalid_id = 0xff;

namespace
{

void add_signature(std::vector<char> & data, std::string const & signature)
{
    data.insert(data.end(), signature.begin(), signature.end());
}

void add_field_str(std::vector<char> & data, char id, std::string const & field)
{
    if (field.size() > 0xffffff)
    {
        throw std::runtime_error("field too large"); 
    }

    data.push_back(id);
    data.push_back( (field.size() >> 16) & 0xff );
    data.push_back( (field.size() >>  8) & 0xff );
    data.push_back( field.size() & 0xff );

    data.insert(data.end(), field.begin(), field.end());
}

void add_field_u32(std::vector<char> & data, char id, uint32_t value)
{
    data.push_back(id);
    data.push_back(0);
    data.push_back(0);
    data.push_back(4);
    data.push_back( (value >> 24) & 0xff );
    data.push_back( (value >> 16) & 0xff );
    data.push_back( (value >> 8) & 0xff );
    data.push_back( value & 0xff );
}

void add_end_of_info(std::vector<char> & data)
{
    size_t const size = data.size() + 4 + sizeof(signature);

    data.push_back( end_of_info_id);
    data.push_back( (size >> 16) & 0xff );
    data.push_back( (size >> 8) & 0xff );
    data.push_back( (size) & 0xff );

    add_signature(data, std::string(signature, sizeof(signature)));
}

char parse_next(std::vector<char> const & data, size_t &pos, std::string & value)
{
    auto const id = data.at(pos++);
    if (id != end_of_info_id)
    {
        size_t size = (((size_t) (data.at(pos++)) & 0xff) << 16) |
               (((size_t) (data.at(pos++)) & 0xff) <<  8) |
                ((size_t) (data.at(pos++)) & 0xff);
        if ((pos + size) >= data.size())
        {
            return 0xff;
        }

        value = std::string(&data.data()[pos], size);
        pos += size;
    }

    return id;
}

unsigned int parse_uint(std::string const & value)
{
    unsigned int result = 0;
    for (size_t i = 0; i < 4; i++)
    {
        result <<= 8;
        result |= (value.at(i) & 0xff);
    }
    return result;
}

}

void create_encryption_info(
    std::vector<char> & data,
    std::string const & salt,
    std::string const & digest,
    unsigned int iterations,
    std::string const & nonce,
    std::string const & tag,
    std::string const & additional_data)
{
    add_field_str(data,kdf_algorithm_id, pbkdf2_algorithm);
    add_field_str(data, kdf_salt_id, salt);
    add_field_str(data, kdf_digest_id, digest);
    add_field_u32(data, kdf_interations_id, iterations);
    add_field_str(data, encryption_method_id, encryption_method);
    add_field_str(data, nonce_id, nonce);
    add_field_str(data, tag_id, tag);
    add_field_str(data, additional_data_id, additional_data);
    add_end_of_info(data);
}



bool parse_encryption_info(
    std::vector<char> const & data,
    encryption_info & info)
{
    info.size = data.size();

    size_t pos = 0;
    bool done = false;
    while (!done)
    {
        std::string value;
        auto const c = parse_next(data, pos, value);
        switch (c)
        {
            case end_of_info_id:
                done = true;
                break;
            case kdf_algorithm_id:
                info.kdf.algorithm = value;
                break;
            case kdf_salt_id:
                info.kdf.salt = value;
                break;
            case kdf_digest_id:
                info.kdf.digest = value;
                break;
            case kdf_interations_id:
                info.kdf.iterations = parse_uint(value);
                break;
            case encryption_method_id:
                info.encryption_method = value;
                break;
            case nonce_id:
                info.nonce = value;
                break;
            case tag_id:
                info.tag = value;
                break;
            case additional_data_id:
                info.additional_data = value;
                break;
            case invalid_id:
                // fall-through
            default:
                std::cerr << "error: invalid id" << std::endl;
                return false;                    
        }
    }

    return true;
}
    

}