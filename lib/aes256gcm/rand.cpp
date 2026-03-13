#include "aes256gcm/rand.hpp"
#include "aes256gcm/openssl_error.hpp"

#include <openssl/rand.h>

#include <vector>

namespace aes256gcm
{

std::string rand(size_t size)
{
    std::vector<char> data(size);

    int const rc = RAND_bytes(reinterpret_cast<unsigned char*>(data.data()), data.size());
    if (rc != 1)
    {
        throw openssl_error();
    }

    return std::string(data.data(), data.size());
}


}