#ifndef AES256GCM_PROPRIETARY_MEMMAPPED_FILE_HPP
#define AES256GCM_PROPRIETARY_MEMMAPPED_FILE_HPP

#include <string>

namespace aes256gcm::proprietary
{

class memmapped_file
{
    memmapped_file(memmapped_file const &) = delete;
    memmapped_file& operator=(memmapped_file const &) = delete;
    memmapped_file(memmapped_file &&) = delete;
    memmapped_file& operator=(memmapped_file &&) = delete;
public:
    explicit memmapped_file(std::string const & filename);
    ~memmapped_file();
    char * address() const noexcept;
    size_t size() const noexcept;
private:
    int m_fd;
    size_t m_size;
    char * m_address;
};

}

#endif
