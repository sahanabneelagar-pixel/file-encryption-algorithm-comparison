#include "aes256gcm/proprietary/memmapped_file.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <filesystem>
#include <stdexcept>

namespace aes256gcm::proprietary
{

memmapped_file::memmapped_file(std::string const & filename)
{
    auto const file_size = std::filesystem::file_size(filename);
    if (file_size > SIZE_MAX)
    {
        throw std::runtime_error("file too large");
    }
    m_size = static_cast<size_t>(file_size);

    m_fd = open(filename.c_str(), O_RDWR);
    if (m_fd < 0)
    {
        throw std::runtime_error("failed to open file");
    }

    m_address = reinterpret_cast<char*>(mmap(nullptr, m_size, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0));
    if (nullptr == m_address)
    {
        close(m_fd);
        throw std::runtime_error("failed to memmap file");
    }
}

memmapped_file::~memmapped_file()
{
    munmap(m_address, m_size);
    close(m_fd);
}

char * memmapped_file::address() const noexcept
{
    return m_address;
}

size_t memmapped_file::size() const noexcept
{
    return m_size;
}


}