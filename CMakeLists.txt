cmake_minimum_required(VERSION 3.20)
project(aes256gcm)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(aes256gcm STATIC
    lib/aes256gcm/rand.cpp
    lib/aes256gcm/pbkdf2.cpp
    lib/aes256gcm/openssl_error.cpp
    lib/aes256gcm/encrypter.cpp
    lib/aes256gcm/decrypter.cpp
    
    lib/aes256gcm/proprietary/encryption_info.cpp
    lib/aes256gcm/proprietary/encrypt_file.cpp
    lib/aes256gcm/proprietary/decrypt_file.cpp
    lib/aes256gcm/proprietary/get_encryption_info.cpp
    lib/aes256gcm/proprietary/encrypt_file_inplace.cpp
    lib/aes256gcm/proprietary/decrypt_file_inplace.cpp
    lib/aes256gcm/proprietary/memmapped_file.cpp
)
target_link_libraries(aes256gcm PUBLIC OpenSSL::Crypto)
target_include_directories(aes256gcm PUBLIC inc)
target_include_directories(aes256gcm PRIVATE lib)

add_executable(aes256gcm_app src/main.cpp)
target_link_libraries(aes256gcm_app PRIVATE aes256gcm)
set_target_properties(aes256gcm_app PROPERTIES OUTPUT_NAME aes256gcm)

enable_testing()
include(CTest)

find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(alltests 
    test-src/test_pbkdf2.cpp
    test-src/test_xcrypt.cpp
)
target_link_libraries(alltests PRIVATE aes256gcm GTest::gtest GTest::gtest_main)
target_include_directories(alltests PRIVATE lib)

gtest_discover_tests(alltests)
