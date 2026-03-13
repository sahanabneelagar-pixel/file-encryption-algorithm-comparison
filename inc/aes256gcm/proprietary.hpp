#ifndef AES256GCM_PROPRIETARY_HPP
#define AES256GCM_PROPRIETARY_HPP

#include <string>

namespace aes256gcm::proprietary
{

/// @brief Encryption Information.
struct encryption_info
{
    size_t size;                    ///< size of the encryption info in the encrypted file
    struct {
        std::string algorithm;      ///< algorithm used for key derivation, always "PBKDF2"
        std::string salt;           ///< salt for key derivation
        std::string digest;         ///< digest used for key derivation
        unsigned int iterations;    ///< iterations used for key derivation    
    } kdf;
    std::string encryption_method;  ///< encryption method, always "AES256-GCM"
    std::string nonce;              ///< none / initialization vector for encryption
    std::string tag;                ///< tag to check authenticity
    std::string additional_data;    ///< additional authenticated but unencrypted data
};


/// @brief Reads encryption info from the given file.
///
/// @note This function uses s proprietary file format.
///
/// @param filename Path of the encrypted file.
/// @param info Result where to store the encryption info.
/// @return true, if encryption info is read successfulle, false otherwiese
bool get_encryption_info(
    std::string const & filename,
    encryption_info & info);


/// @brief Encrypt a given file.
///
/// @note The file is encrypted in a proprietary file format
///       in order to store encryption information and
///       additional data.
///
/// @param input_filename path of the unencrypted file
/// @param output_filename path where to store the encrypted file to
/// @param password password to encrypt the file
/// @param additional_data additional data that is stored unencrypted but
///                        authenticated in the encrypted file
void encrypt_file(
    std::string const & input_filename,
    std::string const & output_filename,
    std::string const & password,
    std::string const & additional_data = "");


/// @brief Encrypt a given file inplace.
///
/// @note The file is encrypted in a proprietary file format
///       in order to store encryption information and
///       additional data.
///
/// @param filename path of the file to encrypt
/// @param password password to encrypt the file
/// @param additional_data additional data that is stored unencrypted but
///                        authenticated in the encrypted file
void encrypt_file_inplace(
    std::string const & filename,
    std::string const & password,
    std::string const & additional_data = "");


/// @brief Decrypts a given file.
///
/// @note The input file uses the proprietary file format
///       produces by the encrypt_file function.
///
/// @note The file might be corrupted if decryption
///       fails.
///
/// @param input_filename path of encrypted file
/// @param output_filename path where the decrypted file is stored to
/// @param password password to decrypt file
/// @return 0 on success, otherwise failure.
int decrypt_file(
    std::string const & input_filename,
    std::string const & output_filename,
    std::string const & password);


/// @brief Decrypt a given file inplace.
///
/// @note The input file uses the proprietary file format
///       produces by the encrypt_file function.
///
/// @note The file might be corrupted if decryption
///       fails.
///
/// @param filename path of the file to decrypt
/// @param password password to decrypt file
/// @return 0 on success, otherwise failure.
int decrypt_file_inplace(
    std::string const & filename,
    std::string const & password);    

}

#endif