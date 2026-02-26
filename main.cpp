#include <aes256gcm/aes256gcm.hpp>

#include <getopt.h>

#include <iostream>
#include <iomanip>
#include <string>

using aes256gcm::proprietary::encrypt_file;
using aes256gcm::proprietary::encrypt_file_inplace;
using aes256gcm::proprietary::decrypt_file;
using aes256gcm::proprietary::decrypt_file_inplace;
using aes256gcm::proprietary::get_encryption_info;
using aes256gcm::proprietary::encryption_info;

namespace
{

void print_usage()
{
    std::cout << R"(aes256gcm

usage:
    encrypt <command> -i INFILE [-o OUTFILE] [-k KEY]

commands:
    -e, --encrypt encrypt file
    -d, --decrypt decrypt file
    -p, --print   print info of encrypted file

Options:
    -i, --infile  FILE specify input file name
    -o, --outfile FILE specify output file name
                       if not specified, file is encrypted / descripted inplace
    -k, --key     KEY  specify encryption key
                       if not specified, empty key is used
)";
}

enum class command
{
    encrypt,
    decrypt,
    print_info,
    print_help
};

struct context
{
    context(int argc, char* argv[])
    {
        static option const long_opts[] = {
            {"encrypt", no_argument, nullptr, 'e'},
            {"decrypt", no_argument, nullptr, 'd'},
            {"print"  , no_argument, nullptr, 'p'},
            {"infile" , required_argument, nullptr, 'i'},
            {"outfile", required_argument, nullptr, 'o'},
            {"key"    , required_argument, nullptr, 'k'},
            {"help"   , no_argument, nullptr, 'h'},
            {nullptr  , 0, nullptr, 0}
        };

        cmd = command::print_help;
        exit_code = EXIT_SUCCESS;

        optind = 0;
        opterr = 0;

        bool done = false;
        while (!done)
        {
            int idx = 0;
            int const c = getopt_long(argc, argv, "edpi:o:k:h", long_opts, &idx);
            switch (c)
            {
                case -1:
                    done = true;
                    break;
                case 'e':
                    cmd = command::encrypt;
                    break;
                case 'd':
                    cmd = command::decrypt;
                    break;
                case 'p':
                    cmd = command::print_info;
                    break;
                case 'i':
                    infile = optarg;
                    break;
                case 'o':
                    outfile = optarg;
                    break;
                case 'k':
                    key = optarg;
                    break;
                case 'h':
                    cmd = command::print_help;
                    done = true;
                    break;
                default:
                    std::cerr << "error: unrecognized option" << std::endl;
                    exit_code = EXIT_FAILURE;
                    cmd = command::print_help;
                    done = true;
                    break;
            }
        }

        if ((cmd != command::print_help) && (infile.empty())) {
            std::cerr << "error: missing required option -i" << std::endl;
            exit_code = EXIT_FAILURE;
            cmd = command::print_help;
        }
    }

    command cmd;
    int exit_code;
    std::string infile;
    std::string outfile;
    std::string key;
};

void encrypt(
    std::string const & input_file,
    std::string const & output_file,
    std::string const & key)
{
    if (output_file.empty())
    {
        encrypt_file_inplace(input_file, key);
    }
    else
    {
        encrypt_file(input_file, output_file, key);
    }
}

int decrypt(
    std::string const & input_file,
    std::string const & output_file,
    std::string const & key)
{
    if (output_file.empty())
    {
        return decrypt_file_inplace(input_file, key);
    }

    return decrypt_file(input_file, output_file, key);
}

void print_hex(std::string const & caption, std::string const & value)
{
    std::cout << caption;
    for (char const c: value)
    {
        std::cout << std::setfill('0') << std::hex << (static_cast<int>(c) & 0xff);
    }
    std::cout << std::endl;
}

int print_info(std::string const & filename)
{
    encryption_info info;
    if (!get_encryption_info(filename, info))
    {
        std::cerr << "error: missing encryption info" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Encryption Info Size: " << std::dec << info.size << std::endl;
    std::cout << "Key Derivation Function:" << std::endl;
    std::cout << "    Algorithm: " << info.kdf.algorithm << std::endl;
    print_hex(   "    Salt: ", info.kdf.salt);
    std::cout << "    Digest: " << info.kdf.digest << std::endl;
    std::cout << "    Iterations: " << std::dec << info.kdf.iterations << std::endl;
    std::cout << "Encryption Settings:" << std::endl;
    std::cout << "    Encryption Method: " << info.encryption_method << std::endl;
    print_hex("    Nonce: ", info.nonce);
    print_hex("    Tag: ", info.tag);
    print_hex("    Additional Data: ", info.additional_data);

    return EXIT_SUCCESS;
}

}

int main(int argc, char* argv[])
{
    context ctx(argc, argv);

    try
    {
        switch (ctx.cmd)
        {
            case command::encrypt:
                encrypt(ctx.infile, ctx.outfile, ctx.key);
                break;
            case command::decrypt:
                ctx.exit_code = decrypt(ctx.infile, ctx.outfile, ctx.key);
                break;
            case command::print_info:
                ctx.exit_code = print_info(ctx.infile);
                break;
            case command::print_help:
                // fall-through
            default:
                print_usage();
                break;
        }
    }
    catch (std::exception const & ex)
    {
        std::cerr << "error: " << ex.what() << std::endl;
        ctx.exit_code = EXIT_FAILURE;
    }
    catch (...)
    {
        std::cerr << "fatal: unexpected error" << std::endl;
        ctx.exit_code = EXIT_FAILURE;
    }

    return ctx.exit_code;
}
