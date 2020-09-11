//
// Created by areful on 2020/07/09/.
// https://blog.csdn.net/yp18792574062/article/details/102845506
//

#include <vector>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <string>
#include <iostream>
#include <openssl/pem.h>
#include "rsa.h"

// encrypt by public key file
std::vector<char> EncryptByPubkeyFile(const std::string &message,
                                      const std::string &pub_filename) {
    BIO *in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return std::vector<char>();
    }
    BIO_read_filename(in, pub_filename.c_str());

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return std::vector<char>();
    }
    int size = RSA_size(rsa);
    std::vector<char> encrypt_data;
    encrypt_data.resize(size);
    int ret = RSA_public_encrypt(
            message.length(), (unsigned char *) message.c_str(),
            (unsigned char *) encrypt_data.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_public_encrypt failed" << std::endl;
        return std::vector<char>();
    }
    return encrypt_data;
}

// decrypt by private key file
std::string DecryptByPriKeyFile(char *cipher, uint32_t len,
                                const std::string &priFile) {
    BIO *in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return "";
    }
    BIO_read_filename(in, priFile.c_str());

    RSA *rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return "";
    }

    int size = RSA_size(rsa);
    std::vector<char> data;
    data.resize(size);
    int ret = RSA_private_decrypt(len, (unsigned char *) cipher,
                                  (unsigned char *) data.data(), rsa,
                                  RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_private_decrypt failed" << std::endl;
        return "";
    }
    std::string decrypt_data(data.begin(), data.end());
    return decrypt_data;
}

// encrypt by public key string
std::vector<char> EncryptByPubkeyString(const std::string &message,
                                        const std::string &pubKey) {
    BIO *in = BIO_new_mem_buf((void *) pubKey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return std::vector<char>();
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return std::vector<char>();
    }

    int size = RSA_size(rsa);
    std::vector<char> encrypt_data;
    encrypt_data.resize(size);
    int ret = RSA_public_encrypt(
            message.length(), (unsigned char *) message.c_str(),
            (unsigned char *) encrypt_data.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_public_encrypt failed" << std::endl;
        return std::vector<char>();
    }

    return encrypt_data;
}

// decrypt by private key string
std::string DecryptByPriKeyString(char *cipher, uint32_t len,
                                  std::string& priKey) {
    BIO *in = BIO_new_mem_buf((void *) priKey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return "";
    }

    RSA *rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return "";
    }

    int size = RSA_size(rsa);
    std::vector<char> data;
    data.resize(size);
    int ret = RSA_private_decrypt(len, (unsigned char *) cipher,
                                  (unsigned char *) data.data(), rsa,
                                  RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_private_decrypt failed" << std::endl;
        return "";
    }
    std::string decrypt_data(data.begin(), data.end());
    return decrypt_data;
}

// encrypt by private key file
std::vector<char> EncryptByPriKeyFile(const std::string &message,
                                      const std::string &pri_file) {
    BIO *in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return std::vector<char>();
    }
    BIO_read_filename(in, pri_file.c_str());

    RSA *rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }
    int size = RSA_size(rsa);
    std::vector<char> encrypt_data;
    encrypt_data.resize(size);
    int ret = RSA_private_encrypt(
            message.length(), (unsigned char *) message.c_str(),
            (unsigned char *) encrypt_data.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_private_encrypt failed" << std::endl;
        return std::vector<char>();
    }
    return encrypt_data;
}

// decrypt by public key file
std::string DecryptByPubkeyFile(char *cipher, uint32_t len,
                                const std::string &pub_filename) {
    BIO *in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return "";
    }
    BIO_read_filename(in, pub_filename.c_str());

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return "";
    }

    int size = RSA_size(rsa);
    std::vector<char> data;
    data.resize(size);
    int ret = RSA_public_decrypt(len, (unsigned char *) cipher,
                                 (unsigned char *) data.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_public_decrypt failed" << std::endl;
        return "";
    }
    std::string decrypt_data(data.begin(), data.end());
    return decrypt_data;
}

// encrypt by private key string
std::vector<char> EncryptByPrikeyString(const std::string &message,
                                        const std::string &priKey) {
    BIO *in = BIO_new_mem_buf((void *) priKey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return std::vector<char>();
    }

    RSA *rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }

    int size = RSA_size(rsa);
    std::vector<char> encrypt_data;
    encrypt_data.resize(size);
    int ret = RSA_private_encrypt(
            message.length(), (unsigned char *) message.c_str(),
            (unsigned char *) encrypt_data.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_private_encrypt failed" << std::endl;
        return std::vector<char>();
    }

    return encrypt_data;
}

// decrypt by public key string
std::string DecryptByPubkeyString(char *cipher, uint32_t len,
                                  const std::string &pubkey) {
    BIO *in = BIO_new_mem_buf((void *) pubkey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return "";
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return "";
    }

    int size = RSA_size(rsa);
    std::vector<char> data;
    data.resize(size);
    int ret = RSA_public_decrypt(len, (unsigned char *) cipher,
                                 (unsigned char *) data.data(), rsa, RSA_PKCS1_PADDING);
    RSA_free(rsa);
    if (ret == -1) {
        std::cout << "RSA_public_decrypt failed" << std::endl;
        return "";
    }
    std::string decrypt_data(data.begin(), data.end());
    return decrypt_data;
}

// sign by private key file
std::vector<char> GenerateRsaSignByFile(const std::string &message,
                                        const std::string &pri_filename) {
    OpenSSL_add_all_algorithms();
    BIO *in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return std::vector<char>();
    }
    BIO_read_filename(in, pri_filename.c_str());
    RSA *rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);

    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }
    unsigned int size = RSA_size(rsa);
    std::vector<char> sign;
    sign.resize(size);

    int ret = RSA_sign(NID_sha1, (const unsigned char *) message.c_str(),
                       message.length(), (unsigned char *) sign.data(), &size, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_sign failed" << std::endl;
        return std::vector<char>();
    }
    return sign;
}

// verify sign by public key file
bool VerifyRsaSignByFile(char *sign, uint32_t sign_len,
                         const std::string &pub_filename,
                         const std::string &verify_str) {
    OpenSSL_add_all_algorithms();
    BIO *in = BIO_new(BIO_s_file());
    if (in == nullptr) {
        std::cout << "BIO_new failed" << std::endl;
        return false;
    }

    BIO_read_filename(in, pub_filename.c_str());

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(in, nullptr, nullptr, nullptr);

    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return false;
    }
    BIO_free(in);

    int ret = RSA_verify(NID_sha1, (const unsigned char *) verify_str.c_str(),
                         verify_str.length(), (unsigned char *) sign, sign_len, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_verify failed" << std::endl;
        return false;
    }
    return true;
}

// sign by private key string
std::vector<char> GenerateRsaSignByString(const std::string &message,
                                          const std::string &prikey) {
    OpenSSL_add_all_algorithms();
    BIO *in = BIO_new_mem_buf((void *) prikey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return std::vector<char>();
    }

    RSA *rsa = PEM_read_bio_RSAPrivateKey(in, nullptr, nullptr, nullptr);
    BIO_free(in);

    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSAPrivateKey failed" << std::endl;
        return std::vector<char>();
    }
    unsigned int size = RSA_size(rsa);
    std::vector<char> sign;
    sign.resize(size);

    int ret = RSA_sign(NID_sha1, (const unsigned char *) message.c_str(),
                       message.length(), (unsigned char *) sign.data(), &size, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_sign failed" << std::endl;
        return std::vector<char>();
    }
    return sign;
}

// verify sign by public key string
bool VerifyRsaSignByString(char *sign, uint32_t sign_len,
                           const std::string &pubkey,
                           const std::string &verify_str) {
    BIO *in = BIO_new_mem_buf((void *) pubkey.c_str(), -1);
    if (in == nullptr) {
        std::cout << "BIO_new_mem_buf failed" << std::endl;
        return false;
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(in, nullptr, nullptr, nullptr);
    BIO_free(in);

    if (rsa == nullptr) {
        std::cout << "PEM_read_bio_RSA_PUBKEY failed" << std::endl;
        return false;
    }

    int ret = RSA_verify(NID_sha1, (const unsigned char *) verify_str.c_str(),
                         verify_str.length(), (unsigned char *) sign, sign_len, rsa);
    RSA_free(rsa);
    if (ret != 1) {
        std::cout << "RSA_verify failed" << std::endl;
        return false;
    }
    return true;
}
