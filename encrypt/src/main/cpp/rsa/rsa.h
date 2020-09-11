//
// Created by areful on 2020/07/09/.
// thanks to: https://blog.csdn.net/yp18792574062/article/details/102845506
//

#ifndef CPPRSAWITHOPENSSL_RSA_H
#define CPPRSAWITHOPENSSL_RSA_H

#include <string>
#include <vector>

// encrypt by public key file
std::vector<char> EncryptByPubkeyFile(const std::string &message, const std::string &pub_filename);

// decrypt by private key file
std::string DecryptByPriKeyFile(char *cipher, uint32_t len, const std::string &priFile);

// encrypt by public key string
std::vector<char> EncryptByPubkeyString(const std::string &message, const std::string &pubKey);

// decrypt by private key string
std::string DecryptByPriKeyString(char *cipher, uint32_t len, std::string& priKey);

// encrypt by private key file
std::vector<char> EncryptByPriKeyFile(const std::string &message, const std::string &pri_file);

// decrypt by public key file
std::string DecryptByPubkeyFile(char *cipher, uint32_t len, const std::string &pub_filename);

// encrypt by private key string
std::vector<char> EncryptByPrikeyString(const std::string &message, const std::string &priKey);

// decrypt by public key string
std::string DecryptByPubkeyString(char *cipher, uint32_t len, const std::string &pubkey);

// sign by private key file
std::vector<char> GenerateRsaSignByFile(const std::string &message, const std::string &pri_filename);

// verify sign by public key file
bool VerifyRsaSignByFile(char *sign, uint32_t sign_len,
                         const std::string &pub_filename,
                         const std::string &verify_str);

// sign by private key string
std::vector<char> GenerateRsaSignByString(const std::string &message, const std::string &prikey);

// verify sign by public key string
bool VerifyRsaSignByString(char *sign, uint32_t sign_len,
                           const std::string &pubkey,
                           const std::string &verify_str);

#endif //CPPRSAWITHOPENSSL_RSA_H
