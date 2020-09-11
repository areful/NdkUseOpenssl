//2
// Created by gj on 8/26/2020.
//

#ifndef CPPRSAWITHOPENSSL_CBD_AES5_H
#define CPPRSAWITHOPENSSL_CBD_AES5_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>

#define SUCCESS 0
#define FAILURE -1

class CbdAes {
public:
    CbdAes();

    size_t setAesKey(unsigned char *aesKey, size_t aesKeyLengthgth);

//    size_t getAesKey(unsigned char **aesKey);

    size_t setAesIv(unsigned char *aesIv, size_t aesIvLengthgth);

//    size_t getAesIv(unsigned char **aesIv);

    size_t aesEncrypt(const unsigned char *message, size_t messageLength, unsigned char **encryptedMessage);

    size_t aesDecrypt(unsigned char *encryptedMessage, size_t encryptedMessageLength, unsigned char **decryptedMessage);

    ~CbdAes();

private:
    EVP_CIPHER_CTX *aesEncryptContext;
    EVP_CIPHER_CTX *aesDecryptContext;

    unsigned char *mAesKey = nullptr;
    unsigned char *mAesIv = nullptr;

    size_t aesKeyLength;
    size_t aesIvLength;
};

#endif //CPPRSAWITHOPENSSL_CBD_AES5_H
