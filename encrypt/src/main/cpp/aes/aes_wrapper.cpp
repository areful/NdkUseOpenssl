//
// Created by gj on 8/26/2020.
//

#include "aes_wrapper.h"

CbdAes::CbdAes() {
    aesEncryptContext = EVP_CIPHER_CTX_new();
    aesDecryptContext = EVP_CIPHER_CTX_new();

    /* Don't set key or IV right away; we want to set lengths */
    EVP_CIPHER_CTX_init(aesEncryptContext);
    EVP_CIPHER_CTX_init(aesDecryptContext);

    EVP_CipherInit_ex(aesEncryptContext, EVP_aes_128_cbc(), nullptr, nullptr, nullptr, 1);

    /* Now we can set key and IV lengths */
    aesKeyLength = EVP_CIPHER_CTX_key_length(aesEncryptContext);
    aesIvLength = EVP_CIPHER_CTX_iv_length(aesEncryptContext);
}

//size_t CbdAes::getAesKey(unsigned char **aesKey) {
//    *aesKey = mAesKey;
//    return aesKeyLength;
//}

size_t CbdAes::setAesKey(unsigned char *aesKey, size_t aesKeyLengthgth) {
    // Ensure the new key is the proper size
    if (aesKeyLengthgth != aesKeyLength) {
        return FAILURE;
    }

    mAesKey = static_cast<unsigned char *>(calloc(1, aesIvLength));
    memcpy(mAesKey, aesKey, aesKeyLength);

    return SUCCESS;
}

//size_t CbdAes::getAesIv(unsigned char **aesIv) {
//    *aesIv = mAesKey;
//    return aesIvLength;
//}

size_t CbdAes::setAesIv(unsigned char *aesIv, size_t aesIvLengthgth) {
    // Ensure the new IV is the proper size
    if (aesIvLengthgth != aesIvLength) {
        return FAILURE;
    }

    mAesIv = static_cast<unsigned char *>(calloc(1, aesIvLength));
    memcpy(mAesIv, aesIv, aesIvLength);

    return SUCCESS;
}

size_t CbdAes::aesEncrypt(const unsigned char *message,
                          size_t messageLength,
                          unsigned char **encryptedMessage) {
    // Allocate memory for everything
    size_t blockLength = 0;
    size_t encryptedMessageLength = 0;

    *encryptedMessage = (unsigned char *) malloc(messageLength + AES_BLOCK_SIZE);

    // Encrypt it!
    if (!EVP_EncryptInit_ex(aesEncryptContext, EVP_aes_128_cbc(), nullptr, mAesKey, mAesIv)) {
        return FAILURE;
    }

    if (!EVP_EncryptUpdate(aesEncryptContext, *encryptedMessage, (int *) &blockLength,
                           (unsigned char *) message, messageLength)) {
        return FAILURE;
    }
    encryptedMessageLength += blockLength;

    if (!EVP_EncryptFinal_ex(aesEncryptContext, *encryptedMessage + encryptedMessageLength,
                             (int *) &blockLength)) {
        return FAILURE;
    }

    return encryptedMessageLength + blockLength;
}

size_t CbdAes::aesDecrypt(unsigned char *encryptedMessage,
                          size_t encryptedMessageLength,
                          unsigned char **decryptedMessage) {
    // Allocate memory for everything
    size_t decryptedMessageLength = 0;
    size_t blockLength = 0;

    *decryptedMessage = (unsigned char *) malloc(encryptedMessageLength);
    if (*decryptedMessage == nullptr) {
        return FAILURE;
    }

    // Decrypt it!
    if (!EVP_DecryptInit_ex(aesDecryptContext, EVP_aes_128_cbc(), nullptr, mAesKey, mAesIv)) {
        return FAILURE;
    }

    if (!EVP_DecryptUpdate(aesDecryptContext,
                           (unsigned char *) *decryptedMessage,
                           (int *) &blockLength,
                           encryptedMessage, (int) encryptedMessageLength)) {
        return FAILURE;
    }
    decryptedMessageLength += blockLength;

    if (!EVP_DecryptFinal_ex(aesDecryptContext,
                             (unsigned char *) *decryptedMessage + decryptedMessageLength,
                             (int *) &blockLength)) {
        return FAILURE;
    }
    decryptedMessageLength += blockLength;

    return (int) decryptedMessageLength;
}

CbdAes::~CbdAes() {
    free(aesEncryptContext);
    free(aesDecryptContext);
    aesEncryptContext = nullptr;
    aesDecryptContext = nullptr;

    if (mAesKey != nullptr) {
        free(mAesKey);
        mAesKey = nullptr;
    }
    if (mAesIv != nullptr) {
        free(mAesIv);
        mAesIv = nullptr;
    }
}