//
// Created by gj on 8/26/2020.
//
#include "test_aes.h"
#include "aes_wrapper.h"
#include "base64.h"
#include "../common.h"
#include <iostream>

using namespace std;

int test_aes() {
    unsigned char KEY_HTTP[AES_BLOCK_SIZE + 1] = "0123456789ABCDEF";
    unsigned char IV_HTTP[AES_BLOCK_SIZE] = {
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
    };

    auto *aes = new CbdAes();
    aes->setAesKey(KEY_HTTP, 16);
    aes->setAesIv(IV_HTTP, 16);

    // encrypt aes
    string msg = string("hello,world!2. 点击切换tab的展示的主页面不展示返回icon；当进入下一级页面的时候，在页面的右下位置增加一个返回icon；");
    const auto *in = reinterpret_cast<const unsigned char *>(msg.c_str());
    size_t in_len = msg.size() + 1;
    unsigned char *encrypted = nullptr;
    int encrypted_len = aes->aesEncrypt(in, in_len, &encrypted);
    if (encrypted_len == FAILURE) {
        LOGW("Encryption failed\n");
        return FAILURE;
    }

//    // decrypt aes
//    unsigned char *decrypted = nullptr;
//    int decrypted_len = aes->aesDecrypt(encrypted, encrypted_len, (unsigned char **) &decrypted);
//    if (decrypted_len == FAILURE) {
//        LOGW("Decryption failed\n");
//        return FAILURE;
//    }

    // encode base64
    char *b64_encoded = base64Encode(encrypted, encrypted_len);
    LOGW("Encrypted message: %s\n", b64_encoded);

    // decode base64
    unsigned char *b64_decoded = nullptr;
    int b64_decode_len = base64Decode(b64_encoded, strlen(b64_encoded), &b64_decoded);

    // decrypt aes
    unsigned char *decrypted = nullptr;
    int decrypted_len = aes->aesDecrypt(b64_decoded, b64_decode_len, (unsigned char **) &decrypted);
    if (decrypted_len == FAILURE) {
        LOGW("Decryption failed\n");
        return FAILURE;
    }

    LOGW("Decrypted message: %s\n", decrypted);

    free(b64_encoded);
    free(b64_decoded);
    free(encrypted);
    free(decrypted);

    return SUCCESS;
}