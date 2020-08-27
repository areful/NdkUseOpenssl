#include <jni.h>
#include <string>
#include <iostream>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "common.h"
#include "native-lib.h"

#include "aes/aes_wrapper.h"
#include "aes/base64.h"
#include "aes/test_aes.h"
#include "b64/test_b64.h"
#include "rsa/test_rsa.h"

using namespace std;

static char *vector_to_p_char(const vector<char> &chars);

static int setKeyIv(CbdAes &pAes, jint type);

const char *KEY_HTTP = "MTMkfnwRuZJ2Cbfe";

const unsigned char IV_HTTP[AES_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

const char *KEY_PASSWORD = "MTMkfnwRuZJ2Cbfe";
const unsigned char IV_PASSWORD[AES_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

const char *KEY_TRACK = "MTMkfnwRuZJ2Cbfe";
const unsigned char IV_TRACK[AES_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
};

extern "C" JNIEXPORT jstring JNICALL
Java_com_chebada_encrypt_Encryption_stringFromJNI(
        JNIEnv *env,
        jclass /* this */) {
    std::string hello = "Hello from C++";

    test_base64();

    test_rsa();

    test_aes();

    return env->NewStringUTF(hello.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_chebada_encrypt_Encryption_encode(JNIEnv *env,
                                           jclass,
                                           jstring content,
                                           jint type) {
    CbdAes aes;
    if (setKeyIv(aes, type)) {
        return env->NewStringUTF("");
    }

    const char *in = env->GetStringUTFChars(content, (jboolean *) false);
    int in_len = strlen(in);
    unsigned char *encrypted = nullptr;
    int encrypted_len = aes.aesEncrypt(reinterpret_cast<const unsigned char *>(in),
                                       in_len,
                                       &encrypted);
    if (encrypted_len == FAILURE) {
        LOGW("Encryption failed\n");
        return env->NewStringUTF("");
    }

    // encode base64
    char *b64_encoded = base64Encode(encrypted, encrypted_len);
    if (b64_encoded == nullptr) {
        LOGW("Base64 decode failed\n");
        free(encrypted);
        return env->NewStringUTF("");
    }

    LOGW("Encrypted message: %s\n", b64_encoded);
    jstring result = env->NewStringUTF(b64_encoded);
    free(encrypted);
    free(b64_encoded);
    return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_chebada_encrypt_Encryption_decode(JNIEnv *env,
                                           jclass,
                                           jstring content,
                                           jint type) {
    CbdAes aes;
    if (setKeyIv(aes, type)) {
        return env->NewStringUTF("");
    }

    // decode base64
    const char *b64_encoded = env->GetStringUTFChars(content, (jboolean *) false);
    unsigned char *b64_decoded = nullptr;
    int b64_decode_len = base64Decode(b64_encoded, strlen(b64_encoded), &b64_decoded);
    if (b64_decode_len == FAILURE) {
        return env->NewStringUTF("");
    }

    // decrypt aes
    unsigned char *decrypted = nullptr;
    int decrypted_len = aes.aesDecrypt(b64_decoded,
                                       b64_decode_len,
                                       (unsigned char **) &decrypted);
    if (decrypted_len == FAILURE) {
        LOGW("Decryption failed\n");
        free(b64_decoded);
        return env->NewStringUTF("");
    }

    *(decrypted + decrypted_len) = '\0';

    LOGW("Decrypted message: %s\n", decrypted);
    jstring result = env->NewStringUTF(reinterpret_cast<const char *>(decrypted));
    free(b64_decoded);
    free(decrypted);
    return result;
}

static int setKeyIv(CbdAes &aes, jint type) {
    if (type == 1) {
        if (aes.setAesKey((unsigned char *) KEY_TRACK, AES_BLOCK_SIZE) ||
            aes.setAesIv(const_cast<unsigned char *>(IV_TRACK), AES_BLOCK_SIZE)) {
            return FAILURE;
        }
    } else if (type == 2) {
        if (aes.setAesKey((unsigned char *) KEY_HTTP, AES_BLOCK_SIZE) ||
            aes.setAesIv(const_cast<unsigned char *>(IV_HTTP), AES_BLOCK_SIZE)) {
            return FAILURE;
        }
    } else {
        if (aes.setAesKey((unsigned char *) KEY_PASSWORD, AES_BLOCK_SIZE) ||
            aes.setAesIv(const_cast<unsigned char *>(IV_PASSWORD), AES_BLOCK_SIZE)) {
            return FAILURE;
        }
    }
    return SUCCESS;
}