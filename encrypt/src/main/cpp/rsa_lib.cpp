//
// Created by areful on 2020/9/2.
//

#include "rsa_lib.h"
#include "rsa/rsa.h"
#include "b64/b64.h"
#include "utils.h"
#include<string>

using namespace std;

/**
 * nativeEncrypt
 */
jstring JNI_CRYPTO(nativeEncrypt)(JNIEnv *env, jclass,
                                  jstring jKey, jstring jContent) {
    if (jKey == nullptr || jContent == nullptr) {
        return env->NewStringUTF("");
    }

    const char *key = env->GetStringUTFChars(jKey, nullptr);
    const char *content = env->GetStringUTFChars(jContent, nullptr);
    if (key == nullptr || content == nullptr) {
        return env->NewStringUTF("");
    }

    const vector<char> &chars = EncryptByPubkeyString(content, key);
    char *buffer = vector_to_p_char(chars);
    char *encode_result = base64Encode(buffer, chars.size(), false);

    delete[] key;
    delete[] content;
    delete[] buffer;
    return env->NewStringUTF(encode_result);
}

/**
 * nativeVerify
 */
jboolean JNI_CRYPTO (nativeVerify)(JNIEnv *env, jclass,
                                   jstring jKey, jstring jContent, jbyteArray jSignBytes) {
    if (jKey == nullptr || jContent == nullptr) {
        return false;
    }

    const char *key = env->GetStringUTFChars(jKey, nullptr);
    const char *content = env->GetStringUTFChars(jContent, nullptr);
    if (key == nullptr || content == nullptr) {
        return false;
    }

    char *signBytes = jByteArrayToChars(env, jSignBytes);
    jboolean result = VerifyRsaSignByString(signBytes, strlen(signBytes), key, content);

    delete[] key;
    delete[] content;
    delete[] signBytes;
    return result;
}