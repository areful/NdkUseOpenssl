#include <jni.h>
#include <string>

#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <string>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "native-lib.h"
#include "common.h"

#include "rsa/test_rsa.h"
#include "aes/test_aes.h"
#include "b64/test_b64.h"

using namespace std;

static char *vector_to_p_char(const vector<char> &chars);

extern "C" JNIEXPORT jstring JNICALL
Java_cn_areful_openssl_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";

    test_base64();

    test_rsa();

    test_aes();

    return env->NewStringUTF(hello.c_str());
}