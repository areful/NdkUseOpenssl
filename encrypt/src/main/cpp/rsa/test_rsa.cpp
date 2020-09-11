//
// Created by areful on 2020/07/09/.
//

#include <iostream>
#include "test_rsa.h"
#include "rsa.h"
#include "../common.h"
#include "../b64/b64.h"

using namespace std;

static void test_cipher_within_key_strings();

static void test_sign_within_key_strings();

static void test_cipher_within_key_files();

static void test_sign_within_key_files();

static char *vector_to_p_char(const vector<char> &chars);

void test_rsa() {
    test_cipher_within_key_strings();

    test_sign_within_key_strings();

//    test_cipher_within_key_files();

//    test_sign_within_key_files();
}

static void test_cipher_within_key_strings() {
    string msg = "Hello, RSA cipher within key strings!";
    string publicKeyStr = "-----BEGIN PUBLIC KEY-----\n"
                          "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJnB+YXiGyEhuK0xGkEEDtieUw\n"
                          "k8ZrWGupzKzJ1irzRyXEnXoZGpTTAi3ldIokEoHwH0K6+TRJtOSMviEQSiZBisJ+\n"
                          "TzwDMD0yMRtxO6Ek8Ml6dsWE8HfjiFMFTGe4juAIDHCSrlDYeDRDf80xuprkAzlO\n"
                          "WNEGIY87QI534WMB5QIDAQAB\n"
                          "-----END PUBLIC KEY-----";
    string privateKeyString = "-----BEGIN RSA PRIVATE KEY-----\n"
                              "MIICXQIBAAKBgQDJnB+YXiGyEhuK0xGkEEDtieUwk8ZrWGupzKzJ1irzRyXEnXoZ\n"
                              "GpTTAi3ldIokEoHwH0K6+TRJtOSMviEQSiZBisJ+TzwDMD0yMRtxO6Ek8Ml6dsWE\n"
                              "8HfjiFMFTGe4juAIDHCSrlDYeDRDf80xuprkAzlOWNEGIY87QI534WMB5QIDAQAB\n"
                              "AoGAOr9ksYiUdwgxwGU62bzmvpEVGO+mvPb6AHOk0fe3ckaEKePdhV0qisYyy48H\n"
                              "BfXiqS7iygr+ApBUnPJ2PgHtXV19L/DTxBuGAMBa7Fc/h/ezx6p1qMwd8TUMH+RA\n"
                              "PSo/tQmt584qpPsqJtfU5zGi3gtwfkkCpw8+f0LP0jE5xcECQQDn1UKWFJXQhqNn\n"
                              "mLzuXmw1tDYswfUqwSkCzvzKU7427l0ZPXaeq/6HonP1DoAuhseM9A+cN1B75+to\n"
                              "d9LkQCJ1AkEA3qBSVnSCHw7hmZdWzEN/CA8z4Lz3VLKYbqDosUNEGycmnyLXsYGb\n"
                              "YUdzosU/lPqUFhgStQb8+lBKqmAeW/qTsQJAbLSY1lqsrOyU7ly2KmdoAf6QcIg5\n"
                              "92Q/YKvB6PU/ee5nBRDG8Dvhy6OnD79O54IXS8adEzj0qkTjI0ccQh64iQJBAM5U\n"
                              "wHsoWED4xdZYETYXiHCrxmUQPhrdu7EsqP1BXqnby0vKOyZk/OFYG7BMJ/WnmAAy\n"
                              "J4RoCablK45krz6IKsECQQC7Fxg8+6KtnS6/IOVRDwsF1swXe9ondnI9xixQrWbV\n"
                              "DO8u5vGwbwVSfqhMhA4s6d1wbT0IBGrg1Mj9W373JvM1\n"
                              "-----END RSA PRIVATE KEY-----";
    {
        const vector<char> &chars = EncryptByPubkeyString(msg, publicKeyStr);
        char *buffer = vector_to_p_char(chars);
        char *encode_result = base64Encode(buffer, chars.size(), false);
        LOGW("base64 encrypted result:\t%s", encode_result);

        string result = DecryptByPriKeyString(buffer, chars.size(), privateKeyString);
        LOGW("decode_result:\t%s", result.c_str());
        delete[] buffer;
    }

    {
        const vector<char> &chars = EncryptByPrikeyString(msg, privateKeyString);
        char *buffer = vector_to_p_char(chars);
        string result = DecryptByPubkeyString(buffer, chars.size(), publicKeyStr);
        LOGW("decode_result:\t%s", result.c_str());
        delete[] buffer;
    }
}

static void test_sign_within_key_strings() {
    string msg = "Hello, RSA sign and verify within key strings!";
    string publicKeyStr = "-----BEGIN PUBLIC KEY-----\n"
                          "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJnB+YXiGyEhuK0xGkEEDtieUw\n"
                          "k8ZrWGupzKzJ1irzRyXEnXoZGpTTAi3ldIokEoHwH0K6+TRJtOSMviEQSiZBisJ+\n"
                          "TzwDMD0yMRtxO6Ek8Ml6dsWE8HfjiFMFTGe4juAIDHCSrlDYeDRDf80xuprkAzlO\n"
                          "WNEGIY87QI534WMB5QIDAQAB\n"
                          "-----END PUBLIC KEY-----";
    string privateKeyString = "-----BEGIN RSA PRIVATE KEY-----\n"
                              "MIICXQIBAAKBgQDJnB+YXiGyEhuK0xGkEEDtieUwk8ZrWGupzKzJ1irzRyXEnXoZ\n"
                              "GpTTAi3ldIokEoHwH0K6+TRJtOSMviEQSiZBisJ+TzwDMD0yMRtxO6Ek8Ml6dsWE\n"
                              "8HfjiFMFTGe4juAIDHCSrlDYeDRDf80xuprkAzlOWNEGIY87QI534WMB5QIDAQAB\n"
                              "AoGAOr9ksYiUdwgxwGU62bzmvpEVGO+mvPb6AHOk0fe3ckaEKePdhV0qisYyy48H\n"
                              "BfXiqS7iygr+ApBUnPJ2PgHtXV19L/DTxBuGAMBa7Fc/h/ezx6p1qMwd8TUMH+RA\n"
                              "PSo/tQmt584qpPsqJtfU5zGi3gtwfkkCpw8+f0LP0jE5xcECQQDn1UKWFJXQhqNn\n"
                              "mLzuXmw1tDYswfUqwSkCzvzKU7427l0ZPXaeq/6HonP1DoAuhseM9A+cN1B75+to\n"
                              "d9LkQCJ1AkEA3qBSVnSCHw7hmZdWzEN/CA8z4Lz3VLKYbqDosUNEGycmnyLXsYGb\n"
                              "YUdzosU/lPqUFhgStQb8+lBKqmAeW/qTsQJAbLSY1lqsrOyU7ly2KmdoAf6QcIg5\n"
                              "92Q/YKvB6PU/ee5nBRDG8Dvhy6OnD79O54IXS8adEzj0qkTjI0ccQh64iQJBAM5U\n"
                              "wHsoWED4xdZYETYXiHCrxmUQPhrdu7EsqP1BXqnby0vKOyZk/OFYG7BMJ/WnmAAy\n"
                              "J4RoCablK45krz6IKsECQQC7Fxg8+6KtnS6/IOVRDwsF1swXe9ondnI9xixQrWbV\n"
                              "DO8u5vGwbwVSfqhMhA4s6d1wbT0IBGrg1Mj9W373JvM1\n"
                              "-----END RSA PRIVATE KEY-----";
    const vector<char> &sign_bytes = GenerateRsaSignByString(msg, privateKeyString);
    char *sign = vector_to_p_char(sign_bytes);
    char *encode_result = base64Encode(sign, sign_bytes.size(), false);
    LOGW("base64 encrypted result:\t%s", encode_result);

    bool result = VerifyRsaSignByString(sign, sign_bytes.size(), publicKeyStr, msg);
    LOGW("verify result:\t%d", result);
    delete[] sign;
}

static void test_cipher_within_key_files() {
    string msg = "Hello, RSA cipher within key files!";
    string public_key_file = "../rsa_public_key.pem";
    string private_key_file = "../rsa_private_key.pem";

    {
        const vector<char> &chars = EncryptByPubkeyFile(msg, public_key_file);
        char *buffer = vector_to_p_char(chars);
        char *encode_result = base64Encode(buffer, chars.size(), false);
        LOGW("base64 encrypted result:\t%s", encode_result);

        string result = DecryptByPriKeyFile(buffer, chars.size(), private_key_file);
        LOGW("decode_result:\t%s", result.c_str());
        delete[] buffer;
    }

    {
        const vector<char> &chars = EncryptByPriKeyFile(msg, private_key_file);
        char *buffer = vector_to_p_char(chars);
        char *encode_result = base64Encode(buffer, chars.size(), false);
        LOGW("base64 encrypted result:\t%s", encode_result);

        string result = DecryptByPubkeyFile(buffer, chars.size(), public_key_file);
        LOGW("decode_result:\t%s", result.c_str());
        delete[] buffer;
    }
}

static void test_sign_within_key_files() {
    string msg = "Hello, RSA sign and verify within key files!";
    string public_key_file = "../rsa_public_key.pem";
    string private_key_file = "../rsa_private_key.pem";

    const vector<char> &sign_bytes = GenerateRsaSignByFile(msg, private_key_file);
    char *sign = vector_to_p_char(sign_bytes);
    char *encode_result = base64Encode(sign, sign_bytes.size(), false);
    LOGW("base64 encrypted result:\t%s", encode_result);

    bool result = VerifyRsaSignByFile(sign, sign_bytes.size(), public_key_file, msg);
    LOGW("verify result:\t%d", result);
    delete[] sign;
}

static char *vector_to_p_char(const vector<char> &chars) {
    char *buffer = new char[chars.size()];
    std::copy(chars.begin(), chars.end(), buffer);
    return buffer;
}