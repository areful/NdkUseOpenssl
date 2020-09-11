//
// Created by gj21798 on 2020/9/2.
//

#include "utils.h"

using namespace std;

char *vector_to_p_char(const vector<char> &chars) {
    char *buffer = new char[chars.size()];
    std::copy(chars.begin(), chars.end(), buffer);
    return buffer;
}

char *jByteArrayToChars(JNIEnv *env, jbyteArray jByteArray) {
    jbyte *bytes = env->GetByteArrayElements(jByteArray, nullptr);
    int chars_len = env->GetArrayLength(jByteArray);
    char *chars = new char[chars_len + 1];
    memset(chars, 0, chars_len + 1);
    memcpy(chars, bytes, chars_len);
    chars[chars_len] = 0;

    env->ReleaseByteArrayElements(jByteArray, bytes, 0);
    return chars;
}

jbyteArray charsToJByteArray(JNIEnv *env, char *content, int content_len) {
    jbyteArray ja = env->NewByteArray(content_len);
    env->SetByteArrayRegion(ja, 0, content_len, (jbyte *) content);
    return ja;
}