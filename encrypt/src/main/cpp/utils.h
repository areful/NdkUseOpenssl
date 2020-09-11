//
// Created by gj21798 on 2020/9/2.
//

#ifndef NDKUSEOPENSSL_UTILS_H
#define NDKUSEOPENSSL_UTILS_H

#include<jni.h>
#include<vector>
#include<string>

char *vector_to_p_char(const std::vector<char> &chars);

char *jByteArrayToChars(JNIEnv *env, jbyteArray jByteArray);

jbyteArray charsToJByteArray(JNIEnv *env, char *content, int content_len);

#endif //NDKUSEOPENSSL_UTILS_H
