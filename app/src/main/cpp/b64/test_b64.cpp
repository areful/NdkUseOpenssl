//
// Created by gj on 7/9/20.
//

#include "b64.h"
#include "test_b64.h"

#include <iostream>
#include <string>
#include <cstring>
#include "../common.h"

using namespace std;

void test_base64() {
    string msg("Hello, base64 string!");

    const char *p = msg.c_str();
    char *encode_result = base64Encode(p, strlen(p), false);
    cout << encode_result << endl;
    LOGW("base64 encode_result:\t%s", encode_result);

    char *decode_result = base64Decode(encode_result, strlen(encode_result), false);
    cout << decode_result << endl;
    LOGW("base64 decode_result:\t%s", decode_result);
}