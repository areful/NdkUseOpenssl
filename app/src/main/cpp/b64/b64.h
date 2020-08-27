//
// Created by areful on 2020/07/08.
//

#ifndef CPPRSAWITHOPENSSL_B64_H
#define CPPRSAWITHOPENSSL_B64_H

char * base64Encode(const char *buffer, int length, bool newLine);
char * base64Decode(char *input, int length, bool newLine);

#endif //CPPRSAWITHOPENSSL_B64_H
