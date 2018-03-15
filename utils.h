//
// Created by Urs Gerber on 08.03.18.
//

#ifndef RS_HTTP_UTILS_H
#define RS_HTTP_UTILS_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

void phex(byte* ary, size_t len);

size_t buffer_to_hexstring(char** string, byte* buffer, size_t buf_len);
size_t hexstring_to_buffer(byte** buffer, char* string, size_t string_len);


#endif //RS_HTTP_UTILS_H
