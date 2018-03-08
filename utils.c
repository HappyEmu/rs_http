//
// Created by Urs Gerber on 08.03.18.
//

#include "utils.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

void phex(byte* ary, size_t len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", ary[i]);
    }
    printf("\n");
}

size_t hexstring_to_buffer(byte **buffer, char *string, size_t string_len) {
    size_t out_length = string_len / 2;
    byte* block = malloc(out_length);

    for (unsigned int i = 0; i < out_length; i++) {
        char buf[3] = {string[2*i], string[2*i+1], 0};
        block[i] = (byte) strtol(buf, 0, 16);
    }

    *buffer = block;

    return out_length;
}
