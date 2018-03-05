//
// Created by Urs Gerber on 05.03.18.
//

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifndef RS_HTTP_SYMMETRIC_H
#define RS_HTTP_SYMMETRIC_H

#define TAG_SIZE 8
#define KEY_SIZE 16
#define NONCE_SIZE 7

int rs_encrypt(byte* cipher,
               byte* plain, word32 sz_plain,
               byte* nonce, word32 sz_nonce,
               byte* tag, word32 sz_tag,
               byte* aad, word32 sz_aad);

#endif //RS_HTTP_SYMMETRIC_H
