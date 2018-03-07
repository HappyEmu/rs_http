//
// Created by Urs Gerber on 05.03.18.
//

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

#ifndef RS_HTTP_SYMMETRIC_H
#define RS_HTTP_SYMMETRIC_H

#define TAG_SIZE 8
#define KEY_SIZE 16
#define NONCE_SIZE 7

struct Suite {
    word32 key_size;
    word32 nonce_size;
    word32 tag_size;
};

int rs_encrypt(byte *cipher, byte *plain, word32 sz_plain, byte *key, byte *nonce, byte *tag, byte *aad, word32 sz_aad);

int rs_decrypt(byte *plain, byte *cipher, word32 sz_cipher, byte *key, byte *nonce, byte *tag, byte *aad, word32 sz_aad);



#endif //RS_HTTP_SYMMETRIC_H
