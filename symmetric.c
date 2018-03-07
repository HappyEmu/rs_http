#include "symmetric.h"
#include <wolfssl/wolfcrypt/aes.h>

struct Suite suite = {
        .key_size = KEY_SIZE,
        .nonce_size = NONCE_SIZE,
        .tag_size = TAG_SIZE
};

int rs_encrypt(byte *cipher, byte *plain, word32 sz_plain,
               byte *key, byte *nonce, byte *tag,
               byte *aad, word32 sz_aad) {

    Aes aes;
    wc_AesCcmSetKey(&aes, key, suite.key_size);

    int ret = wc_AesCcmEncrypt(&aes, cipher,
                               plain, sz_plain,
                               nonce, suite.nonce_size,
                               tag, suite.tag_size,
                               aad, sz_aad);

    return ret;
}

int rs_decrypt(byte *plain, byte *cipher, word32 sz_cipher,
               byte *key, byte *nonce, byte *tag,
               byte *aad, word32 sz_aad) {

    Aes aes;
    wc_AesCcmSetKey(&aes, key, suite.key_size);

    int ret = wc_AesCcmDecrypt(&aes, plain,
                               cipher, sz_cipher,
                               nonce, suite.nonce_size,
                               tag, suite.tag_size,
                               aad, sz_aad);

    return ret;
}