#include "symmetric.h"

int rs_encrypt(byte* cipher,
               byte* plain, word32 sz_plain,
               byte* nonce, word32 sz_nonce,
               byte* tag, word32 sz_tag,
               byte* aad, word32 sz_aad) {
    Aes aes;

    int ret = wc_AesCcmEncrypt(&aes, cipher,
                               plain, sz_plain,
                               nonce, sz_nonce,
                               tag, sz_tag,
                               aad, sz_aad);

    return ret;
}
