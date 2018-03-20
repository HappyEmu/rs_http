//
// Created by Urs Gerber on 16.03.18.
//

#ifndef RS_HTTP_COSE_H
#define RS_HTTP_COSE_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include "rs_types.h"

typedef struct cose_sign1 {
    bytes payload;
    bytes external_aad;
    bytes protected_header;
    bytes unprotected_header;
} cose_sign1;

typedef struct cose_encrypt0 {
    bytes plaintext;
    bytes external_aad;
} cose_encrypt0;

void cose_encode_signed(cose_sign1* sign1,
                        ecc_key* signing_key,
                        uint8_t* out,
                        size_t out_size,
                        size_t* out_len);

void cose_sign1_structure(const char* context,
                          bytes* body_protected,
                          bytes* external_aad,
                          bytes* payload,
                          uint8_t* out,
                          size_t out_size,
                          size_t* out_len);

#endif //RS_HTTP_COSE_H
