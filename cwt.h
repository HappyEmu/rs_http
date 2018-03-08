//
// Created by Urs Gerber on 08.03.18.
//

#ifndef RS_HTTP_CWT_H
#define RS_HTTP_CWT_H

#include <cbor.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>

typedef struct rs_key {
    char* x;
    char* y;
    char* d;
    ecc_curve_id curve_id;
} rs_key;

typedef struct rs_cwt {
    cbor_item_t* protected;
    cbor_item_t* unprotected;
    cbor_item_t* payload;
    cbor_item_t* signature;
} rs_cwt;

void cwt_parse(rs_cwt* cwt, cbor_item_t *encoded);
int cwt_verify(rs_cwt* cwt, cbor_item_t *external_aad, rs_key* key);


#endif //RS_HTTP_CWT_H
