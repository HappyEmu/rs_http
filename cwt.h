//
// Created by Urs Gerber on 08.03.18.
//

#ifndef RS_HTTP_CWT_H
#define RS_HTTP_CWT_H

#include "tinycbor.h"
#include "rs_types.h"
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
    CborValue protected;
    CborValue unprotected;
    CborValue payload;
    CborValue signature;
} rs_cwt;

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len);
int cwt_verify(rs_cwt* cwt, bytes eaad, rs_key* key);


#endif //RS_HTTP_CWT_H
