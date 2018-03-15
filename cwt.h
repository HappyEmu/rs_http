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

typedef struct cose_key {
    bytes kid;
    uint8_t kty;
    uint8_t crv;
    char* x;
    char* y;
} cose_key;

typedef struct rs_cwt {
    CborValue h_protected;
    CborValue h_unprotected;
    CborValue payload;
    CborValue signature;
} rs_cwt;

typedef struct rs_payload {
    char* iss;
    int iat;
    int exp;
    int cti;
    char* scope;
    char* aud;
    bytes cnf;
} rs_payload;

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len);
int cwt_verify(rs_cwt* cwt, bytes eaad, rs_key* key);
void cwt_parse_payload(rs_cwt* cwt, rs_payload*);
void cwt_parse_cose_key(bytes* encoded, cose_key* out);


#endif //RS_HTTP_CWT_H
