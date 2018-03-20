//
// Created by Urs Gerber on 16.03.18.
//

#ifndef RS_HTTP_COSE_H
#define RS_HTTP_COSE_H

#include "rs_types.h"

typedef struct cose_sign1 {
    bytes plaintext;
    bytes external_aad;
    bytes protected_header;
    bytes unprotected_header;
} cose_sign1;

typedef struct cose_encrypt0 {
    bytes plaintext;
    bytes external_aad;
} cose_encrypt0;

#endif //RS_HTTP_COSE_H
