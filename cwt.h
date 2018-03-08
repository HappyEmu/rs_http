//
// Created by Urs Gerber on 08.03.18.
//

#ifndef RS_HTTP_CWT_H
#define RS_HTTP_CWT_H

#include <cbor.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>

void cwt_parse(cbor_item_t* cwt);
void cwt_verify(cbor_item_t* signature, cbor_item_t *protected, cbor_item_t *payload, cbor_item_t *external_aad);


#endif //RS_HTTP_CWT_H
