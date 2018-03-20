//
// Created by Urs Gerber on 08.03.18.
//

#ifndef RS_HTTP_EDHOC_H
#define RS_HTTP_EDHOC_H

#include <stdint.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include "tinycbor.h"
#include "rs_types.h"
#include "cose.h"

typedef struct edhoc_msg_1 {
    uint8_t tag;
    bytes session_id;
    bytes nonce;
    bytes eph_key;
} edhoc_msg_1;

typedef struct edhoc_msg_2 {
    uint8_t tag;
    bytes session_id;
    bytes peer_session_id;
    bytes peer_nonce;
    bytes peer_key;
    cose_sign1 _sig_v;
    bytes _cose_enc_2;
} edhoc_msg_2;

typedef struct edhoc_msg_3 {
    uint8_t tag;
    bytes peer_session_id;
    bytes cose_enc_3;
} edhoc_msg_3;

typedef struct edhoc_server_session_state {
    bytes session_id;
    ecc_key pop_key;
    bytes message1;
    bytes message2;
    bytes message3;
} edhoc_server_session_state;

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, unsigned char* buffer, size_t buf_size);

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len);
void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len);

void edhoc_aad2(edhoc_msg_2 *msg2, bytes message1, byte* out_hash);
void edhoc_msg2_sig_v(edhoc_msg_2 *msg2, const byte* aad2);

#endif //RS_HTTP_EDHOC_H
