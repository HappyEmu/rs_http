//
// Created by Urs Gerber on 08.03.18.
//

#include "edhoc.h"



void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, cbor_item_t *encoded) {
    cbor_item_t* tag        = cbor_array_get(encoded, 0);
    cbor_item_t* session_id = cbor_array_get(encoded, 1);
    cbor_item_t* nonce      = cbor_array_get(encoded, 2);
    cbor_item_t* key        = cbor_array_get(encoded, 3);

    byte* b_session_id = cbor_bytestring_handle(session_id);
    byte* b_nonce      = cbor_bytestring_handle(nonce);
    byte* b_key        = cbor_bytestring_handle(key);

    msg1->tag = cbor_get_uint8(tag);
    msg1->session_id = (struct bytes) { b_session_id, cbor_bytestring_length(session_id) };
    msg1->nonce      = (struct bytes) { b_nonce,      cbor_bytestring_length(nonce) };
    msg1->eph_key    = (struct bytes) { b_key,        cbor_bytestring_length(key) };
}

void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, cbor_item_t *encoded) {
    cbor_item_t* tag          = cbor_array_get(encoded, 0);
    cbor_item_t* peer_sess_id = cbor_array_get(encoded, 1);
    cbor_item_t* cose_enc_3   = cbor_array_get(encoded, 2);

    byte* b_peer_session_id = cbor_bytestring_handle(peer_sess_id);
    byte* b_cose_enc_3      = cbor_bytestring_handle(cose_enc_3);

    msg3->tag = cbor_get_uint8(tag);
    msg3->peer_session_id = (struct bytes) { b_peer_session_id, cbor_bytestring_length(peer_sess_id) };
    msg3->cose_enc_3      = (struct bytes) { b_cose_enc_3,      cbor_bytestring_length(cose_enc_3) };
}

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, unsigned char* buffer, size_t buf_size) {
    cbor_item_t* msg2_cbor = cbor_new_definite_array(6);

    cbor_array_push(msg2_cbor, cbor_build_uint8(msg2->tag));
    cbor_array_push(msg2_cbor, cbor_build_bytestring(msg2->session_id.b, msg2->session_id.len));
    cbor_array_push(msg2_cbor, cbor_build_bytestring(msg2->peer_session_id.b, msg2->peer_session_id.len));
    cbor_array_push(msg2_cbor, cbor_build_bytestring(msg2->peer_nonce.b, msg2->peer_nonce.len));
    cbor_array_push(msg2_cbor, cbor_build_bytestring(msg2->peer_key.b, msg2->peer_key.len));
    cbor_array_push(msg2_cbor, cbor_build_bytestring(msg2->cose_enc_2.b, msg2->cose_enc_2.len));

    // Serialize to buffer
    size_t len = cbor_serialize_array(msg2_cbor, buffer, buf_size);

    cbor_decref(&msg2_cbor);
    return len;
}
