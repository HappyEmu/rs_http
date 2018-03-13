//
// Created by Urs Gerber on 08.03.18.
//

#include "edhoc.h"

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    cbor_parser_init(buffer, len, 0, &parser, &value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cbor_value_get_tag(&elem, (CborTag *) &msg1->tag);
    cbor_value_advance(&elem);

    cbor_value_dup_byte_string(&elem, &msg1->session_id.buf, &msg1->session_id.len, &elem);
    cbor_value_advance(&elem);

    cbor_value_dup_byte_string(&elem, &msg1->nonce.buf, &msg1->nonce.len, &elem);
    cbor_value_advance(&elem);

    cbor_value_dup_byte_string(&elem, &msg1->eph_key.buf, &msg1->eph_key.len, &elem);
}

void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    cbor_parser_init(buffer, len, 0, &parser, &value);

    CborValue element;
    cbor_value_enter_container(&value, &element);

    CborTag tag;
    cbor_value_get_tag(&element, &tag);

    cbor_value_advance(&element);

    uint8_t* peer_sess_id;
    size_t peer_sess_id_length;
    cbor_value_dup_byte_string(&element, &peer_sess_id, &peer_sess_id_length, &element);

    cbor_value_advance(&element);

    uint8_t* cose_enc_3;
    size_t cose_enc_3_length;
    cbor_value_dup_byte_string(&element, &cose_enc_3, &cose_enc_3_length, &element);

    msg3->tag = (uint8_t) tag;
    msg3->peer_session_id = (struct bytes) { peer_sess_id, peer_sess_id_length };
    msg3->cose_enc_3      = (struct bytes) { cose_enc_3,   cose_enc_3_length };
}

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, unsigned char* buffer, size_t buf_size) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 6);

    cbor_encode_tag(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->session_id.buf, msg2->session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_session_id.buf, msg2->peer_session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_nonce.buf, msg2->peer_nonce.len);
    cbor_encode_byte_string(&ary, msg2->peer_key.buf, msg2->peer_key.len);
    cbor_encode_byte_string(&ary, msg2->cose_enc_2.buf, msg2->cose_enc_2.len);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}
