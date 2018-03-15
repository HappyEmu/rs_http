//
// Created by Urs Gerber on 08.03.18.
//

#include "cwt.h"
#include "tinycbor.h"
#include "utils.h"

#define CBOR_LABEL_COSE_KEY 25
#define CBOR_LABEL_AUDIENCE 3

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* enc = encoded;
    cbor_parser_init(enc, len, 0, &parser, &value);

    uint8_t tag;
    cbor_value_get_tag(&value, &tag);
    cbor_value_advance(&value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cwt->h_protected = elem;
    cbor_value_advance(&elem);

    cwt->h_unprotected = elem;
    cbor_value_advance(&elem);

    cwt->payload = elem;
    cbor_value_advance(&elem);

    cwt->signature = elem;
}

int cwt_verify(rs_cwt* cwt, bytes eaad, rs_key* key) {
    CborEncoder enc;
    uint8_t buffer[256];
    cbor_encoder_init(&enc, buffer, 256, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, "Signature1");

    uint8_t* protected;
    size_t len;
    cbor_value_dup_byte_string(cwt->h_protected, &protected, &len)
    cbor_encode_byte_string(&enc, NULL);
    
    return 1;
}

void cwt_parse_payload(rs_cwt* cwt, rs_payload* out) {
    uint8_t* payload;
    size_t len;

    cbor_value_dup_byte_string(&cwt->payload, &payload, &len, NULL);
    phex(payload, len);

    CborParser parser;
    CborValue map;
    cbor_parser_init(payload, len, 0, &parser, &map);

    CborValue elem;
    cbor_value_enter_container(&map, &elem);

    while (!cbor_value_at_end(&elem)) {
        int label;
        cbor_value_get_int(&elem, &label);
        cbor_value_advance(&elem);

        if (label == CBOR_LABEL_AUDIENCE) {
            char* audience;
            size_t aud_len;
            cbor_value_dup_text_string(&elem, &audience, &aud_len, &elem);
            out->aud = audience;
        } else if (label == CBOR_LABEL_COSE_KEY) {
            CborValue cnf_elem;
            cbor_value_enter_container(&elem, &cnf_elem);

            int cnf_tag;
            cbor_value_get_int(&cnf_elem, &cnf_tag);
            cbor_value_advance(&cnf_elem);

            uint8_t* cnf;
            size_t cnf_len;
            cbor_value_dup_byte_string(&cnf_elem, &cnf, &cnf_len, &cnf_elem);
            out->cnf = (bytes) {cnf, cnf_len};

            cbor_value_leave_container(&elem, &cnf_elem);
        } else {
            cbor_value_advance(&elem);
        }
    }

    free(payload);
}

#define CBOR_LABEL_COSE_KEY_KTY 1
#define CBOR_LABEL_COSE_KEY_KID 2
#define CBOR_LABEL_COSE_KEY_CRV (-1)
#define CBOR_LABEL_COSE_KEY_X (-2)
#define CBOR_LABEL_COSE_KEY_Y (-3)

void cwt_parse_cose_key(bytes* encoded, cose_key* out) {
    CborParser parser;
    CborValue map;

    cbor_parser_init(encoded->buf, encoded->len, 0, &parser, &map);

    CborValue elem;
    cbor_value_enter_container(&map, &elem);

    while (!cbor_value_at_end(&elem)) {
        int label;
        cbor_value_get_int(&elem, &label);
        cbor_value_advance(&elem);

        if (label == CBOR_LABEL_COSE_KEY_KTY) {
            int kty;
            cbor_value_get_int(&elem, &kty);
            cbor_value_advance(&elem);
            out->kty = (uint8_t) kty;
        } else if (label == CBOR_LABEL_COSE_KEY_KID) {
            uint8_t* kid;
            size_t kid_len;
            cbor_value_dup_byte_string(&elem, &kid, &kid_len, &elem);
            out->kid = (bytes) {kid, kid_len};
        } else if (label == CBOR_LABEL_COSE_KEY_CRV) {
            int crv;
            cbor_value_get_int(&elem, &crv);
            cbor_value_advance(&elem);
            out->crv = (uint8_t) crv;
        } else if (label == CBOR_LABEL_COSE_KEY_X) {
            // Somehow need to skip (negative) tag
            cbor_value_advance(&elem);

            uint8_t* x;
            size_t x_len;
            cbor_value_dup_byte_string(&elem, &x, &x_len, &elem);

            char* hex_string;
            buffer_to_hexstring(&hex_string, x, x_len);
            out->x = hex_string;
        } else if (label == CBOR_LABEL_COSE_KEY_Y) {
            // Somehow need to skip (negative) tag
            cbor_value_advance(&elem);

            uint8_t* y;
            size_t y_len;
            cbor_value_dup_byte_string(&elem, &y, &y_len, &elem);

            char* hex_string;
            buffer_to_hexstring(&hex_string, y, y_len);
            out->y = hex_string;
        } else {
            cbor_value_advance(&elem);
        }
    }
}
