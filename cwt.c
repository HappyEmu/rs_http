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
    cbor_value_dup_byte_string(&cwt->h_protected, &protected, &len, NULL);
    cbor_encode_byte_string(&ary, protected, len);
    free(protected);

    cbor_encode_byte_string(&ary, eaad.buf, eaad.len);

    uint8_t* payload;
    size_t p_len;
    cbor_value_dup_byte_string(&cwt->payload, &payload, &p_len, NULL);
    cbor_encode_byte_string(&ary, payload, p_len);
    free(payload);

    cbor_encoder_close_container(&enc, &ary);
    size_t buf_len = cbor_encoder_get_buffer_size(&enc, buffer);

    // Import key
    ecc_key as_key;
    wc_ecc_import_raw_ex(&as_key, key->x, key->y, key->d, key->curve_id);

    // Compute digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, buffer, (word32) buf_len);
    wc_Sha256Final(&sha, digest);

    // Extract Signature
    uint8_t* signature;
    size_t sig_len;
    cbor_value_dup_byte_string(&cwt->signature, &signature, &sig_len, NULL);

    int ret, verified = 0;
    ret = wc_ecc_verify_hash(signature, (word32) sig_len, digest, sizeof(digest), &verified, &as_key);

    free(signature);

    return verified;
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
    out->kid = (bytes) {NULL, 0};

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
            uint8_t* x;
            size_t x_len;
            cbor_value_dup_byte_string(&elem, &x, &x_len, &elem);

            out->x = (bytes) { x, x_len };
        } else if (label == CBOR_LABEL_COSE_KEY_Y) {
            uint8_t* y;
            size_t y_len;
            cbor_value_dup_byte_string(&elem, &y, &y_len, &elem);

            out->y = (bytes) { y, y_len };
        } else {
            cbor_value_advance(&elem);
        }
    }
}

void cwt_encode_cose_key(cose_key* key, uint8_t* buffer, size_t buf_size, size_t* len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);
    
    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 5);
    
    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_KTY);
    cbor_encode_int(&map, key->kty);
    
    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_CRV);
    cbor_encode_int(&map, key->crv);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_X);
    cbor_encode_byte_string(&map, key->x.buf, key->x.len);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_Y);
    cbor_encode_byte_string(&map, key->y.buf, key->y.len);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_KID);
    cbor_encode_byte_string(&map, key->kid.buf, key->kid.len);

    cbor_encoder_close_container(&enc, &map);

    *len = cbor_encoder_get_buffer_size(&enc, buffer);
}

void cwt_encode_ecc_key(ecc_key* key, uint8_t* buffer, size_t buf_size, size_t* len) {
    byte x[32];
    byte y[32];
    word32 x_len, y_len;

    // WHY TWICE NECESSARY?
    wc_ecc_export_public_raw(key, x, &x_len, y, &y_len);
    wc_ecc_export_public_raw(key, x, &x_len, y, &y_len);

    cose_key cose = {
            .crv = 1, // P-256
            .kid = (bytes) {(uint8_t *) "abcd", 4},
            .kty = 2, // EC2
            .x = (bytes) { x, x_len },
            .y = (bytes) { y, y_len }
    };

    cwt_encode_cose_key(&cose, buffer, buf_size, len);
}

void cwt_import_key(ecc_key* key, cose_key* cose) {
    char *x, *y;
    buffer_to_hexstring(&x, cose->x.buf, cose->x.len);
    buffer_to_hexstring(&y, cose->y.buf, cose->y.len);

    wc_ecc_import_raw_ex(key, x, y, NULL, ECC_SECP256R1);
}
