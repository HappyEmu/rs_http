//
// Created by Urs Gerber on 16.03.18.
//

#include "cose.h"
#include "tinycbor.h"

void cose_encode_signed(cose_sign1* sign1, ecc_key* signing_key,
                        uint8_t* out, size_t out_size, size_t* out_len) {
    uint8_t sign_structure[256];
    size_t sign_struct_len = sizeof(sign_structure);

    cose_sign1_structure("Signature1", &sign1->protected_header, &sign1->external_aad, &sign1->payload,
                         sign_structure, sizeof(sign_structure), &sign_struct_len);

    // Hash sign structure
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, sign_structure, (word32) sign_struct_len);
    wc_Sha256Final(&sha, digest);

    byte signature[512];
    size_t sig_len = sizeof(signature);
    // Compute signature
    RNG rng;
    wc_InitRng(&rng);
    wc_ecc_sign_hash(digest, sizeof(digest), signature, (word32 *) &sig_len, &rng, signing_key);

    // Encode sign1 structure
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(&ary, sign1->protected_header.buf, sign1->protected_header.len);
    cbor_encode_byte_string(&ary, sign1->unprotected_header.buf, sign1->unprotected_header.len);
    cbor_encode_byte_string(&ary, sign1->payload.buf, sign1->payload.len);
    cbor_encode_byte_string(&ary, signature, sig_len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_sign1_structure(const char* context,
                          bytes* body_protected,
                          bytes* external_aad,
                          bytes* payload,
                          uint8_t* out,
                          size_t out_size,
                          size_t* out_len) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);
    cbor_encode_byte_string(&ary, payload->buf, payload->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}
