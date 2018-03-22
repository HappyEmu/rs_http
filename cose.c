//
// Created by Urs Gerber on 16.03.18.
//

#include "cose.h"
#include "utils.h"
#include "symmetric.h"
#include "tinycbor.h"
#include <wolfssl/wolfcrypt/hmac.h>

void cose_encode_signed(cose_sign1* sign1, ecc_key* signing_key,
                        uint8_t* out, size_t out_size, size_t* out_len) {
    uint8_t sign_structure[256];
    size_t sign_struct_len = sizeof(sign_structure);

    cose_sign1_structure("Signature1", &sign1->protected_header, &sign1->external_aad, &sign1->payload,
                         sign_structure, sizeof(sign_structure), &sign_struct_len);

    printf("to_verify: ");
    phex(sign_structure, sign_struct_len);

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
    cbor_encode_tag(&enc, 18);

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

void cose_encode_encrypted(cose_encrypt0 *enc0, bytes *key, bytes *iv, uint8_t *out, size_t out_size, size_t *out_len) {
    byte* prot_header;
    size_t prot_len = hexstring_to_buffer(&prot_header, "a1010c", strlen("a1010c"));
    bytes b_prot_header = {prot_header, prot_len};

    // Compute aad
    uint8_t aad[128];
    size_t aad_len;
    cose_enc0_structure(&b_prot_header, &enc0->external_aad, aad, sizeof(aad), &aad_len);

    // Encrypt
    uint8_t ciphertext[enc0->plaintext.len];
    uint8_t tag[TAG_SIZE];
    rs_encrypt(ciphertext, enc0->plaintext.buf, (word32) enc0->plaintext.len, key->buf, iv->buf, tag, aad,
               (word32) aad_len);

    uint8_t tagged_ciphertext[sizeof(ciphertext) + sizeof(tag)];
    memcpy(tagged_ciphertext, ciphertext, sizeof(ciphertext));
    memcpy(tagged_ciphertext + sizeof(ciphertext), tag, sizeof(tag));

    // Encode
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, 16);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_byte_string(&ary, b_prot_header.buf, b_prot_header.len);
    cbor_encode_byte_string(&ary, NULL, 0);
    cbor_encode_byte_string(&ary, tagged_ciphertext, sizeof(tagged_ciphertext));

    cbor_encoder_close_container(&enc, &ary);

    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_enc0_structure(bytes* body_protected, bytes* external_aad,
                         uint8_t* out, size_t out_size, size_t* out_len) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_text_stringz(&ary, "Encrypt0");
    cbor_encode_byte_string(&ary, body_protected->buf, body_protected->len);
    cbor_encode_byte_string(&ary, external_aad->buf, external_aad->len);

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_kdf_context(const char* algorithm_id, int key_length, bytes other, uint8_t* out, size_t out_size, size_t *out_len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, algorithm_id);

    CborEncoder partyUInfo;
    cbor_encoder_create_array(&ary, &partyUInfo, 3);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encoder_close_container(&ary, &partyUInfo);

    CborEncoder partyVInfo;
    cbor_encoder_create_array(&ary, &partyVInfo, 3);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encoder_close_container(&ary, &partyVInfo);

    CborEncoder suppPubInfo;
    cbor_encoder_create_array(&ary, &suppPubInfo, 3);
    cbor_encode_int(&suppPubInfo, key_length);
    cbor_encode_byte_string(&suppPubInfo, NULL, 0);
    cbor_encode_byte_string(&suppPubInfo, other.buf, other.len);
    cbor_encoder_close_container(&ary, &suppPubInfo);

    cbor_encoder_close_container(&enc, &ary);

    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void derive_key(bytes input_key, bytes info, uint8_t* out, size_t out_size) {
    wc_HKDF(SHA256, input_key.buf, (word32) input_key.len, NULL, 0, info.buf, (word32) info.len, out, (word32) out_size);
}

void cose_decrypt_enc0(bytes* enc0, uint8_t *key, uint8_t *iv, bytes* external_aad,
                       uint8_t* out, size_t out_size, size_t *out_len) {
    // Parse encoded enc0
    CborParser parser;
    CborValue val;
    cbor_parser_init(enc0->buf, enc0->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    bytes ciphertext;
    cbor_value_dup_byte_string(&e, &ciphertext.buf, &ciphertext.len, &e);
    cbor_value_leave_container(&val, &e);

    // Compute AAD
    uint8_t aad[64];
    size_t aad_len;
    cose_enc0_structure(&protected, external_aad, aad, sizeof(aad), &aad_len);

    // Allocate Resources
    uint8_t plaintext[ciphertext.len - TAG_SIZE];
    uint8_t auth_tag[TAG_SIZE];
    memcpy(auth_tag, ciphertext.buf + ciphertext.len - TAG_SIZE, TAG_SIZE);

    // Decrypt
    rs_decrypt(plaintext, ciphertext.buf, sizeof(plaintext), key, iv, auth_tag, aad, (word32) aad_len);
    phex(plaintext, sizeof(plaintext));

    // Return plaintext to caller
    memcpy(out, plaintext, sizeof(plaintext));
    *out_len = sizeof(plaintext);
}

int cose_verify_sign1(bytes* sign1, ecc_key* key, bytes* external_aad) {
    /// Parse
    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1->buf, sign1->len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    bytes protected;
    cbor_value_dup_byte_string(&e, &protected.buf, &protected.len, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    bytes payload;
    cbor_value_dup_byte_string(&e, &payload.buf, &payload.len, &e);

    bytes signature;
    cbor_value_dup_byte_string(&e, &signature.buf, &signature.len, &e);

    /// Verify
    uint8_t to_verify[256];
    size_t to_verify_len;
    cose_sign1_structure("Signature1", &protected, external_aad, &payload, to_verify, sizeof(to_verify), &to_verify_len);

    // Compute digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, to_verify, (word32) to_verify_len);
    wc_Sha256Final(&sha, digest);

    int ret, verified = 0;
    ret = wc_ecc_verify_hash(signature.buf, (word32) signature.len, digest, sizeof(digest), &verified, key);

    return verified;
}
