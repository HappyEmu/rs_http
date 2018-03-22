//
// Created by Urs Gerber on 08.03.18.
//

#include "edhoc.h"
#include "cose.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "utils.h"

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, len, 0, &parser, &value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cbor_value_get_uint64(&elem, (CborTag *) &msg1->tag);
    cbor_value_advance(&elem);

    cbor_value_dup_byte_string(&elem, &msg1->session_id.buf, &msg1->session_id.len, &elem);
    cbor_value_dup_byte_string(&elem, &msg1->nonce.buf, &msg1->nonce.len, &elem);
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

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, msg_2_context* context, unsigned char* buffer, size_t buf_size) {
    // Compute AAD
    byte aad2[SHA256_DIGEST_SIZE];
    edhoc_aad2(msg2, context->message1, aad2);

    // Compute Signature
    uint8_t sig_v[256];
    size_t sig_v_len = sizeof(sig_v);
    edhoc_msg2_sig_v(msg2, aad2, context->sign_key, sig_v, sizeof(sig_v), &sig_v_len);

    bytes b_sig_v = {sig_v, sig_v_len};
    printf("siv_v: ");
    phex(sig_v, sig_v_len);

    // Derive keys
    bytes other = {aad2, SHA256_DIGEST_SIZE};

    uint8_t context_info_k2[128];
    size_t ci_k2_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, other, context_info_k2, sizeof(context_info_k2), &ci_k2_len);

    uint8_t context_info_iv2[128];
    size_t ci_iv2_len;
    cose_kdf_context("IV-Generation", 7, other, context_info_iv2, sizeof(context_info_iv2), &ci_iv2_len);

    bytes b_ci_k2 = {context_info_k2, ci_k2_len};
    bytes b_ci_iv2 = {context_info_iv2, ci_iv2_len};

    uint8_t k2[16];
    derive_key(context->shared_secret, b_ci_k2, k2, sizeof(k2));

    uint8_t iv2[7];
    derive_key(context->shared_secret, b_ci_iv2, iv2, sizeof(iv2));

    printf("AAD2: ");
    phex(aad2, SHA256_DIGEST_SIZE);
    printf("K2: ");
    phex(k2, 16);
    printf("IV2: ");
    phex(iv2, 7);

    // Encrypt
    uint8_t enc_2[256];
    size_t enc_2_len = sizeof(enc_2);
    bytes b_k2 = {k2, 16};
    bytes b_iv2 = {iv2, 7};
    edhoc_msg2_enc_0(msg2, aad2, &b_sig_v, &b_k2, &b_iv2, enc_2, sizeof(enc_2), &enc_2_len);

    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 6);

    cbor_encode_int(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->session_id.buf, msg2->session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_session_id.buf, msg2->peer_session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_nonce.buf, msg2->peer_nonce.len);
    cbor_encode_byte_string(&ary, msg2->peer_key.buf, msg2->peer_key.len);
    cbor_encode_byte_string(&ary, enc_2, enc_2_len);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

void edhoc_aad2(edhoc_msg_2 *msg2, bytes message1, byte* out_hash) {
    uint8_t data2[256];

    // Compute data2
    CborEncoder enc;
    cbor_encoder_init(&enc, data2, sizeof(data2), 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 5);

    cbor_encode_int(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->session_id.buf, msg2->session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_session_id.buf, msg2->peer_session_id.len);
    cbor_encode_byte_string(&ary, msg2->peer_nonce.buf, msg2->peer_nonce.len);
    cbor_encode_byte_string(&ary, msg2->peer_key.buf, msg2->peer_key.len);

    cbor_encoder_close_container(&enc, &ary);
    size_t data2_len = cbor_encoder_get_buffer_size(&enc, data2);

    printf("data2: ");
    phex(data2, data2_len);

    printf("message1: ");
    phex(message1.buf, message1.len);

    // Compute aad2
    uint8_t aad2[message1.len + data2_len];

    memcpy(aad2, message1.buf, message1.len);
    memcpy((aad2+message1.len), data2, data2_len);

    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, aad2, sizeof(aad2));
    wc_Sha256Final(&sha, out_hash);
}

void edhoc_msg2_sig_v(edhoc_msg_2 *msg2, const byte* aad2, ecc_key* sign_key,
                      uint8_t* out, size_t out_size, size_t* out_len) {

    byte* prot_header, *unprot_header;
    size_t prot_len = hexstring_to_buffer(&prot_header, "a10126", strlen("a10126"));
    size_t unprot_len = hexstring_to_buffer(&unprot_header, "a104524173796d6d65747269634543445341323536", strlen("a104524173796d6d65747269634543445341323536"));

    cose_sign1 sig_v;
    sig_v.payload = (bytes) {NULL, 0};
    sig_v.protected_header = (bytes) {prot_header, prot_len};
    sig_v.unprotected_header = (bytes) {unprot_header, unprot_len};
    sig_v.external_aad = (bytes) {(uint8_t *) aad2, SHA256_DIGEST_SIZE};

    cose_encode_signed(&sig_v, sign_key, out, out_size, out_len);
}

void edhoc_msg2_enc_0(edhoc_msg_2 *msg2, byte *aad2, bytes *sig_v, bytes *key, bytes *iv,
                      uint8_t* out, size_t out_size, size_t* out_len) {
    bytes eaad = {aad2, SHA256_DIGEST_SIZE};
    cose_encrypt0 enc2 = {
            .external_aad = eaad,
            .plaintext = *sig_v
    };

    cose_encode_encrypted(&enc2, key, iv, out, out_size, out_len);
}
