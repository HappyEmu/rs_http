#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "tinycbor.h"

#include "mongoose.h"
#include "symmetric.h"
#include "cwt.h"
#include "edhoc.h"
#include "cose.h"
#include "utils.h"
#include "rs_types.h"

#define AUDIENCE "tempSensor0"



static const char *s_http_port = "8000";

static struct rs_key AS_ID = {
        .x = "5aeec31f9e64aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d",
        .y = "27c9977ca32d544e6342676ef00fa434b3aaed99f4823750517ca3390374753",
        .d = NULL,
        .curve_id = ECC_SECP256R1
};

static rs_key RS_ID_ = {
        .x = "49a2da855bc480028e71cbdf09b51545b20f73837c6a24c90957ce1cf46458af",
        .y = "d88ea8c7e63b0129466603bf50cd8369eeaa32c18bef9fb45ae2cdf593d826a1",
        .d = "39a1e3cbcc09b741d29d38f67a4e18f6263647735f855f139528cb1437d6c21a",
        .curve_id = ECC_SECP256R1
};

ecc_key RS_ID;

static edhoc_server_session_state edhoc_state;

static void edhoc_handler_message_1(struct mg_connection* nc, int ev, void* ev_data) ;
static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) ;

static size_t error_buffer(uint8_t* buf, size_t buf_len, char* text) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buf_len, 0);

    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 1);

    cbor_encode_text_stringz(&map, "error");
    cbor_encode_text_stringz(&map, text);
    cbor_encoder_close_container(&enc, &map);

    return cbor_encoder_get_buffer_size(&enc, buf);
}

static void ev_handler(struct mg_connection *c, int ev, void *p) {
    if (ev == MG_EV_HTTP_REQUEST) {
        struct http_message *hm = (struct http_message *) p;

        mg_send_head(c, 200, hm->message.len, "Content-Type: text/plain");
        mg_printf(c, "%.*s", (int)hm->message.len, hm->message.p);
    }
}

static void authz_info_handler(struct mg_connection* nc, int ev, void* ev_data) {
    // Parse HTTP Message
    struct http_message *hm = (struct http_message *) ev_data;
    struct mg_str data = hm->body;

    printf("Received CWT: ");
    phex((void*)data.p, data.len);

    // Parse CWT
    rs_cwt cwt;
    cwt_parse(&cwt, (void*) data.p, data.len);

    // Verify CWT
    bytes eaad = {.buf = NULL, .len = 0};

    int verified = cwt_verify(&cwt, eaad, &AS_ID);

    if (verified != 1) {
        // Not authorized!
        uint8_t buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "Signature could not be verified!");

        mg_send_head(nc, 401, (int64_t) len, "Content-Type: application/octet-stream");
        mg_send(nc, buf, (int) len);

        return;
    }

    // Parse Payload
    rs_payload payload;
    cwt_parse_payload(&cwt, &payload);

    // Verify audience
    if (strcmp(AUDIENCE, payload.aud) != 0) {
        uint8_t buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "Audience mismatch!");

        mg_send_head(nc, 403, (int64_t) len, "Content-Type: application/octet-stream");
        mg_send(nc, buf, (int) len);

        return;
    }

    cose_key cose_pop_key;
    cwt_parse_cose_key(&payload.cnf, &cose_pop_key);

    cwt_import_key(&edhoc_state.pop_key, &cose_pop_key);
    int key_check = wc_ecc_check_key(&edhoc_state.pop_key);

    // Send response
    mg_send_head(nc, 204, 0, "Content-Type: application/octet-stream");
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data) {
    int temperature = 30;

    /// Create Response
    uint8_t response[128];
    CborEncoder enc;
    cbor_encoder_init(&enc, response, sizeof(response), 0);

    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_text_stringz(&map, "temperature");
    cbor_encode_int(&map, temperature);
    cbor_encoder_close_container(&enc, &map);

    size_t len = cbor_encoder_get_buffer_size(&enc, response);

    /// Compute OSCORE Context
    uint8_t exchange_hash[SHA256_DIGEST_SIZE];
    oscore_exchange_hash(&edhoc_state.message1, &edhoc_state.message2, &edhoc_state.message3, exchange_hash);

    bytes ex_hash = {exchange_hash, SHA256_DIGEST_SIZE};

    // Master Secret
    uint8_t ci_secret[128];
    size_t ci_secret_len;
    cose_kdf_context("EDHOC OSCORE Master Secret", 16, ex_hash, ci_secret, sizeof(ci_secret), &ci_secret_len);
    bytes b_ci_secret = {ci_secret, ci_secret_len};

    // Master Salt
    uint8_t ci_salt[128];
    size_t ci_salt_len;
    cose_kdf_context("EDHOC OSCORE Master Salt", 7, ex_hash, ci_salt, sizeof(ci_salt), &ci_salt_len);
    bytes b_ci_salt = {ci_salt, ci_salt_len};

    uint8_t master_secret[16];
    derive_key(edhoc_state.shared_secret, b_ci_secret, master_secret, sizeof(master_secret));

    uint8_t master_salt[7];
    derive_key(edhoc_state.shared_secret, b_ci_salt, master_salt, sizeof(master_salt));

    printf("MASTER SALT: ");
    phex(master_salt, sizeof(master_salt));
    printf("MASTER SECRET: ");
    phex(master_secret, sizeof(master_secret));

    /// Encrypt response
    cose_encrypt0 enc_response = {.plaintext = (bytes) {response, len}, .external_aad = {NULL, 0}};
    uint8_t res[256];
    size_t res_len;
    cose_encode_encrypted(&enc_response, master_secret, master_salt, res, sizeof(res), &res_len);

    mg_send_head(nc, 200, (int64_t) res_len, "Content-Type: application/octet-stream");
    mg_send(nc, res, (int) res_len);
}

static void edhoc_handler(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    char method[8];
    sprintf(method, "%.*s", hm->method.len, hm->method.p);

    if (strcmp(method, "POST") != 0) {
        mg_send_head(nc, 404, 0, NULL);
        return;
    }

    printf("Received EDHOC MSG: ");
    phex((void*)hm->body.p, hm->body.len);

    CborParser parser;
    CborValue ary;
    cbor_parser_init((void*)hm->body.p, hm->body.len, 0, &parser, &ary);

    CborValue elem;
    cbor_value_enter_container(&ary, &elem);

    uint64_t tag;
    cbor_value_get_uint64(&elem, &tag);

    switch (tag) {
        case 1:
            edhoc_handler_message_1(nc, ev, ev_data);
            break;
        case 3:
            edhoc_handler_message_3(nc, ev, ev_data);
            break;
        default: break;
    }
}

static void edhoc_handler_message_1(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    // Read msg1
    edhoc_msg_1 msg1;
    edhoc_deserialize_msg1(&msg1, (void*)hm->body.p, hm->body.len);

    // Save message1 for later
    edhoc_state.message1.buf = malloc(hm->body.len);
    edhoc_state.message1.len = hm->body.len;
    memcpy(edhoc_state.message1.buf, hm->body.p, hm->body.len);

    // Generate random session id
    RNG rng;
    wc_InitRng(&rng);

    byte* session_id = malloc(2);
    wc_RNG_GenerateBlock(&rng, session_id, 2);
    edhoc_state.session_id = (bytes){ session_id, 2 };

    // Generate nonce
    byte nonce[8];
    wc_RNG_GenerateBlock(&rng, nonce, 8);

    // Generate session key
    ecc_key session_key;
    wc_ecc_init(&session_key);
    wc_ecc_make_key_ex(&rng, 32, &session_key, ECC_SECP256R1);

    // Compute shared secret
    cose_key cose_eph_key;
    cwt_parse_cose_key(&msg1.eph_key, &cose_eph_key);

    ecc_key eph_key;
    cwt_import_key(&eph_key, &cose_eph_key);

    byte secret[256];
    word32 secret_sz = sizeof(secret);
    wc_ecc_shared_secret(&session_key, &eph_key, secret, &secret_sz);
    printf("Shared Secret: ");
    phex(secret, secret_sz);

    // Save shared secret to state
    edhoc_state.shared_secret.buf = malloc(secret_sz);
    edhoc_state.shared_secret.len = secret_sz;
    memcpy(edhoc_state.shared_secret.buf, secret, secret_sz);

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t n;
    cwt_encode_ecc_key(&session_key, enc_sess_key, sizeof(enc_sess_key), &n);

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .session_id = msg1.session_id,
            .peer_session_id = edhoc_state.session_id,
            .peer_nonce = {nonce, 8},
            .peer_key = {enc_sess_key, n},
    };

    msg_2_context ctx2 = {
            .sign_key = &RS_ID,
            .shared_secret = (bytes) {secret, secret_sz},
            .message1 = edhoc_state.message1
    };

    unsigned char msg_serialized[512];
    size_t len = edhoc_serialize_msg_2(&msg2, &ctx2, msg_serialized, sizeof(msg_serialized));

    edhoc_state.message2.buf = malloc(len);
    edhoc_state.message2.len = len;
    memcpy(edhoc_state.message2.buf, msg_serialized, len);

    printf("Sending EDHOC MSG: ");
    phex(msg_serialized, len);

    mg_send_head(nc, 200, len, "Content-Type: application/octet-stream");
    mg_send(nc, msg_serialized, len);
}

static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    // Save message3 for later
    edhoc_state.message3.buf = malloc(hm->body.len);
    edhoc_state.message3.len = hm->body.len;
    memcpy(edhoc_state.message3.buf, hm->body.p, hm->body.len);

    // Deserialize msg3
    edhoc_msg_3 msg3;
    edhoc_deserialize_msg3(&msg3, (void*)hm->body.p, hm->body.len);

    // Compute aad3
    byte aad3[SHA256_DIGEST_SIZE];
    edhoc_aad3(&msg3, &edhoc_state.message1, &edhoc_state.message2, aad3);

    // Derive k3, iv3
    bytes other = {aad3, SHA256_DIGEST_SIZE};

    uint8_t context_info_k3[128];
    size_t ci_k3_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, other, context_info_k3, sizeof(context_info_k3), &ci_k3_len);

    uint8_t context_info_iv3[128];
    size_t ci_iv3_len;
    cose_kdf_context("IV-Generation", 7, other, context_info_iv3, sizeof(context_info_iv3), &ci_iv3_len);

    bytes b_ci_k3 = {context_info_k3, ci_k3_len};
    bytes b_ci_iv3 = {context_info_iv3, ci_iv3_len};

    uint8_t k3[16];
    derive_key(edhoc_state.shared_secret, b_ci_k3, k3, sizeof(k3));

    uint8_t iv3[7];
    derive_key(edhoc_state.shared_secret, b_ci_iv3, iv3, sizeof(iv3));

    printf("AAD3: ");
    phex(aad3, SHA256_DIGEST_SIZE);
    printf("K3: ");
    phex(k3, 16);
    printf("IV3: ");
    phex(iv3, 7);

    bytes b_aad3 = {aad3, SHA256_DIGEST_SIZE};

    uint8_t sig_u[256];
    size_t sig_u_len;
    cose_decrypt_enc0(&msg3.cose_enc_3, k3, iv3, &b_aad3, sig_u, sizeof(sig_u), &sig_u_len);

    bytes b_sig_u = {sig_u, sig_u_len};
    int verified = cose_verify_sign1(&b_sig_u, &edhoc_state.pop_key, &b_aad3);

    if (verified != 1) {
        // Not authorized!
        uint8_t buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "You are not the one who uploaded the token!");

        mg_send_head(nc, 401, (int64_t) len, "Content-Type: application/octet-stream");
        mg_send(nc, buf, (int) len);

        return;
    }

    uint8_t *buf;
    size_t buf_len = hexstring_to_buffer(&buf, "81624f4b", strlen("81624f4b"));
    mg_send_head(nc, 401, (int64_t) buf_len, "Content-Type: application/octet-stream");
    mg_send(nc, buf, (int) buf_len);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
#pragma ide diagnostic ignored "OCDFAInspection"
int main(void) {
    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr, NULL);
    c = mg_bind(&mgr, s_http_port, ev_handler);
    mg_set_protocol_http_websocket(c);

    mg_register_http_endpoint(c, "/authz-info", authz_info_handler);
    mg_register_http_endpoint(c, "/.well-known/edhoc", edhoc_handler);
    mg_register_http_endpoint(c, "/temperature", temperature_handler);

    wc_ecc_import_raw_ex(&RS_ID, RS_ID_.x, RS_ID_.y, RS_ID_.d, RS_ID_.curve_id);
    int check = wc_ecc_check_key(&RS_ID);

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
#pragma clang diagnostic pop