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

static struct rs_key AS_KEY = {
        .x = "5aeec31f9e64aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d",
        .y = "27c9977ca32d544e6342676ef00fa434b3aaed99f4823750517ca3390374753",
        .d = NULL,
        .curve_id = ECC_SECP256R1
};

static ecc_key RS_KEY;

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

    int verified = cwt_verify(&cwt, eaad, &AS_KEY);

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

    ecc_key pop_key;
    cwt_import_key(&pop_key, &cose_pop_key);
    int key_check = wc_ecc_check_key(&pop_key);

    edhoc_state.pop_key = pop_key;

    // Send response
    mg_send_head(nc, 204, 0, "Content-Type: application/octet-stream");
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data) {
    mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[Temperature: 30C, cbor: %i]", TINYCBOR_VERSION);
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
    edhoc_state.message1 = (struct bytes) { (void*)hm->body.p, hm->body.len };

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

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t n;
    cwt_encode_ecc_key(&session_key, enc_sess_key, sizeof(enc_sess_key), &n);

    byte nonsense[16];

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .session_id = msg1.session_id,
            .peer_session_id = edhoc_state.session_id,
            .peer_nonce = {nonce, 8},
            .peer_key = {enc_sess_key, n},
    };

    byte aad2[SHA256_DIGEST_SIZE];
    edhoc_aad2(&msg2, edhoc_state.message1, aad2);
    edhoc_msg2_sig_v(&msg2, aad2);

    uint8_t sig_v_serialized[256];
    size_t sig_v_len = sizeof(sig_v_serialized);
    cose_encode_signed(&msg2._sig_v, &RS_KEY, sig_v_serialized, sizeof(sig_v_serialized), &sig_v_len);

    unsigned char msg_serialized[512];
    size_t len = edhoc_serialize_msg_2(&msg2, msg_serialized, sizeof(msg_serialized));

    printf("Sending EDHOC MSG: ");
    phex(msg_serialized, len);

    mg_send_head(nc, 200, len, "Content-Type: application/octet-stream");
    mg_send(nc, msg_serialized, len);
}

static void edhoc_handler_message_3(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    edhoc_msg_3 msg3;
    edhoc_deserialize_msg3(&msg3, (void*)hm->body.p, hm->body.len);

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

    wc_ecc_init(&RS_KEY);
    RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key_ex(&rng, 32, &RS_KEY, ECC_SECP256R1);

    byte x[] = {};
    byte y[] = {};
    word32 x_len, y_len;
    wc_ecc_export_public_raw(&RS_KEY, x, &x_len, y, &y_len);

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
#pragma clang diagnostic pop