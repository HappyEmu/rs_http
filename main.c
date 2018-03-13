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
#include "utils.h"
#include "rs_types.h"

#define AUDIENCE "tempSensor0"

#define CBOR_LABEL_COSE_KEY 25
#define CBOR_LABEL_AUDIENCE 3

static const char *s_http_port = "8000";

static struct rs_key AS_KEY = {
        .x = "5aeec31f9e64aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d",
        .y = "27c9977ca32d544e6342676ef00fa434b3aaed99f4823750517ca3390374753",
        .d = NULL,
        .curve_id = ECC_SECP256R1
};

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

        // We have received an HTTP request. Parsed request is contained in `hm`.
        // Send HTTP reply to the client which shows full original request.
        mg_send_head(c, 200, hm->message.len, "Content-Type: text/plain");
        mg_printf(c, "%.*s", (int)hm->message.len, hm->message.p);
    }
}

static void authz_info_handler(struct mg_connection* nc, int ev, void* ev_data) {
    // Parse HTTP Message
    struct http_message *hm = (struct http_message *) ev_data;
    struct mg_str cwt = hm->body;

    printf("Received CWT: ");
    phex((void*)cwt.p, cwt.len);

    // Parse CWT

    rs_cwt parsed_cwt;
    cwt_parse(&parsed_cwt, (void*) cwt.p, cwt.len);

    // Verify CWT
    bytes eaad = {.buf = NULL, .len = 0};

    int verified = cwt_verify(&parsed_cwt, eaad, &AS_KEY);

    if (verified != 1) {
        // Not authorized!
        char buf[128];
        size_t len = error_buffer(buf, sizeof(buf), "Signature could not be verified!");

        mg_send_head(nc, 401, len, "Content-Type: application/octet-stream");
        mg_printf(nc, "%.*s", (int)len, buf);

        nc->flags |= MG_F_SEND_AND_CLOSE;
        return;
    }

    /*// Check audience
    cbor_item_t *payload;
    cwt_get_payload(&parsed_cwt, &payload);

    struct cbor_pair *entries = cbor_map_handle(payload);
    for (int i = 0; i < cbor_map_size(payload); i++) {
        uint8_t label = cbor_get_uint8(entries[i].key);
        cbor_item_t* value = entries[i].value;

        if (label == CBOR_LABEL_AUDIENCE) {
            char audience[cbor_string_length(value) + 1];
            strcpy(audience, cbor_string_handle(value));

            if (strcmp(audience, AUDIENCE) != 0) {
                char buf[128];
                size_t len = error_buffer(buf, sizeof(buf), "Audience mismatch!");

                mg_send_head(nc, 403, len, "Content-Type: application/octet-stream");
                mg_printf(nc, "%.*s", (int) len, buf);

                nc->flags |= MG_F_SEND_AND_CLOSE;
                return;
            }
        } else if (label == CBOR_LABEL_COSE_KEY) {
            struct cbor_pair *cnf = cbor_map_handle(value);
            cbor_item_t* cose_key = cnf[0].value;

            bytes cose_key_ = { cbor_bytestring_handle(cose_key), cbor_bytestring_length(cose_key) };
            phex(cose_key_.b, cose_key_.len);

            cbor_item_t* cose_key_map = cbor_load(cose_key_.b, cose_key_.len, &res);
            struct cbor_pair* cose_key_pairs = cbor_map_handle(cose_key_map);

            unsigned char *xcoord, *ycoord;

            for (int j = 0; j < cbor_map_size(cose_key_map); j++) {
                uint8_t key_label = cbor_get_uint8(cose_key_pairs[j].key);
                cbor_type type = cose_key_pairs[j].key->type;
                cbor_item_t* key_value = cose_key_pairs[j].value;

                if (key_label == 1 && type == CBOR_TYPE_NEGINT) {
                    // x-coord
                    unsigned char* hex_string;
                    cbor_item_t* tag_item = cbor_tag_item(key_value);
                    byte* buffer = cbor_bytestring_handle(tag_item);
                    buffer_to_hexstring(&hex_string, buffer, cbor_bytestring_length(tag_item));

                    printf("X-Coord: %s\n", hex_string);
                    xcoord = hex_string;
                } else if (key_label == 2 && type == CBOR_TYPE_NEGINT) {
                    unsigned char* hex_string;
                    cbor_item_t* tag_item = cbor_tag_item(key_value);
                    byte* buffer = cbor_bytestring_handle(tag_item);
                    buffer_to_hexstring(&hex_string, buffer, cbor_bytestring_length(tag_item));

                    printf("Y-Coord: %s\n", hex_string);
                    ycoord = hex_string;
                }
            }

            ecc_key pop_key;
            wc_ecc_import_raw_ex(&pop_key, xcoord, ycoord, NULL, ECC_SECP256R1);
            int key_check = wc_ecc_check_key(&pop_key);

            edhoc_state.pop_key = pop_key;

        } else {
            continue;
        }

        // TODO: extract PoP key and use for EDHOC verification
    }*/

    // Send response
    mg_send_head(nc, 204, 0, "Content-Type: application/octet-stream");
    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data) {
    mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[Temperature: 30C, cbor: %i]", TINYCBOR_VERSION);
    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void edhoc_handler(struct mg_connection* nc, int ev, void* ev_data) {
    struct http_message *hm = (struct http_message *) ev_data;

    char method[8];
    sprintf(method, "%.*s", hm->method.len, hm->method.p);

    if (strcmp(method, "POST") != 0) {
        mg_send_head(nc, 404, 0, NULL);
        nc->flags |= MG_F_SEND_AND_CLOSE;
        return;
    }

    CborParser parser;
    CborValue val;
    cbor_parser_init((void*)hm->body.p, hm->body.len, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);

    switch (tag) {
        case 1:
            edhoc_handler_message_1(nc, ev, ev_data);
            break;
        case 3:
            edhoc_handler_message_3(nc, ev, ev_data);
            break;
        default: break;
    }

    mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[Temperature: 30C, cbor: %i]", TINYCBOR_VERSION);
    nc->flags |= MG_F_SEND_AND_CLOSE;
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

    byte nonsense[16];

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .session_id = msg1.session_id,
            .peer_session_id = edhoc_state.session_id,
            .peer_nonce = {nonce, 8},
            .peer_key = {nonsense, sizeof(nonsense)},
            .cose_enc_2 = {nonsense, sizeof(nonsense)}
    };

    unsigned char msg_serialized[256];
    size_t len = edhoc_serialize_msg_2(&msg2, msg_serialized, sizeof(msg_serialized));

    mg_send_head(nc, 200, len, "Content-Type: application/octet-stream");
    mg_printf(nc, "%.*s", (int)len, msg_serialized);
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

    mg_register_http_endpoint(c, "/authz-info", authz_info_handler);
    mg_register_http_endpoint(c, "/.well-known/edhoc", edhoc_handler);
    mg_register_http_endpoint(c, "/temperature", temperature_handler);

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
#pragma clang diagnostic pop