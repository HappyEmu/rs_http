#include <cbor.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "mongoose.h"
#include "symmetric.h"
#include "cwt.h"
#include "utils.h"

#define AUDIENCE "tempSensor0"

static const char *s_http_port = "8000";

static struct rs_key AS_KEY = {
        .x = "5aeec31f9e64aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d",
        .y = "27c9977ca32d544e6342676ef00fa434b3aaed99f4823750517ca3390374753",
        .d = NULL,
        .curve_id = ECC_SECP256R1
};

static size_t error_buffer(char* buf, size_t buf_len, char* text) {
    cbor_item_t* error = cbor_new_definite_map(1);
    struct cbor_pair entry = {
            .key = cbor_build_string("error"),
            .value = cbor_build_string(text)
    };
    cbor_map_add(error, entry);

    size_t length = cbor_serialize(error, buf, buf_len);
    cbor_decref(&error);

    return length;
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
    phex(cwt.p, cwt.len);

    // Parse CWT
    struct cbor_load_result res;
    cbor_item_t* cbor_cwt = cbor_load((cbor_data) cwt.p, cwt.len, &res);

    rs_cwt parsed_cwt;
    cwt_parse(&parsed_cwt, cbor_cwt);

    // Verify CWT
    byte eaad[0];
    cbor_item_t* c_eaad = cbor_build_bytestring(eaad, 0);

    int verified = cwt_verify(&parsed_cwt, c_eaad, &AS_KEY);
    cbor_decref(&cbor_cwt);

    if (verified != 1) {
        // Not authorized!
        cbor_item_t* error = cbor_new_definite_map(1);
        struct cbor_pair entry = {
                .key = cbor_build_string("error"),
                .value = cbor_build_string("Signature could not be verified!")
        };
        cbor_map_add(error, entry);

        byte buf[128];
        size_t length = cbor_serialize(error, &buf, sizeof(buf));

        mg_send_head(nc, 401, length, "Content-Type: application/octet-stream");
        mg_printf(nc, "%.*s", (int)length, buf);

        nc->flags |= MG_F_SEND_AND_CLOSE;
        return;
    }

    // Check audience
    cbor_item_t* payload;
    cwt_get_payload(&parsed_cwt, &payload);

    struct cbor_pair* entries = cbor_map_handle(payload);
    for (int i = 0; i < cbor_map_size(payload); i++) {
        uint8_t label = cbor_get_uint8(entries[i].key);

        if (label == 3) {
            char audience[cbor_string_length(entries[i].value) + 1];
            strcpy(audience, cbor_string_handle(entries[i].value));

            if (strcmp(audience, AUDIENCE) != 0) {
                char buf[128];
                size_t len = error_buffer(buf, sizeof(buf), "Audience mismatch!");

                mg_send_head(nc, 403, len, "Content-Type: application/octet-stream");
                mg_printf(nc, "%.*s", (int)len, buf);

                nc->flags |= MG_F_SEND_AND_CLOSE;
                return;
            }
        } else {
            continue;
        }
    }

    // Send response
    mg_send_head(nc, 204, 0, "Content-Type: application/octet-stream");
    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data) {
    mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[Temperature: 30C, cbor: %s]", CBOR_VERSION);
    nc->flags |= MG_F_SEND_AND_CLOSE;
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
    mg_register_http_endpoint(c, "/temperature", temperature_handler);

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
#pragma clang diagnostic pop