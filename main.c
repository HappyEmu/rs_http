#include "mongoose.h"
#include <cbor.h>
#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>

#define BLOCK_SIZE 16

static const char *s_http_port = "8000";

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
    /* Preallocate the map structure */
    cbor_item_t * root = cbor_new_definite_map(2);
    /* Add the content */
    cbor_map_add(root, (struct cbor_pair) {
            .key = cbor_move(cbor_build_string("Is CBOR awesome?")),
            .value = cbor_move(cbor_build_bool(true))
    });
    cbor_map_add(root, (struct cbor_pair) {
            .key = cbor_move(cbor_build_uint8(42)),
            .value = cbor_move(cbor_build_string("Is the answer"))
    });


    unsigned char * payload;
    size_t buffer_size, length = cbor_serialize_alloc(root, &payload, &buffer_size);

    mg_send_head(nc, 200, length, "Content-Type: application/octet-stream");
    mg_send(nc, payload, length);

    cbor_decref(&root);

    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void temperature_handler(struct mg_connection* nc, int ev, void* ev_data) {
    mg_printf(nc, "HTTP/1.0 200 OK\r\n\r\n[Temperature: 30C, cbor: %s]", CBOR_VERSION);
    nc->flags |= MG_F_SEND_AND_CLOSE;
}

static void gen_random(byte* out, int size) {
    RNG rng;
    wc_InitRng(&rng);

    wc_RNG_GenerateBlock(&rng, out, size);
}

static void aes() {
    byte key[16] = { 0x03, 0xbd, 0x56, 0xc3, 0x50, 0x26, 0x9c, 0xcd, 0xae, 0x87, 0x2b, 0xf0, 0xa4, 0xf5, 0xec, 0xb1 };

    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);

    byte plain[14] = "asecretmessage";
    byte cipher[sizeof(plain)];

    byte nonce[7] = { 0xa7, 0x5b, 0xbf, 0x7a, 0x7c, 0x17, 0xaa };

    byte aad[9] = "publicaad";

    byte tag[8];
    wc_AesCcmEncrypt(&aes, cipher, plain, sizeof(plain), nonce, sizeof(nonce), tag, sizeof(tag), aad, sizeof(aad));
    wc_AesCcmDecrypt(&aes, plain, cipher, sizeof(cipher), nonce, sizeof(nonce), tag, sizeof(tag), aad, sizeof(aad));


    printf("%s", plain);
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

    aes();

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
#pragma clang diagnostic pop