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

static const char *s_http_port = "8000";

static struct rs_key AS_KEY = {
        .x = "5aeec31f9e64aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d",
        .y = "27c9977ca32d544e6342676ef00fa434b3aaed99f4823750517ca3390374753",
        .d = NULL,
        .curve_id = ECC_SECP256R1
};

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

    cwt_verify(&parsed_cwt, c_eaad, &AS_KEY);

    cbor_decref(&cbor_cwt);

    // Send response
    mg_send_head(nc, 204, 0, "Content-Type: application/octet-stream");
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

    byte plain[14] = "asecretmessage";
    byte cipher[sizeof(plain)];
    byte nonce[7] = { 0xa7, 0x5b, 0xbf, 0x7a, 0x7c, 0x17, 0xaa };
    byte aad[9] = "publicaad";
    byte tag[8];

    rs_encrypt(cipher, plain, sizeof(plain), key, nonce, tag, aad, sizeof(aad));

    memset(plain, 0, sizeof(plain));

    rs_decrypt(plain, cipher, sizeof(cipher), key, nonce, tag, aad, sizeof(aad));

    printf("%.*s\n", sizeof(plain), plain);
}

static void ecdsa() {
    RNG rng;
    wc_InitRng(&rng);

    ecc_key key;

    char qx[] = "b46df9b9467df092dbcd5c79a7818a8e98039c78580c0ad018e71efd886e16c9";
    char qy[] = "ddf6dd34cf08e6ed51b92205f08bf43f56008564bf6044a1ad5bcf42b3ebee1a";
    char d[] = "94f7d46cb97b7bf61dd23018b180a206993be622837930c2a66c18b92d2e9def";

    wc_ecc_import_raw_ex(&key, qx, qy, d, ECC_SECP256R1);
    wc_ecc_check_key(&key);

    byte message[] = "This is a message";
    byte buf[1024];
    byte sig[512];
    byte digest[SHA256_DIGEST_SIZE];

    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, message, sizeof(message));
    wc_Sha256Final(&sha, digest);

    phex(digest, sizeof(digest));
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

    //aes();
    //ecdsa();

    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    mg_mgr_free(&mgr);

    return 0;
}
#pragma clang diagnostic pop