//
// Created by Urs Gerber on 08.03.18.
//

#include "cwt.h"
#include "utils.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dsa.h>

struct rs_key {
    char* x;
    char* y;
    char* d;
    ecc_curve_id curve_id;
};

struct rs_key AS_KEY = {
        .x = "5aeec31f9e64aad45aba2d365e71e84dee0da331badab9118a2531501fd9861d",
        .y = "27c9977ca32d544e6342676ef00fa434b3aaed99f4823750517ca3390374753",
        .d = NULL,
        .curve_id = ECC_SECP256R1
};

size_t read_key(byte** out, char* key, size_t len) {
    size_t out_length = len / 2;
    byte* block = malloc(out_length);

    for (unsigned int i = 0; i < out_length; i++) {
        char buf[3] = {key[2*i], key[2*i+1], 0};
        block[i] = (byte) strtol(buf, 0, 16);
    }

    *out = block;

    return out_length;
}


void cwt_parse(cbor_item_t *cwt) {
    cbor_describe(cwt, stdout);

    // Extract tag
    cbor_item_t* ary = cbor_tag_item(cwt);

    // Extract ary members
    cbor_item_t* prot = cbor_array_get(ary, 0);
    cbor_item_t* unprot = cbor_array_get(ary, 1);
    cbor_item_t* payload = cbor_array_get(ary, 2);
    cbor_item_t* sig = cbor_array_get(ary, 3);

    // Verify
    byte eaad[0];
    cbor_item_t* c_eaad = cbor_build_bytestring(eaad, 0);

    cwt_verify(sig, prot, payload, c_eaad);
}

void cwt_verify(cbor_item_t* signature, cbor_item_t *protected, cbor_item_t *payload, cbor_item_t *external_aad) {
    cbor_item_t* enc_structure = cbor_new_definite_array(4);

    cbor_item_t* context = cbor_build_string("Signature1");
    cbor_array_push(enc_structure, context);
    cbor_array_push(enc_structure, protected);
    cbor_array_push(enc_structure, external_aad);
    cbor_array_push(enc_structure, payload);

    unsigned char * buffer;
    size_t buffer_size, length = cbor_serialize_alloc(enc_structure, &buffer, &buffer_size);

    phex(buffer, length);

    cbor_decref(&enc_structure);

    // Make Key
    ecc_key as_key;
    wc_ecc_import_raw_ex(&as_key, AS_KEY.x, AS_KEY.y, AS_KEY.d, AS_KEY.curve_id);

    // Compute Digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, buffer, length);
    wc_Sha256Final(&sha, digest);

    phex(digest, sizeof(digest));

    byte* sig_data = cbor_bytestring_handle(signature);
    size_t sig_data_length = cbor_bytestring_length(signature);

    phex(sig_data, sig_data_length);

    int ret, verified = 0;
    ret = wc_ecc_verify_hash(sig_data, sig_data_length, digest, sizeof(digest), &verified, &as_key);

    free(buffer);
}
