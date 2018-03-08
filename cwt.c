//
// Created by Urs Gerber on 08.03.18.
//

#include "cwt.h"
#include "utils.h"

void cwt_parse(rs_cwt* cwt, cbor_item_t *encoded) {
    cbor_describe(encoded, stdout);

    // Extract tag
    cbor_item_t* ary = cbor_tag_item(encoded);

    // Extract ary members
    cwt->protected   = cbor_array_get(ary, 0);
    cwt->unprotected = cbor_array_get(ary, 1);
    cwt->payload     = cbor_array_get(ary, 2);
    cwt->signature   = cbor_array_get(ary, 3);
}

int cwt_verify(rs_cwt* cwt, cbor_item_t *external_aad, rs_key* key) {
    // Define enc_structure
    cbor_item_t *enc_structure = cbor_new_definite_array(4);

    cbor_item_t *context = cbor_build_string("Signature1");
    cbor_array_push(enc_structure, context);
    cbor_array_push(enc_structure, cwt->protected);
    cbor_array_push(enc_structure, external_aad);
    cbor_array_push(enc_structure, cwt->payload);

    // Create enc_structure
    unsigned char *buffer;
    size_t buffer_size, length = cbor_serialize_alloc(enc_structure, &buffer, &buffer_size);
    printf("Enc-Structure: ");
    phex(buffer, length);
    cbor_decref(&enc_structure);

    // Make Key
    ecc_key as_key;
    wc_ecc_import_raw_ex(&as_key, key->x, key->y, key->d, key->curve_id);

    // Compute Digest
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, buffer, length);
    wc_Sha256Final(&sha, digest);

    printf("Digest: ");
    phex(digest, sizeof(digest));

    byte *sig_data = cbor_bytestring_handle(cwt->signature);
    size_t sig_data_length = cbor_bytestring_length(cwt->signature);

    printf("Signature: ");
    phex(sig_data, sig_data_length);

    int ret, verified = 0;
    ret = wc_ecc_verify_hash(sig_data, sig_data_length, digest, sizeof(digest), &verified, &as_key);

    free(buffer);

    return verified;
}


size_t cwt_get_payload(rs_cwt *cwt, cbor_item_t **out) {
    struct cbor_load_result res;
    size_t payload_length = cbor_bytestring_length(cwt->payload);

    cbor_item_t* payload = cbor_load((cbor_data) cwt->payload->data, payload_length, &res);
    *out = payload;

    return payload_length;
}
