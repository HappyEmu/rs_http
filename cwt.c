//
// Created by Urs Gerber on 08.03.18.
//

#include "cwt.h"
#include "tinycbor.h"
#include "utils.h"

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len) {
    CborParser parser;
    CborValue value;

    cbor_parser_init(encoded, len, 0, &parser, &value);

    uint8_t tag;
    cbor_value_get_tag(&value, &tag);
    cbor_value_advance(&value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cwt->protected = elem;
    cbor_value_advance(&elem);

    cwt->unprotected = elem;
    cbor_value_advance(&elem);

    cwt->payload = elem;
    cbor_value_advance(&elem);

    cwt->signature = elem;
}

int cwt_verify(rs_cwt* cwt, bytes eaad, rs_key* key) {
    return 1;
}
