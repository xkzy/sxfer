#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../sxfer_mod.h"

int main()
{
    printf("=== Testing Baseband Modulation & Scrambler ===\n");

    // 1. Test LFSR scrambler symmetry
    uint8_t data[256];
    uint8_t original[256];
    for (int i = 0; i < 256; i++) {
        data[i] = (uint8_t)i;
        original[i] = (uint8_t)i;
    }
    lfsr_scramble(data, 256, 0x1234);
    assert(memcmp(data, original, 256) != 0);
    lfsr_scramble(data, 256, 0x1234);
    assert(memcmp(data, original, 256) == 0);
    printf("LFSR scrambler test passed.\n");

    // 2. Test COBS encode / decode with zeros, ones, and mixed
    uint8_t test_payload[1000];
    uint8_t encoded[1200];
    uint8_t decoded[1200];

    // Case A: all zeros
    memset(test_payload, 0, sizeof(test_payload));
    size_t elen = cobs_encode(test_payload, sizeof(test_payload), encoded);
    for (size_t i = 0; i < elen; i++) {
        assert(encoded[i] != 0); // No zeros in COBS body
    }
    size_t dlen = cobs_decode(encoded, elen, decoded);
    assert(dlen == sizeof(test_payload));
    assert(memcmp(test_payload, decoded, dlen) == 0);

    // Case B: random data
    for (int i = 0; i < 1000; i++) test_payload[i] = rand() % 256;
    elen = cobs_encode(test_payload, 1000, encoded);
    for (size_t i = 0; i < elen; i++) assert(encoded[i] != 0);
    dlen = cobs_decode(encoded, elen, decoded);
    assert(dlen == 1000);
    assert(memcmp(test_payload, decoded, 1000) == 0);
    printf("COBS encode/decode test passed.\n");

    // 3. Test Frame wrapper in all 3 modes
    int modes[] = { MOD_RAW, MOD_SCRAMBLE, MOD_COBS };
    for (int m = 0; m < 3; m++) {
        uint8_t frame[2000];
        uint8_t out_pay[1000];
        size_t out_len = 0;

        size_t flen = mod_frame_encode(test_payload, 1000, frame, modes[m]);
        assert(flen > 0);

        int rc = mod_frame_decode(frame, flen, out_pay, &out_len, modes[m]);
        assert(rc == 0);
        assert(out_len == 1000);
        assert(memcmp(test_payload, out_pay, 1000) == 0);

        // Test corruption detection
        frame[flen / 2] ^= 0x55;
        rc = mod_frame_decode(frame, flen, out_pay, &out_len, modes[m]);
        assert(rc != 0); // Corrupted frame rejected
    }
    printf("Modulation frame wrapper tests (RAW, SCRAMBLE, COBS) passed.\n");

    printf("ALL MODULATION TESTS PASSED!\n");
    return 0;
}
