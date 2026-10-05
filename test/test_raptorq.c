#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../sxfer_raptorq.h"

int main()
{
    printf("=== Testing RaptorQ Fountain Coding Engine ===\n");

    size_t test_sizes[] = { 100, 1024, 4096, 16384, 50000 };
    uint32_t symbol_sizes[] = { 64, 256, 1024 };

    for (size_t s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]); s++) {
        for (size_t sy = 0; sy < sizeof(symbol_sizes)/sizeof(symbol_sizes[0]); sy++) {
            size_t data_len = test_sizes[s];
            uint32_t symbol_size = symbol_sizes[sy];
            if (symbol_size > data_len) continue;

            uint8_t *orig_data = malloc(data_len);
            for (size_t i = 0; i < data_len; i++) orig_data[i] = (uint8_t)(i * 37 + (i >> 5));

            rq_encoder *enc = rq_create_encoder(orig_data, data_len, symbol_size);
            assert(enc != NULL);
            uint32_t K = rq_get_k(enc);

            rq_decoder *dec = rq_create_decoder(data_len, symbol_size);
            assert(dec != NULL);

            uint8_t *sym = malloc(symbol_size);
            uint32_t esi = 0;
            uint32_t received = 0;
            uint8_t *recovered = malloc(data_len);

            // 50% erasure simulation: receive fountain symbols until decoded
            while (1) {
                if (rand() % 100 < 50) {
                    esi++;
                    continue;
                }
                rq_encode_symbol(enc, esi, sym);
                rq_receive_symbol(dec, esi, sym);
                received++;
                esi++;

                if (rq_decode_is_ready(dec)) {
                    int dec_rc = rq_decode_data(dec, recovered, data_len);
                    if (dec_rc == 0) {
                        assert(memcmp(orig_data, recovered, data_len) == 0);
                        break;
                    }
                }
            }

            printf("Size %6zu B, Symbol %4u B (K=%3u): Decoded with %3u symbols (overhead +%d = %.1f%%)\n",
                   data_len, symbol_size, K, received, (int)received - (int)K,
                   ((double)received - (double)K) * 100.0 / (double)K);

            free(sym);
            free(orig_data);
            free(recovered);
            rq_free_encoder(enc);
            rq_free_decoder(dec);
        }
    }

    printf("ALL RAPTORQ STRESS TESTS PASSED!\n");
    return 0;
}
