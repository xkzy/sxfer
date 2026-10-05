# RaptorQ Rateless Fountain Coding, Dynamic Chunk Sizing, Continuous Pipeline & Baseband Modulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 6330 RaptorQ rateless fountain coding, dynamic baud-adaptive chunk sizing, a 3-stage asynchronous continuous streaming pipeline, and a baseband line modulation layer (COBS + LFSR scrambler) for `sxfer`.

**Architecture:**
- Standalone RaptorQ codec engine (`sxfer_raptorq.h`/`.c`) performing systematic pre-coding over $GF(256)$ and inactivation decoding.
- Baseband modulation layer (`sxfer_mod.h`/`.c`) providing polynomial data scrambling / whitening and Consistent Overhead Byte Stuffing (COBS).
- Dynamic chunk sizing (1 KiB to 16 KiB) based on baud rate.
- 3-stage pipeline (Reader/Compressor -> RaptorQ Encoder & Modulator -> Serial TX Worker) with thread-safe ring buffering.

**Tech Stack:** C11, POSIX Threads (`pthread`), fast-lzma2, GCC, Linux.

## Global Constraints

- Pure C11 compliant, compatible with GCC on Linux.
- Fast LZMA2 codec interface must remain functional for compression.
- Frame CRC-32 and file-level CRC-32 must be preserved.
- No external dependencies beyond libc, libpthread, and the in-tree fast-lzma2 library.

---

### Task 1: Baseband Line Modulation & Scrambler (`sxfer_mod.h` / `sxfer_mod.c`)

**Files:**
- Create: `sxfer_mod.h`
- Create: `sxfer_mod.c`
- Test: `test/test_mod.c`

**Interfaces:**
- Produces:
  - `void lfsr_scramble(uint8_t *data, size_t len, uint16_t seed);`
  - `size_t cobs_encode(const uint8_t *src, size_t len, uint8_t *dst);`
  - `size_t cobs_decode(const uint8_t *src, size_t len, uint8_t *dst);`
  - `size_t mod_frame_encode(const uint8_t *payload, size_t len, uint8_t *out_frame, int mode);`
  - `int mod_frame_decode(const uint8_t *frame, size_t len, uint8_t *out_payload, size_t *out_len, int mode);`

- [ ] **Step 1: Write unit test for COBS and LFSR scrambler in `test/test_mod.c`**
  - Test encoding and decoding of arbitrary byte sequences containing zeros, ones, and random data.
  - Verify that COBS encoded frames contain zero `0x00` bytes except the trailing frame delimiter.
  - Verify transition density enhancement from the LFSR whitener.

- [ ] **Step 2: Implement Galois LFSR whitener and COBS encoder/decoder in `sxfer_mod.c`**
  - Implement fast table-driven or loop LFSR scrambler.
  - Implement standard COBS encoding and decoding.

- [ ] **Step 3: Compile and run unit test `test_mod`**
  - Verify all roundtrip assertions pass.

---

### Task 2: RFC 6330 RaptorQ Fountain Coding Engine (`sxfer_raptorq.h` / `sxfer_raptorq.c`)

**Files:**
- Create: `sxfer_raptorq.h`
- Create: `sxfer_raptorq.c`
- Test: `test/test_raptorq.c`

**Interfaces:**
- Produces:
  - `rq_encoder *rq_create_encoder(const uint8_t *source_data, size_t data_len, uint32_t symbol_size);`
  - `void rq_free_encoder(rq_encoder *rq);`
  - `int rq_encode_symbol(rq_encoder *rq, uint32_t esi, uint8_t *out_symbol);`
  - `rq_decoder *rq_create_decoder(size_t data_len, uint32_t symbol_size);`
  - `void rq_free_decoder(rq_decoder *dec);`
  - `int rq_receive_symbol(rq_decoder *dec, uint32_t esi, const uint8_t *symbol_data);`
  - `int rq_decode_is_ready(const rq_decoder *dec);`
  - `int rq_decode_data(rq_decoder *dec, uint8_t *out_data, size_t out_len);`

- [ ] **Step 1: Write unit test for RaptorQ encoder/decoder in `test/test_raptorq.c`**
  - Test systematic symbols ($ESI < K$) and repair symbols ($ESI \ge K$).
  - Test recovery from $K + 2$ random received symbols under 30% packet loss.

- [ ] **Step 2: Implement GF(256) arithmetic, RFC 6330 tuple generator, and pre-code matrix solver**
  - Implement log/exp table lookups and vector SIMD/aligned operations.
  - Generate constraint equations (LDPC + HDPC + LT) and solve for intermediate symbols $C$.

- [ ] **Step 3: Implement Inactivation Decoder in `sxfer_raptorq.c`**
  - Implement peeling decoding schedule for degree-1 check equations.
  - Inactivate unpeeled variables and perform dense Gaussian elimination over $GF(256)$.
  - Back-substitute to reconstruct all original source symbols.

- [ ] **Step 4: Compile and run `test_raptorq`**
  - Verify complete recovery across various erasure rates.

---

### Task 3: Dynamic Chunk Sizing & Continuous 3-Stage TX Pipeline in `sxfer.c`

**Files:**
- Modify: `sxfer.c`
- Test: `test/test_pipeline.sh`

**Interfaces:**
- Produces:
  - `uint32_t auto_chunk_size(long baud_rate, uint64_t file_size);`
  - `struct stage_queue` (thread-safe bounded ring buffer with mutex/cond).
  - Reader/Compressor Stage, RaptorQ Encoder & Modulator Stage, Serial TX Stage.

- [ ] **Step 1: Implement `auto_chunk_size` and aligned buffer allocations**
  - Auto-select: 1024 B (<500 kbaud), 4096 B (500 kbaud - 2.5 Mbaud), 16384 B (>=2.5 Mbaud).

- [ ] **Step 2: Implement thread-safe ring buffer queues and worker threads**
  - Thread 1: Reads files and compresses data via fast-lzma2 into Queue 1.
  - Thread 2: Pre-codes source blocks, generates RaptorQ symbols, applies baseband modulation, and pushes frames into Queue 2.
  - Thread 3: Streams frames from Queue 2 directly to serial device in 64 KiB batches to saturate UART TX FIFO.

- [ ] **Step 3: Test continuous pipeline throughput over FIFO pipe**
  - Verify zero inter-frame/inter-file gaps.

---

### Task 4: Receiver Integration for RaptorQ & Baseband Demodulation

**Files:**
- Modify: `sxfer.c`
- Test: `test/test_recv_fountain.sh`

**Interfaces:**
- Updates receiver state machine to demux modulated frames (COBS/scrambler) and feed symbols into `rq_decoder`.
- Finalizes files as soon as $K(1+\varepsilon)$ symbols are received.

- [ ] **Step 1: Implement COBS / scrambler frame parser in `feed()`**
  - Stream reassembler with zero-delimiter $O(1)$ boundary recovery and LFSR descrambler.

- [ ] **Step 2: Integrate `rq_decoder` in `on_data` and file finalization**
  - Collect symbols by ESI; trigger `rq_decode_data` when ready.
  - Decompress with fast-lzma2, verify CRC-32, and write file.

- [ ] **Step 3: Run receiver test under 30% random packet loss**
  - Verify error-free file reconstruction.

---

### Task 5: End-to-End Verification, Makefile & Man Page Updates

**Files:**
- Modify: `Makefile`
- Modify: `sxfer.1`
- Test: `test/test_e2e_full.sh`

- [ ] **Step 1: Update `Makefile`**
  - Add `sxfer_mod.c` and `sxfer_raptorq.c` to `SRC`.
  - Add `test` target.

- [ ] **Step 2: Update `sxfer.1` man page**
  - Document RaptorQ fountain coding, dynamic chunk sizing, baseband modulation options (`-m cobs|scramble|raw`), and continuous pipeline streaming.

- [ ] **Step 3: Run comprehensive end-to-end verification suite**
  - Verify transfers across baud rates, with frame drops, compression, directory hierarchies, and symlinks.
