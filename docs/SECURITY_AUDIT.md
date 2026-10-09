# sxfer Security Audit

| | |
|---|---|
| Revision audited | `40c00f8` (v2.0.2, branch `main`) |
| Date | 2026-10-09 |
| Scope | `src/*.rs`, `Cargo.toml`, `Cargo.lock`, `Makefile`, `test/*`, systemd installer, Windows tray |
| Method | Full manual read of every source file; reproduction of each "Confirmed" item against a **scratch copy** of the tree (release build, `panic = "abort"` as shipped); regression tests in `docs/audit/audit_regressions.rs` |
| Code changes to `src/` | Initial audit: none. **Follow-up: F-01..F-04 fixed** (`header_problem()` validator in `on_header`, `CappedWriter` in `lzma2.rs`); all other findings remain open. |

Evidence labels used throughout:

* **CONFIRMED (executed)**: reproduced on this host; the command or test is named.
* **CONFIRMED (inspection)**: the code path is unambiguous but was not executed here (needs root, Windows, or hardware). Stated explicitly each time.
* **HYPOTHESIS**: plausible, depends on conditions I could not verify.
* **DESIGN LIMITATION**: working as designed, but unsafe for the stated threat model.

---

## 1. Executive summary

sxfer's *filesystem containment* is in much better shape than the task brief assumes. The v2.0.1 hardening (`b7c2f93`, `5006bae`) already makes `prep_dest()` walk every parent without following symlinks, writes temp files with `O_EXCL`, strips setuid/setgid, and refuses to apply metadata through symlinks. I found **no way to write outside the output directory** from the wire (Section 5, "Verified not exploitable").

The receiver is, however, **trivially crashable and memory-exhaustible by a single forged frame**, because every header field is trusted before allocation, and nothing authenticates the sender.

Headline results:

| # | Finding | Severity | Status |
|---|---|---|---|
| F-01 | `on_header()` `unwrap()` aborts on `psize>0, csz=0` | **High** | **FIXED** (patch + regression test; was CONFIRMED) |
| F-02 | Header `psize`/`csz` drive unbounded allocations, abort | **High** | **FIXED** (patch + regression test; was CONFIRMED) |
| F-03 | Header `size` becomes `Vec::with_capacity`, abort | **High** | **FIXED** (patch + regression test; was CONFIRMED) |
| F-04 | LZMA decompression is unbounded (ignores `size`) | **High** | **FIXED** (patch + regression test; was CONFIRMED) |
| F-05 | Receive buffer grows without limit; scan is quadratic | Medium | CONFIRMED (executed) |
| F-06 | Receiver state (`table`, `early_syms`, `dirs`) never bounded or evicted | Medium | CONFIRMED (executed) |
| F-07 | One forged symbol permanently poisons a transfer | Medium | CONFIRMED (executed) |
| F-08 | Root receiver always `lchown`s to uid 1000; `-p` and header modes are unchecked | Medium | CONFIRMED (inspection; needs root) |
| F-09 | Watch mode deletes sources after failed/partial transmission | **High** (data loss) | CONFIRMED (executed) |
| F-10 | FIFO in watch dir hangs the sender, ignores SIGTERM | Medium (local) | CONFIRMED (executed) |
| F-11 | No authentication: CRC-32 only, no replay protection | **High** (design) | DESIGN LIMITATION |
| F-12 | Arbitrary symlink targets and silent overwrite policy | Medium | CONFIRMED (executed) / by design |
| F-13 | Temp name `with_extension("sxfer-part")` clobbers siblings | Low | CONFIRMED (executed) |
| F-14 | Wire-controlled strings reach the terminal/journal unescaped | Low | CONFIRMED (executed) |
| F-15 | A `d` header chmods/chowns an existing *regular file* | Low | CONFIRMED (executed) |
| F-16 | systemd unit: runs as root, fragile `ReadWritePaths`; daemon passes unsupported `-k` | Medium | CONFIRMED (inspection + executed for `-k`) |
| F-17 | Config parser panics on a lone `"` | Low (local) | CONFIRMED (executed) |
| F-18 | `-r 0` transmits headers only, then watch mode deletes | Low | CONFIRMED (executed) |
| F-19 | Windows: timestamp overflow panic, reserved device names, PATH lookups | Low–Medium | HYPOTHESIS / inspection (not executed) |
| F-20 | Hand-written FFI structs, `lzma-rs` has no output limit, no advisory scan run | Low | inspection |

The three items most worth fixing first are **F-01..F-04** (one header validator plus a bounded decompressor closes all four), **F-09** (silent data loss on the sender), and **F-11** (add a keyed MAC; the transport has no integrity beyond CRC-32).

Two negative results are worth recording: a CPU-amplification attack via junk frames (the resync loop tries many candidates) did **not** materialise (8 MiB of adversarial noise processed in well under a second), and the RaptorQ/LDPC decoders themselves are bounded (`k <= 128` per block, LDPC `<= 2048` blocks per frame).

---

## 2. Threat model and trust boundaries

```
 ┌────────────┐   UART/serial, one way   ┌──────────────────────────────┐
 │  SENDER    │ ───────────────────────► │  RECEIVER (often root daemon) │
 │ (trusted?) │      untrusted bytes     │  parse → decode → write files │
 └────────────┘                          └──────────────────────────────┘
        ▲                                             ▲
 local users who can write                   local users who can read/write
 the watch directory                         the output directory
```

| Boundary | Assumed trust | Notes |
|---|---|---|
| Serial line → receiver | **Untrusted.** Anyone with physical or cable access, a compromised sender, or a noisy/faulty line. | The one-way design is the reason there is no handshake; any authentication has to be **in-band and keyed** (pre-shared key MAC). |
| Header fields (`size`, `psize`, `k`, `csz`, `meth`, mode, uid, gid, mtime, path, link) | Untrusted | Currently trusted almost verbatim. |
| Output directory contents | Receiver-owned; other local users may be able to write there | Containment code assumes an attacker may plant symlinks (it handles that). |
| Watch directory | Writable by whoever feeds files to the sender | A hostile writer can plant FIFOs, sockets, or racing files. |
| `/etc/sxfer.conf`, `%APPDATA%\sxfer\sxfer.conf` | Admin/user trusted | Panics here are robustness bugs, not privilege boundaries. |

Attacker profiles used below:

* **A1 – line injector**: can put arbitrary bytes on the serial line. Can compute CRC-32, COBS, and LDPC trivially (public algorithms, no key).
* **A2 – malicious or compromised sender**: same capabilities, authenticated by nothing.
* **A3 – local unprivileged user** with write access to the watch dir and/or output dir.

**Out of scope / explicit non-claims:** no remote code execution path was found. Rust memory safety holds in the safe code; the `unsafe` blocks are FFI calls (Section F-20). Every impact listed is availability, integrity, or data-loss, not code execution.

---

## 3. Findings

> **Fix status (follow-up):** F-01, F-02, F-03, F-04 are fixed. Header sizes are validated before any allocation or decoder construction (`ReceiverContext::header_problem`, limits `MAX_CSZ` 32 KiB, `MAX_PSIZE` 1 GiB, `MAX_SIZE` 4 GiB, `MAX_LZMA_RATIO` 8192; the `unwrap()` is gone), and LZMA output is capped at the declared size by a `CappedWriter` with pre-allocation limited to 64 MiB. Verified by `f01`..`f04` tests (fail before, pass after), the original PoC streams (now `REJECT header ...` or a clean `LZMA2 decompression failed`, exit 0, no abort under a 600 MB limit), and a round trip of 3 MB text, 500 KB random, an empty file and a subdirectory. The text of F-01..F-04 below describes the audited revision. Windows was not tested. Remaining open: everything else.

Line numbers refer to revision `40c00f8`.

### F-01 `on_header()` aborts the receiver on `psize > 0, csz = 0` — **High**, CONFIRMED (executed)

* **Location:** `src/main.rs`, `ReceiverContext::on_header`, lines 919–932; the `unwrap()` is at **line 921**. Root cause is the missing validation in lines 846–905; `RaptorQDecoder::new` returns `None` for `symbol_size == 0` (`src/raptorq.rs:440-443`).
* **Path:** serial read (`do_recv`, 1385) → `mod_frame_decode` (needs only a correct CRC-32, which the attacker computes) → `process_frame` (1010) → `on_header` → `RaptorQDecoder::new(10, 0).unwrap()` → panic. The release profile has `panic = "abort"` (`Cargo.toml`), so the process dies with SIGABRT and drops all in-flight state.
* **Prerequisites:** A1/A2. One frame. The header must pass `p.len() >= 56`, `ftype == 'f'`, non-empty path, `psize > 0`, `csz == 0`.
* **Impact:** remote single-frame crash. Under the shipped unit (`Restart=always`, `RestartSec=3`) an attacker can keep it down by repeating the frame every 3 s.
* **Evidence:**
  ```
  $ sxfer recv -d A_csz0.bin -q 1 -o out
  [..] START a.txt (f, 10 B, 1 RaptorQ symbols @ 0 B, CRC 00000000)
  thread 'main' panicked at src/main.rs:921:77:
  called `Option::unwrap()` on a `None` value
  exit=134
  ```
* **Regression test:** `f01_zero_csz_header_must_not_abort`.

### F-02 Header `psize` and `csz` drive unbounded allocations — **High**, CONFIRMED (executed)

* **Location:** `on_header` 919–932 → `RaptorQDecoder::new` (`raptorq.rs:439-457`) → `BlockDecoder::new` (`raptorq.rs:237-249`): `Vec::with_capacity(num_blocks)`, `vec![0u8; data_len]`, `Vec::with_capacity((k + 32) * symbol_size)`. No bound on either field is applied anywhere in `on_header` (846–905). `k` from the header is stored but never used for sizing.
* **Executed:**
  | Header | Result |
  |---|---|
  | `psize=2^40, csz=1` | `memory allocation of 1305670057984 bytes failed`, SIGABRT |
  | `psize=1, csz=0x7fffffff` | `memory allocation of 70866960351 bytes failed`, SIGABRT |
* **Subtlety:** with default Linux overcommit (`vm.overcommit_memory=0`) allocations *below* free RAM succeed lazily, so a moderately large `csz` costs address space rather than RSS; each header with a fresh 8-byte id adds another. On strict-overcommit embedded targets (`=2`, common on small UART gateways) this exhausts commit quickly. The `data` path cannot deliver a symbol larger than the frame limit (`mod_codec.rs:100`, about 44 KB payload), so any `csz` above that can never complete and is pure cost.
* **Prerequisites:** A1/A2, one frame.
* **Regression tests:** `f02_huge_psize_header_must_not_abort`, `f02_huge_csz_header_must_not_abort`.

### F-03 Header `size` becomes `Vec::with_capacity` — **High**, CONFIRMED (executed)

* **Location:** `decompress_lzma2`, `src/lzma2.rs:12-15`, called from `finalize_file` (`main.rs:710-712`) as `decompress_lzma2(&dec_payload, size as usize)`. `size` is the header value.
* **Path:** header `meth=1, psize=1, csz=1, size=2^50` + one 1-byte data symbol → decoder completes → `finalize_file` → `Vec::with_capacity(2^50)`.
* **Evidence:** `memory allocation of 1125899906842624 bytes failed`, exit 134. Also truncates silently on 32-bit (`size as usize`).
* **Regression test:** `f03_huge_size_with_lzma_must_not_abort`.

### F-04 LZMA decompression is unbounded — **High**, CONFIRMED (executed)

* **Location:** `src/lzma2.rs:12-17`; call site `main.rs:710-720`. `lzma_rs::lzma_decompress` is called with default options (`memlimit: None`, unpacked size taken from the *attacker-supplied* .lzma header), and the result is only compared against `size` **after** it is fully materialised (`main.rs:722-726`).
* **Note:** the module is named `lzma2` but uses `lzma-rs`'s **LZMA (alone)** format. The README/spec language ("fast-lzma2") is inaccurate; harmless but misleading for reviewers.
* **Evidence:**
  * 800 MiB of zeros → 118 KB `.lzma` stream (ratio ≈ 7000:1). Header claimed `size = 64`. Receiver under `ulimit -v 600000`: `memory allocation of 1073741824 bytes failed` (output vector doubled to 1 GiB, ignoring `size = 64`).
  * In-process: an 8 MiB-of-zeros bomb of **1272 bytes** decompresses to 8 MiB although `expected_size = 1024` (`f04` fails with that message).
* **Impact:** a few hundred KB on the wire forces gigabytes of RAM → OOM kill (or abort). `lzma-rs`'s `memlimit` only limits the dictionary buffer, not the output `Vec`, so setting it alone is **not** sufficient (see fix).
* **Regression test:** `f04_decompress_must_not_exceed_declared_size` (needs the `xz` CLI to build the bomb; skips if absent).

### F-05 Receive buffer is unbounded and rescanned — **Medium**, CONFIRMED (executed)

* **Location:** `do_recv`, `main.rs:1344` (`in_buf`), `1395` (`extend_from_slice`), `1398-1435` (frame search). If the bytes after `p` contain no `0x00`, the inner `position()` returns `None`, `found` stays `false`, and nothing is drained. The next read appends and rescans the whole buffer.
* **Evidence:** 64 MiB of `A` (no delimiter): `maxrss=66496KB`, `wall=11.35s` (4× the data takes ≈16× the time: quadratic). Test child: `RETAINED 15956 KiB` for 16 MiB.
* **Impact:** memory grows at line rate. At 3 Mbaud (~300 KB/s) that is about 1 GB/hour; at 115200 about 40 MB/hour. Self-limiting on slow links, serious on fast ones or with a malfunctioning transmitter. CPU grows quadratically.
* **Regression test:** `f05_delimiterless_stream_must_not_grow_input_buffer`.

### F-06 Receiver state is never bounded or evicted — **Medium**, CONFIRMED (executed)

* **Locations:**
  * `on_data`, `main.rs:959-993`: any 8-byte id creates a `FileState`; until a header arrives every symbol is pushed to `early_syms` (986-993), each up to ≈44 KB. No cap per id, no cap on ids, no timeout.
  * `table` entries are **never removed**, even when `done` (`finalize_file` 752-755 sets `done`, keeps path/link strings). A long-running daemon leaks one entry per file ever received.
  * `self.dirs` (793) grows per directory header; it is applied only in `finish()` (1027-1030), which a daemon only reaches on SIGTERM/SIGINT. Directory mtimes/modes are therefore not applied during normal daemon operation.
  * `BlockDecoder::visited_esis` (`raptorq.rs:231, 261`) and per-block symbol buffers grow with distinct ESIs when the matrix is rank-deficient.
* **Evidence:** 400 unknown-id data frames of 40 000 B (24 MB on the wire): `maxrss=17864KB` (≈ 16 MB retained, linear). 1000 frames of 4096 B retained 4 096 000 bytes (`f06` fails).
* **Impact:** ≈ 2/3 of every wire byte injected is retained forever. At 3 Mbaud ≈ 0.7 GB/hour. Also a benign leak for legitimate long-lived daemons.
* **Regression test:** `f06_early_symbols_for_unknown_ids_are_bounded`.

### F-07 One forged symbol permanently poisons a transfer; per-frame work amplification — **Medium**, CONFIRMED (executed)

* **Location:** `BlockDecoder::receive_symbol`/`decode_block` (`raptorq.rs:251-268, 270-431`) latch `is_decoded = true` the moment `k` symbols arrive, whether or not they are consistent. `on_data` then treats every further symbol as `ready` (`main.rs:995-1007`) and calls `finalize_file` each time: full `decode_data()` copy + LZMA decode + CRC, then "CRC32 mismatch, waiting for more symbols" (723-726). That message is false: nothing more can ever be learned.
* **Evidence:** header + 2 genuine symbols + 1 forged symbol, then 200 genuine repair symbols: output has **202 `FAIL … CRC32 mismatch` lines, 0 `OK`, and `h.bin` is never written**. (Each of the 200 extra 1 KiB frames cost a full decode + CRC.)
* **Prerequisites:** A1 who can see the 8-byte id (it is in every frame). It also fires on a legitimate noisy link if a corrupted symbol ever passes its frame CRC (probability ≈ 2⁻³² per damaged frame, but then the file is unrecoverable until the sender retransmits under a new id).
* **Impact:** targeted integrity-of-delivery denial for any single transfer; CPU amplification of ≈ file-size work per injected frame (bounded by file size).
* **Regression test:** `f07_forged_symbol_must_not_permanently_poison_a_transfer`.

### F-08 Ownership/permission handling — **Medium**, CONFIRMED (inspection; not executed: needs root)

* **Locations:** `apply_meta` `main.rs:660-663`; `apply_file_metadata` `129-159`.
  1. **`-p` has no effect on whether root chowns.** `apply_meta` substitutes `(1000, 1000)` when `restore_owner` is false (661), but `apply_file_metadata` calls `lchown` whenever `geteuid() == 0` (138-143). A receiver running as root (the shipped systemd unit does) therefore **gives every received file and directory to uid/gid 1000** by default. On many systems uid 1000 is the first interactive user; they can then modify "verified" files afterwards.
  2. **With `-p`, uid/gid come straight from the wire.** An A2 can create files owned by any uid, and directories owned by an unprivileged uid with mode `0777`. That uid can then rename/replace entries inside, racing the receiver's `symlink_metadata` checks in `prep_dest` (TOCTOU between check and `open`/`rename`; HYPOTHESIS, requires a cooperating local account).
  3. **Mode comes from the wire**, masked only with `0o1777` (148). Setuid/setgid are correctly stripped, but world-writable (`0o666/0o777`) and sticky bits are honoured, and mode `0o000` on a directory is honoured at `finish()`.
  4. The `chown` extern (67) is declared but unused.
* **Impact:** unexpected ownership (always, as root), attacker-chosen mode/owner. No privilege escalation was found because setuid/setgid and capabilities are not set and symlinks are never followed.
* **Regression test:** `f08_root_receiver_must_not_chown_to_uid_1000_without_dash_p` (`#[ignore]`, run as root).

### F-09 Watch mode deletes sources that were not transmitted — **High (data loss)**, CONFIRMED (executed)

* **Locations:** `do_send` `main.rs:1259-1283`; `send_batch` `1105-1134`; `tx_worker` `524-556`; `crawl_and_compress` `307-421`; `walkdir` `423-439`.
  * `tx_worker` discards every write error (`let _ = file.write_all(...)`, lines 528, 538, 546, 552). `send_batch` returns `Ok(())` regardless (1133).
  * `crawl_and_compress` logs and `continue`s on read failure (383-385), and silently ignores entries that are neither file, dir nor symlink (FIFOs, sockets, devices: no `else` after 376). `walkdir` ignores `read_dir` errors (428).
  * `fcrc` is computed in a separate pass (378) from the data read (380); a file changing in between yields a header CRC that can never match, and the receiver can never complete it.
  * Files added to a watched **directory** after `walkdir` ran, but before `remove_dir_all` (1278), are deleted without ever being sent.
  * `is_file_ready_to_send` (1136-1182) is a 250 ms debounce, not a lock; the file can change right after it returns.
  * `encode_stage` swallows `tx.send` errors (`let _ =` at 481, 498, 510, 518).
  * The receiver never confirms anything (one-way), so "sent" can only mean "written to the device", and even that is not checked.
* **Evidence:** `sxfer send -d /dev/full -w w` (every write returns ENOSPC): `SENT & DELETED w/important.txt`, file gone. Regression child output shows `DELETED-UNSENT`.
* **Prerequisites:** none beyond ordinary faults (unplugged adapter, full device buffer, disk error). A3 can additionally exploit the directory race.
* **Impact:** irreversible loss of the only copy of data.
* **Regression test:** `f09_watch_mode_must_not_delete_when_device_writes_fail`.

### F-10 FIFO in the watch directory hangs the sender — **Medium (local)**, CONFIRMED (executed)

* **Location:** `check_file_locked`, `main.rs:221` (`OpenOptions::new().read(true).open(path)`) called from `is_file_ready_to_send` 1159. `open(2)` of a FIFO with no writer blocks forever. The call is made before any file-type check.
* **Evidence:** `timeout 6 sxfer send -d j3.bin -w w3` was still running at the timeout; the signal handler's `STOP_FLAG` is only polled in the loop, and glibc `signal()` restarts `open`, so **SIGTERM does not stop it** (systemd would need to escalate to SIGKILL). The legitimate `zz.txt` next to it was never sent.
* **Prerequisites:** A3 with write access to the watch dir. Also (inspection only, not executed): sockets/devices there fail the `open` and are treated as "locked", so they are retried forever every 150 ms with a log line each time.
* **Regression test:** `f10_fifo_in_watch_dir_must_not_hang_the_sender`.

### F-11 No authentication, no replay protection — **High**, DESIGN LIMITATION

* **Locations:** `mod_codec.rs:73-90, 99-131` (CRC-32 + LDPC, both keyless); `FileState` creation `main.rs:819-840, 959-980`; `on_header` first-header-wins (842).
* **Facts:** every integrity check is CRC-32 over public data. Frame CRC, LDPC parity, COBS and the scrambler (`0x5A3C` constant) are all keyless; an attacker produces valid frames with the same `mod_frame_encode`. `mod_codec.rs:120-121` computes the LDPC CRC and then ignores it (`_expected_ldpc_crc`, `_actual_ldpc_crc`), so one of the two checksums is dead.
* **Impact (A1/A2):** write any file, with any content, mode, mtime and name, anywhere under the output directory; overwrite existing files; plant symlinks; replay old captures (after a daemon restart the `done` table is empty, so rollback of files to older contents is possible); pre-empt a legitimate header (first header wins) or inject symbols into a legitimate id (F-07). All of the DoS findings above need no authentication either.
* **Not a bug in isolation:** the project advertises integrity against line noise, not against adversaries. But the brief's threat model (untrusted serial input) requires something stronger.
* **Constraint honoured:** the recommendation (Section 6) is a pre-shared-key MAC carried in-band; no handshake, no network, no change to SC-LDPC/RaptorQ/modulation.

### F-12 Symlink targets and overwrite policy — **Medium**, CONFIRMED (executed) / partly by design

* **Location:** `finalize_other` `main.rs:795-803`; `create_symlink` `185-190` (Unix: no target validation). Windows has a validator (191-210); Unix does not.
* **Evidence:** header `l`, path `lnk`, link `/etc/shadow` → `lnk -> /etc/shadow` created in the output dir.
* **Analysis:** sxfer itself never follows the link (verified, Section 5). But every other consumer of the output directory (users, `rsync -L`, backup agents, web servers, `cp -r`, an unzip-style post-processor) will. Absolute or `..`-relative targets turn the incoming folder into a read/write primitive against the *consumer's* privileges.
* **Also:** `fs::remove_file(&dest)` (796) and the `rename` in `finalize_file` replace any pre-existing entry in the output dir, so a hostile sender destroys previously received data. There is no no-clobber mode.

### F-13 Temp name collisions — **Low**, CONFIRMED (executed)

* **Location:** `finalize_file`, `main.rs:728-743`. `dest.with_extension("sxfer-part")` *replaces* the extension: `a.txt`, `a.log`, `a` all map to `a.sxfer-part` (no-extension `a` → `a.sxfer-part`), and `fs::remove_file(&tmp_path)` deletes whatever is there first.
* **Evidence:** pre-existing `src_n/a.sxfer-part` containing `precious` was deleted by receiving `src_n/a.txt`.
* **Other:** a crash between create and rename leaves stale `*.sxfer-part` files forever; no `fsync` before `rename`, so a power loss can leave a zero-length destination. The write happens with default umask before `set_permissions`, so there is a short window where the file has umask permissions rather than the final mode.
* **Containment note:** the `O_EXCL` + `remove_file` sequence is safe against planted symlinks (the earlier symlink-write issue is fixed).
* **Regression test:** `f13_temp_name_must_not_clobber_sibling_files`.

### F-14 Wire strings reach the terminal and journal unescaped — **Low**, CONFIRMED (executed)

* **Locations:** every `logmsg` that interpolates `f.path` / `link` (`main.rs:689, 702, 714, 724, 739, 758, 782, 794, 799, 801, 908-917, 1037-1043`).
* **Evidence:** a directory header with path `\x1b]0;PWNED\x07dir` printed `DIR   ^[]0;PWNED^Gdir` containing raw ESC/BEL; the directory was created with those bytes in its name (`]0;PWNEDdir`).
* **Impact:** terminal escape injection in an operator's terminal (title/clipboard OSC sequences on some terminals), forged log lines via embedded `\n` (journald stores the raw newline).
* **Regression test:** `f14_log_output_must_not_contain_raw_control_bytes_from_the_wire`.

### F-15 `d` header applies metadata to an existing regular file — **Low**, CONFIRMED (executed)

* **Location:** `finalize_other` 791-794 (`create_dir_all` result ignored but `dirs.push` always executed), `finish()` 1027-1030, `apply_file_metadata` 133-136 (only checks symlink-ness, not that a directory is a directory).
* **Evidence:** an existing 0644 file `x`; header `d` path `x` mode `000`; after `finish()` the file's mode is `000`. Stays inside the output dir. Combined with F-08 (`-p`) it also changes its owner.
* **Regression test:** `f15_directory_header_must_not_chmod_a_regular_file`.

### F-16 systemd installation and daemon wiring — **Medium**, CONFIRMED

* **Locations:** `src/service.rs:36-39, 41-55, 63-133`.
  1. **Runs as root** (no `User=`/`DynamicUser=`) with `CAP_DAC_OVERRIDE` in the bounding set (111), so any parser bug executes with root file access inside the writable paths. `ProtectSystem=strict`, `NoNewPrivileges`, `RestrictAddressFamilies=AF_UNIX` etc. are good but not a substitute for a dedicated user.
  2. **No device confinement.** `DevicePolicy=closed` + `DeviceAllow=<port> rw` are absent, so the root service can open any device node.
  3. **No resource limits** (`MemoryMax=`, `TasksMax=`, `LimitNOFILE=`, `LimitCORE=0`); a single F-02/F-04 header can take the host down rather than just the service.
  4. **`ReadWritePaths=` fragility:** installed with whatever `dest_dir`/`watch_dir` say, space-separated (`service.rs:85,112`). A path containing a space becomes two paths. A directory that does not exist (the defaults `/var/spool/sxfer/{incoming,outgoing}` are never created by the installer) makes systemd fail namespace setup (`status=226/NAMESPACE`); use `-` prefixed paths and `StateDirectory=`.
  5. `ExecStart=/usr/local/bin/sxfer` is hard-coded while the Makefile honours `PREFIX`/`DESTDIR`.
  6. Config precedence falls back to `$HOME/.config/sxfer/sxfer.conf` (`config.rs:78-82`) when `/etc/sxfer.conf` is absent, which is unexpected for a root service.
  7. **Config/daemon mismatch bug:** when `keep_damaged = true`, `service.rs:36-38` appends `-k`, which `do_recv` rejects (`Unknown option: -k`), so the daemon never starts (restart loop every 3 s). Executed: `sxfer recv -d x -k` → `sxfer: Unknown option: -k`.
  8. The installer writes `/etc/sxfer.conf` and the unit with `fs::write` (follows symlinks, non-atomic); only root can plant the link, so this is robustness only.
* **Regression test:** `f16_daemon_receiver_args_must_be_accepted_by_recv`.

### F-17 Config parser panics on a lone quote — **Low (local)**, CONFIRMED (executed)

* **Location:** `src/config.rs:122-126`. `val = "` satisfies both `starts_with('"')` and `ends_with('"')`, then `&val[1..val.len()-1]` is `&val[1..0]`.
* **Evidence:** `port = "` → `panicked at src/config.rs:125:31: begin <= end (1 <= 0)`.
* **Other:** `redundancy` accepts `NaN`, negative and huge values; `(cfg.redundancy + 0.5) as usize` saturates and the sender then loops `usize::MAX` rounds (`service.rs:42`, `encode_stage` 493). `baud`, `poll_interval_ms` (parsed, unused) are not range-checked.
* **Regression test:** `f17_config_with_lone_quote_must_not_panic`.

### F-18 `-r 0` sends headers only — **Low**, CONFIRMED (executed)

* **Location:** `do_send` 1199 (no minimum), `encode_stage` 493 (`for round in 0..rounds`). With `rounds = 0` no data symbols are emitted; the stream finishes "successfully" (`FINISHED`) and in watch mode the source is deleted. Receiver: `INCOMPLETE f.txt: received 0 symbols`. (The daemon clamps to ≥ 1 at `service.rs:42-43`; the CLI does not.)
* **Regression test:** `f18_zero_rounds_must_be_rejected`.

### F-19 Windows-specific — HYPOTHESIS / inspection (not executed; no Windows host)

| Item | Location | Assessment |
|---|---|---|
| mtime overflow panic | `main.rs:175-179`: `UNIX_EPOCH + Duration::new(mt_s as u64, mt_ns)`. `SystemTime + Duration` panics on overflow; on Windows the representable range is ≈ 3×10¹¹ s past 1970. A header with `mtime = 10¹²` plausibly aborts the tray/daemon. | Likely (std documents the panic); verify on Windows. |
| Reserved device names | `prep_dest` (625-658) rejects `\` and `:` on Windows but not `CON`, `NUL`, `COM1`, `LPT1`, `AUX`, `NUL.txt`, or trailing dots/spaces. Opening them targets devices, not files (can touch a serial port in use). | Plausible; add a Windows-name denylist. |
| Junctions / reparse points | `prep_dest` relies on `symlink_metadata().is_symlink()`. Whether Rust reports directory **junctions** as symlinks depends on the std version; if not, a pre-planted junction is followed. | Verify with the toolchain in CI. |
| Windows symlink validator | `main.rs:191-210` is sound (rejects UNC, drive, root, `..`). Unix has none (F-12). | Fine. |
| `Command::new("explorer.exe")` / `"notepad.exe"` | `tray_windows.rs:174-182`: bare names resolved by search path. | Use absolute `%SystemRoot%` paths. |
| Tray reloads the *default* config | `tray_windows.rs:146,173` call `load_default()` ignoring `--config`; "Open Incoming Folder" can open a directory different from the one the daemon writes to. | Correctness, not security. |
| Tray runs as the logged-in user | (`run_tray_service_impl`) | Good: no service privilege. |

### F-20 Dependencies, unsafe code, parser ambiguity — **Low**

* **Dependencies:** `lzma-rs 0.3.0` (only Linux dependency; checksum in `Cargo.lock`), `serialport`/`windows-sys` on Windows. `cargo audit`/`cargo deny` are **not installed here and were not run**; no advisory result is claimed. Recommend adding `cargo audit` and `cargo deny` to CI. `lzma-rs` has no output cap (F-04) and is a low-activity crate.
* **`unsafe`/FFI** (`main.rs:40-78`, `serial.rs:50-72`, `main.rs:138-159`): hand-written `extern "C"` declarations and `#[repr(C)]` structs (`Timespec { i64, i64 }`, `Termios`, `PollFd`). `Timespec` is only correct where `time_t` and `long` are 64-bit; on 32-bit ARM (a plausible UART gateway) `utimensat` would read the wrong layout. The `Termios` layout is Linux-generic and architecture-fragile. Paths are passed through `to_string_lossy()` (156, 140), so a non-UTF-8 output directory name is changed (harmlessly failing, but not the path intended). The signal handler only touches an atomic (async-signal-safe). No memory-safety bug found.
* **Parser ambiguity** (informational):
  * `process_frame` (1020) decides header vs. data by `pay[8] ∈ {'f','d','l'}`, which is *also* the high byte of a data frame's ESI. A data frame with `esi >= 0x64000000` and length ≥ 32 is parsed as a header. Legitimate senders never get there; an injector can pick either interpretation.
  * `cobs_decode` (`mod_codec.rs:52-71`) accepts zero codes and truncated runs; `sc_ldpc_decode` accepts ±24 bytes of slack (`ldpc.rs:290-300`); the LDPC CRC is ignored (F-11). Many distinct byte strings decode to the same payload. Not exploitable on its own, but it defeats "canonical frame" reasoning and makes a future MAC harder to apply to raw bytes: **MAC the decoded payload, never the wire bytes.**
  * Header field `k` is never validated against `ceil(psize/csz)`.
  * The `hex` module and `level` byte are decorative.

---

## 4. Reproduction

The reproductions live in `src/audit_regressions.rs` (`#[cfg(test)]`). Tests for open findings carry `#[ignore = "open finding F-xx"]`; remove the attribute when fixing that finding. F-01..F-04 are active and pass. To run everything including open ones:

```sh
cargo test audit_regressions                       # F-01..F-04 pass
cargo test audit_regressions -- --ignored          # open findings: fail by design on 40c00f8
sudo -E cargo test f08 -- --ignored                # root-only chown test
```

Properties of the suite: every test asserts the *secure* outcome; dangerous cases (aborts, allocation failures, hangs, deletions) run in a child copy of the test binary under `RLIMIT_AS = 512 MiB`, in a per-test temp directory, with a 20-30 s kill timer; nothing outside `$TMPDIR` is touched.

Result on `40c00f8` (scratch copy, `cargo test`, 18 tests): **16 failed, 1 passed (`audit_child`, a helper), 1 ignored (F-08, needs root)**. The failures were each inspected and fail for the stated reason (e.g. `f01`: child exit 134 with the `unwrap()` message; `f07`: 202 `CRC32 mismatch` lines and no output file; `f09`: `DELETED-UNSENT`).

| Test | Finding |
|---|---|
| `f01_zero_csz_header_must_not_abort` | F-01 |
| `f02_huge_csz_header_must_not_abort`, `f02_huge_psize_header_must_not_abort` | F-02 |
| `f03_huge_size_with_lzma_must_not_abort` | F-03 |
| `f04_decompress_must_not_exceed_declared_size` | F-04 |
| `f05_delimiterless_stream_must_not_grow_input_buffer` | F-05 |
| `f06_early_symbols_for_unknown_ids_are_bounded` | F-06 |
| `f07_forged_symbol_must_not_permanently_poison_a_transfer` | F-07 |
| `f08_root_receiver_must_not_chown_to_uid_1000_without_dash_p` (ignored) | F-08 |
| `f09_watch_mode_must_not_delete_when_device_writes_fail` | F-09 |
| `f10_fifo_in_watch_dir_must_not_hang_the_sender` | F-10 |
| `f13_temp_name_must_not_clobber_sibling_files` | F-13 |
| `f14_log_output_must_not_contain_raw_control_bytes_from_the_wire` | F-14 |
| `f15_directory_header_must_not_chmod_a_regular_file` | F-15 |
| `f16_daemon_receiver_args_must_be_accepted_by_recv` | F-16 |
| `f17_config_with_lone_quote_must_not_panic` | F-17 |
| `f18_zero_rounds_must_be_rejected` | F-18 |

Not covered by a test (and why): F-11 (design; needs a keyed format), F-12 (policy decision), F-19 (Windows), F-20 (inspection). F-16 items 1–6 are unit-file properties; test with `systemd-analyze security sxfer.service` and a VM.

---

## 5. Verified not exploitable (brief items that no longer hold at this revision)

These were checked because the task brief listed them. They are **not** findings at `40c00f8`; they depend on the existing code staying as is.

| Brief item | Result | Why |
|---|---|---|
| Path traversal / absolute paths in `prep_dest` | Not exploitable | Only `Normal`/`CurDir` components accepted (`main.rs:633-643`); `..`, root, prefix rejected; NUL rejected; leading `/` trimmed. |
| Parent-directory symlink escape / race | Not exploitable (single-threaded; residual TOCTOU needs a local attacker, see F-08.2) | Each parent is checked with `symlink_metadata`, refused if symlink or non-directory, created with `create_dir` (645-655). Covered by existing test `prep_dest_rejects_traversal_and_symlinks`. |
| Predictable temp filename → write through planted symlink | Fixed in 5006bae | `remove_file` + `create_new` (`O_EXCL`) never follows symlinks (728-737). Collision issue remains (F-13). |
| `finalize_other` deleting unrelated files | Limited to files **inside the output directory** | `remove_file(&dest)` (796) follows prep_dest's containment; it cannot reach outside, but it does remove existing received files (F-12). |
| Metadata through symlinks | Not exploitable | `apply_file_metadata` returns unless `ftype=='l'` matches `is_symlink` (133-136); `lchown`/`AT_SYMLINK_NOFOLLOW` used; existing test `metadata_never_follows_symlink_or_sets_suid`. Residual: check-then-use race and F-15. |
| setuid/setgid from the wire | Not exploitable | Masked with `0o1777` (148). |
| `-p` privilege escalation | None found | No setuid, no capabilities, symlinks never followed. See F-08 for the unexpected-ownership problems. |
| Integer overflow in framing/LDPC | Not found | `sc_ldpc_decode` bounds `orig_len`/blocks (`ldpc.rs:283-300`), `mod_frame_decode` bounds frame length (100). Release build has overflow checks off, but no arithmetic on untrusted sizes can wrap before the allocation checks above fail first (`(k+32)*symbol_size` is the closest; see F-02). |
| CPU amplification through resync | Not reproduced | 8 MiB of random bytes vs. 8 MiB of `(40 non-zero bytes + 0x00)` repeated both finished in about 1 s total (idle quit dominated); the `frame_end - p < 1024` bound limits retries. |

---

## 6. Recommended fixes and compatibility risks

None of these has been applied. Each should be implemented together with the matching test above.

### 6.1 One validator for headers (closes F-01, F-02, F-03, partly F-06, F-15)

Parse the header into a struct, validate **before** inserting into `table` or touching the decoder. Reject (drop frame, count it, do not crash):

* `ftype ∈ {f,d,l}`; for `d`/`l`: `size == psize == 0`, `k == 0|1`, `meth == 0`.
* `csz ∈ [MIN_CSZ, MAX_CSZ]` where `MAX_CSZ` is derived from the frame limit (≤ 32 768).
* `psize ≤ MAX_PAYLOAD`, `size ≤ MAX_FILE`, `k == ceil(psize/csz)`, `k ≤ MAX_K`.
* `meth ∈ {0,1}`; if `0` then `size == psize`; if `1` then `size ≤ psize × MAX_RATIO`.
* path ≤ 4096 B, ≤ 255 B per component, depth ≤ 64, no control characters (F-14); link ≤ 4096 B; `mtime` in a sane range; `mtime_nsec < 10⁹`.
* Replace the `unwrap()` with `match` (fail closed). Make `RaptorQDecoder::new` return `Result` and refuse `num_blocks`/total bytes over a budget.

*Compatibility:* none for compliant senders (the sender already derives `csz`, `psize`, `k` consistently). Any sender configured with `-c` above `MAX_CSZ` will be refused; the frame limit already makes that unusable.

### 6.2 Bounded decompression (F-04)

Do not rely on `lzma-rs` limits: its `memlimit` caps only the dictionary. Use `lzma_decompress_with_options` with `UnpackedSize::ReadHeaderButUseProvided(Some(size))` **and** a capped `Write` adaptor that returns an error once more than `size` bytes (or a global budget) would be written. Allocate `Vec::with_capacity(min(size, cap))`, never raw `size`. Check `size ≤ MAX_FILE` before decoding.

*Compatibility:* the sender writes the standard `.lzma` header; `ReadHeaderButUseProvided` still consumes it. Streams with the unknown-size marker + end marker (what the sender's encoder emits) work with `Some(size)`. Decide whether to also verify the header's own size equals `size`.

### 6.3 Bounded receive buffer and state (F-05, F-06, F-07)

* In `do_recv`, if there is no `0x00` and `in_buf.len() - p > MAX_FRAME` (66 560 + slack), discard up to that many bytes and resync; drain `in_buf` on every iteration; keep a read cursor to avoid the quadratic rescan.
* Cap `table` entries (e.g. 1024) with oldest-first eviction, expire entries idle for N seconds, and **remove `done` entries** (keep a small ring of recent finished ids to suppress duplicates). Cap `early_syms` per id (≤ `2×MAX_K` symbols) and in total (≤ 16 MiB). Drop `FileState.path/link` once done.
* Make the decoder not latch on a bad decode: keep collecting symbols, and when `finalize_file` finds a CRC mismatch, call `decoder.reset_to_collect()` (or mark the file failed and stop calling `finalize_file` per frame). At minimum, stop treating `is_decoded` as "ready for finalize" more than once per decode attempt. Without authentication (F-11) poisoning cannot be fully prevented; with per-symbol MAC it can.
* In daemon mode, apply directory metadata when the directory's subtree is quiet or on a timer, not only in `finish()`.

*Compatibility:* eviction means very late symbols for an evicted id are dropped; size the timeout to the longest expected transfer. Limits must be configurable.

### 6.4 Sender data safety (F-09, F-10, F-18)

* Propagate errors: `tx_worker` returns `io::Result`, `encode_stage` and `crawl_and_compress` return a status; `send_batch` fails if *any* item was skipped, any write failed, or any symbol was dropped. Only then delete.
* Read each file **once**: read into memory (or `mmap` with a stat-before/after check), compute CRC from that buffer, abort if `mtime`/size changed between stat and read. After sending, delete only the exact files that were sent (not `remove_dir_all` of the directory), after re-checking `(dev, ino, size, mtime)` is unchanged; otherwise leave them for the next pass.
* Skip (and log once) unsupported types **before** opening them; open with `O_NONBLOCK|O_NOFOLLOW` or check `symlink_metadata().file_type()` first so a FIFO cannot block (F-10). Honour `STOP_FLAG` in all waits.
* Because the channel is one-way, add an optional "quarantine instead of delete" mode (move to `sent/` and let an admin prune) as the safe default; deletion can be opt-in.
* `-r` minimum 1; reject NaN/negative/huge `redundancy` in config.

*Compatibility:* deletion becomes more conservative (a failing device now blocks progress instead of silently emptying the folder); this is the intended behaviour.

### 6.5 Authenticity (F-11)

Add an optional pre-shared-key MAC (e.g. HMAC-SHA-256 or BLAKE2-MAC, truncated to ≥ 128 bits) over the **decoded** header (id, type, sizes, csz, meth, path, link, mode, mtime, plus a per-session random salt and a monotonic counter) and a cryptographic content hash (SHA-256) in place of/in addition to CRC-32. Authenticate data symbols with a short truncated MAC keyed per id, or bind them through the file hash and drop non-conforming ESIs early. Receiver option `--require-auth` drops everything unauthenticated. Replay protection: persist the highest accepted counter (state file under `StateDirectory=`).

*Compatibility:* this changes the header layout (use a new version byte/length-extended trailer so old receivers ignore it); it does **not** touch SC-LDPC, RaptorQ, framing or modulation, and needs no handshake or network. Adds either a crypto crate or about 150 lines of in-tree SHA-256/HMAC. Keys must be provisioned out-of-band.

### 6.6 Filesystem policy (F-08, F-12, F-13, F-14, F-15)

* Only `lchown` when `restore_owner` is set **and** the euid is 0; otherwise never. Validate `uid/gid` against an allow-range or a configured mapping; default to "leave as the receiving user".
* Ignore wire `mode` bits beyond `0o755`/`0o644` (apply `umask`-like policy: `mode & 0o755 & !receiver_umask`), never grant write to group/other, force directories to at least `0o700` during receive, apply final modes at the end.
* Symlinks: option `--no-symlinks` (default off for a locked-down profile) or restrict targets to relative paths that resolve inside the output directory.
* Overwrite policy: `--no-clobber` / write into a per-session subdirectory (`incoming/<session-id>/...`) so a hostile sender cannot replace earlier deliveries.
* Temp files: `format!(".{}.{}.sxfer-part", file_name, rand_u64)` in the same directory, `O_EXCL`, `fsync` file then directory, `rename`, and sweep stale `*.sxfer-part` at start-up. Do not `remove_file` an existing temp name.
* Escape control characters (`\x00-\x1f`, `\x7f`, `\x1b`) in every logged wire string (`escape_default`-style helper).
* `d` headers: apply metadata only if the final component is a real directory (`symlink_metadata().is_dir()`); skip and log otherwise.

### 6.7 Service hardening (F-16)

Run as a dedicated user; sample unit changes:

```ini
User=sxfer
Group=dialout
DynamicUser=no
StateDirectory=sxfer
ReadWritePaths=-/var/spool/sxfer/incoming -/var/spool/sxfer/outgoing
DevicePolicy=closed
DeviceAllow=/dev/ttyUSB1 rw
CapabilityBoundingSet=
AmbientCapabilities=
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
SystemCallFilter=@system-service
SystemCallArchitectures=native
MemoryMax=512M
TasksMax=64
LimitNOFILE=256
LimitCORE=0
UMask=0077
ProtectProc=invisible
ProtectKernelLogs=yes
ProtectClock=yes
MemoryDenyWriteExecute=yes
```

Create the spool directories in the installer with mode `0750`; quote/escape or refuse `ReadWritePaths` entries with whitespace; ignore `$HOME` config for the service; drop `-k` from `service.rs` or implement it; write `/etc/sxfer.conf` with `OpenOptions::create_new` + mode `0644`. If owner restore (`-p`) is a requirement, keep `CAP_CHOWN` only in that profile.

*Compatibility:* a dedicated user needs `dialout` (or udev rule) for the port and ownership of the spool dirs; existing installs need `systemctl daemon-reload` and a `chown` migration.

### 6.8 Config and Windows (F-17, F-19)

Use `strip_prefix`/`strip_suffix` with a length check for quotes; clamp numeric options; reject unknown keys with a log line. On Windows: a reserved-name denylist (`CON PRN AUX NUL COM1-9 LPT1-9`, with or without extension, trailing space/dot), refuse reparse points of any kind, clamp `mtime` to `[1980-01-01, now+1 day]` and use `checked_add`, spawn `explorer`/`notepad` through `%SystemRoot%` absolute paths, pass `--config` to the tray menu handlers.

### 6.9 Supply chain and unsafe (F-20)

CI: `cargo audit`, `cargo deny`, `cargo clippy -- -D warnings`, `cargo fuzz` targets for `mod_frame_decode`, `on_header`/`process_frame`, `decompress_lzma2`, `parse_str`. Replace hand-rolled FFI structs with the `libc` crate (or `nix`) so layouts follow the target, use `OsStrExt::as_bytes` rather than `to_string_lossy` for paths, pin `lzma-rs` and review on update.

---

## 7. Resource limits that need explicit definition

Suggested defaults (all configurable; the receiver should refuse and log, never abort):

| Limit | Suggested default | Enforced where |
|---|---|---|
| Max frame length on the wire | 66 560 B (existing `mod_codec.rs:100`) | `do_recv` (new), `mod_frame_decode` |
| Max `in_buf` (unterminated data) | ≈ 2 × max frame | `do_recv` |
| `csz` range | 16 … 32 768 B | `on_header` |
| `k` per file | ≤ `MAX_FILE / csz` | `on_header` |
| `psize` (payload bytes) | ≤ 1 GiB (configurable) | `on_header` |
| `size` (uncompressed) | ≤ 4 GiB and ≤ `psize × 8192` | `on_header`, decompressor |
| Decompression output | exactly `size`; abort at `size + 0` | `decompress_lzma2` wrapper |
| Concurrent in-flight entries | 1 024 | `table` |
| Early symbols | ≤ 2×MAX_K per id, ≤ 16 MiB total | `on_data` |
| Entry idle timeout | 10 min (≥ longest expected transfer) | `table` GC |
| Path length / component / depth | 4096 / 255 / 64 | `on_header`, `prep_dest` |
| Symlink target length | 4096 B | `on_header` |
| Files per session / total bytes per session | e.g. 100 000 / 16 GiB | `ReceiverContext` |
| Free disk reserve | ≥ 5% or 512 MiB; check before write | `finalize_file` |
| Process memory | `MemoryMax=` 512 MiB (unit), `RLIMIT_AS` self-imposed | systemd / `main` |
| Sender: file size held in memory | ≤ configured max, stream instead of `fs::read` + `clone()` (up to 3× file size resident, `main.rs:380,388,392`) | `crawl_and_compress` |
| Sender: watch queue / entries per pass | bounded count | `do_send` |
| Open fds / tasks | `LimitNOFILE=256`, `TasksMax=64` | unit |

---

## 8. Cross-platform considerations

| Topic | Linux | Windows |
|---|---|---|
| Symlink creation from wire | Any target accepted (F-12) | Validator present; requires privilege/developer mode to create |
| Containment (`prep_dest`) | Symlink-safe component walk; TOCTOU only via local writers | Backslash/colon refused; no reserved-name or trailing-dot/space rules; junction handling unverified (F-19) |
| Ownership | `lchown` as root (F-08) | Not applicable (`uid/gid` ignored) |
| Permissions | `0o1777` mask; chmod via path | Only read-only bit |
| Timestamps | `utimensat` (i64 `Timespec`, wrong on 32-bit) | `set_modified` with unchecked `SystemTime + Duration` (panic) |
| Service model | root systemd daemon (F-16) | Tray app as the user (good); `run_daemon` restarts every 1 s on error |
| Serial open | `O_NOCTTY`, `flock` on TTY, hand-rolled termios | `serialport` crate with exclusive open |
| File-lock probing | `flock` (advisory; a FIFO blocks, F-10) | `LockFileEx` |
| Case sensitivity / name aliasing | Case-sensitive | Case-insensitive; 8.3 short names and alternate data streams (colon blocked) |

---

## 9. Remediation checklist (testable acceptance criteria)

| ID | Task | Acceptance criterion |
|---|---|---|
| R-01 | Header validator (6.1) | `f01`, `f02*`, `f03` pass; receiving the A/C/D/B streams from this audit exits 0 (no SIGABRT) and logs `REJECT header`; a fuzz target of `process_frame` runs ≥ 10 min with no panic/abort/alloc > 64 MiB. |
| R-02 | Bounded decompression (6.2) | `f04` passes; decompressing the 1272-byte, 8 MiB-of-zeros stream with `size=1024` returns `Err` and peak RSS < 8 MiB. |
| R-03 | Bounded input buffer (6.3) | `f05` passes: 16 MiB of delimiter-less data leaves `VmHWM` growth < 4 MiB; 64 MiB input takes < 2 s. |
| R-04 | Bounded/evicting state (6.3) | `f06` passes; sending 10⁶ distinct small files through one daemon keeps RSS growth < 50 MiB. |
| R-05 | Non-latching decoder (6.3) | `f07` passes; the finalize path executes at most once per attempt (no per-frame decode loop). |
| R-06 | Sender fail-safe deletion (6.4) | `f09` passes: with `/dev/full`, a read-failing file, a dropped queue item, and a file modified mid-send, no source is removed; log says `NOT DELETED`. |
| R-07 | FIFO/special-file safety (6.4) | `f10` passes (exits within 5 s); SIGTERM stops the sender within 2 s in every state. |
| R-08 | `-r`/config validation (6.4, 6.8) | `f17`, `f18` pass; `redundancy = nan/-1/1e300` is rejected with a message. |
| R-09 | Ownership/mode policy (6.6) | `f08` passes as root; received files are owned by the receiver's euid unless `-p`; modes never exceed `0o755` and never group/other-writable. |
| R-10 | Temp-file + dir-metadata fixes (6.6) | `f13`, `f15` pass; stale `*.sxfer-part` are removed at start-up. |
| R-11 | Log escaping (6.6) | `f14` passes. |
| R-12 | systemd hardening (6.7) | `systemd-analyze security sxfer.service` exposure ≤ 3.0; installer creates directories; unit starts on a clean VM; `f16` passes. |
| R-13 | Authentication (6.5) | With `--require-auth`, a frame with a wrong or missing MAC is dropped (counter incremented, no state created); replaying a captured session after restart is rejected; unauthenticated mode remains available and labelled. |
| R-14 | Windows hardening (6.8) | Cross-built tests on `windows-latest`: reserved names rejected, `mtime = 10¹²` accepted without panic (clamped), junction in the path rejected. |
| R-15 | CI security gates (6.9) | `cargo audit` and `cargo deny` clean or documented exceptions; fuzz targets run nightly; `cargo test` includes `audit_regressions`. |

Each item stays "open" until its patch lands **and** the named test passes in CI.

---

## 10. Limits of this audit

* Windows paths (F-19) and the root-only `lchown` behaviour (F-08) were assessed by inspection only.
* `cargo audit`/`cargo deny` were not available; no dependency-advisory verdict is given.
* No physical serial hardware was used; the receiver was driven through its regular-file/FIFO input mode, which exercises the same parsing code (`do_recv` is device-agnostic).
* Memory-exhaustion results were taken under `ulimit -v`/`RLIMIT_AS` on a host with limited free RAM, to avoid destabilising it; they demonstrate unbounded growth and abort, not a specific OOM threshold.
* No code in `src/` was modified.
