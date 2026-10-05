# sxfer

> **High-Speed, One-Way Serial File Tree Transfer Engine with Concatenated Multi-Level Forward Error Correction (SC-LDPC + Systematic RaptorQ)**

`sxfer` is a high-performance, single-binary unidirectional file transfer utility engineered for **simplex (one-way / TX-only)** communication channels, such as hardware data diodes, optical isolators, high-speed serial links (UART, RS-232, RS-422, RS-485 up to 4+ Mbaud), laser links, and pipe/socket streams.

Because simplex links have **zero reverse channel** (no ACKs, no NACKs, no backpressure flow control), `sxfer` guarantees 100% bit-exact transmission across heavy line noise, bit flips, and massive packet loss using a **3-tier Concatenated Forward Error Correction (FEC)** architecture.

---

## Features

- **100% Pure Rust**: Standalone, single-file binary with zero external runtime C dependencies.
- **3-Tier Concatenated Multi-Level Parity**:
  - **Level 1 (Inner Bit-Level FEC)**: Rate $2/3$ Quasi-Cyclic Spatially-Coupled LDPC (**SC-LDPC**) with multi-pass Belief Propagation / energy-minimizing bit-flipping gradient descent. Corrects $5\% - 10\%$ random bit flips directly on raw frames.
  - **Level 2 (Outer Packet-Level FEC)**: RFC 6330 Systematic Rateless **RaptorQ Fountain Codes** over $\text{GF}(256)$ with Two-Phase Fast Inactivation Gaussian Elimination. Reconstructs missing packets across severe erasures (verified up to **$81.4\%+$ packet loss**).
  - **Level 3 (End-to-End Integrity)**: Dual-layer IEEE 802.3 CRC-32 (Inner payload check + Outer file table CRC-32) providing $P_e \le 2^{-32}$.
- **High-Ratio LZMA2 Level 9 Compression**: Automatic dictionary compression enforced for all payload streams.
- **Unified Baseband Modulation & Framing**: Integrated Galois 16-bit PRBS scrambler/whitener (`0x5A3C`) and Consistent Overhead Byte Stuffing (COBS) with `0x00` frame delimiters.
- **Asynchronous 3-Stage Pipeline**: Reader/Compressor $\to$ RaptorQ Encoder/Framer $\to$ 64 KiB Batched Zero-Copy Serial TX.
- **Watch Directory Spool Mode (`-w DIR`)**: Automatically creates the directory, watches for incoming files or trees, streams them across the link, and deletes them upon successful transfer.
- **Filesystem Fidelity**: Preserves full directory trees, permissions (`chmod`), nanosecond timestamps (`utimensat`), relative symlinks, and ownership.

---

## Architecture

```
                              ┌───────────────────────────────────────────────────────────┐
                              │                 SOURCE FILE / DIRECTORY TREE              │
                              └─────────────────────────────┬─────────────────────────────┘
                                                            │
  Level 3: File Integrity                                   ▼
  ───────────────────────                   [ IEEE 802.3 End-to-End CRC-32 ]
                                                            │
  Compression Layer                                         ▼
  ─────────────────                          [ Pure Rust LZMA2 Level 9 ]
                                                            │
  Level 2: Packet-Level FEC                                 ▼
  ─────────────────────────             [ RFC 6330 Systematic RaptorQ Fountain ]
                                        (Fountain matrix over GF(256) with Gaussian Elimination)
                                           • Recovers 0% → 80%+ lost / dropped packets
                                                            │
  Level 1: Bit-Level FEC                                    ▼
  ──────────────────────                  [ Spatially-Coupled LDPC (SC-LDPC) ]
                                          (Quasi-Cyclic parity checks over GF(2) with BP)
                                             • Fixes bit flips & physical line noise
                                                            │
  Framing & Line Modulation                                 ▼
  ─────────────────────────             [ Dual CRC32 + Galois LFSR Scrambler + COBS ]
                                                            │
                                                            ▼
                                                PHYSICAL SERIAL TX / DIODE
```

---

## Installation & Building

Requires standard Rust (1.75+):

```bash
# Clone the repository
git clone https://github.com/xkzy/sxfer.git
cd sxfer

# Build single release binary
cargo build --release
# or
make
```

The compiled binary will be placed at `./sxfer`.

---

## Quick Start

### 1. Simple Single-Shot Transfer
```bash
# On the receiving machine:
sxfer recv -d /dev/ttyUSB0 -o ./received_files

# On the transmitting machine:
sxfer send -d /dev/ttyUSB0 -f 35 /path/to/my_folder
```

### 2. Continuous Watch Directory Spool Mode
```bash
# Sender watches /var/spool/sxfer, transmits present files, and purges them:
sxfer send -d /dev/ttyUSB0 -w /var/spool/sxfer -f 35
```

### 3. File Checksum Verification
```bash
sxfer crc /path/to/file
```

---

## CLI Reference

### `sxfer send`
```text
Usage: sxfer send [options] [PATH...]

Options:
  -d DEV    Serial device, FIFO pipe, or regular file (default: /dev/ttyUSB0)
  -b BAUD   Baud rate from 1200 up to 4000000+ (default: 115200)
  -w DIR    Watch directory mode: auto-creates DIR, streams present files, and deletes them
  -c BYTES  Symbol chunk size in bytes (default: auto-selected by baud rate)
  -f PCT    RaptorQ fountain repair percentage overhead (default: 35)
  -r ROUNDS Number of fountain repeat rounds with unique ESIs (default: 1)
```

### `sxfer recv`
```text
Usage: sxfer recv [options]

Options:
  -d DEV    Serial device, FIFO pipe, or regular file (default: /dev/ttyUSB0)
  -b BAUD   Baud rate (default: 115200)
  -o DIR    Output directory for reconstructed files (default: ./recv)
  -q SEC    Quit SEC seconds after line quiet/idle (default: 0 = keep listening)
  -p        Restore original file owner UID and group GID (requires root)
```

### `sxfer daemon`
```text
Usage: sxfer daemon [--config /path/to/sxfer.conf]

Runs sxfer as a background service daemon according to /etc/sxfer.conf (Linux)
or %APPDATA%\sxfer\sxfer.conf (Windows).
```

### `sxfer systemd install`
```text
Usage: sxfer systemd install

Automatically generates /etc/sxfer.conf, installs /etc/systemd/system/sxfer.service,
and enables the systemd service unit.
```

### `sxfer tray` (Windows)
```text
Usage: sxfer.exe tray [--config /path/to/sxfer.conf]

Launches the native Windows System Tray background service in the notification area
with Balloon/Toast notifications, context menu, and Explorer integration.
(Running sxfer.exe with no arguments on Windows launches Tray mode by default).
```

---

## Configuration File (`/etc/sxfer.conf` or `%APPDATA%\sxfer\sxfer.conf`)

```ini
[general]
role = receiver           # "receiver" or "sender" / "watch"
port = /dev/ttyUSB1       # Linux: /dev/ttyUSBx | Windows: COM3 or \\.\COM10
baud = 115200             # 1200 to 3000000
redundancy = 1.0          # Multiplier for RaptorQ fountain overhead
fast_lzma2 = true         # Enable Fast-LZMA2 Level 9 dictionary compression

[receiver]
dest_dir = /var/spool/sxfer/incoming
keep_damaged = false
notify = true             # Enable desktop/balloon toast notifications

[sender]
watch_dir = /var/spool/sxfer/outgoing
poll_interval_ms = 100
delete_after_send = true
```

---

## Windows Support (CMD + System Tray)

1. **Command Line (CMD / PowerShell)**:
   ```cmd
   sxfer.exe send -d COM3 -b 115200 C:\path\to\data
   sxfer.exe recv -d COM4 -b 115200 -o C:\path\to\incoming
   ```
2. **System Tray Background Service**:
   - Double-click `sxfer.exe` or execute `sxfer.exe tray`.
   - Adds tray icon with status tooltip, start/stop toggle, file send dialog, and direct access to download folder.

---

## Automated Test Suites

```bash
cargo test            # Pure Rust Unit Tests (SC-LDPC, RaptorQ, Framing, Compression, Config)
make test-e2e         # End-to-End Multi-File Tree Pipeline Transfers
make test-noise       # 5-Channel Noise & Erasure Stress Tests (Corruption, Bursts, 80% Drop Rate)
make test-regression  # Full System Regression Suite
make test-watch       # Watch Directory Spool & Auto-Purge Verification Suite
make test-writer      # Active Writer Settlement Debouncing Suite
make test-daemon      # Linux Service Daemon & Configuration Verification Suite
make test-speeds      # Complete Spectrum Hardware Baud Benchmark (1.2k to 3Mbaud)
```

---

## License

GNU3.0 License. See [LICENSE](LICENSE) for details.
