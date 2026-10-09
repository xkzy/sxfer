# sxfer Cryptographic Security Architecture & Authenticated Transfer Layer

## 1. Threat Model & Security Objectives

`sxfer` operates across high-speed unidirectional serial lines, optical data diodes, and simplex UART channels. In unidirectional environments, the receiver has **no back-channel** to challenge the sender, negotiate symmetric session keys, request retransmissions, or perform bidirectional TLS/SSH handshakes.

### Threat Vectors Addressed

1. **Wire-Level Tampering & Active Adversary Injection**: An attacker who gains physical, electrical, or optical access to the serial line can inject, modify, truncate, duplicate, or reorder frames.
2. **Untrusted Metadata & Path Traversal**: An adversary transmitting malicious payloads could attempt to write outside target destination directories using directory traversal (`../`), absolute paths, Windows namespace escapes (`C:\`, `\\?\`), control characters, or embedded symlink loops.
3. **Privilege Escalation via Metadata Restoration**: Attackers attempting to drop setuid/setgid binaries or hijack system file ownership via unvalidated header metadata.
4. **Replay Attacks**: Re-transmitting previously recorded genuine transfers to overwrite newly modified files with stale data.
5. **Denial of Service (DoS) & Resource Exhaustion**: Malicious frames with oversized symbol counts, infinite LZMA2 compression ratios (zip-bombs), or unconstrained allocation requests designed to panic or crash the receiver daemon.

### Security Guarantees in Authenticated Mode

* **Integrity & Authenticity**: Every transfer batch is cryptographically bound to an Ed25519 digital signature verified against a locally trusted public key.
* **Content Verification**: Individual file payloads are verified against individual 256-bit SHA-256 hashes declared in the signed manifest.
* **Atomic Batch Commitment**: Received files are staged in isolated quarantine (`.sxfer_staging_<transfer_id>/`) and only published to final target destinations when the entire manifest is received and 100% verified.
* **Replay Protection**: The receiver tracks unique transfer IDs within a configurable freshness window (default: 300 seconds), persisting seen transfer identifiers across daemon restarts.
* **Non-Repudiation**: The private key holder alone can produce transfers that the receiver will accept.

---

## 2. Cryptographic Architecture

`sxfer` uses standardized, modern, and rigorously audited cryptographic primitives:

| Component | Primitive | Library / Implementation | Purpose |
| :--- | :--- | :--- | :--- |
| **Digital Signatures** | **Ed25519** (RFC 8032 / Ed25519ph) | `ring` (BoringSSL/Rust cryptographic core) | Manifest authentication & non-repudiation |
| **Content Hashing** | **SHA-256** (FIPS 180-4) | `sha2` (RustCrypto verified implementation) | Per-file cryptographic integrity verification |
| **Forward Error Correction**| **RaptorQ (RFC 6330)** & **SC-LDPC** | Pure Rust SIMD / GF(256) | Loss recovery and bit-flip correction on physical line |
| **Physical Error Checking** | **CRC-32 / ISO-HDLC** | Hardware CRC32 instruction / Slice-by-8 | Wire frame delimiter and corruption rejection |

> **Design Principle**: CRC-32 and SC-LDPC are exclusively used for noise tolerance and packet framing. All security guarantees are strictly provided by Ed25519 and SHA-256.

---

## 3. Canonical Manifest Specification

When transfer signing is enabled on the sender (`--sign-key <path>`), the sender generates a deterministic canonical JSON transfer manifest prior to transmitting data frames.

### Wire Representation

The manifest is transmitted over the wire as a specialized frame type (`'m'`) using standard RaptorQ fountain coding with high redundancy (ensuring delivery even under 80%+ packet loss).

### Manifest JSON Structure

```json
{
  "version": 1,
  "transfer_id": "67060410000000000000000000000001",
  "timestamp_sec": 1728475200,
  "total_entries": 2,
  "total_bytes": 1048576,
  "entries": [
    {
      "path": "data/sample.bin",
      "type": "f",
      "size": 1048576,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "link": "",
      "mode": 420,
      "mtime_sec": 1728475100,
      "mtime_nsec": 0
    },
    {
      "path": "data/symlink",
      "type": "l",
      "size": 0,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "link": "sample.bin",
      "mode": 511,
      "mtime_sec": 1728475100,
      "mtime_nsec": 0
    }
  ]
}
```

### Signed Envelope Format

The manifest is wrapped in a signed envelope:

```json
{
  "manifest": { ...canonical manifest json... },
  "signature": "32_byte_signature_in_hex_64_chars...",
  "public_key": "32_byte_public_key_in_hex_64_chars..."
}
```

---

## 4. Quarantine Staging & Atomic Batch Commit

To prevent malicious or partially received files from polluting destination directories:

```
[ Incoming Frames ('m', 'f', 'd', 'l') ]
                  │
                  ▼
         [ Decode & FEC Layer ]
                  │
                  ▼
  ┌─────────────────────────────────┐
  │   Quarantine Staging Area       │
  │   (.sxfer_staging_<transfer_id>)│
  └───────────────┬─────────────────┘
                  │
                  ▼
  ┌─────────────────────────────────┐
  │ Manifest & SHA-256 Verification │
  │ - Signature matches trusted key │
  │ - Timestamp within fresh window │
  │ - Transfer ID unique (no replay)│
  │ - File SHA-256 matches manifest │
  └───────────────┬─────────────────┘
                  │
          (All Entries OK?)
          ├── YES ──► Atomic Move / Rename to Dest Dir
          └── NO  ──► Purge Quarantine; Zero Destination Impact
```

---

## 5. Simplex Replay Protection

Because a simplex receiver cannot send a cryptographic challenge (nonce) to the sender, replay protection is achieved via **Signed Timestamp Freshness** and **Transfer Identifier Deduplication**:

1. **Sliding Freshness Window**:
   $$|T_{\text{receiver}} - T_{\text{manifest}}| \le \Delta_{\text{max\_skew}}$$
   Default $\Delta_{\text{max\_skew}} = 300\text{ seconds}$ (5 minutes). Transfers with timestamps older or farther in the future than $\Delta_{\text{max\_skew}}$ are discarded.
2. **Transfer ID Cache**:
   The receiver records every successfully validated `transfer_id` in a persistent cache file (`.sxfer_replay_cache.txt`). Any subsequent transmission with an already-seen `transfer_id` is immediately rejected.

---

## 6. CLI Usage & Key Management

### Key Generation

Generate a new Ed25519 keypair:

```bash
sxfer keygen -o /etc/sxfer/keys/sxfer_prod
```

Outputs:
- `/etc/sxfer/keys/sxfer_prod.priv` (Private key, mode `0600`)
- `/etc/sxfer/keys/sxfer_prod.pub` (Public key, mode `0644`)

### Sender (Signing Transfers)

```bash
# Direct send with signature
sxfer send -d /dev/ttyUSB0 -b 115200 -s /etc/sxfer/keys/sxfer_prod.priv /path/to/files/

# Watch mode with signature
sxfer send -d /dev/ttyUSB0 -b 115200 -s /etc/sxfer/keys/sxfer_prod.priv -w /srv/sxfer/spool
```

### Receiver (Verifying Transfers)

```bash
# Authenticated mode (verifies signatures, allows only valid transfers)
sxfer recv -d /dev/ttyUSB0 -b 115200 -o /srv/sxfer/incoming --verify-key /etc/sxfer/keys/sxfer_prod.pub

# Strict authentication mode (rejects all unauthenticated transfers)
sxfer recv -d /dev/ttyUSB0 -b 115200 -o /srv/sxfer/incoming --verify-key /etc/sxfer/keys/sxfer_prod.pub --require-auth
```

---

## 7. Service & System Hardening

### Systemd Sandboxing (`/etc/systemd/system/sxfer.service`)

The systemd unit file generated via `sxfer systemd install` enforces comprehensive OS-level containment:

* `ProtectSystem=strict` & `ProtectHome=yes`: Read-only OS filesystem.
* `PrivateTmp=yes`: Isolated `/tmp` namespace.
* `DevicePolicy=closed` & `DeviceAllow=/dev/ttyUSB* rw`: Confined exclusively to serial devices.
* `MemoryMax=512M` & `TasksMax=64`: Hard resource boundaries preventing DoS.
* `LimitCORE=0`: Disables core dumps containing private key or buffer memory.
* `NoNewPrivileges=yes` & `RestrictSUIDSGID=yes`: Prevents privilege escalation.
* `CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE`: Restricts root capabilities only to ownership restoration when `-p` is requested.

---

## 8. Backward Compatibility & Migration

* **Legacy Mode**: Unauthenticated transfers continue to function for backward compatibility when `--verify-key` and `--require-auth` are not specified.
* **Audit Logging**: Legacy transfers are explicitly logged as `[UNAUTHENTICATED (legacy mode)]` to ensure security administrators can monitor non-cryptographic transfers.
* **Enforced Migration**: Production data-diode environments should configure `require_auth = true` in `/etc/sxfer.conf` to guarantee zero unauthenticated writes.

---

## 9. Impossibility of Remote Control Through UART

### Application-Level Guarantees

`sxfer` is architected strictly as a unidirectional file-transfer transport and contains no command execution mechanisms:
1. **Zero Command Dispatchers**: `sxfer` does not implement a remote shell, RPC protocol, command dispatcher, or debug console over the wire.
2. **Inert Passive Storage**: Received files (including shell scripts, binaries, and executables) are written purely as inert byte streams. `sxfer` never spawns, executes, sources, or evaluates received payloads.
3. **No Dynamic Plugins or Configuration Mutation**: Incoming frames cannot alter receiver settings, destination folders, or daemon parameters.
4. **Stripped Permissions**: All received file modes are masked with `0o0777`, stripping SUID (`0o4000`), SGID (`0o2000`), and sticky (`0o1000`) bits.
5. **Strict Path Containment**: All relative paths are checked against directory traversal (`..`), absolute prefixes (`/`, `\`), Windows drive colons (`:`), and DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`).
6. **Simplex Independence**: No return channel or acknowledgement frames exist. Transmission and reception channels operate completely independently.

### OS-Level & Hardware Serial Port Requirements

Application-level software safeguards alone cannot protect against operating-system serial consoles. Deployments must enforce the following OS and hardware measures:

1. **Disable OS Serial Login Consoles (`getty` / `serial-getty`)**:
   On Linux systems, ensure no login prompt is attached to the transfer port:
   ```bash
   sudo systemctl stop serial-getty@ttyS0.service
   sudo systemctl mask serial-getty@ttyS0.service
   ```
2. **Disable Bootloader / Kernel Console on Dedicated Ports**:
   Ensure `console=ttyS0,...` is removed from `/boot/cmdline.txt` or kernel arguments so kernel crash dumps and SysRq keys cannot be triggered over the data-diode port.
3. **Physical Diode & UART Wiring**:
   - For true unidirectional hardware isolation, physically sever or omit the receiver's TX wire ($TX \to RX$ only).
   - Do not connect hardware flow control lines ($RTS/CTS$, $DTR/DSR$) across the security boundary.

