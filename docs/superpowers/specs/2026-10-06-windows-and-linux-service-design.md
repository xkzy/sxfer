# Design Specification: Windows Support (CMD + System Tray) & Linux Service Daemon with `/etc/sxfer.conf`

**Date**: 2026-10-06  
**Status**: Proposed  
**Components**: Cross-Platform Serial (`src/serial.rs`), Configuration Engine (`src/config.rs`), Windows System Tray & GUI Dialogs (`src/tray_windows.rs`), Linux Systemd / Service Daemon (`src/service.rs`), Unified CLI Subcommands (`src/main.rs`).

---

## 1. Overview & Objectives

This specification defines the architecture for:
1. **Windows CMD Support**: Full native Windows CLI operation (`sxfer.exe send COM3 <files>` / `sxfer.exe recv COM4 <dest>`), using native Win32 Serial APIs (`\\.\COMx`, `DCB`, `SetCommTimeouts`, `PurgeComm`, and atomic non-blocking `LockFileEx` port locking).
2. **Windows System Tray Service**: Native Win32 background service running in the notification area with a status menu, Start/Stop RX daemon, Balloon/Toast notifications, "Send File/Folder" file picker, and Configuration Dialog.
3. **Linux Service Daemon & `/etc/sxfer.conf`**: Daemon service mode reading `/etc/sxfer.conf` (or `~/.config/sxfer/sxfer.conf`), compatible with systemd unit management (`systemctl enable --now sxfer-rx`).
4. **Unified Configuration Engine**: Standard INI/TOML configuration file shared across Linux and Windows for sender, receiver, watch mode, baud rate, redundancy, and paths.

---

## 2. Architecture & Platform Abstraction

```
                                  +-----------------------+
                                  |    Unified sxfer      |
                                  |   (Linux & Windows)   |
                                  +-----------+-----------+
                                              |
               +------------------------------+-------------------------------+
               |                              |                               |
     [CLI Command Mode]             [Linux Service Mode]           [Windows System Tray]
  sxfer send / sxfer recv           sxfer daemon --config         sxfer tray / sxfer.exe
  (Standard I/O Streams)            /etc/sxfer.conf (systemd)     (Win32 Shell Notify Icon)
               |                              |                               |
               +------------------------------+-------------------------------+
                                              |
                                   +----------v----------+
                                   |  src/config.rs      |
                                   |  Config & Profiles  |
                                   +----------+----------+
                                              |
               +------------------------------+-------------------------------+
               |                                                              |
    [Unix Serial Layer]                                            [Win32 Serial Layer]
  - termios / cfmakeraw                                          - CreateFileW (\\.\COMx)
  - flock(LOCK_EX | LOCK_NB)                                     - DCB / SetCommState
  - /dev/ttyUSB*, FIFOs                                          - LockFileEx (Exclusive)
               |                                                              |
               +------------------------------+-------------------------------+
                                              |
                               +--------------v--------------+
                               | 3-Stage Pipeline:           |
                               | Fast-LZMA2 + SC-LDPC + RQ   |
                               +-----------------------------+
```

---

## 3. Configuration Engine (`src/config.rs`)

### 3.1 Config File Locations
* **Linux**: `/etc/sxfer.conf` (system-wide), fallback to `~/.config/sxfer/sxfer.conf` or `./sxfer.conf`.
* **Windows**: `%APPDATA%\sxfer\sxfer.conf` (or `%PROGRAMDATA%\sxfer\sxfer.conf`, `./sxfer.conf`).

### 3.2 Configuration File Format
```ini
# /etc/sxfer.conf or %APPDATA%\sxfer\sxfer.conf

[general]
role = "receiver"          # "receiver" | "sender" | "watch"
baud = 115200              # 1200 .. 3000000
port = "/dev/ttyUSB1"      # Linux: /dev/ttyUSBx, Windows: COM3 or \\.\COM10
redundancy = 1.0           # 0.0 .. 5.0
fast_lzma2 = true          # Enable Fast-LZMA2 Level 9 compression

[receiver]
dest_dir = "/var/spool/sxfer/incoming"
keep_damaged = false
notify = true              # Desktop/Tray notifications

[sender]
watch_dir = "/var/spool/sxfer/outgoing"
poll_interval_ms = 100
delete_after_send = true
```

### 3.3 Zero-Dependency Parser
A clean, robust INI/Key-Value parser without external heavy TOML crates, ensuring fast builds and musl / Windows GNU cross-compilation compatibility.

---

## 4. Windows Support Architecture

### 4.1 Serial Port Driver (`src/serial.rs` on Windows)
* **Port Path Normalization**:
  * Formats `COM1` through `COM9` directly, and `\\.\COM10`+ automatically.
* **Win32 Handles**:
  * Opened with `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, `FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING`.
* **Port Locking**:
  * Mutual exclusion using Win32 `LockFileEx` with `LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY` on byte 0 of the handle.
  * If another instance holds the lock, returns `"Port 'COMx' is already in use by another active sxfer TX/RX instance (port locked)"`.
* **Comm Configuration**:
  * `DCB` structure configured for:
    * `BaudRate`: 1,200 to 3,000,000 baud
    * `ByteSize`: 8, `Parity`: `NOPARITY`, `StopBits`: `ONESTOPBIT`
    * `fBinary`: TRUE, `fDtrControl`: `DTR_CONTROL_ENABLE`, `fRtsControl`: `RTS_CONTROL_ENABLE`
  * `COMMTIMEOUTS`:
    * `ReadIntervalTimeout`: 20ms, `ReadTotalTimeoutConstant`: 200ms, `ReadTotalTimeoutMultiplier`: 0
* **File Operations**:
  * Platform-agnostic file metadata: uses `std::fs::Metadata` methods instead of Unix-specific `MetadataExt` / `PermissionsExt`.
  * Symlinks: `std::os::windows::fs::symlink_file` and `symlink_dir` with graceful fallback on unprivileged accounts.

### 4.2 Windows System Tray Service (`src/tray_windows.rs`)
* **Subsystem**: Compiled with Win32 GUI integration; when launched as `sxfer.exe tray` or without arguments in Explorer, does not flash a terminal window.
* **Tray Icon**:
  * Embedded icon loaded into system tray via `Shell_NotifyIconW` (`NIM_ADD`, `NIM_MODIFY`, `NIM_DELETE`).
  * Tooltip displaying status: `sxfer: Receiving on COM3 @ 115200 baud`.
* **Context Menu**:
  * `Status: [Listening / Receiving: file.txt / Paused]` (Disabled item)
  * `Pause / Resume Receiver`
  * `Send File...` -> Native `GetOpenFileNameW` dialog.
  * `Send Directory...` -> Native folder browser dialog.
  * `Open Incoming Folder` -> `explorer.exe <dest_dir>`.
  * `Settings...` -> GUI dialog for Port, Baud Rate, Redundancy, Destination.
  * `Exit` -> Shuts down threads, releases port locks, removes tray icon.
* **Toast / Balloon Notifications**:
  * Emitted on transfer start: `Receiving 'firmware.bin' (1.4 MB)`.
  * Emitted on completion: `Received 'firmware.bin' successfully (100% verified)`.
  * Emitted on error/warning: `Transfer failed: SC-LDPC unrecoverable frame`.

---

## 5. Linux Service Mode & Systemd Integration

### 5.1 Daemon Mode (`sxfer daemon`)
* Runs in foreground or background based on `/etc/sxfer.conf`.
* Traps `SIGTERM`, `SIGINT`, and `SIGHUP` (reloads configuration).
* Emits structured systemd journal logging (`sd_notify` / stdout).

### 5.2 Systemd Unit File (`sxfer.service`)
```ini
[Unit]
Description=sxfer High-Speed Unidirectional Serial Transfer Service
After=network.target local-fs.target
Documentation=man:sxfer(1) https://github.com/khing/sxfer

[Service]
Type=simple
ExecStart=/usr/local/bin/sxfer daemon --config /etc/sxfer.conf
Restart=always
RestartSec=3
User=root
Group=dialout
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 5.3 Quick Setup Helper
* `sxfer systemd install`: Auto-creates `/etc/sxfer.conf`, copies `/usr/local/bin/sxfer`, installs `/etc/systemd/system/sxfer.service`, runs `systemctl daemon-reload && systemctl enable --now sxfer`.

---

## 6. Verification & Test Plan

1. **Linux Build & Tests**:
   - `cargo test`: Unit tests pass (SC-LDPC, CRC32, Fast-LZMA2, RaptorQ, Config parser).
   - E2E Test Suite (`test/test_e2e_full.sh`, `test_noise_recovery.sh`, `test_regression.sh`, `test_watch_mode.sh`): 100% PASS.
   - Config Daemon test: `sxfer daemon --config /tmp/test_sxfer.conf` over virtual FIFOs.
2. **Windows Cross-Compilation**:
   - Compile target `x86_64-pc-windows-gnu` / `x86_64-pc-windows-msvc`.
   - Verify zero compiler warnings/errors on Windows targets.
3. **Hardware & Serial Verification**:
   - Validate COM port naming (`COM1` .. `COM32`, `\\.\COMx`).
   - Validate port exclusivity locks (`LockFileEx`).
