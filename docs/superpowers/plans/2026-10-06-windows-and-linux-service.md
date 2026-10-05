# Windows Support (CMD + System Tray) & Linux Service Daemon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add complete Windows support (both Command Prompt / PowerShell CLI and Windows System Tray background service) and a Linux Service Daemon with `/etc/sxfer.conf` and systemd integration.

**Architecture:** A unified binary `sxfer` / `sxfer.exe` with modular components:
1. `src/config.rs`: Zero-dependency INI/TOML configuration parser for `/etc/sxfer.conf` and `%APPDATA%\sxfer\sxfer.conf`.
2. `src/serial.rs`: Cross-platform serial abstraction using POSIX `termios`/`flock` on Unix and Win32 `DCB`/`SetCommTimeouts`/`LockFileEx` on Windows.
3. `src/service.rs`: Linux headless daemon with signal handling and systemd unit installer (`sxfer systemd install`).
4. `src/tray_windows.rs`: Native Win32 system tray service with notification balloons, context menus, file picker, and configuration dialog.

**Tech Stack:** Rust 2021 edition, `windows-sys` (Windows target only), standard library `std::os::unix` / `std::os::windows`. Zero runtime C dependencies.

## Global Constraints
- Pure Rust codebase, zero runtime C dependencies.
- Retain exact 3-stage Fast-LZMA2 + SC-LDPC + RaptorQ transmission pipeline.
- Single-instance mutual exclusion locking per port (`flock` on POSIX, `LockFileEx` on Windows).
- All existing Linux E2E test suites must pass 100%.

---

### Task 1: Configuration Engine (`src/config.rs`)

**Files:**
- Create: `src/config.rs`
- Modify: `src/main.rs` (add `mod config;`)
- Test: `src/config.rs` (inline module tests `test_config_parser`)

**Interfaces:**
- Produces:
  ```rust
  pub struct SxferConfig {
      pub role: String, // "receiver", "sender", "watch"
      pub port: String,
      pub baud: u64,
      pub redundancy: f64,
      pub fast_lzma2: bool,
      pub dest_dir: String,
      pub keep_damaged: bool,
      pub watch_dir: String,
      pub poll_interval_ms: u64,
      pub delete_after_send: bool,
  }
  impl SxferConfig {
      pub fn load_default() -> Self;
      pub fn load_from_file(path: &Path) -> io::Result<Self>;
      pub fn default_config_path() -> PathBuf;
      pub fn generate_default_conf() -> String;
  }
  ```

- [ ] **Step 1: Write the failing unit tests for configuration parsing**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse_custom() {
        let conf_str = r#"
[general]
role = receiver
port = /dev/ttyUSB1
baud = 921600
redundancy = 1.5
fast_lzma2 = true

[receiver]
dest_dir = /tmp/incoming
keep_damaged = false

[sender]
watch_dir = /tmp/outgoing
poll_interval_ms = 250
delete_after_send = true
"#;
        let cfg = SxferConfig::parse_str(conf_str).unwrap();
        assert_eq!(cfg.role, "receiver");
        assert_eq!(cfg.port, "/dev/ttyUSB1");
        assert_eq!(cfg.baud, 921600);
        assert!((cfg.redundancy - 1.5).abs() < 1e-6);
        assert_eq!(cfg.dest_dir, "/tmp/incoming");
        assert_eq!(cfg.watch_dir, "/tmp/outgoing");
        assert_eq!(cfg.poll_interval_ms, 250);
        assert!(cfg.delete_after_send);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config::tests`
Expected: FAIL (module or function not found)

- [ ] **Step 3: Implement `src/config.rs`**

Write parser handling sections `[general]`, `[receiver]`, `[sender]`, stripping comments (`#` / `;`), trimming whitespace, and setting cross-platform default paths (`/etc/sxfer.conf` on Unix, `%APPDATA%\sxfer\sxfer.conf` on Windows).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test config::tests`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "feat(config): add unified /etc/sxfer.conf and %APPDATA% config parser"
```

---

### Task 2: Cross-Platform Serial Abstraction (`src/serial.rs`)

**Files:**
- Modify: `Cargo.toml` (add `[target.'cfg(windows)'.dependencies] windows-sys`)
- Modify: `src/serial.rs`
- Test: `cargo test` and `cargo check --target x86_64-unknown-linux-musl`

**Interfaces:**
- Consumes: Windows Win32 API (`CreateFileW`, `SetCommState`, `SetCommTimeouts`, `PurgeComm`, `LockFileEx`), POSIX `termios`/`flock`.
- Produces:
  ```rust
  pub fn auto_chunk_size(baud: u64) -> usize;
  pub fn baud_to_speed(baud: u64) -> Option<u32>;
  pub fn lock_device(file: &File, path: &Path) -> std::io::Result<()>;
  pub fn open_line_send(path: &Path, baud: u64) -> std::io::Result<File>;
  pub fn open_line_recv(path: &Path, baud: u64) -> std::io::Result<File>;
  pub fn flush_tty(file: &File);
  ```

- [ ] **Step 1: Update `Cargo.toml` with Windows dependencies**

Add `windows-sys` under `[target.'cfg(windows)'.dependencies]`:
```toml
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_Devices_Communication",
    "Win32_Foundation",
    "Win32_Storage_FileSystem",
    "Win32_System_IO",
    "Win32_UI_WindowsAndMessaging",
    "Win32_UI_Shell",
    "Win32_System_Threading",
] }
```

- [ ] **Step 2: Implement Windows COM port handling in `src/serial.rs`**

Add `#[cfg(windows)]` implementation for COM port name expansion (`COM1` -> `\\.\COM1`), `CreateFileW`, DCB setup, timeouts, and `LockFileEx` exclusive lock. Retain `#[cfg(unix)]` implementation with `flock` and `termios`.

- [ ] **Step 3: Verify build on Linux**

Run: `cargo check && cargo test`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml src/serial.rs
git commit -m "feat(serial): add cross-platform Win32 serial driver with LockFileEx mutual exclusion"
```

---

### Task 3: Platform-Neutral Filesystem & Symlink Helpers

**Files:**
- Modify: `src/main.rs`
- Test: `cargo test` and `./test/test_e2e_full.sh`

**Interfaces:**
- Replace direct `std::os::unix::fs::{symlink, MetadataExt, PermissionsExt}` imports with cross-platform wrappers:
  ```rust
  fn create_symlink(src: &Path, dst: &Path) -> io::Result<()>;
  fn get_file_mode(meta: &fs::Metadata) -> u32;
  fn set_file_mode(path: &Path, mode: u32) -> io::Result<()>;
  ```

- [ ] **Step 1: Write helper functions for symlinks and permissions**

Implement `create_symlink`, `get_file_mode`, and `set_file_mode` conditioned on `#[cfg(unix)]` and `#[cfg(windows)]`.

- [ ] **Step 2: Replace Unix-specific calls in `src/main.rs`**

Update `walk_dir`, `spool_worker`, and `process_frame` to use the new helpers.

- [ ] **Step 3: Run regression tests on Linux**

Run: `./test/test_e2e_full.sh`
Expected: 100% PASS with symlink and permission preservation.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "refactor(fs): generalize symlink and file metadata for cross-platform compatibility"
```

---

### Task 4: Linux Service Daemon & Systemd Integration (`src/service.rs`)

**Files:**
- Create: `src/service.rs`
- Modify: `src/main.rs`
- Test: `test/test_daemon_mode.sh`

**Interfaces:**
- Produces:
  ```rust
  pub fn run_daemon(config_path: Option<&Path>) -> Result<(), Box<dyn std::error::Error>>;
  pub fn install_systemd_service() -> Result<(), Box<dyn std::error::Error>>;
  ```

- [ ] **Step 1: Implement `src/service.rs`**

Implement `run_daemon` which loads `/etc/sxfer.conf` (or specified path), sets up SIGINT/SIGTERM handlers, and runs the receiver or watch-sender loop continuously. Implement `install_systemd_service` which writes `/etc/systemd/system/sxfer.service` and `/etc/sxfer.conf`.

- [ ] **Step 2: Wire `sxfer daemon` and `sxfer systemd install` into `src/main.rs` CLI parser**

Handle subcommands:
- `sxfer daemon [--config <path>]`
- `sxfer systemd install`

- [ ] **Step 3: Write and run daemon integration test**

Create `test/test_daemon_mode.sh` verifying `sxfer daemon --config ...` transfers files over virtual FIFO.
Run: `chmod +x test/test_daemon_mode.sh && ./test/test_daemon_mode.sh`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/service.rs src/main.rs test/test_daemon_mode.sh
git commit -m "feat(service): add linux service daemon mode and systemd installer"
```

---

### Task 5: Windows System Tray Service (`src/tray_windows.rs`)

**Files:**
- Create: `src/tray_windows.rs`
- Modify: `src/main.rs`
- Test: `cargo check`

**Interfaces:**
- Produces:
  ```rust
  #[cfg(windows)]
  pub fn run_tray_service(config_path: Option<&Path>) -> Result<(), Box<dyn std::error::Error>>;
  ```

- [ ] **Step 1: Implement Win32 System Tray in `src/tray_windows.rs`**

Using `windows-sys`:
- Register hidden message window class (`RegisterClassW`, `CreateWindowExW`).
- Setup `NOTIFYICONDATAW` (`Shell_NotifyIconW`) with tray icon and tooltip.
- Implement context popup menu (`CreatePopupMenu`, `InsertMenuItemW`, `TrackPopupMenuEx`):
  - Status header
  - Pause / Resume
  - Send File... (`GetOpenFileNameW`)
  - Send Directory...
  - Open Downloads Folder (`explorer.exe`)
  - Settings...
  - Exit
- Background worker thread for receiver loop.
- Balloon notifications on start/finish/error.

- [ ] **Step 2: Wire `sxfer tray` into `src/main.rs`**

When invoked on Windows without arguments or with `tray`, launch `run_tray_service`.

- [ ] **Step 3: Verify build and module structure**

Run: `cargo check`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/tray_windows.rs src/main.rs
git commit -m "feat(tray): add native Windows system tray service with notifications and context menu"
```

---

### Task 6: Documentation, Makefile & Final Verification

**Files:**
- Modify: `README.md`, `sxfer.1`, `Makefile`
- Test: Full test suite (`cargo test`, `make test-all`)

- [ ] **Step 1: Update documentation and man page**

Document Windows usage (CMD and System Tray), `/etc/sxfer.conf` syntax, and `sxfer daemon` / `sxfer systemd install`.

- [ ] **Step 2: Update `Makefile`**

Add targets:
- `make service-install`: installs systemd service and default `/etc/sxfer.conf`.
- `make test-daemon`: runs daemon test.

- [ ] **Step 3: Run full test suite**

Run: `cargo test && ./test/test_e2e_full.sh && ./test/test_noise_recovery.sh && ./test/test_regression.sh && ./test/test_slow_writer.sh && ./test/test_watch_mode.sh && ./test/test_daemon_mode.sh`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md sxfer.1 Makefile
git commit -m "docs: document Windows support, system tray, and Linux service mode"
```
