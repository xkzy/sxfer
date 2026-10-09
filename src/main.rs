//! sxfer - One-way, high-speed serial file tree transfer tool in Rust.

mod auth;
mod config;
mod crc32;
mod ldpc;
mod lzma2;
mod mod_codec;
mod raptorq;
mod serial;
mod service;
mod tray_windows;

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crc32::{crc32_file, Crc32};
use lzma2::{compress_lzma2, decompress_lzma2};
use mod_codec::{mod_frame_decode, mod_frame_encode};
use raptorq::{RaptorQDecoder, RaptorQEncoder};
use serial::{auto_chunk_size, flush_tty, open_line_recv, open_line_send};

// Receiver-side limits (SECURITY_AUDIT F-01..F-08).
const MIN_CSZ: u64 = 1;
const MAX_CSZ: u64 = 32 * 1024; // symbols must fit in one frame (mod_frame_decode caps frames at ~64 KiB)
const MAX_PSIZE: u64 = 1 << 30; // payload bytes on the wire per file (1 GiB)
const MAX_SIZE: u64 = 4 << 30; // uncompressed bytes per file (4 GiB)
const MAX_LZMA_RATIO: u64 = 8192; // LZMA cannot exceed ~7000:1; anything above is a bomb
const MAX_PATH_LEN: usize = 4096;
const MAX_LINK_LEN: usize = 4096;
const MAX_PATH_DEPTH: usize = 64;
const MAX_COMPONENT_LEN: usize = 255;
const MAX_ACTIVE_ENTRIES: usize = 256;
const MAX_EARLY_SYMBOLS_PER_ID: usize = 256;
const MAX_TOTAL_EARLY_BYTES: usize = 1024 * 1024; // 1 MiB
const MAX_COMPLETED_IDS: usize = 256;
const MAX_IN_BUF: usize = 128 * 1024; // 128 KiB

static STOP_FLAG: AtomicBool = AtomicBool::new(false);
static TRANSFER_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn sanitize_log_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() || c == '\x1b' {
            out.push('?');
        } else {
            out.push(c);
        }
    }
    out
}

pub fn logmsg(msg: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    eprintln!("[{:>5}s] {}", now % 86400, msg);
}

#[cfg(unix)]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(unix)]
#[repr(C)]
struct PollFd {
    fd: std::os::raw::c_int,
    events: std::os::raw::c_short,
    revents: std::os::raw::c_short,
}

#[cfg(unix)]
const POLLIN: std::os::raw::c_short = 0x0001;
#[cfg(unix)]
const LOCK_EX: std::os::raw::c_int = 2;
#[cfg(unix)]
const LOCK_NB: std::os::raw::c_int = 4;
#[cfg(unix)]
const LOCK_UN: std::os::raw::c_int = 8;

#[cfg(unix)]
extern "C" {
    fn geteuid() -> u32;
    fn lchown(path: *const std::os::raw::c_char, owner: u32, group: u32) -> std::os::raw::c_int;
    fn utimensat(
        dirfd: std::os::raw::c_int,
        pathname: *const std::os::raw::c_char,
        times: *const Timespec,
        flags: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    fn signal(signum: std::os::raw::c_int, handler: extern "C" fn(std::os::raw::c_int)) -> usize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: std::os::raw::c_int) -> std::os::raw::c_int;
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

#[cfg(unix)]
extern "C" fn sig_handler(_: std::os::raw::c_int) {
    STOP_FLAG.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    #[cfg(unix)]
    unsafe {
        signal(2, sig_handler); // SIGINT (Ctrl-C)
        signal(15, sig_handler); // SIGTERM
        signal(1, sig_handler); // SIGHUP
    }

    #[cfg(windows)]
    unsafe {
        unsafe extern "system" fn win_ctrl_handler(_: u32) -> i32 {
            STOP_FLAG.store(true, Ordering::SeqCst);
            1
        }
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(win_ctrl_handler), 1);
    }
}

fn get_file_metadata(meta: &fs::Metadata) -> (u32, u32, u32, i64, u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            meta.mode() & 0o7777,
            meta.uid(),
            meta.gid(),
            meta.mtime(),
            meta.mtime_nsec() as u32,
        )
    }
    #[cfg(not(unix))]
    {
        let mode = if meta.permissions().readonly() {
            0o444
        } else {
            0o644
        };
        let (sec, nsec) = match meta.modified() {
            Ok(st) => match st.duration_since(UNIX_EPOCH) {
                Ok(dur) => (dur.as_secs() as i64, dur.subsec_nanos()),
                Err(err) => (-(err.duration().as_secs() as i64), 0),
            },
            Err(_) => (0, 0),
        };
        (mode, 1000, 1000, sec, nsec)
    }
}

fn apply_file_metadata(
    path: &Path,
    ftype: char,
    mode: u32,
    owner: Option<(u32, u32)>,
    mt_s: i64,
    mt_ns: u32,
) {
    #[cfg(unix)]
    {
        // Never operate through a symlink, whatever the header claims.
        let is_link = fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if (ftype == 'l') != is_link {
            return;
        }

        if let Some((uid, gid)) = owner {
            unsafe {
                if geteuid() == 0 {
                    if let Ok(c_path) = std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
                        lchown(c_path.as_ptr(), uid, gid);
                    }
                }
            }
        }

        if ftype != 'l' {
            use std::os::unix::fs::PermissionsExt;
            // Strip setuid/setgid and sticky bits: received files must never become privileged.
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o0777));
        }

        unsafe {
            let times = [
                Timespec {
                    tv_sec: mt_s,
                    tv_nsec: mt_ns as i64,
                },
                Timespec {
                    tv_sec: mt_s,
                    tv_nsec: mt_ns as i64,
                },
            ];
            if let Ok(c_path) = std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
                let flags = if ftype == 'l' { 0x100 } else { 0 }; // AT_SYMLINK_NOFOLLOW = 0x100
                utimensat(-100, c_path.as_ptr(), times.as_ptr(), flags); // AT_FDCWD = -100
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = owner;
        if ftype != 'l' {
            if let Ok(mut perms) = fs::metadata(path).map(|m| m.permissions()) {
                if (mode & 0o200) == 0 {
                    perms.set_readonly(true);
                } else {
                    #[allow(clippy::permissions_set_readonly_false)]
                    perms.set_readonly(false);
                }
                let _ = fs::set_permissions(path, perms);
            }
            if mt_s >= 0 {
                if let Ok(f) = OpenOptions::new().write(true).open(path) {
                    if let Some(st) = UNIX_EPOCH.checked_add(Duration::new(mt_s as u64, mt_ns)) {
                        let _ = f.set_modified(st);
                    }
                }
            }
        }
    }
}

fn is_windows_reserved_name(name: &str) -> bool {
    let stem = match name.split_once('.') {
        Some((base, _)) => base,
        None => name,
    };
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn create_symlink(link_target: &str, dest_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(link_target, dest_path)
    }
    #[cfg(windows)]
    {
        let target_path = Path::new(link_target);
        // Refuse UNC / absolute / drive-prefixed targets: probing them would
        // make Windows authenticate to attacker-chosen hosts (NTLM leak).
        let bad = Path::new(link_target)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
            || link_target.starts_with("\\\\")
            || link_target.starts_with("//")
            || link_target.contains(':')
            || target_path.has_root()
            || target_path.is_absolute();
        if bad {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "absolute or UNC symlink target rejected",
            ));
        }
        let resolved = dest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(target_path);
        if resolved.is_dir() {
            std::os::windows::fs::symlink_dir(target_path, dest_path)
        } else {
            std::os::windows::fs::symlink_file(target_path, dest_path)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Symlinks not supported",
        ))
    }
}

fn check_file_locked(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        if let Ok(f) = OpenOptions::new()
            .read(true)
            .custom_flags(0o04000) // O_NONBLOCK: never block on a FIFO
            .open(path)
        {
            let fd = f.as_raw_fd();
            let lock_res = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
            if lock_res != 0 {
                return true;
            }
            unsafe {
                flock(fd, LOCK_UN);
            }
            false
        } else {
            true
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::Storage::FileSystem::{
            LockFileEx, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };
        use windows_sys::Win32::System::IO::OVERLAPPED;

        if let Ok(f) = OpenOptions::new().read(true).open(path) {
            let handle = f.as_raw_handle() as HANDLE;
            unsafe {
                let mut ov: OVERLAPPED = std::mem::zeroed();
                let res = LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut ov,
                );
                if res == 0 {
                    return true;
                }
                UnlockFileEx(handle, 0, 1, 0, &mut ov);
            }
            false
        } else {
            true
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

// ----------------------------------------------------------------- SENDER PIPELINE
#[derive(Clone)]
struct QueueItem {
    id: [u8; 8],
    ftype: char,
    rel_path: String,
    link_target: String,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    size: u64,
    psize: u64,
    k: u32,
    csz: u32,
    meth: u8,
    fcrc: u32,
    payload: Vec<u8>,
}

fn generate_id(rel: &str) -> [u8; 8] {
    let nonce = TRANSFER_NONCE.fetch_add(1, Ordering::Relaxed);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut crc1 = Crc32::new();
    crc1.update(rel.as_bytes());
    crc1.update(&nonce.to_be_bytes());
    let h1 = crc1.finalize();

    let mut crc2 = Crc32::new();
    crc2.update(b"sxfer_nonce_2026");
    crc2.update(rel.as_bytes());
    crc2.update(&now_ns.to_be_bytes());
    let h2 = crc2.finalize();

    let mut id = [0u8; 8];
    id[..4].copy_from_slice(&h1.to_be_bytes());
    id[4..].copy_from_slice(&h2.to_be_bytes());
    id
}

fn crawl_and_compress(
    paths: Vec<PathBuf>,
    chunk_size: usize,
    tx: SyncSender<QueueItem>,
    sign_key: Option<&ring::signature::Ed25519KeyPair>,
) -> usize {
    const COMPRESSION_LEVEL: i32 = 9;
    // Anything that could not be queued faithfully; the caller must not delete sources if non-zero.
    let mut problems = 0usize;
    let mut items = Vec::new();
    let mut raw_datas = Vec::new();

    for path in paths {
        let root = path.clone();
        let walker = walkdir(&path, &mut problems);
        for entry in walker {
            let rel = if !entry.is_absolute() {
                entry.to_string_lossy().to_string()
            } else if let Ok(stripped) = entry.strip_prefix(root.parent().unwrap_or(&root)) {
                stripped.to_string_lossy().to_string()
            } else {
                entry
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            };

            let clean_rel = rel
                .trim_start_matches('/')
                .trim_start_matches("./")
                .to_string();
            if clean_rel.is_empty() {
                continue;
            }

            let meta = match fs::symlink_metadata(&entry) {
                Ok(m) => m,
                Err(e) => {
                    logmsg(&format!("skip (stat failed): {} ({})", entry.display(), e));
                    problems += 1;
                    continue;
                }
            };

            let id = generate_id(&clean_rel);
            let (mode, uid, gid, mtime_sec, mtime_nsec) = get_file_metadata(&meta);
            let mut item = QueueItem {
                id,
                ftype: 'f',
                rel_path: clean_rel,
                link_target: String::new(),
                mode,
                uid,
                gid,
                mtime_sec,
                mtime_nsec,
                size: meta.len(),
                psize: meta.len(),
                k: 1,
                csz: chunk_size as u32,
                meth: 0,
                fcrc: 0,
                payload: Vec::new(),
            };

            if meta.file_type().is_symlink() {
                item.ftype = 'l';
                item.size = 0;
                item.psize = 0;
                item.link_target = match fs::read_link(&entry) {
                    Ok(t) => t.to_string_lossy().to_string(),
                    Err(e) => {
                        logmsg(&format!(
                            "skip (readlink failed): {} ({})",
                            entry.display(),
                            e
                        ));
                        problems += 1;
                        continue;
                    }
                };
                logmsg(&format!(
                    "QUEUED {} (symlink -> {})",
                    item.rel_path, item.link_target
                ));
                items.push(item);
                raw_datas.push(Vec::new());
            } else if meta.is_dir() {
                item.ftype = 'd';
                item.size = 0;
                item.psize = 0;
                logmsg(&format!("QUEUED {} (dir)", item.rel_path));
                items.push(item);
                raw_datas.push(Vec::new());
            } else if meta.is_file() {
                item.ftype = 'f';
                let raw_data = match fs::read(&entry) {
                    Ok(d) => d,
                    Err(e) => {
                        logmsg(&format!("skip (read failed): {} ({})", entry.display(), e));
                        problems += 1;
                        continue;
                    }
                };
                // Size/CRC must describe the bytes actually sent, so derive them from one read.
                if raw_data.len() as u64 != meta.len() {
                    logmsg(&format!(
                        "skip (changed while reading): {}",
                        entry.display()
                    ));
                    problems += 1;
                    continue;
                }
                item.fcrc = Crc32::calculate(&raw_data);

                let mut payload = raw_data.clone();
                let mut meth = 0u8;

                if !raw_data.is_empty() {
                    if let Ok(compressed) = compress_lzma2(&raw_data, COMPRESSION_LEVEL) {
                        if compressed.len() < raw_data.len() {
                            payload = compressed;
                            meth = 1;
                        }
                    }
                }

                item.psize = payload.len() as u64;
                item.meth = meth;
                item.payload = payload;
                item.k = (item.psize as usize).div_ceil(chunk_size).max(1) as u32;

                if item.meth != 0 {
                    logmsg(&format!(
                        "QUEUED {} (f, {} B -> {} B fast-lzma2 L{}, {} symbols @ {} B)",
                        item.rel_path, item.size, item.psize, COMPRESSION_LEVEL, item.k, item.csz
                    ));
                } else {
                    logmsg(&format!(
                        "QUEUED {} (f, {} B, stored uncompressed, {} symbols @ {} B)",
                        item.rel_path, item.size, item.k, item.csz
                    ));
                }

                raw_datas.push(raw_data);
                items.push(item);
            } else {
                logmsg(&format!(
                    "skip (unsupported file type): {}",
                    entry.display()
                ));
                problems += 1;
            }
        }
    }

    if let Some(keypair) = sign_key {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let nonce = TRANSFER_NONCE.fetch_add(1, Ordering::Relaxed);
        let transfer_id = format!("{:016x}{:016x}", now_sec as u64, nonce);
        let mut manifest = auth::TransferManifest::new(&transfer_id, now_sec);

        for (item, raw) in items.iter().zip(raw_datas.iter()) {
            let sha256_hex = if item.ftype == 'f' {
                auth::compute_sha256_hex(raw)
            } else {
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            };
            manifest.add_entry(auth::ManifestEntry {
                path: item.rel_path.clone(),
                entry_type: item.ftype,
                size: item.size,
                sha256_hex,
                link_target: item.link_target.clone(),
                mode: item.mode,
                mtime_sec: item.mtime_sec,
                mtime_nsec: item.mtime_nsec,
            });
        }

        let signed = manifest.sign(keypair);
        let manifest_bytes = signed.to_envelope_json().into_bytes();
        let manifest_fcrc = Crc32::calculate(&manifest_bytes);
        let manifest_item = QueueItem {
            id: [0x53, 0x58, 0x4d, 0x46, 0x53, 0x54, 0x31, 0x00], // "SXMFST1\0"
            ftype: 'm',
            rel_path: auth::MANIFEST_FILENAME.to_string(),
            link_target: String::new(),
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime_sec: now_sec,
            mtime_nsec: 0,
            size: manifest_bytes.len() as u64,
            psize: manifest_bytes.len() as u64,
            k: (manifest_bytes.len()).div_ceil(chunk_size).max(1) as u32,
            csz: chunk_size as u32,
            meth: 0,
            fcrc: manifest_fcrc,
            payload: manifest_bytes,
        };

        logmsg(&format!(
            "[AUTH] Generated signed transfer manifest: id={}, {} entries, {} bytes (Ed25519 signed)",
            transfer_id, manifest.total_entries, manifest.total_bytes
        ));

        if tx.send(manifest_item).is_err() {
            return problems + 1;
        }
    }

    for item in items {
        if tx.send(item).is_err() {
            return problems + 1;
        }
    }

    problems
}

fn walkdir(dir: &Path, problems: &mut usize) -> Vec<PathBuf> {
    let mut result = Vec::new();
    result.push(dir.to_path_buf());
    if dir.is_dir() && !dir.is_symlink() {
        match fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(_) => {
                            *problems += 1;
                            continue;
                        }
                    };
                    let p = entry.path();
                    if p.is_dir() && !p.is_symlink() {
                        result.extend(walkdir(&p, problems));
                    } else {
                        result.push(p);
                    }
                }
            }
            Err(e) => {
                logmsg(&format!("skip (cannot list): {} ({})", dir.display(), e));
                *problems += 1;
            }
        }
    }
    result
}

fn encode_stage(
    rx: Receiver<QueueItem>,
    tx: SyncSender<Vec<u8>>,
    pct: usize,
    rounds: usize,
) -> bool {
    let mut ok = true;
    while let Ok(item) = rx.recv() {
        // 1. Build Header Frame
        let mut hdr = Vec::with_capacity(512);
        hdr.extend_from_slice(&item.id);
        hdr.push(item.ftype as u8);
        hdr.extend_from_slice(&item.mode.to_be_bytes());
        hdr.extend_from_slice(&item.uid.to_be_bytes());
        hdr.extend_from_slice(&item.gid.to_be_bytes());
        hdr.extend_from_slice(&(item.mtime_sec as u64).to_be_bytes());
        hdr.extend_from_slice(&item.mtime_nsec.to_be_bytes());
        hdr.extend_from_slice(&item.size.to_be_bytes());
        hdr.extend_from_slice(&item.psize.to_be_bytes());
        hdr.extend_from_slice(&item.k.to_be_bytes());
        hdr.extend_from_slice(&item.csz.to_be_bytes());
        hdr.extend_from_slice(&(pct as u16).to_be_bytes());
        hdr.push(item.meth);
        hdr.push(9); // level 9
        hdr.extend_from_slice(&item.fcrc.to_be_bytes());

        let rel_bytes = item.rel_path.as_bytes();
        hdr.extend_from_slice(&(rel_bytes.len() as u16).to_be_bytes());
        hdr.extend_from_slice(rel_bytes);

        let link_bytes = item.link_target.as_bytes();
        hdr.extend_from_slice(&(link_bytes.len() as u16).to_be_bytes());
        hdr.extend_from_slice(link_bytes);

        let num_hdr_copies = if item.ftype == 'f' || item.ftype == 'm' {
            ((pct / 15) + 8).clamp(8, 32).max(rounds * 8)
        } else {
            ((pct / 10) + 12).clamp(12, 48).max(rounds * 10)
        };
        for _ in 0..num_hdr_copies {
            let frame = mod_frame_encode(&hdr);
            ok &= tx.send(frame).is_ok();
        }

        // 2. RaptorQ Fountain Symbols
        if (item.ftype == 'f' || item.ftype == 'm') && item.psize > 0 {
            if item.k as u64 * item.csz as u64 > u32::MAX as u64 {
                ok = false; // ESI space (u32) cannot address this file
            }
            if let Some(rq) = RaptorQEncoder::new(&item.payload, item.csz as usize) {
                let num_symbols = rq.total_symbols_to_send(pct);
                let mut sym_buf = vec![0u8; item.csz as usize];
                let mut pkt = Vec::with_capacity(16 + item.csz as usize);
                let hdr_freq = if pct >= 100 {
                    4
                } else if pct >= 50 {
                    8
                } else {
                    16
                };

                for round in 0..rounds {
                    for s in 0..num_symbols {
                        let esi = (round * num_symbols + s) as u32;
                        if esi > 0 && (esi as usize).is_multiple_of(hdr_freq) {
                            let mid_hdr = mod_frame_encode(&hdr);
                            ok &= tx.send(mid_hdr).is_ok();
                        }

                        rq.encode_symbol(esi, &mut sym_buf);

                        pkt.clear();
                        pkt.extend_from_slice(&item.id);
                        pkt.extend_from_slice(&esi.to_be_bytes());
                        pkt.extend_from_slice(&item.csz.to_be_bytes());
                        pkt.extend_from_slice(&sym_buf);

                        let tx_frame = mod_frame_encode(&pkt);
                        ok &= tx.send(tx_frame).is_ok();
                    }
                }
            }

            let end_copies = ((pct / 15) + 8).clamp(8, 32);
            for _ in 0..end_copies {
                let end_hdr = mod_frame_encode(&hdr);
                ok &= tx.send(end_hdr).is_ok();
            }
        }
    }
    ok
}

fn tx_worker(rx: Receiver<Vec<u8>>, file: &mut File, baud: u64) -> bool {
    // After the first device error keep draining the channel (so producers never block)
    // but report failure: the caller must not treat the data as sent.
    let mut ok = true;
    if baud >= 2_500_000 {
        while let Ok(pkt) = rx.recv() {
            if !ok {
                continue;
            }
            for chunk in pkt.chunks(64) {
                if let Err(e) = file.write_all(chunk) {
                    eprintln!("TX device write error: {}", e);
                    ok = false;
                    break;
                }
                thread::sleep(Duration::from_micros(150));
            }
            // Inter-frame line recovery time (allows UART to return to idle HIGH)
            thread::sleep(Duration::from_micros(350));
        }
    } else {
        let mut batch = Vec::with_capacity(4096);
        while let Ok(pkt) = rx.recv() {
            if !ok {
                continue;
            }
            if batch.len() + pkt.len() > 4096 {
                if let Err(e) = file.write_all(&batch) {
                    eprintln!("TX device write error: {}", e);
                    ok = false;
                }
                batch.clear();
            }
            if pkt.len() > 4096 {
                if !batch.is_empty() {
                    if let Err(e) = file.write_all(&batch) {
                        eprintln!("TX device write error: {}", e);
                        ok = false;
                    }
                    batch.clear();
                }
                if let Err(e) = file.write_all(&pkt) {
                    eprintln!("TX device write error: {}", e);
                    ok = false;
                }
            } else {
                batch.extend_from_slice(&pkt);
            }
        }
        if ok && !batch.is_empty() {
            if let Err(e) = file.write_all(&batch) {
                eprintln!("TX device write error: {}", e);
                ok = false;
            }
        }
    }
    flush_tty(file);
    ok
}

// ----------------------------------------------------------------- RECEIVER
struct EarlySymbol {
    esi: u32,
    csz: u32,
    data: Vec<u8>,
}

struct FileState {
    id: [u8; 8],
    has_hdr: bool,
    done: bool,
    ftype: char,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    size: u64,
    psize: u64,
    k: u32,
    csz: u32,
    meth: u8,
    crc: u32,
    path: String,
    link: String,
    dec: Option<RaptorQDecoder>,
    nsymbols: u32,
    early_syms: Vec<EarlySymbol>,
}

#[derive(Debug, Clone)]
struct ParsedHeader {
    id: [u8; 8],
    ftype: char,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    size: u64,
    psize: u64,
    k: u32,
    csz: u32,
    #[allow(dead_code)]
    pct: u16,
    meth: u8,
    fcrc: u32,
    path: String,
    link: String,
}

impl ParsedHeader {
    fn parse(p: &[u8]) -> Result<Self, &'static str> {
        if p.len() < 8 + 1 + 4 + 4 + 4 + 8 + 4 + 8 + 8 + 4 + 4 + 2 + 1 + 1 + 4 + 2 + 2 {
            return Err("header frame too short");
        }

        let mut id = [0u8; 8];
        id.copy_from_slice(&p[..8]);

        let ftype = p[8] as char;
        if ftype != 'f' && ftype != 'd' && ftype != 'l' && ftype != 'm' {
            return Err("invalid entry type");
        }

        let mode = u32::from_be_bytes(p[9..13].try_into().unwrap());
        let uid = u32::from_be_bytes(p[13..17].try_into().unwrap());
        let gid = u32::from_be_bytes(p[17..21].try_into().unwrap());
        let mt_s = i64::from_be_bytes(p[21..29].try_into().unwrap());
        let mt_ns = u32::from_be_bytes(p[29..33].try_into().unwrap());
        let size = u64::from_be_bytes(p[33..41].try_into().unwrap());
        let psize = u64::from_be_bytes(p[41..49].try_into().unwrap());
        let k = u32::from_be_bytes(p[49..53].try_into().unwrap());
        let csz = u32::from_be_bytes(p[53..57].try_into().unwrap());
        let pct = u16::from_be_bytes(p[57..59].try_into().unwrap());
        let meth = p[59];
        // let level = p[60];
        let fcrc = u32::from_be_bytes(p[61..65].try_into().unwrap());
        let pl = u16::from_be_bytes(p[65..67].try_into().unwrap()) as usize;

        if pl == 0 {
            return Err("empty path");
        }
        if pl > MAX_PATH_LEN {
            return Err("path length exceeds maximum");
        }
        let pl_end = 67 + pl;
        if pl_end + 2 > p.len() {
            return Err("header truncated at path");
        }

        let path_str = match std::str::from_utf8(&p[67..pl_end]) {
            Ok(s) => s,
            Err(_) => return Err("path is not valid utf-8"),
        };
        if path_str.chars().any(|c| c.is_control()) {
            return Err("path contains control characters");
        }
        if path_str.contains('\0') {
            return Err("path contains null character");
        }

        // Validate normalized path components
        if path_str.starts_with('/') || path_str.starts_with('\\') || path_str.contains(':') {
            return Err("invalid or absolute path prefix");
        }
        let clean_path = path_str;
        if clean_path.is_empty() {
            return Err("path is empty");
        }

        let mut depth = 0;
        for comp in Path::new(clean_path).components() {
            match comp {
                std::path::Component::Normal(p) => {
                    if p.len() > MAX_COMPONENT_LEN {
                        return Err("path component too long");
                    }
                    let s = p.to_string_lossy();
                    if is_windows_reserved_name(&s) {
                        return Err("path contains Windows reserved name");
                    }
                    depth += 1;
                    if depth > MAX_PATH_DEPTH {
                        return Err("path depth exceeded");
                    }
                }
                std::path::Component::CurDir => {}
                _ => return Err("path contains traversal or root component"),
            }
        }
        if depth == 0 {
            return Err("path has no normal components");
        }

        let ll = u16::from_be_bytes(p[pl_end..pl_end + 2].try_into().unwrap()) as usize;
        let ll_end = pl_end + 2 + ll;
        if ll_end > p.len() {
            return Err("header truncated at link");
        }

        let link_str = if ll > 0 {
            if ll > MAX_LINK_LEN {
                return Err("symlink target too long");
            }
            let s = match std::str::from_utf8(&p[pl_end + 2..ll_end]) {
                Ok(s) => s,
                Err(_) => return Err("link target is not valid utf-8"),
            };
            if s.chars().any(|c| c.is_control()) {
                return Err("link target contains control characters");
            }
            s
        } else {
            ""
        };

        if ftype == 'l' && link_str.is_empty() {
            return Err("symlink with empty target");
        }

        if mt_ns >= 1_000_000_000 {
            return Err("mtime_nsec out of range");
        }
        if !(0..(1i64 << 40)).contains(&mt_s) {
            return Err("mtime_sec out of range");
        }

        if ftype != 'f' && ftype != 'm' {
            if size != 0 || psize != 0 || meth != 0 {
                return Err("non-file with data size or compression");
            }
            if k > 1 {
                return Err("non-file with symbol count > 1");
            }
        } else {
            if meth > 1 {
                return Err("unknown compression method");
            }
            if size > MAX_SIZE || psize > MAX_PSIZE {
                return Err("size limit exceeded");
            }
            if meth == 0 && size != psize {
                return Err("stored size mismatch");
            }
            if meth == 1 {
                if psize == 0 {
                    return Err("compressed payload has zero size");
                }
                if size == 0 {
                    return Err("compressed payload declares zero unpacked size");
                }
                if size > psize.saturating_mul(MAX_LZMA_RATIO) {
                    return Err("implausible compression ratio");
                }
            }
            if psize == 0 {
                if size != 0 {
                    return Err("zero payload with nonzero size");
                }
            } else {
                if (csz as u64) < MIN_CSZ || (csz as u64) > MAX_CSZ {
                    return Err("symbol size out of range");
                }
                let expected_k = (psize as usize).div_ceil(csz as usize) as u32;
                if k != expected_k {
                    return Err("symbol count does not match psize/csz");
                }
                if (k as u64).saturating_mul(csz as u64) > (u32::MAX as u64) + MAX_CSZ {
                    return Err("symbol address space overflow");
                }
            }
        }

        Ok(ParsedHeader {
            id,
            ftype,
            mode,
            uid,
            gid,
            mtime_sec: mt_s,
            mtime_nsec: mt_ns,
            size,
            psize,
            k,
            csz,
            pct,
            meth,
            fcrc,
            path: clean_path.to_string(),
            link: link_str.to_string(),
        })
    }
}

struct ReceiverContext {
    out_dir: PathBuf,
    restore_owner: bool,
    verify_key: Option<Vec<u8>>,
    require_auth: bool,
    replay_cache: auth::ReplayCache,
    max_clock_skew_secs: i64,
    active_batch: Option<auth::QuarantineBatch>,
    table: HashMap<[u8; 8], FileState>,
    completed_ids: std::collections::HashSet<[u8; 8]>,
    completed_order: std::collections::VecDeque<[u8; 8]>,
    total_early_bytes: usize,
    dirs: Vec<(PathBuf, u32, u32, u32, i64, u32)>,
    nok: usize,
    nbad: usize,
    ndone: usize,
    sc_ldpc_bit_flips: usize,
    sc_ldpc_frames_corrected: usize,
    total_valid_frames: usize,
    total_raw_bytes: u64,
    total_wire_payload_bytes: u64,
    total_symbols_received: usize,
    total_symbols_needed: usize,
}

impl ReceiverContext {
    fn new(
        out_dir: PathBuf,
        restore_owner: bool,
        verify_key: Option<Vec<u8>>,
        require_auth: bool,
        replay_cache_path: Option<PathBuf>,
        max_clock_skew_secs: i64,
    ) -> Self {
        let replay_cache = auth::ReplayCache::new(replay_cache_path);
        Self {
            out_dir,
            restore_owner,
            verify_key,
            require_auth,
            replay_cache,
            max_clock_skew_secs: if max_clock_skew_secs > 0 {
                max_clock_skew_secs
            } else {
                auth::DEFAULT_MAX_CLOCK_SKEW_SECS
            },
            active_batch: None,
            table: HashMap::new(),
            completed_ids: std::collections::HashSet::new(),
            completed_order: std::collections::VecDeque::new(),
            total_early_bytes: 0,
            dirs: Vec::new(),
            nok: 0,
            nbad: 0,
            ndone: 0,
            sc_ldpc_bit_flips: 0,
            sc_ldpc_frames_corrected: 0,
            total_valid_frames: 0,
            total_raw_bytes: 0,
            total_wire_payload_bytes: 0,
            total_symbols_received: 0,
            total_symbols_needed: 0,
        }
    }

    fn mark_done(&mut self, id: [u8; 8]) {
        if let Some(f) = self.table.get_mut(&id) {
            f.done = true;
            f.dec = None;
            self.total_early_bytes = self
                .total_early_bytes
                .saturating_sub(f.early_syms.iter().map(|e| e.data.len()).sum());
            f.early_syms.clear();
        }
        self.completed_ids.insert(id);
        self.completed_order.push_back(id);
        if self.completed_order.len() > MAX_COMPLETED_IDS {
            if let Some(old) = self.completed_order.pop_front() {
                self.completed_ids.remove(&old);
                self.table.remove(&old);
            }
        }
    }

    fn prep_dest(&self, rel: &str) -> Option<PathBuf> {
        use std::path::Component;
        if rel.is_empty()
            || rel.starts_with('/')
            || rel.starts_with('\\')
            || rel.contains('\0')
            || rel.contains(':')
        {
            return None;
        }
        let rel_path = Path::new(rel);
        let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
        for c in rel_path.components() {
            match c {
                Component::Normal(p) => {
                    let s = p.to_string_lossy();
                    if is_windows_reserved_name(&s) {
                        return None;
                    }
                    parts.push(p);
                }
                Component::CurDir => {}
                _ => return None,
            }
        }
        if parts.is_empty() {
            return None;
        }

        // Walk every parent directory without following symlinks.
        let mut cur = self.out_dir.clone();
        fs::create_dir_all(&cur).ok()?;
        for p in &parts[..parts.len() - 1] {
            cur.push(p);
            match fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return None,
                Ok(_) => {}
                Err(_) => fs::create_dir(&cur).ok()?,
            }
        }
        cur.push(parts[parts.len() - 1]);
        Some(cur)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_meta(
        &self,
        path: &Path,
        ftype: char,
        mode: u32,
        uid: u32,
        gid: u32,
        mt_s: i64,
        mt_ns: u32,
    ) {
        let owner = if self.restore_owner {
            Some((uid, gid))
        } else {
            None
        };
        apply_file_metadata(path, ftype, mode, owner, mt_s, mt_ns);
    }

    fn check_active_batch_completion(&mut self) {
        let mut is_done = false;
        let mut transfer_info = String::new();
        let mut total_entries = 0;
        let mut total_bytes = 0;

        if let Some(ref mut batch) = self.active_batch {
            // If any pending files in .sxfer_staging_pending exist, move them to batch.staging_dir
            let pending_dir = self.out_dir.join(".sxfer_staging_pending");
            if pending_dir.exists() {
                if let Ok(entries) = fs::read_dir(&pending_dir) {
                    for entry in entries.flatten() {
                        let target = batch.staging_dir.join(entry.file_name());
                        let _ = fs::rename(entry.path(), target);
                    }
                }
                let _ = fs::remove_dir_all(&pending_dir);
            }

            // Check if any unverified manifest entries are present in staging_dir
            if let Some(ref manifest) = batch.manifest.clone() {
                for entry in &manifest.entries {
                    if entry.entry_type == 'f' && !batch.verified_paths.contains(&entry.path) {
                        let staged = batch.staging_dir.join(&entry.path);
                        if staged.exists() {
                            let _ = batch.verify_received_file(&entry.path);
                        }
                    } else if entry.entry_type != 'f' {
                        batch.verified_paths.insert(entry.path.clone());
                    }
                }
                transfer_info = batch.transfer_id.clone();
                total_entries = manifest.total_entries;
                total_bytes = manifest.total_bytes;
            }

            if batch.is_complete() {
                is_done = true;
            }
        }

        if is_done {
            if let Some(batch) = self.active_batch.take() {
                logmsg(&format!(
                    "[AUTH] All {} items in transfer '{}' ({} B) verified successfully. Committing to destination...",
                    total_entries, transfer_info, total_bytes
                ));
                if let Err(e) = batch.commit_to_dest(&self.out_dir) {
                    logmsg(&format!("[AUTH] FAIL commit failed: {}", e));
                } else {
                    logmsg(&format!(
                        "[AUTH] TRANSFER COMPLETE: Published transfer '{}' to {}",
                        transfer_info,
                        self.out_dir.display()
                    ));
                }
            }
        }
    }

    fn finalize_file(&mut self, id: [u8; 8]) {
        let (path, size, psize, crc, meth, mode, uid, gid, mtime_sec, mtime_nsec, nsymbols, ftype) = {
            let f = match self.table.get(&id) {
                Some(f) if !f.done => f,
                _ => return,
            };
            (
                f.path.clone(),
                f.size,
                f.psize,
                f.crc,
                f.meth,
                f.mode,
                f.uid,
                f.gid,
                f.mtime_sec,
                f.mtime_nsec,
                f.nsymbols,
                f.ftype,
            )
        };

        let dest = match self.prep_dest(&path) {
            Some(d) => d,
            None => {
                logmsg(&format!(
                    "SKIP  unsafe path in header: {}",
                    sanitize_log_str(&path)
                ));
                self.mark_done(id);
                self.ndone += 1;
                return;
            }
        };

        let dec_payload = if psize > 0 {
            match self
                .table
                .get(&id)
                .and_then(|f| f.dec.as_ref())
                .and_then(|d| d.decode_data())
            {
                Some(p) => p,
                None => {
                    logmsg(&format!("FAIL  {}: decoder error", sanitize_log_str(&path)));
                    if let Some(f) = self.table.get_mut(&id) {
                        f.dec = RaptorQDecoder::new(f.psize as usize, f.csz as usize);
                    }
                    return;
                }
            }
        } else {
            Vec::new()
        };

        let final_data = if meth != 0 {
            match decompress_lzma2(&dec_payload, size as usize) {
                Ok(d) => d,
                Err(_) => {
                    logmsg(&format!(
                        "FAIL  {}: LZMA2 decompression failed",
                        sanitize_log_str(&path)
                    ));
                    if let Some(f) = self.table.get_mut(&id) {
                        f.dec = RaptorQDecoder::new(f.psize as usize, f.csz as usize);
                    }
                    return;
                }
            }
        } else {
            dec_payload
        };

        let fcrc = Crc32::calculate(&final_data);
        if final_data.len() != size as usize || fcrc != crc {
            logmsg(&format!(
                "FAIL  {}: CRC32 mismatch, waiting for more symbols",
                sanitize_log_str(&path)
            ));
            if let Some(f) = self.table.get_mut(&id) {
                f.dec = RaptorQDecoder::new(f.psize as usize, f.csz as usize);
            }
            return;
        }

        if ftype == 'm' {
            let manifest_str = match std::str::from_utf8(&final_data) {
                Ok(s) => s,
                Err(_) => {
                    logmsg("[AUTH] REJECT manifest: not valid utf-8");
                    self.mark_done(id);
                    return;
                }
            };

            let signed_manifest = match auth::SignedManifest::parse(manifest_str) {
                Ok(sm) => sm,
                Err(e) => {
                    logmsg(&format!("[AUTH] REJECT manifest: parse error ({})", e));
                    self.mark_done(id);
                    return;
                }
            };

            if let Some(ref trusted_pub) = self.verify_key {
                let manifest = match signed_manifest.verify(trusted_pub) {
                    Ok(m) => m,
                    Err(e) => {
                        logmsg(&format!("[AUTH] REJECT manifest: {}", e));
                        self.mark_done(id);
                        return;
                    }
                };

                if let Err(e) = self.replay_cache.check_and_record(
                    &manifest.transfer_id,
                    manifest.timestamp_sec,
                    self.max_clock_skew_secs,
                ) {
                    logmsg(&format!("[AUTH] REJECT manifest: {}", e));
                    self.mark_done(id);
                    return;
                }

                logmsg(&format!(
                    "[AUTH] Validated signed manifest for transfer '{}' ({} entries, {} bytes, signed by Ed25519 key)",
                    manifest.transfer_id, manifest.total_entries, manifest.total_bytes
                ));

                let mut batch =
                    match auth::QuarantineBatch::new(&self.out_dir, &manifest.transfer_id) {
                        Ok(b) => b,
                        Err(e) => {
                            logmsg(&format!(
                                "[AUTH] Failed to initialize quarantine batch: {}",
                                e
                            ));
                            self.mark_done(id);
                            return;
                        }
                    };
                if let Err(e) = batch.set_manifest(manifest) {
                    logmsg(&format!("[AUTH] Error setting manifest: {}", e));
                    self.mark_done(id);
                    return;
                }

                self.active_batch = Some(batch);
                self.check_active_batch_completion();
            } else {
                logmsg("[AUTH] Manifest received but receiver is running in unauthenticated mode (no verify key configured)");
            }

            self.mark_done(id);
            return;
        }

        if self.verify_key.is_some() {
            // Authenticated Transfer Mode: stage under quarantine
            let staging_dest = if let Some(ref batch) = self.active_batch {
                batch.staging_dir.join(&path)
            } else {
                self.out_dir
                    .join(format!(".sxfer_staging_pending/{}", &path))
            };

            if let Some(parent) = staging_dest.parent() {
                let _ = fs::create_dir_all(parent);
            }

            let _ = fs::remove_file(&staging_dest);
            let wrote = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging_dest)
                .and_then(|mut f| f.write_all(&final_data))
                .is_ok();
            if !wrote {
                logmsg(&format!(
                    "FAIL  {}: failed to write to quarantine staging",
                    sanitize_log_str(&path)
                ));
                return;
            }

            self.apply_meta(&staging_dest, 'f', mode, uid, gid, mtime_sec, mtime_nsec);
            self.total_raw_bytes += size;
            self.total_wire_payload_bytes += if meth != 0 { psize } else { size };
            self.total_symbols_received += nsymbols as usize;
            if let Some(f) = self.table.get(&id) {
                self.total_symbols_needed += f.k as usize;
            }

            self.mark_done(id);
            self.nok += 1;
            self.ndone += 1;

            if let Some(ref mut batch) = self.active_batch {
                match batch.verify_received_file(&path) {
                    Ok(()) => {
                        logmsg(&format!(
                            "[AUTH] OK    {} ({} B, SHA-256 match, staged in quarantine)",
                            sanitize_log_str(&path),
                            size
                        ));
                        self.check_active_batch_completion();
                    }
                    Err(e) => {
                        logmsg(&format!(
                            "[AUTH] FAIL  {} verification failed: {}",
                            sanitize_log_str(&path),
                            e
                        ));
                    }
                }
            } else {
                logmsg(&format!(
                    "[AUTH] STAGED {} ({} B, CRC {:08x}, awaiting signed manifest)",
                    sanitize_log_str(&path),
                    size,
                    crc
                ));
            }
        } else {
            // Legacy / Unauthenticated Mode
            if self.require_auth {
                logmsg(&format!(
                    "[AUTH] REJECT {}: transfer is unauthenticated but --require-auth is active",
                    sanitize_log_str(&path)
                ));
                self.mark_done(id);
                self.nbad += 1;
                return;
            }

            let tmp_path = match dest.parent() {
                Some(parent) => {
                    let file_name = dest.file_name().unwrap_or_default().to_string_lossy();
                    parent.join(format!(".{}.{}.sxfer-part", file_name, hex::encode(id)))
                }
                None => dest.with_extension("sxfer-part"),
            };

            // A planted symlink at the temp name must not redirect the write:
            // clear it and create exclusively (O_EXCL never follows symlinks).
            let _ = fs::remove_file(&tmp_path);
            let wrote = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .and_then(|mut f| f.write_all(&final_data))
                .is_ok();
            if !wrote || fs::rename(&tmp_path, &dest).is_err() {
                logmsg(&format!(
                    "FAIL  {}: failed to write to disk",
                    sanitize_log_str(&path)
                ));
                let _ = fs::remove_file(&tmp_path);
                return;
            }

            self.total_raw_bytes += size;
            self.total_wire_payload_bytes += if meth != 0 { psize } else { size };
            self.total_symbols_received += nsymbols as usize;
            if let Some(f) = self.table.get(&id) {
                self.total_symbols_needed += f.k as usize;
            }

            self.apply_meta(&dest, 'f', mode, uid, gid, mtime_sec, mtime_nsec);
            self.mark_done(id);
            self.nok += 1;
            self.ndone += 1;
            logmsg(&format!(
                "[UNAUTHENTICATED (legacy mode)] OK    {} ({} B, CRC {:08x}, {} symbols received)",
                sanitize_log_str(&path),
                size,
                crc,
                nsymbols
            ));
        }
    }

    fn finalize_other(&mut self, id: [u8; 8]) {
        let (path, link, ftype, mode, uid, gid, mtime_sec, mtime_nsec) = {
            let f = match self.table.get(&id) {
                Some(f) if !f.done => f,
                _ => return,
            };
            (
                f.path.clone(),
                f.link.clone(),
                f.ftype,
                f.mode,
                f.uid,
                f.gid,
                f.mtime_sec,
                f.mtime_nsec,
            )
        };

        if self.verify_key.is_some() || self.require_auth {
            if let Some(ref mut batch) = self.active_batch {
                batch.verified_paths.insert(path.clone());
                self.check_active_batch_completion();
            }
            self.mark_done(id);
            self.ndone += 1;
            return;
        }

        let dest = match self.prep_dest(&path) {
            Some(d) => d,
            None => {
                logmsg(&format!(
                    "SKIP  unsafe path in header: {}",
                    sanitize_log_str(&path)
                ));
                self.mark_done(id);
                self.ndone += 1;
                return;
            }
        };

        if ftype == 'd' {
            let _ = fs::create_dir_all(&dest);
            self.dirs
                .push((dest, mode, uid, gid, mtime_sec, mtime_nsec));
            logmsg(&format!(
                "[UNAUTHENTICATED (legacy mode)] DIR   {}",
                sanitize_log_str(&path)
            ));
        } else if ftype == 'l' {
            let _ = fs::remove_file(&dest);
            if create_symlink(&link, &dest).is_ok() {
                self.apply_meta(&dest, 'l', mode, uid, gid, mtime_sec, mtime_nsec);
                logmsg(&format!(
                    "[UNAUTHENTICATED (legacy mode)] LINK  {} -> {}",
                    sanitize_log_str(&path),
                    sanitize_log_str(&link)
                ));
            } else {
                logmsg(&format!(
                    "FAIL  {}: symlink creation failed",
                    sanitize_log_str(&path)
                ));
            }
        }

        self.mark_done(id);
        self.ndone += 1;
    }

    fn on_header(&mut self, p: &[u8]) {
        let hdr = match ParsedHeader::parse(p) {
            Ok(h) => h,
            Err(why) => {
                let id_str = if p.len() >= 8 {
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&p[..8]);
                    hex::encode(id)
                } else {
                    "unknown".to_string()
                };
                logmsg(&format!("REJECT header {}: {}", id_str, why));
                return;
            }
        };

        if self.completed_ids.contains(&hdr.id) {
            return;
        }

        if !self.table.contains_key(&hdr.id) && self.table.len() >= MAX_ACTIVE_ENTRIES {
            // Evict oldest incomplete entry if table full
            if let Some(&oldest_id) = self.table.keys().next() {
                if let Some(f) = self.table.remove(&oldest_id) {
                    self.total_early_bytes = self
                        .total_early_bytes
                        .saturating_sub(f.early_syms.iter().map(|e| e.data.len()).sum());
                }
            }
        }

        let total_early = &mut self.total_early_bytes;
        let f = self.table.entry(hdr.id).or_insert_with(|| FileState {
            id: hdr.id,
            has_hdr: false,
            done: false,
            ftype: 'f',
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            size: 0,
            psize: 0,
            k: 1,
            csz: 1024,
            meth: 0,
            crc: 0,
            path: String::new(),
            link: String::new(),
            dec: None,
            nsymbols: 0,
            early_syms: Vec::new(),
        });

        if f.done || f.has_hdr {
            return;
        }

        f.ftype = hdr.ftype;
        f.mode = hdr.mode;
        f.uid = hdr.uid;
        f.gid = hdr.gid;
        f.mtime_sec = hdr.mtime_sec;
        f.mtime_nsec = hdr.mtime_nsec;
        f.size = hdr.size;
        f.psize = hdr.psize;
        f.k = hdr.k;
        f.csz = hdr.csz;
        f.meth = hdr.meth;
        f.crc = hdr.fcrc;
        f.path = hdr.path.clone();
        f.link = hdr.link.clone();
        f.has_hdr = true;

        let safe_path = sanitize_log_str(&f.path);
        if f.meth != 0 {
            logmsg(&format!(
                "START {} ({}, {} B, {} B fast-lzma2, {} RaptorQ symbols @ {} B, CRC {:08x})",
                safe_path, f.ftype, f.size, f.psize, f.k, f.csz, f.crc
            ));
        } else {
            logmsg(&format!(
                "START {} ({}, {} B, {} RaptorQ symbols @ {} B, CRC {:08x})",
                safe_path, f.ftype, f.size, f.k, f.csz, f.crc
            ));
        }

        let mut ready = false;
        if (hdr.ftype == 'f' || hdr.ftype == 'm') && hdr.psize > 0 {
            let mut dec = match RaptorQDecoder::new(hdr.psize as usize, hdr.csz as usize) {
                Some(d) => d,
                None => {
                    f.has_hdr = false;
                    return;
                }
            };
            let early = std::mem::take(&mut f.early_syms);
            for es in early {
                *total_early = total_early.saturating_sub(es.data.len());
                if es.csz == f.csz {
                    f.nsymbols += 1;
                    if dec.receive_symbol(es.esi, &es.data) {
                        ready = true;
                    }
                }
            }
            f.dec = Some(dec);
        }

        if ready {
            self.finalize_file(hdr.id);
        } else if (hdr.ftype != 'f' && hdr.ftype != 'm') || hdr.psize == 0 {
            if hdr.ftype == 'f' || hdr.ftype == 'm' {
                self.finalize_file(hdr.id);
            } else {
                self.finalize_other(hdr.id);
            }
        }
    }

    fn on_data(&mut self, p: &[u8]) {
        if p.len() < 16 {
            return;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&p[..8]);
        let esi = u32::from_be_bytes(p[8..12].try_into().unwrap());
        let csz = u32::from_be_bytes(p[12..16].try_into().unwrap());
        let sym_data = &p[16..];

        if sym_data.len() != csz as usize {
            return;
        }
        if (csz as u64) < MIN_CSZ || (csz as u64) > MAX_CSZ {
            return;
        }
        if self.completed_ids.contains(&id) {
            return;
        }

        if !self.table.contains_key(&id) {
            if self.table.len() >= MAX_ACTIVE_ENTRIES {
                return;
            }
            if self.total_early_bytes + sym_data.len() > MAX_TOTAL_EARLY_BYTES {
                return;
            }
        }

        let f = self.table.entry(id).or_insert_with(|| FileState {
            id,
            has_hdr: false,
            done: false,
            ftype: 'f',
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            size: 0,
            psize: 0,
            k: 1,
            csz,
            meth: 0,
            crc: 0,
            path: String::new(),
            link: String::new(),
            dec: None,
            nsymbols: 0,
            early_syms: Vec::new(),
        });

        if f.done {
            return;
        }

        if !f.has_hdr {
            if f.early_syms.len() >= MAX_EARLY_SYMBOLS_PER_ID {
                return;
            }
            if self.total_early_bytes + sym_data.len() > MAX_TOTAL_EARLY_BYTES {
                return;
            }
            if f.early_syms.iter().any(|e| e.esi == esi) {
                return;
            }
            self.total_early_bytes += sym_data.len();
            f.early_syms.push(EarlySymbol {
                esi,
                csz,
                data: sym_data.to_vec(),
            });
            return;
        }

        let mut ready = false;
        if let Some(dec) = f.dec.as_mut() {
            if csz == f.csz {
                f.nsymbols += 1;
                if dec.receive_symbol(esi, sym_data) {
                    ready = true;
                }
            }
        }

        if ready {
            self.finalize_file(id);
        }
    }

    fn process_frame(&mut self, pay: &[u8], bit_flips: usize) {
        if pay.len() < 8 {
            return;
        }
        self.total_valid_frames += 1;
        if bit_flips > 0 {
            self.sc_ldpc_bit_flips += bit_flips;
            self.sc_ldpc_frames_corrected += 1;
        }

        if pay.len() >= 32 && (pay[8] == b'f' || pay[8] == b'd' || pay[8] == b'l' || pay[8] == b'm')
        {
            self.on_header(pay);
        } else {
            self.on_data(pay);
        }
    }

    fn finish(&mut self) {
        if let Some(batch) = self.active_batch.take() {
            if !batch.is_complete() {
                logmsg(&format!(
                    "[AUTH] Transfer '{}' incomplete at finish: quarantine purged, unverified files discarded.",
                    batch.transfer_id
                ));
                batch.purge();
            }
        }
        let pending_dir = self.out_dir.join(".sxfer_staging_pending");
        if pending_dir.exists() {
            let _ = fs::remove_dir_all(&pending_dir);
        }

        for (path, mode, uid, gid, mt_s, mt_ns) in self.dirs.iter().rev() {
            if let Ok(m) = fs::symlink_metadata(path) {
                if m.is_dir() && !m.file_type().is_symlink() {
                    self.apply_meta(path, 'd', *mode, *uid, *gid, *mt_s, *mt_ns);
                }
            }
        }

        for f in self.table.values() {
            if f.done {
                continue;
            }
            if f.has_hdr {
                logmsg(&format!(
                    "INCOMPLETE {}: received {} symbols (need more RaptorQ repair symbols)",
                    sanitize_log_str(&f.path),
                    f.nsymbols
                ));
            } else {
                let hx = hex::encode(f.id);
                logmsg(&format!("INCOMPLETE entry {}: header never received", hx));
            }
        }

        logmsg(&format!(
            "SUMMARY {} file(s) verified, {} damaged frame(s) dropped, {} entries complete",
            self.nok, self.nbad, self.ndone
        ));

        let lzma_savings = if self.total_raw_bytes > self.total_wire_payload_bytes {
            format!(
                "{:.1}% saved",
                (1.0 - (self.total_wire_payload_bytes as f64 / self.total_raw_bytes as f64))
                    * 100.0
            )
        } else {
            "0.0% (raw)".to_string()
        };

        logmsg(&format!(
            "METRICS [Fast-LZMA2: {} B -> {} B ({})] [SC-LDPC: {} bit flips corrected across {} frames] [RaptorQ: {} symbols received / {} source symbols needed] [Framing: {} frames verified / {} dropped]",
            self.total_raw_bytes,
            self.total_wire_payload_bytes,
            lzma_savings,
            self.sc_ldpc_bit_flips,
            self.sc_ldpc_frames_corrected,
            self.total_symbols_received,
            self.total_symbols_needed,
            self.total_valid_frames,
            self.nbad
        ));
    }
}

mod hex {
    pub fn encode(data: [u8; 8]) -> String {
        let mut s = String::with_capacity(16);
        for b in data {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

// ----------------------------------------------------------------- CLI & MAIN
fn print_usage(prog: &str) {
    eprintln!(
        "sxfer v{ver} - High-Speed Unidirectional Serial File Transfer\n\n\
        Usage:\n  \
          {prog} send -d DEV [-b BAUD] [-r ROUNDS] [-s SIGN_KEY] [-w SPOOL_DIR | PATHS...]\n  \
          {prog} recv -d DEV [-b BAUD] [-o OUT_DIR] [-q QUIET_SEC] [--verify-key KEY] [--require-auth]\n  \
          {prog} keygen [-o KEY_PREFIX]\n  \
          {prog} daemon [--config /path/to/sxfer.conf]\n  \
          {prog} systemd install\n  \
          {prog} tray [--config /path/to/sxfer.conf]\n  \
          {prog} crc FILE\n\n\
        Commands:\n  \
          send      Transmit files or monitor watch directory\n  \
          recv      Receive and verify files continuously\n  \
          keygen    Generate Ed25519 cryptographic signing keypair\n  \
          daemon    Run background daemon based on /etc/sxfer.conf\n  \
          systemd   Install and enable systemd service unit\n  \
          tray      Run Windows System Tray background service\n  \
          crc       Compute and print standard CRC32 of a file",
        ver = env!("CARGO_PKG_VERSION")
    );
}

fn send_batch(
    paths: Vec<PathBuf>,
    dev_file: &mut File,
    baud: u64,
    chunk_size: usize,
    pct: usize,
    rounds: usize,
    sign_key: Option<std::sync::Arc<ring::signature::Ed25519KeyPair>>,
) -> Result<(), String> {
    let (comp_tx, comp_rx) = sync_channel::<QueueItem>(32);
    let (tx_tx, tx_rx) = sync_channel::<Vec<u8>>(128);

    let sign_key_clone = sign_key;

    let mut skipped = 0;
    let mut enc_ok = false;
    let mut tx_ok = false;

    std::thread::scope(|s| {
        let h1 =
            s.spawn(|| crawl_and_compress(paths, chunk_size, comp_tx, sign_key_clone.as_deref()));

        let h2 = s.spawn(|| encode_stage(comp_rx, tx_tx, pct, rounds));

        let h3 = s.spawn(|| tx_worker(tx_rx, dev_file, baud));

        skipped = h1.join().unwrap_or(0);
        enc_ok = h2.join().unwrap_or(false);
        tx_ok = h3.join().unwrap_or(false);
    });

    if skipped > 0 {
        return Err(format!("{} item(s) could not be read or queued", skipped));
    }
    if !enc_ok {
        return Err("encoder could not queue all frames".to_string());
    }
    if !tx_ok {
        return Err("device write failed".to_string());
    }
    Ok(())
}

type SnapshotItem = (PathBuf, u64, Option<SystemTime>, u64);

/// (path, len, mtime, inode) of everything under `path`, or None if any part cannot be inspected.
fn tree_snapshot(path: &Path) -> Option<Vec<SnapshotItem>> {
    fn walk(p: &Path, out: &mut Vec<SnapshotItem>) -> Option<()> {
        let m = fs::symlink_metadata(p).ok()?;
        #[cfg(unix)]
        let ino = {
            use std::os::unix::fs::MetadataExt;
            m.ino()
        };
        #[cfg(not(unix))]
        let ino = 0u64;
        out.push((p.to_path_buf(), m.len(), m.modified().ok(), ino));
        if m.is_dir() {
            let mut names: Vec<PathBuf> = fs::read_dir(p)
                .ok()?
                .map(|e| e.map(|e| e.path()))
                .collect::<Result<_, _>>()
                .ok()?;
            names.sort();
            for c in names {
                walk(&c, out)?;
            }
        }
        Some(())
    }
    let mut v = Vec::new();
    walk(path, &mut v)?;
    Some(v)
}

fn is_file_ready_to_send(path: &Path) -> bool {
    let meta1 = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    if meta1.file_type().is_symlink() {
        return true;
    }

    if meta1.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                if !is_file_ready_to_send(&entry.path()) {
                    return false;
                }
            }
        }
        return true;
    }

    if !meta1.file_type().is_file() {
        return false;
    }

    // Regular file:
    // 1. Check non-blocking lock to see if writing process holds an exclusive lock
    if check_file_locked(path) {
        return false;
    }

    // 2. Measure size and timestamp stability over 250ms debounce
    let size1 = meta1.len();
    let mod1 = meta1.modified().ok();

    thread::sleep(Duration::from_millis(250));

    let meta2 = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    let size2 = meta2.len();
    let mod2 = meta2.modified().ok();

    if size1 != size2 || mod1 != mod2 {
        return false;
    }

    true
}

pub fn do_send(args: &[String]) -> Result<(), String> {
    install_signal_handlers();
    let mut dev = "/dev/ttyUSB0".to_string();
    let mut baud = 115200u64;
    let mut rounds = 1usize;
    let mut chunk = 0usize;
    let mut pct = 35usize;
    let mut watch_dir: Option<PathBuf> = None;
    let mut sign_key_path: Option<PathBuf> = None;
    let mut paths = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => {
                i += 1;
                dev = args.get(i).ok_or("-d requires device")?.clone();
            }
            "-b" => {
                i += 1;
                baud = args
                    .get(i)
                    .ok_or("-b requires baud")?
                    .parse()
                    .map_err(|_| "invalid baud")?;
            }
            "-r" => {
                i += 1;
                rounds = args
                    .get(i)
                    .ok_or("-r requires rounds")?
                    .parse()
                    .map_err(|_| "invalid rounds")?;
                if rounds == 0 {
                    return Err("rounds must be at least 1".to_string());
                }
            }
            "-c" => {
                i += 1;
                chunk = args
                    .get(i)
                    .ok_or("-c requires chunk size")?
                    .parse()
                    .map_err(|_| "invalid chunk size")?;
            }
            "-f" => {
                i += 1;
                pct = args
                    .get(i)
                    .ok_or("-f requires pct")?
                    .parse()
                    .map_err(|_| "invalid pct")?;
            }
            "-s" | "--sign-key" => {
                i += 1;
                let kpath = args.get(i).ok_or("-s / --sign-key requires key path")?;
                sign_key_path = Some(PathBuf::from(kpath));
            }
            "-w" | "--watch" => {
                i += 1;
                let dir_str = args.get(i).ok_or("-w requires directory")?;
                watch_dir = Some(PathBuf::from(dir_str));
            }
            "-h" | "--help" => {
                eprintln!("Usage: sxfer send [options] [PATH...]\n\
                           -d DEV          serial device or file (default /dev/ttyUSB0)\n\
                           -b BAUD         baud rate (default 115200)\n\
                           -s KEY_PATH     sign transfers with Ed25519 private key\n\
                           -w DIR          watch directory: auto-create, transmit present files, and delete them\n\
                           -c BYTES        symbol chunk size (default: auto)\n\
                           -f PCT          RaptorQ repair percentage (default 35)\n\
                           -r ROUNDS       repeat rounds (default 1)");
                return Ok(());
            }
            arg if !arg.starts_with('-') => {
                paths.push(PathBuf::from(arg));
            }
            other => return Err(format!("Unknown option: {}", other)),
        }
        i += 1;
    }

    if watch_dir.is_none() && paths.is_empty() {
        return Err("No paths specified to send (use -w DIR for watch directory mode)".to_string());
    }

    let sign_key = if let Some(ref kp) = sign_key_path {
        let key = auth::load_private_key(kp)?;
        logmsg(&format!(
            "[AUTH] Loaded Ed25519 signing key from {}",
            kp.display()
        ));
        Some(std::sync::Arc::new(key))
    } else {
        None
    };

    if baud >= 2_500_000 && pct == 35 {
        pct = 100;
    }

    let chunk_size = if chunk != 0 {
        chunk
    } else {
        auto_chunk_size(baud)
    };
    let mut file = open_line_send(Path::new(&dev), baud)
        .map_err(|e| format!("Failed to open {}: {}", dev, e))?;

    if let Some(wdir) = watch_dir {
        if !wdir.exists() {
            fs::create_dir_all(&wdir).map_err(|e| {
                format!("Failed to create watch directory {}: {}", wdir.display(), e)
            })?;
            logmsg(&format!("WATCH created directory: {}", wdir.display()));
        }
        logmsg(&format!(
            "WATCH monitoring {} (device {}, {} baud, chunk {} B) (Ctrl-C to stop)",
            wdir.display(),
            dev,
            baud,
            chunk_size
        ));

        while !STOP_FLAG.load(Ordering::Relaxed) {
            let mut entries: Vec<PathBuf> = match fs::read_dir(&wdir) {
                Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(_) => Vec::new(),
            };

            if entries.is_empty() {
                thread::sleep(Duration::from_millis(250));
                continue;
            }

            entries.sort();

            for entry in entries {
                if !entry.exists() {
                    continue;
                }

                // If file is actively being written by another process, wait until writing is finished
                if !is_file_ready_to_send(&entry) {
                    logmsg(&format!(
                        "WATCH waiting for file to finish writing: {}",
                        sanitize_log_str(&entry.to_string_lossy())
                    ));
                    continue;
                }

                logmsg(&format!(
                    "WATCH processing: {}",
                    sanitize_log_str(&entry.to_string_lossy())
                ));
                let before = tree_snapshot(&entry);
                if let Err(e) = send_batch(
                    vec![entry.clone()],
                    &mut file,
                    baud,
                    chunk_size,
                    pct,
                    rounds,
                    sign_key.clone(),
                ) {
                    logmsg(&format!(
                        "ERROR sending {}: {}",
                        sanitize_log_str(&entry.to_string_lossy()),
                        e
                    ));
                    continue;
                }

                // Delete only if everything was transmitted AND the tree is exactly what was sent:
                // files added or modified during transmission must survive for the next pass.
                if before.is_none() || before != tree_snapshot(&entry) {
                    logmsg(&format!(
                        "WATCH changed during send, NOT DELETED: {}",
                        sanitize_log_str(&entry.to_string_lossy())
                    ));
                    continue;
                }
                if entry.is_dir() && !entry.is_symlink() {
                    let _ = fs::remove_dir_all(&entry);
                } else {
                    let _ = fs::remove_file(&entry);
                }
                logmsg(&format!(
                    "SENT & DELETED {}",
                    sanitize_log_str(&entry.to_string_lossy())
                ));
            }

            thread::sleep(Duration::from_millis(150));
        }

        logmsg("WATCH stopped");
        return Ok(());
    }

    logmsg(&format!(
        "STREAM starting continuous 3-stage pipeline (device {}, {} baud, chunk {} B)",
        dev, baud, chunk_size
    ));

    send_batch(paths, &mut file, baud, chunk_size, pct, rounds, sign_key)?;
    logmsg("FINISHED");
    Ok(())
}

pub fn do_recv(args: &[String]) -> Result<(), String> {
    install_signal_handlers();
    let mut dev = "/dev/ttyUSB0".to_string();
    let mut baud = 115200u64;
    let mut out_dir = PathBuf::from("./recv");
    let mut idle_sec = 0u64;
    let mut restore_owner = false;
    let mut verify_key_path: Option<PathBuf> = None;
    let mut require_auth = false;
    let mut replay_cache_path: Option<PathBuf> = None;
    let mut max_clock_skew_secs = auth::DEFAULT_MAX_CLOCK_SKEW_SECS;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => {
                i += 1;
                dev = args.get(i).ok_or("-d requires device")?.clone();
            }
            "-b" => {
                i += 1;
                baud = args
                    .get(i)
                    .ok_or("-b requires baud")?
                    .parse()
                    .map_err(|_| "invalid baud")?;
            }
            "-o" => {
                i += 1;
                out_dir = PathBuf::from(args.get(i).ok_or("-o requires out dir")?);
            }
            "-q" => {
                i += 1;
                idle_sec = args
                    .get(i)
                    .ok_or("-q requires seconds")?
                    .parse()
                    .map_err(|_| "invalid seconds")?;
            }
            "-p" => {
                restore_owner = true;
            }
            "-k" => { /* accept daemon keep_damaged flag */ }
            "--verify-key" => {
                i += 1;
                let kpath = args.get(i).ok_or("--verify-key requires public key path")?;
                verify_key_path = Some(PathBuf::from(kpath));
            }
            "--require-auth" => {
                require_auth = true;
            }
            "--replay-cache" => {
                i += 1;
                let cpath = args.get(i).ok_or("--replay-cache requires cache path")?;
                replay_cache_path = Some(PathBuf::from(cpath));
            }
            "--max-clock-skew" => {
                i += 1;
                max_clock_skew_secs = args
                    .get(i)
                    .ok_or("--max-clock-skew requires seconds")?
                    .parse()
                    .map_err(|_| "invalid max clock skew seconds")?;
            }
            "-h" | "--help" => {
                eprintln!("Usage: sxfer recv [options]\n\
                           -d DEV              serial device or file (default /dev/ttyUSB0)\n\
                           -b BAUD             baud rate (default 115200)\n\
                           -o DIR              output directory (default ./recv)\n\
                           -q SEC              quit SEC seconds after quiet (default: 0 = loop indefinitely)\n\
                           -p                  restore owner/group (requires root)\n\
                           --verify-key PATH   trusted Ed25519 public key file for signature verification\n\
                           --require-auth      reject all unauthenticated / unsigned transfers\n\
                           --replay-cache PATH replay protection cache file path\n\
                           --max-clock-skew S  maximum allowed transfer age / clock skew in seconds (default: 300)");
                return Ok(());
            }
            other => return Err(format!("Unknown option: {}", other)),
        }
        i += 1;
    }

    let verify_key = if let Some(ref kp) = verify_key_path {
        let key_bytes = auth::load_public_key(kp)?;
        logmsg(&format!(
            "[AUTH] Loaded trusted Ed25519 public key from {}",
            kp.display()
        ));
        Some(key_bytes)
    } else {
        None
    };

    fs::create_dir_all(&out_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;
    let canon_out = out_dir
        .canonicalize()
        .map_err(|e| format!("Failed to canonicalize output dir: {}", e))?;

    let default_cache_path =
        replay_cache_path.or_else(|| canon_out.join(".sxfer_replay_cache.txt").into());

    let mut ctx = ReceiverContext::new(
        canon_out.clone(),
        restore_owner,
        verify_key.clone(),
        require_auth,
        default_cache_path,
        max_clock_skew_secs,
    );
    let mut file = open_line_recv(Path::new(&dev), baud)
        .map_err(|e| format!("Failed to open {}: {}", dev, e))?;

    if verify_key.is_some() {
        logmsg(&format!(
            "listening on {} [AUTHENTICATED MODE: Ed25519 verification active], writing to {} (Ctrl-C to stop)",
            dev,
            canon_out.display()
        ));
    } else if require_auth {
        logmsg(&format!(
            "listening on {} [STRICT AUTHENTICATION REQUIRED: rejecting unauthenticated transfers], writing to {} (Ctrl-C to stop)",
            dev,
            canon_out.display()
        ));
    } else {
        logmsg(&format!(
            "listening on {} [LEGACY MODE: unauthenticated transfers accepted], writing to {} (Ctrl-C to stop)",
            dev,
            canon_out.display()
        ));
    }

    let mut in_buf = Vec::with_capacity(1 << 20);
    let mut read_buf = [0u8; 65536];
    let mut last_activity = Instant::now();
    let mut started = false;

    #[cfg(unix)]
    let raw_fd = {
        use std::os::unix::io::AsRawFd;
        file.as_raw_fd()
    };
    #[cfg(unix)]
    let mut pfd = PollFd {
        fd: raw_fd,
        events: POLLIN,
        revents: 0,
    };

    while !STOP_FLAG.load(Ordering::Relaxed) {
        #[cfg(unix)]
        {
            let poll_timeout = if idle_sec > 0 { 200 } else { 500 };
            let ret = unsafe { poll(&mut pfd, 1, poll_timeout) };
            if STOP_FLAG.load(Ordering::Relaxed) {
                break;
            }
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                logmsg(&format!("poll error: {}", err));
                break;
            }
            if ret == 0 {
                if idle_sec > 0 && started && last_activity.elapsed().as_secs() >= idle_sec {
                    break;
                }
                continue;
            }
        }

        match file.read(&mut read_buf) {
            Ok(0) => {
                if idle_sec > 0 && started && last_activity.elapsed().as_secs() >= idle_sec {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Ok(n) => {
                started = true;
                last_activity = Instant::now();
                in_buf.extend_from_slice(&read_buf[..n]);

                let mut p = 0;
                while p < in_buf.len() {
                    while p < in_buf.len() && in_buf[p] == 0x00 {
                        p += 1;
                    }
                    if p >= in_buf.len() {
                        break;
                    }

                    let mut found = false;
                    let mut search_start = p;
                    while let Some(pos) = in_buf[search_start..].iter().position(|&b| b == 0x00) {
                        let frame_end = search_start + pos;
                        let candidate = &in_buf[p..frame_end];
                        if candidate.len() >= 32 {
                            if let Some(res) = mod_frame_decode(candidate) {
                                ctx.process_frame(&res.payload, res.bit_corrections);
                                p = frame_end + 1;
                                found = true;
                                break;
                            }
                        }
                        if frame_end + 1 < in_buf.len() && frame_end - p < 1024 {
                            search_start = frame_end + 1;
                        } else {
                            if candidate.len() >= 32 {
                                ctx.nbad += 1;
                            }
                            p = frame_end + 1;
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        break;
                    }
                }
                in_buf.drain(..p);

                // Bound buffer memory: if no frame boundary found in MAX_IN_BUF, drop old data
                if in_buf.len() > MAX_IN_BUF {
                    let drain_len = in_buf.len() - (32 * 1024);
                    in_buf.drain(..drain_len);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if STOP_FLAG.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if idle_sec > 0 && started && last_activity.elapsed().as_secs() >= idle_sec {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                logmsg(&format!("read error: {}", e));
                break;
            }
        }

        if idle_sec > 0 && started && last_activity.elapsed().as_secs() >= idle_sec {
            break;
        }
    }

    ctx.finish();
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        #[cfg(windows)]
        {
            if let Err(e) = tray_windows::run_tray_service(None) {
                eprintln!("sxfer: {}", e);
                std::process::exit(1);
            }
            return;
        }
        #[cfg(not(windows))]
        {
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }

    match args[1].as_str() {
        "--version" | "-V" => {
            println!("sxfer {}", env!("CARGO_PKG_VERSION"));
        }
        "send" => {
            if let Err(e) = do_send(&args[2..]) {
                eprintln!("sxfer: {}", e);
                std::process::exit(1);
            }
        }
        "recv" => {
            if let Err(e) = do_recv(&args[2..]) {
                eprintln!("sxfer: {}", e);
                std::process::exit(1);
            }
        }
        "keygen" => {
            let mut out_prefix = PathBuf::from("sxfer_key");
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-o" | "--output" => {
                        i += 1;
                        if let Some(p) = args.get(i) {
                            out_prefix = PathBuf::from(p);
                        }
                    }
                    "-h" | "--help" => {
                        eprintln!(
                            "Usage: {} keygen [-o PREFIX]\n\
                             Generates a new Ed25519 signing keypair for authenticated transfers.\n\
                             -o PREFIX    output key file prefix (default: sxfer_key)",
                            args[0]
                        );
                        return;
                    }
                    _ => {}
                }
                i += 1;
            }
            let priv_path = out_prefix.with_extension("priv");
            let pub_path = out_prefix.with_extension("pub");
            let (priv_bytes, pub_bytes) = match auth::generate_keypair() {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("sxfer keygen: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = auth::save_keypair(&priv_path, &pub_path, &priv_bytes, &pub_bytes) {
                eprintln!("sxfer keygen: {}", e);
                std::process::exit(1);
            }
            println!("Generated Ed25519 transfer keypair:");
            println!("  Private Key (keep secret!): {}", priv_path.display());
            println!("  Public Key (for receiver):  {}", pub_path.display());
        }
        "daemon" | "service" => {
            let mut conf_path: Option<PathBuf> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" | "-c" => {
                        i += 1;
                        if let Some(p) = args.get(i) {
                            conf_path = Some(PathBuf::from(p));
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if let Err(e) = service::run_daemon(conf_path.as_deref()) {
                eprintln!("sxfer daemon: {}", e);
                std::process::exit(1);
            }
        }
        "systemd" => {
            if args.len() >= 3 && args[2] == "install" {
                if let Err(e) = service::install_systemd_service() {
                    eprintln!("sxfer systemd install: {}", e);
                    std::process::exit(1);
                }
            } else {
                eprintln!("Usage: {} systemd install", args[0]);
                std::process::exit(1);
            }
        }
        "tray" => {
            let mut conf_path: Option<PathBuf> = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" | "-c" => {
                        i += 1;
                        if let Some(p) = args.get(i) {
                            conf_path = Some(PathBuf::from(p));
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            if let Err(e) = tray_windows::run_tray_service(conf_path.as_deref()) {
                eprintln!("sxfer tray: {}", e);
                std::process::exit(1);
            }
        }
        "crc" | "crc32" => {
            if args.len() < 3 {
                eprintln!("Usage: {} crc FILE", args[0]);
                std::process::exit(1);
            }
            let path = Path::new(&args[2]);
            match crc32_file(path) {
                Ok(c) => println!("{:08x}  {}", c, path.display()),
                Err(e) => {
                    eprintln!("sxfer: {}: {}", path.display(), e);
                    std::process::exit(1);
                }
            }
        }
        "-h" | "--help" => {
            print_usage(&args[0]);
        }
        other => {
            eprintln!("Unknown command: {}", other);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }
}

#[cfg(all(test, unix))]
mod security_tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("sxfer_sec_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn prep_dest_rejects_traversal_and_symlinks() {
        let root = tmp("root");
        let outside = tmp("outside");
        let rx = ReceiverContext::new(root.clone(), false, None, false, None, 300);

        assert!(rx.prep_dest("../x").is_none());
        assert!(rx.prep_dest("a/../../x").is_none());
        assert!(rx.prep_dest("").is_none());
        assert!(rx.prep_dest("ok/file.txt").is_some());

        // planted symlink to an outside dir must not be traversed or populated
        std::os::unix::fs::symlink(&outside, root.join("evil")).unwrap();
        assert!(rx.prep_dest("evil/sub/pwn.txt").is_none());
        assert!(!outside.join("sub").exists());
        assert!(rx.prep_dest("evil/pwn.txt").is_none());
    }

    #[test]
    fn metadata_never_follows_symlink_or_sets_suid() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmp("meta");
        let outside = tmp("meta_out");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        let link = root.join("dirlink");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        // header claims a directory, but the path is a symlink -> ignored
        apply_file_metadata(&link, 'd', 0o777, Some((0, 0)), 1, 0);
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o7777,
            0o700
        );

        let f = root.join("f");
        fs::write(&f, b"x").unwrap();
        apply_file_metadata(&f, 'f', 0o6755, Some((0, 0)), 1, 0);
        assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o7000, 0);
    }
}

#[cfg(test)]
mod audit_regressions;
