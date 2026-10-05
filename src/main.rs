//! sxfer - One-way, high-speed serial file tree transfer tool in Rust.

mod config;
mod crc32;
mod ldpc;
mod lzma2;
mod mod_codec;
mod raptorq;
mod serial;


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

static STOP_FLAG: AtomicBool = AtomicBool::new(false);
static TRANSFER_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn logmsg(msg: &str) {
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
    fn chown(path: *const std::os::raw::c_char, owner: u32, group: u32) -> std::os::raw::c_int;
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
        signal(2, sig_handler);  // SIGINT (Ctrl-C)
        signal(15, sig_handler); // SIGTERM
        signal(1, sig_handler);  // SIGHUP
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
            (meta.mode() & 0o7777) as u32,
            meta.uid(),
            meta.gid(),
            meta.mtime(),
            meta.mtime_nsec() as u32,
        )
    }
    #[cfg(not(unix))]
    {
        let mode = if meta.permissions().readonly() { 0o444 } else { 0o644 };
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

fn apply_file_metadata(path: &Path, ftype: char, mode: u32, uid: u32, gid: u32, mt_s: i64, mt_ns: u32) {
    #[cfg(unix)]
    {
        unsafe {
            if geteuid() == 0 {
                let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
                if ftype == 'l' {
                    lchown(c_path.as_ptr(), uid, gid);
                } else {
                    chown(c_path.as_ptr(), uid, gid);
                }
            }
        }

        if ftype != 'l' {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777));
        }

        unsafe {
            let times = [
                Timespec { tv_sec: mt_s, tv_nsec: mt_ns as i64 },
                Timespec { tv_sec: mt_s, tv_nsec: mt_ns as i64 },
            ];
            let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
            let flags = if ftype == 'l' { 0x100 } else { 0 }; // AT_SYMLINK_NOFOLLOW = 0x100
            utimensat(-100, c_path.as_ptr(), times.as_ptr(), flags); // AT_FDCWD = -100
        }
    }

    #[cfg(not(unix))]
    {
        let _ = uid;
        let _ = gid;
        if ftype != 'l' {
            if let Ok(mut perms) = fs::metadata(path).map(|m| m.permissions()) {
                if (mode & 0o200) == 0 {
                    perms.set_readonly(true);
                } else {
                    perms.set_readonly(false);
                }
                let _ = fs::set_permissions(path, perms);
            }
            if mt_s > 0 {
                if let Ok(f) = OpenOptions::new().write(true).open(path) {
                    let st = UNIX_EPOCH + Duration::new(mt_s as u64, mt_ns);
                    let _ = f.set_modified(st);
                }
            }
        }
    }
}

fn create_symlink(link_target: &str, dest_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(link_target, dest_path)
    }
    #[cfg(windows)]
    {
        let target_path = Path::new(link_target);
        if target_path.is_dir() {
            std::os::windows::fs::symlink_dir(target_path, dest_path)
        } else {
            std::os::windows::fs::symlink_file(target_path, dest_path)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Symlinks not supported"))
    }
}

fn check_file_locked(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(f) = OpenOptions::new().read(true).open(path) {
            let fd = f.as_raw_fd();
            let lock_res = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
            if lock_res != 0 {
                return true;
            }
            unsafe { flock(fd, LOCK_UN); }
            false
        } else {
            true
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{LockFileEx, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
        use windows_sys::Win32::Foundation::HANDLE;
        use windows_sys::Win32::System::IO::OVERLAPPED;

        if let Ok(f) = OpenOptions::new().read(true).open(path) {
            let handle = f.as_raw_handle() as HANDLE;
            unsafe {
                let mut ov: OVERLAPPED = std::mem::zeroed();
                let res = LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &mut ov);
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
) {
    const COMPRESSION_LEVEL: i32 = 9;
    for path in paths {
        let root = path.clone();
        let walker = walkdir(&path);
        for entry in walker {
            let rel = if !entry.is_absolute() {
                entry.to_string_lossy().to_string()
            } else if let Ok(stripped) = entry.strip_prefix(root.parent().unwrap_or(&root)) {
                stripped.to_string_lossy().to_string()
            } else {
                entry.file_name().unwrap_or_default().to_string_lossy().to_string()
            };

            let clean_rel = rel.trim_start_matches('/').trim_start_matches("./").to_string();
            if clean_rel.is_empty() {
                continue;
            }


            let meta = match fs::symlink_metadata(&entry) {
                Ok(m) => m,
                Err(e) => {
                    logmsg(&format!("skip (stat failed): {} ({})", entry.display(), e));
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
                item.link_target = fs::read_link(&entry)
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                logmsg(&format!("QUEUED {} (symlink -> {})", item.rel_path, item.link_target));
                let _ = tx.send(item);
            } else if meta.is_dir() {
                item.ftype = 'd';
                item.size = 0;
                item.psize = 0;
                logmsg(&format!("QUEUED {} (dir)", item.rel_path));
                let _ = tx.send(item);
            } else if meta.is_file() {
                item.ftype = 'f';
                item.fcrc = crc32_file(&entry).unwrap_or(0);

                let raw_data = match fs::read(&entry) {
                    Ok(d) => d,
                    Err(e) => {
                        logmsg(&format!("skip (read failed): {} ({})", entry.display(), e));
                        continue;
                    }
                };

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
                item.k = ((item.psize as usize + chunk_size - 1) / chunk_size).max(1) as u32;

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

                let _ = tx.send(item);
            }
        }
    }
}

fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    result.push(dir.to_path_buf());
    if dir.is_dir() && !dir.is_symlink() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() && !p.is_symlink() {
                    result.extend(walkdir(&p));
                } else {
                    result.push(p);
                }
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
) {
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

        let num_hdr_copies = if item.ftype == 'f' {
            ((pct / 30) + 4).clamp(4, 24).max(rounds * 4)
        } else {
            ((pct / 20) + 6).clamp(6, 32).max(rounds * 6)
        };
        for _ in 0..num_hdr_copies {
            let frame = mod_frame_encode(&hdr);
            let _ = tx.send(frame);
        }

        // 2. RaptorQ Fountain Symbols
        if item.ftype == 'f' && item.psize > 0 {
            if let Some(rq) = RaptorQEncoder::new(&item.payload, item.csz as usize) {
                let num_symbols = rq.total_symbols_to_send(pct);
                let mut sym_buf = vec![0u8; item.csz as usize];
                let mut pkt = Vec::with_capacity(16 + item.csz as usize);
                let hdr_freq = if pct >= 100 { 4 } else if pct >= 50 { 8 } else { 16 };


                for round in 0..rounds {
                    for s in 0..num_symbols {
                        let esi = (round * num_symbols + s) as u32;
                        if esi > 0 && (esi as usize % hdr_freq) == 0 {
                            let mid_hdr = mod_frame_encode(&hdr);
                            let _ = tx.send(mid_hdr);
                        }

                        rq.encode_symbol(esi, &mut sym_buf);

                        pkt.clear();
                        pkt.extend_from_slice(&item.id);
                        pkt.extend_from_slice(&esi.to_be_bytes());
                        pkt.extend_from_slice(&item.csz.to_be_bytes());
                        pkt.extend_from_slice(&sym_buf);

                        let tx_frame = mod_frame_encode(&pkt);
                        let _ = tx.send(tx_frame);
                    }
                }
            }

            let end_copies = ((pct / 30) + 4).clamp(4, 24);
            for _ in 0..end_copies {
                let end_hdr = mod_frame_encode(&hdr);
                let _ = tx.send(end_hdr);
            }
        }
    }
}

fn tx_worker(rx: Receiver<Vec<u8>>, mut file: File, baud: u64) {
    if baud >= 2_500_000 {
        while let Ok(pkt) = rx.recv() {
            for chunk in pkt.chunks(64) {
                let _ = file.write_all(chunk);
                thread::sleep(Duration::from_micros(150));
            }
            // Inter-frame line recovery time (allows UART to return to idle HIGH)
            thread::sleep(Duration::from_micros(350));
        }
    } else {
        let mut batch = Vec::with_capacity(4096);
        while let Ok(pkt) = rx.recv() {
            if batch.len() + pkt.len() > 4096 {
                let _ = file.write_all(&batch);
                batch.clear();
            }
            if pkt.len() > 4096 {
                if !batch.is_empty() {
                    let _ = file.write_all(&batch);
                    batch.clear();
                }
                let _ = file.write_all(&pkt);
            } else {
                batch.extend_from_slice(&pkt);
            }
        }
        if !batch.is_empty() {
            let _ = file.write_all(&batch);
        }
    }
    flush_tty(&file);
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

struct ReceiverContext {
    out_dir: PathBuf,
    restore_owner: bool,
    table: HashMap<[u8; 8], FileState>,
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
    fn new(out_dir: PathBuf, restore_owner: bool) -> Self {
        Self {
            out_dir,
            restore_owner,
            table: HashMap::new(),
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

    fn prep_dest(&self, rel: &str) -> Option<PathBuf> {
        let clean = rel.trim_start_matches('/').trim_start_matches("./");
        if clean.is_empty() || clean.contains("..") {
            return None;
        }

        let full = self.out_dir.join(clean);
        if let Some(parent) = full.parent() {
            let _ = fs::create_dir_all(parent);
            if let Ok(canon_parent) = parent.canonicalize() {
                if let Ok(canon_root) = self.out_dir.canonicalize() {
                    if !canon_parent.starts_with(&canon_root) {
                        return None;
                    }
                }
            }
        }
        Some(full)
    }

    fn apply_meta(&self, path: &Path, ftype: char, mode: u32, uid: u32, gid: u32, mt_s: i64, mt_ns: u32) {
        let (u, g) = if self.restore_owner { (uid, gid) } else { (1000, 1000) };
        apply_file_metadata(path, ftype, mode, u, g, mt_s, mt_ns);
    }

    fn finalize_file(&mut self, id: [u8; 8]) {
        let (path, size, psize, crc, meth, mode, uid, gid, mtime_sec, mtime_nsec, nsymbols) = {
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
            )
        };

        let dest = match self.prep_dest(&path) {
            Some(d) => d,
            None => {
                logmsg(&format!("SKIP  unsafe path in header: {}", path));
                if let Some(f) = self.table.get_mut(&id) {
                    f.done = true;
                }
                self.ndone += 1;
                return;
            }
        };

        let dec_payload = if psize > 0 {
            match self.table.get(&id).and_then(|f| f.dec.as_ref()).and_then(|d| d.decode_data()) {
                Some(p) => p,
                None => {
                    logmsg(&format!("FAIL  {}: decoder error", path));
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
                    logmsg(&format!("FAIL  {}: LZMA2 decompression failed", path));
                    return;
                }
            }
        } else {
            dec_payload
        };

        let fcrc = Crc32::calculate(&final_data);
        if final_data.len() != size as usize || fcrc != crc {
            logmsg(&format!("FAIL  {}: CRC32 mismatch, waiting for more symbols", path));
            return;
        }

        let tmp_path = dest.with_extension("sxfer-part");
        if fs::write(&tmp_path, &final_data).is_err() || fs::rename(&tmp_path, &dest).is_err() {
            logmsg(&format!("FAIL  {}: failed to write to disk", path));
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
        if let Some(f) = self.table.get_mut(&id) {
            f.done = true;
            f.dec = None;
        }
        self.nok += 1;
        self.ndone += 1;
        logmsg(&format!("OK    {} ({} B, CRC {:08x}, {} symbols received)", path, size, crc, nsymbols));
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

        let dest = match self.prep_dest(&path) {
            Some(d) => d,
            None => {
                logmsg(&format!("SKIP  unsafe path in header: {}", path));
                if let Some(f) = self.table.get_mut(&id) {
                    f.done = true;
                }
                self.ndone += 1;
                return;
            }
        };

        if ftype == 'd' {
            let _ = fs::create_dir_all(&dest);
            self.dirs.push((dest, mode, uid, gid, mtime_sec, mtime_nsec));
            logmsg(&format!("DIR   {}", path));
        } else if ftype == 'l' {
            let _ = fs::remove_file(&dest);
            if create_symlink(&link, &dest).is_ok() {
                self.apply_meta(&dest, 'l', mode, uid, gid, mtime_sec, mtime_nsec);
                logmsg(&format!("LINK  {} -> {}", path, link));
            } else {
                logmsg(&format!("FAIL  {}: symlink creation failed", path));
            }
        }

        if let Some(f) = self.table.get_mut(&id) {
            f.done = true;
        }
        self.ndone += 1;
    }

    fn on_header(&mut self, p: &[u8]) {
        if p.len() < 8 + 1 + 12 + 8 + 4 + 8 + 8 + 4 + 4 + 2 + 1 + 1 + 4 + 2 {
            return;
        }

        let mut id = [0u8; 8];
        id.copy_from_slice(&p[..8]);

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

        let mut o = 8;
        let ftype = p[o] as char;
        o += 1;
        let mode = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        let uid = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        let gid = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        let mt_s = i64::from_be_bytes(p[o..o + 8].try_into().unwrap());
        o += 8;
        let mt_ns = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        let size = u64::from_be_bytes(p[o..o + 8].try_into().unwrap());
        o += 8;
        let psize = u64::from_be_bytes(p[o..o + 8].try_into().unwrap());
        o += 8;
        let k = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        let csz = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        o += 2; // pct
        let meth = p[o];
        o += 1;
        o += 1; // level
        let fcrc = u32::from_be_bytes(p[o..o + 4].try_into().unwrap());
        o += 4;
        let pl = u16::from_be_bytes(p[o..o + 2].try_into().unwrap()) as usize;
        o += 2;
        if o + pl + 2 > p.len() {
            return;
        }
        let path = String::from_utf8_lossy(&p[o..o + pl]).to_string();
        o += pl;
        let ll = u16::from_be_bytes(p[o..o + 2].try_into().unwrap()) as usize;
        o += 2;
        if o + ll > p.len() {
            return;
        }
        let link = String::from_utf8_lossy(&p[o..o + ll]).to_string();

        if (ftype != 'f' && ftype != 'd' && ftype != 'l') || path.is_empty() {
            return;
        }

        f.ftype = ftype;
        f.mode = mode;
        f.uid = uid;
        f.gid = gid;
        f.mtime_sec = mt_s;
        f.mtime_nsec = mt_ns;
        f.size = size;
        f.psize = psize;
        f.k = k;
        f.csz = csz;
        f.meth = meth;
        f.crc = fcrc;
        f.path = path;
        f.link = link;
        f.has_hdr = true;

        if f.meth != 0 {
            logmsg(&format!(
                "START {} ({}, {} B, {} B fast-lzma2, {} RaptorQ symbols @ {} B, CRC {:08x})",
                f.path, ftype, size, psize, k, csz, fcrc
            ));
        } else {
            logmsg(&format!(
                "START {} ({}, {} B, {} RaptorQ symbols @ {} B, CRC {:08x})",
                f.path, ftype, size, k, csz, fcrc
            ));
        }

        let mut ready = false;
        if ftype == 'f' && psize > 0 {
            let mut dec = RaptorQDecoder::new(psize as usize, csz as usize).unwrap();
            let early = std::mem::take(&mut f.early_syms);
            for es in early {
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
            self.finalize_file(id);
        } else if ftype != 'f' || psize == 0 {
            if ftype == 'f' {
                self.finalize_file(id);
            } else {
                self.finalize_other(id);
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

        if pay.len() >= 32 && (pay[8] == b'f' || pay[8] == b'd' || pay[8] == b'l') {
            self.on_header(pay);
        } else {
            self.on_data(pay);
        }
    }

    fn finish(&mut self) {
        for (path, mode, uid, gid, mt_s, mt_ns) in self.dirs.iter().rev() {
            self.apply_meta(path, 'd', *mode, *uid, *gid, *mt_s, *mt_ns);
        }

        for f in self.table.values() {
            if f.done {
                continue;
            }
            if f.has_hdr {
                logmsg(&format!(
                    "INCOMPLETE {}: received {} symbols (need more RaptorQ repair symbols)",
                    f.path, f.nsymbols
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
            format!("{:.1}% saved", (1.0 - (self.total_wire_payload_bytes as f64 / self.total_raw_bytes as f64)) * 100.0)
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
        "Usage: {} send [opts] PATH...   |   {} recv [opts]   |   {} crc FILE\n\
         (use 'send -h' or 'recv -h' for options)",
        prog, prog, prog
    );
}

fn send_batch(
    paths: Vec<PathBuf>,
    dev_file: &mut File,
    baud: u64,
    chunk_size: usize,
    pct: usize,
    rounds: usize,
) -> Result<(), String> {
    let (comp_tx, comp_rx) = sync_channel::<QueueItem>(32);
    let (tx_tx, tx_rx) = sync_channel::<Vec<u8>>(128);

    let h1 = thread::spawn(move || {
        crawl_and_compress(paths, chunk_size, comp_tx);
    });

    let h2 = thread::spawn(move || {
        encode_stage(comp_rx, tx_tx, pct, rounds);
    });

    let file_clone = dev_file.try_clone().map_err(|e| format!("Failed to clone file descriptor: {}", e))?;
    let h3 = thread::spawn(move || {
        tx_worker(tx_rx, file_clone, baud);
    });

    h1.join().map_err(|_| "Reader thread panicked")?;
    h2.join().map_err(|_| "Encoder thread panicked")?;
    h3.join().map_err(|_| "TX thread panicked")?;
    flush_tty(dev_file);
    Ok(())
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

fn do_send(args: &[String]) -> Result<(), String> {
    install_signal_handlers();
    let mut dev = "/dev/ttyUSB0".to_string();
    let mut baud = 115200u64;
    let mut rounds = 1usize;
    let mut chunk = 0usize;
    let mut pct = 35usize;
    let mut watch_dir: Option<PathBuf> = None;
    let mut paths = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => { i += 1; dev = args.get(i).ok_or("-d requires device")?.clone(); }
            "-b" => { i += 1; baud = args.get(i).ok_or("-b requires baud")?.parse().map_err(|_| "invalid baud")?; }
            "-r" => { i += 1; rounds = args.get(i).ok_or("-r requires rounds")?.parse().map_err(|_| "invalid rounds")?; }
            "-c" => { i += 1; chunk = args.get(i).ok_or("-c requires chunk size")?.parse().map_err(|_| "invalid chunk size")?; }
            "-f" => { i += 1; pct = args.get(i).ok_or("-f requires pct")?.parse().map_err(|_| "invalid pct")?; }
            "-w" | "--watch" => {
                i += 1;
                let dir_str = args.get(i).ok_or("-w requires directory")?;
                watch_dir = Some(PathBuf::from(dir_str));
            }
            "-h" | "--help" => {
                eprintln!("Usage: sxfer send [options] [PATH...]\n\
                           -d DEV    serial device or file (default /dev/ttyUSB0)\n\
                           -b BAUD   baud rate (default 115200)\n\
                           -w DIR    watch directory: auto-create, transmit present files, and delete them\n\
                           -c BYTES  symbol chunk size (default: auto)\n\
                           -f PCT    RaptorQ repair percentage (default 35)\n\
                           -r ROUNDS repeat rounds (default 1)");
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

    if baud >= 2_500_000 && pct == 35 {
        pct = 100;
    }

    let chunk_size = if chunk != 0 { chunk } else { auto_chunk_size(baud) };
    let mut file = open_line_send(Path::new(&dev), baud).map_err(|e| format!("Failed to open {}: {}", dev, e))?;

    if let Some(wdir) = watch_dir {
        if !wdir.exists() {
            fs::create_dir_all(&wdir).map_err(|e| format!("Failed to create watch directory {}: {}", wdir.display(), e))?;
            logmsg(&format!("WATCH created directory: {}", wdir.display()));
        }
        logmsg(&format!(
            "WATCH monitoring {} (device {}, {} baud, chunk {} B) (Ctrl-C to stop)",
            wdir.display(), dev, baud, chunk_size
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
                    logmsg(&format!("WATCH waiting for file to finish writing: {}", entry.display()));
                    continue;
                }

                logmsg(&format!("WATCH processing: {}", entry.display()));
                if let Err(e) = send_batch(vec![entry.clone()], &mut file, baud, chunk_size, pct, rounds) {
                    logmsg(&format!("ERROR sending {}: {}", entry.display(), e));
                    continue;
                }

                // Delete once transmitted successfully
                if entry.is_dir() && !entry.is_symlink() {
                    let _ = fs::remove_dir_all(&entry);
                } else {
                    let _ = fs::remove_file(&entry);
                }
                logmsg(&format!("SENT & DELETED {}", entry.display()));
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

    send_batch(paths, &mut file, baud, chunk_size, pct, rounds)?;
    logmsg("FINISHED");
    Ok(())
}


fn do_recv(args: &[String]) -> Result<(), String> {
    install_signal_handlers();
    let mut dev = "/dev/ttyUSB0".to_string();
    let mut baud = 115200u64;
    let mut out_dir = PathBuf::from("./recv");
    let mut idle_sec = 0u64;
    let mut restore_owner = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => { i += 1; dev = args.get(i).ok_or("-d requires device")?.clone(); }
            "-b" => { i += 1; baud = args.get(i).ok_or("-b requires baud")?.parse().map_err(|_| "invalid baud")?; }
            "-o" => { i += 1; out_dir = PathBuf::from(args.get(i).ok_or("-o requires out dir")?); }
            "-q" => { i += 1; idle_sec = args.get(i).ok_or("-q requires seconds")?.parse().map_err(|_| "invalid seconds")?; }
            "-p" => { restore_owner = true; }
            "-h" | "--help" => {
                eprintln!("Usage: sxfer recv [options]\n\
                           -d DEV    serial device or file (default /dev/ttyUSB0)\n\
                           -b BAUD   baud rate (default 115200)\n\
                           -o DIR    output directory (default ./recv)\n\
                           -q SEC    quit SEC seconds after quiet (default: 0 = loop indefinitely)\n\
                           -p        restore owner/group (requires root)");
                return Ok(());
            }
            other => return Err(format!("Unknown option: {}", other)),
        }
        i += 1;
    }

    fs::create_dir_all(&out_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;
    let canon_out = out_dir.canonicalize().map_err(|e| format!("Failed to canonicalize output dir: {}", e))?;

    let mut ctx = ReceiverContext::new(canon_out.clone(), restore_owner);
    let mut file = open_line_recv(Path::new(&dev), baud).map_err(|e| format!("Failed to open {}: {}", dev, e))?;

    logmsg(&format!(
        "listening on {}, writing to {} (Ctrl-C to stop)",
        dev, canon_out.display()
    ));

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
        print_usage(&args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
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
