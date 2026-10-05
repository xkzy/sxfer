//! sxfer - One-way, high-speed serial file tree transfer tool in Rust.

mod crc32;
mod ldpc;
mod lzma2;
mod mod_codec;
mod raptorq;
mod serial;


use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crc32::{crc32_file, Crc32};
use lzma2::{compress_lzma2, decompress_lzma2};
use mod_codec::{mod_frame_decode, mod_frame_encode, ModMode, MAGIC_RAW};
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

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct PollFd {
    fd: std::os::raw::c_int,
    events: std::os::raw::c_short,
    revents: std::os::raw::c_short,
}

const POLLIN: std::os::raw::c_short = 0x0001;
const LOCK_EX: std::os::raw::c_int = 2;
const LOCK_NB: std::os::raw::c_int = 4;
const LOCK_UN: std::os::raw::c_int = 8;

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

extern "C" fn sig_handler(_: std::os::raw::c_int) {
    STOP_FLAG.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        signal(2, sig_handler);  // SIGINT (Ctrl-C)
        signal(15, sig_handler); // SIGTERM
        signal(1, sig_handler);  // SIGHUP
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
    compression_level: i32,
    tx: SyncSender<QueueItem>,
) {
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
            let mut item = QueueItem {
                id,
                ftype: 'f',
                rel_path: clean_rel,
                link_target: String::new(),
                mode: meta.mode() & 0o7777,
                uid: meta.uid(),
                gid: meta.gid(),
                mtime_sec: meta.mtime(),
                mtime_nsec: meta.mtime_nsec() as u32,
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

                if compression_level > 0 && !raw_data.is_empty() {
                    if let Ok(compressed) = compress_lzma2(&raw_data, compression_level) {
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
                        item.rel_path, item.size, item.psize, compression_level, item.k, item.csz
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
    mod_mode: ModMode,
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
        hdr.push(6); // level
        hdr.extend_from_slice(&item.fcrc.to_be_bytes());

        let rel_bytes = item.rel_path.as_bytes();
        hdr.extend_from_slice(&(rel_bytes.len() as u16).to_be_bytes());
        hdr.extend_from_slice(rel_bytes);

        let link_bytes = item.link_target.as_bytes();
        hdr.extend_from_slice(&(link_bytes.len() as u16).to_be_bytes());
        hdr.extend_from_slice(link_bytes);

        let num_hdr_copies = if item.ftype == 'f' {
            ((pct / 50) + 2).clamp(2, 16).max(rounds * 2)
        } else {
            ((pct / 20) + 4).clamp(4, 24).max(rounds * 4)
        };
        for _ in 0..num_hdr_copies {
            let frame = mod_frame_encode(&hdr, mod_mode);
            let _ = tx.send(frame);
        }

        // 2. RaptorQ Fountain Symbols
        if item.ftype == 'f' && item.psize > 0 {
            if let Some(rq) = RaptorQEncoder::new(&item.payload, item.csz as usize) {
                let num_symbols = rq.total_symbols_to_send(pct);
                let mut sym_buf = vec![0u8; item.csz as usize];
                let mut pkt = Vec::with_capacity(16 + item.csz as usize);
                let hdr_freq = if pct >= 200 { 8 } else { 16 };


                for round in 0..rounds {
                    for s in 0..num_symbols {
                        let esi = (round * num_symbols + s) as u32;
                        if esi > 0 && (esi as usize % hdr_freq) == 0 {
                            let mid_hdr = mod_frame_encode(&hdr, mod_mode);
                            let _ = tx.send(mid_hdr);
                        }

                        rq.encode_symbol(esi, &mut sym_buf);

                        pkt.clear();
                        pkt.extend_from_slice(&item.id);
                        pkt.extend_from_slice(&esi.to_be_bytes());
                        pkt.extend_from_slice(&item.csz.to_be_bytes());
                        pkt.extend_from_slice(&sym_buf);

                        let tx_frame = mod_frame_encode(&pkt, mod_mode);
                        let _ = tx.send(tx_frame);
                    }
                }
            }

            let end_copies = ((pct / 50) + 2).clamp(2, 16);
            for _ in 0..end_copies {
                let end_hdr = mod_frame_encode(&hdr, mod_mode);
                let _ = tx.send(end_hdr);
            }
        }
    }
}

fn tx_worker(rx: Receiver<Vec<u8>>, mut file: File) {
    let mut batch = Vec::with_capacity(65536);
    while let Ok(pkt) = rx.recv() {
        if batch.len() + pkt.len() > 65536 {
            let _ = file.write_all(&batch);
            batch.clear();
        }
        if pkt.len() > 65536 {
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
        if self.restore_owner && unsafe { geteuid() == 0 } {
            let _ = unsafe {
                if ftype == 'l' {
                    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
                    lchown(c_path.as_ptr(), uid, gid)
                } else {
                    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
                    chown(c_path.as_ptr(), uid, gid)
                }
            };
        }

        if ftype != 'l' {
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
            if symlink(&link, &dest).is_ok() {
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

    fn process_frame(&mut self, pay: &[u8]) {
        if pay.len() < 8 {
            return;
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
    chunk_size: usize,
    level: i32,
    mod_mode: ModMode,
    pct: usize,
    rounds: usize,
) -> Result<(), String> {
    let (comp_tx, comp_rx) = sync_channel::<QueueItem>(32);
    let (tx_tx, tx_rx) = sync_channel::<Vec<u8>>(128);

    let h1 = thread::spawn(move || {
        crawl_and_compress(paths, chunk_size, level, comp_tx);
    });

    let h2 = thread::spawn(move || {
        encode_stage(comp_rx, tx_tx, mod_mode, pct, rounds);
    });

    let file_clone = dev_file.try_clone().map_err(|e| format!("Failed to clone file descriptor: {}", e))?;
    let h3 = thread::spawn(move || {
        tx_worker(tx_rx, file_clone);
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
    // 1. Check non-blocking flock to see if writing process holds an exclusive lock
    if let Ok(f) = OpenOptions::new().read(true).open(path) {
        let fd = f.as_raw_fd();
        let lock_res = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
        if lock_res != 0 {
            return false;
        }
        unsafe { flock(fd, LOCK_UN); }
    } else {
        return false;
    }

    // 2. Measure size and timestamp stability over 250ms debounce
    let size1 = meta1.len();
    let mt_s1 = meta1.mtime();
    let mt_ns1 = meta1.mtime_nsec();

    thread::sleep(Duration::from_millis(250));

    let meta2 = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    let size2 = meta2.len();
    let mt_s2 = meta2.mtime();
    let mt_ns2 = meta2.mtime_nsec();

    if size1 != size2 || mt_s1 != mt_s2 || mt_ns1 != mt_ns2 {
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
    let mut mod_mode = ModMode::Cobs;
    let mut level = 6i32;
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
            "-m" => { i += 1; mod_mode = ModMode::from_str(args.get(i).ok_or("-m requires mode")?).ok_or("invalid mode")?; }
            "-z" => { i += 1; level = args.get(i).ok_or("-z requires level")?.parse().map_err(|_| "invalid level")?; }
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
                           -m MODE   cobs, scramble, raw (default cobs)\n\
                           -c BYTES  symbol chunk size (default: auto)\n\
                           -f PCT    RaptorQ repair percentage (default 35)\n\
                           -r ROUNDS repeat rounds (default 1)\n\
                           -z LEVEL  fast-lzma2 level 0-9 (default 6)");
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

    let chunk_size = if chunk != 0 { chunk } else { auto_chunk_size(baud) };
    let mut file = open_line_send(Path::new(&dev), baud).map_err(|e| format!("Failed to open {}: {}", dev, e))?;

    if let Some(wdir) = watch_dir {
        if !wdir.exists() {
            fs::create_dir_all(&wdir).map_err(|e| format!("Failed to create watch directory {}: {}", wdir.display(), e))?;
            logmsg(&format!("WATCH created directory: {}", wdir.display()));
        }
        logmsg(&format!(
            "WATCH monitoring {} (device {}, {} baud, chunk {} B, mod {}) (Ctrl-C to stop)",
            wdir.display(), dev, baud, chunk_size, mod_mode.as_str()
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
                if let Err(e) = send_batch(vec![entry.clone()], &mut file, chunk_size, level, mod_mode, pct, rounds) {
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
        "STREAM starting continuous 3-stage pipeline (device {}, {} baud, chunk {} B, mod {})",
        dev, baud, chunk_size, mod_mode.as_str()
    ));

    send_batch(paths, &mut file, chunk_size, level, mod_mode, pct, rounds)?;
    logmsg("FINISHED");
    Ok(())
}


fn do_recv(args: &[String]) -> Result<(), String> {
    install_signal_handlers();
    let mut dev = "/dev/ttyUSB0".to_string();
    let mut baud = 115200u64;
    let mut out_dir = PathBuf::from("./recv");
    let mut mod_mode = ModMode::Cobs;
    let mut idle_sec = 0u64;
    let mut restore_owner = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => { i += 1; dev = args.get(i).ok_or("-d requires device")?.clone(); }
            "-b" => { i += 1; baud = args.get(i).ok_or("-b requires baud")?.parse().map_err(|_| "invalid baud")?; }
            "-o" => { i += 1; out_dir = PathBuf::from(args.get(i).ok_or("-o requires out dir")?); }
            "-m" => { i += 1; mod_mode = ModMode::from_str(args.get(i).ok_or("-m requires mode")?).ok_or("invalid mode")?; }
            "-q" => { i += 1; idle_sec = args.get(i).ok_or("-q requires seconds")?.parse().map_err(|_| "invalid seconds")?; }
            "-p" => { restore_owner = true; }
            "-h" | "--help" => {
                eprintln!("Usage: sxfer recv [options]\n\
                           -d DEV    serial device or file (default /dev/ttyUSB0)\n\
                           -b BAUD   baud rate (default 115200)\n\
                           -o DIR    output directory (default ./recv)\n\
                           -m MODE   cobs, scramble, raw (default cobs)\n\
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
        "listening on {} ({} modulation), writing to {} (Ctrl-C to stop)",
        dev, mod_mode.as_str(), canon_out.display()
    ));

    let mut in_buf = Vec::with_capacity(1 << 20);
    let mut read_buf = [0u8; 65536];
    let mut last_activity = Instant::now();
    let mut started = false;

    let raw_fd = file.as_raw_fd();
    let mut pfd = PollFd {
        fd: raw_fd,
        events: POLLIN,
        revents: 0,
    };

    while !STOP_FLAG.load(Ordering::Relaxed) {
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

                match mod_mode {
                    ModMode::Cobs => {
                        let mut p = 0;
                        while p < in_buf.len() {
                            if let Some(pos) = in_buf[p..].iter().position(|&b| b == 0x00) {
                                let frame_end = p + pos;
                                if frame_end > p {
                                    if let Some(pay) = mod_frame_decode(&in_buf[p..frame_end], ModMode::Cobs) {
                                        ctx.process_frame(&pay);
                                    } else {
                                        ctx.nbad += 1;
                                    }
                                }
                                p = frame_end + 1;
                            } else {
                                break;
                            }
                        }
                        in_buf.drain(..p);
                    }
                    ModMode::Scramble | ModMode::Raw => {
                        let mut p = 0;
                        while p + 6 <= in_buf.len() {
                            if !in_buf[p..].starts_with(&MAGIC_RAW) {
                                p += 1;
                                continue;
                            }
                            let raw_len = u16::from_be_bytes([in_buf[p + 4], in_buf[p + 5]]) as usize;
                            let tot = 6 + raw_len;
                            if p + tot > in_buf.len() {
                                break;
                            }
                            if let Some(pay) = mod_frame_decode(&in_buf[p..p + tot], mod_mode) {
                                ctx.process_frame(&pay);
                                p += tot;
                            } else {
                                ctx.nbad += 1;
                                p += 1;
                            }
                        }
                        in_buf.drain(..p);
                    }
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
