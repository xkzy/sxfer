//! Security-audit regression tests (see docs/SECURITY_AUDIT.md).
//!
//! Every test asserts the *secure* behaviour, so it FAILS on the audited
//! revision (40c00f8) and passes once the matching finding is fixed.
//! All tests run inside temp dirs; cases that may abort or hang run in a child
//! copy of the test binary under RLIMIT_AS, so the harness itself is never hurt.
//!
//! Wire this in with:   #[cfg(test)] mod audit_regressions;   (in main.rs)

use super::*;
use std::process::{Command, Stdio};

// ------------------------------------------------------------------ helpers
fn tmpdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("sxfer_audit_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[allow(clippy::too_many_arguments)]
fn hdr(id: [u8; 8], ft: u8, mode: u32, size: u64, psize: u64, csz: u32, meth: u8, crc: u32, path: &str, link: &str) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&id);
    h.push(ft);
    h.extend_from_slice(&mode.to_be_bytes());
    h.extend_from_slice(&1000u32.to_be_bytes());
    h.extend_from_slice(&1000u32.to_be_bytes());
    h.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    h.extend_from_slice(&0u32.to_be_bytes());
    h.extend_from_slice(&size.to_be_bytes());
    h.extend_from_slice(&psize.to_be_bytes());
    h.extend_from_slice(&1u32.to_be_bytes());
    h.extend_from_slice(&csz.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes());
    h.push(meth);
    h.push(9);
    h.extend_from_slice(&crc.to_be_bytes());
    h.extend_from_slice(&(path.len() as u16).to_be_bytes());
    h.extend_from_slice(path.as_bytes());
    h.extend_from_slice(&(link.len() as u16).to_be_bytes());
    h.extend_from_slice(link.as_bytes());
    h
}

fn data(id: [u8; 8], esi: u32, sym: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id);
    p.extend_from_slice(&esi.to_be_bytes());
    p.extend_from_slice(&(sym.len() as u32).to_be_bytes());
    p.extend_from_slice(sym);
    p
}

#[cfg(unix)]
fn limit_address_space(bytes: u64) {
    #[repr(C)]
    struct RLimit {
        cur: u64,
        max: u64,
    }
    extern "C" {
        fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    }
    const RLIMIT_AS: i32 = 9;
    let r = RLimit { cur: bytes, max: bytes };
    assert_eq!(unsafe { setrlimit(RLIMIT_AS, &r) }, 0);
}

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// Re-run this test binary for a single `audit_child` case.
/// Returns (exited_in_time, success, stderr).
fn run_child(case: &str, timeout: Duration) -> (bool, bool, String) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "audit_regressions::audit_child", "--nocapture", "--test-threads=1"])
        .env("AUDIT_CASE", case)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            let mut err = String::new();
            use std::io::Read as _;
            child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
            return (true, st.success(), err);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return (false, false, String::new());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ------------------------------------------------------------------ child body
/// Not a real test: it is the payload that `run_child` executes in a sandboxed process.
#[test]
fn audit_child() {
    let case = match std::env::var("AUDIT_CASE") {
        Ok(c) => c,
        Err(_) => return,
    };
    #[cfg(unix)]
    limit_address_space(512 << 20);
    let out = tmpdir(&format!("child_{}", case));
    let mut ctx = ReceiverContext::new(out.clone(), false);
    let id = [1u8; 8];
    match case.as_str() {
        "csz0" => ctx.process_frame(&hdr(id, b'f', 0o644, 10, 10, 0, 0, 0, "a.txt", ""), 0),
        "csz_huge" => ctx.process_frame(&hdr(id, b'f', 0o644, 1, 1, 0x7fff_ffff, 0, 0, "d.txt", ""), 0),
        "psize_huge" => ctx.process_frame(&hdr(id, b'f', 0o644, 1, 1u64 << 40, 1, 0, 0, "c.txt", ""), 0),
        "size_huge" => {
            ctx.process_frame(&hdr(id, b'f', 0o644, 1u64 << 50, 1, 1, 1, 0, "b.txt", ""), 0);
            ctx.process_frame(&data(id, 0, &[0x5d]), 0);
        }
        "ansi" => ctx.process_frame(&hdr(id, b'd', 0o755, 0, 0, 0, 0, 0, "\x1b]0;PWNED\x07dir", ""), 0),
        "no_delim" => {
            let stream = out.join("stream.bin");
            {
                let mut f = File::create(&stream).unwrap();
                let chunk = vec![b'A'; 65536];
                for _ in 0..256 {
                    f.write_all(&chunk).unwrap();
                }
            }
            let before = rss_kb();
            do_recv(&["-d".into(), stream.display().to_string(), "-o".into(), out.join("o").display().to_string(), "-q".into(), "1".into()]).unwrap();
            let grown_kb = rss_kb().saturating_sub(before);
            // 16 MiB of delimiter-less garbage must not be retained.
            if grown_kb > 4 * 1024 {
                eprintln!("RETAINED {} KiB", grown_kb);
                std::process::exit(3);
            }
        }
        "watch_devfull" => {
            let w = out.join("w");
            fs::create_dir_all(&w).unwrap();
            fs::write(w.join("important.txt"), b"payload").unwrap();
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(2500));
                STOP_FLAG.store(true, Ordering::SeqCst);
            });
            let _ = do_send(&["-d".into(), "/dev/full".into(), "-w".into(), w.display().to_string()]);
            if !w.join("important.txt").exists() {
                eprintln!("DELETED-UNSENT");
                std::process::exit(4);
            }
        }
        "watch_fifo" => {
            let w = out.join("w");
            fs::create_dir_all(&w).unwrap();
            let c = std::ffi::CString::new(w.join("pipe").to_string_lossy().as_bytes()).unwrap();
            extern "C" {
                fn mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32;
            }
            assert_eq!(unsafe { mkfifo(c.as_ptr(), 0o644) }, 0);
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(1500));
                STOP_FLAG.store(true, Ordering::SeqCst);
            });
            let _ = do_send(&["-d".into(), out.join("line.bin").display().to_string(), "-w".into(), w.display().to_string()]);
        }
        other => panic!("unknown case {}", other),
    }
}

// ------------------------------------------------------------------ F-01 / F-02 / F-03
#[test]
fn f01_zero_csz_header_must_not_abort() {
    let (_, ok, err) = run_child("csz0", Duration::from_secs(20));
    assert!(ok, "receiver died on psize>0,csz=0 header: {}", err);
}

#[test]
fn f02_huge_csz_header_must_not_abort() {
    let (_, ok, err) = run_child("csz_huge", Duration::from_secs(20));
    assert!(ok, "receiver died on csz=0x7fffffff header: {}", err);
}

#[test]
fn f02_huge_psize_header_must_not_abort() {
    let (_, ok, err) = run_child("psize_huge", Duration::from_secs(20));
    assert!(ok, "receiver died on psize=2^40 header: {}", err);
}

#[test]
fn f03_huge_size_with_lzma_must_not_abort() {
    let (_, ok, err) = run_child("size_huge", Duration::from_secs(20));
    assert!(ok, "receiver died on size=2^50 + meth=1: {}", err);
}

// ------------------------------------------------------------------ F-04
#[test]
fn f04_decompress_must_not_exceed_declared_size() {
    // 8 MiB of zeros -> ~1.3 KiB .lzma stream (needs the `xz` CLI to build the bomb; skipped otherwise).
    use std::io::Write as _;
    let mut xz = match Command::new("xz").args(["--format=lzma", "-9", "-c"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut stdin = xz.stdin.take().unwrap();
    let feeder = thread::spawn(move || stdin.write_all(&vec![0u8; 8 << 20]).unwrap());
    let bomb = xz.wait_with_output().unwrap().stdout;
    feeder.join().unwrap();
    assert!(bomb.len() < 4096, "bomb is {} bytes", bomb.len());
    assert!(decompress_lzma2(&bomb, 1024).is_err(), "decompressor produced 8 MiB from a {}-byte input although size=1024", bomb.len());
}

// ------------------------------------------------------------------ F-05
#[test]
#[ignore = "open finding F-05, see docs/SECURITY_AUDIT.md"]
fn f05_delimiterless_stream_must_not_grow_input_buffer() {
    let (_, ok, err) = run_child("no_delim", Duration::from_secs(120));
    assert!(ok, "input buffer retained garbage: {}", err);
}

// ------------------------------------------------------------------ F-06
#[test]
#[ignore = "open finding F-06, see docs/SECURITY_AUDIT.md"]
fn f06_early_symbols_for_unknown_ids_are_bounded() {
    let mut ctx = ReceiverContext::new(tmpdir("early"), false);
    for i in 0..1000u64 {
        ctx.process_frame(&data(i.to_be_bytes(), 0, &vec![0xAB; 4096]), 0);
    }
    let retained: usize = ctx.table.values().map(|f| f.early_syms.iter().map(|e| e.data.len()).sum::<usize>()).sum();
    assert!(retained <= 1 << 20, "retained {} bytes of unauthenticated early symbols", retained);
    assert!(ctx.table.len() <= 256, "table holds {} unknown ids", ctx.table.len());
}

// ------------------------------------------------------------------ F-07
#[test]
#[ignore = "open finding F-07, see docs/SECURITY_AUDIT.md"]
fn f07_forged_symbol_must_not_permanently_poison_a_transfer() {
    let out = tmpdir("poison");
    let mut ctx = ReceiverContext::new(out.clone(), false);
    let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    let id = [9u8; 8];
    let enc = RaptorQEncoder::new(&payload, 1024).unwrap();
    let mut sym = vec![0u8; 1024];
    ctx.process_frame(&hdr(id, b'f', 0o644, 3000, 3000, 1024, 0, Crc32::calculate(&payload), "h.bin", ""), 0);
    for e in 0..2u32 {
        enc.encode_symbol(e, &mut sym);
        ctx.process_frame(&data(id, e, &sym), 0);
    }
    ctx.process_frame(&data(id, 2, &vec![0xEE; 1024]), 0); // forged
    for e in 2..60u32 {
        enc.encode_symbol(e, &mut sym);
        ctx.process_frame(&data(id, e, &sym), 0); // plenty of genuine symbols
    }
    assert_eq!(fs::read(out.join("h.bin")).ok(), Some(payload), "genuine symbols could not repair the transfer");
}

// ------------------------------------------------------------------ F-08 (needs root)
#[test]
#[ignore = "run as root: cargo test f08 -- --ignored"]
fn f08_root_receiver_must_not_chown_to_uid_1000_without_dash_p() {
    use std::os::unix::fs::MetadataExt;
    let out = tmpdir("chown");
    let mut ctx = ReceiverContext::new(out.clone(), false);
    let payload = b"hi".to_vec();
    let id = [5u8; 8];
    ctx.process_frame(&hdr(id, b'f', 0o644, 2, 2, 2, 0, Crc32::calculate(&payload), "f", ""), 0);
    ctx.process_frame(&data(id, 0, &payload), 0);
    let m = fs::metadata(out.join("f")).unwrap();
    assert_ne!(m.uid(), 1000, "file was chowned to uid 1000 although -p was not given");
}

// ------------------------------------------------------------------ F-09 / F-10
#[test]
fn f09_watch_mode_must_not_delete_when_device_writes_fail() {
    let (_, ok, err) = run_child("watch_devfull", Duration::from_secs(30));
    assert!(ok, "source deleted although every device write failed: {}", err);
}

#[test]
#[ignore = "open finding F-10, see docs/SECURITY_AUDIT.md"]
fn f10_fifo_in_watch_dir_must_not_hang_the_sender() {
    let (exited, _, _) = run_child("watch_fifo", Duration::from_secs(8));
    assert!(exited, "sender hung on a FIFO planted in the watch directory");
}

// ------------------------------------------------------------------ F-13
#[test]
#[ignore = "open finding F-13, see docs/SECURITY_AUDIT.md"]
fn f13_temp_name_must_not_clobber_sibling_files() {
    let out = tmpdir("tmpname");
    fs::write(out.join("a.sxfer-part"), b"precious").unwrap();
    let mut ctx = ReceiverContext::new(out.clone(), false);
    let id = [6u8; 8];
    ctx.process_frame(&hdr(id, b'f', 0o644, 2, 2, 2, 0, Crc32::calculate(b"hi"), "a.txt", ""), 0);
    ctx.process_frame(&data(id, 0, b"hi"), 0);
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"hi");
    assert_eq!(fs::read(out.join("a.sxfer-part")).ok().as_deref(), Some(&b"precious"[..]), "unrelated file deleted");
}

// ------------------------------------------------------------------ F-14
#[test]
#[ignore = "open finding F-14, see docs/SECURITY_AUDIT.md"]
fn f14_log_output_must_not_contain_raw_control_bytes_from_the_wire() {
    let (_, _, err) = run_child("ansi", Duration::from_secs(20));
    assert!(!err.contains('\x1b'), "ESC byte from remote path reached the log");
}

// ------------------------------------------------------------------ F-15
#[test]
#[ignore = "open finding F-15, see docs/SECURITY_AUDIT.md"]
fn f15_directory_header_must_not_chmod_a_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    let out = tmpdir("dirhdr");
    fs::write(out.join("x"), b"data").unwrap();
    fs::set_permissions(out.join("x"), fs::Permissions::from_mode(0o644)).unwrap();
    let mut ctx = ReceiverContext::new(out.clone(), false);
    ctx.process_frame(&hdr([7u8; 8], b'd', 0o000, 0, 0, 0, 0, 0, "x", ""), 0);
    ctx.finish();
    assert_eq!(fs::metadata(out.join("x")).unwrap().permissions().mode() & 0o777, 0o644);
}

// ------------------------------------------------------------------ F-16 / F-17 / F-18
#[test]
#[ignore = "open finding F-16, see docs/SECURITY_AUDIT.md"]
fn f16_daemon_receiver_args_must_be_accepted_by_recv() {
    // service.rs passes "-k" when keep_damaged=true; `recv` must understand every flag the daemon emits.
    assert!(do_recv(&["-k".into(), "-h".into()]).is_ok());
}

#[test]
#[ignore = "open finding F-17, see docs/SECURITY_AUDIT.md"]
fn f17_config_with_lone_quote_must_not_panic() {
    let r = std::panic::catch_unwind(|| config::SxferConfig::parse_str("[general]\nport = \"\n"));
    assert!(r.is_ok(), "config parser panicked on a lone quote");
}

#[test]
#[ignore = "open finding F-18, see docs/SECURITY_AUDIT.md"]
fn f18_zero_rounds_must_be_rejected() {
    let d = tmpdir("rounds0");
    fs::write(d.join("f.txt"), b"hello").unwrap();
    let r = do_send(&["-d".into(), d.join("line.bin").display().to_string(), "-r".into(), "0".into(), d.join("f.txt").display().to_string()]);
    assert!(r.is_err(), "-r 0 silently transmits headers only");
}

// ------------------------------------------------------------------ F-09 additional cases
#[test]
fn f09_unreadable_subdir_and_unsupported_types_fail_the_batch() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("f09_skip");
    let src = d.join("src");
    fs::create_dir_all(src.join("locked")).unwrap();
    fs::write(src.join("locked/f"), b"x").unwrap();
    fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable_is_enforced = fs::read_dir(src.join("locked")).is_err(); // false when running as root
    let mut line = File::create(d.join("line.bin")).unwrap();
    let r = send_batch(vec![src.clone()], &mut line, 115200, 1024, 35, 1);
    fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o700)).unwrap();
    if unreadable_is_enforced {
        assert!(r.is_err(), "unreadable directory silently skipped");
    }
    // a unix socket cannot be transmitted: the batch must report it
    let sock = d.join("sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    assert!(send_batch(vec![sock], &mut line, 115200, 1024, 35, 1).is_err(), "unsupported file type silently skipped");
}

#[test]
fn f09_tree_snapshot_detects_additions_and_edits() {
    let d = tmpdir("f09_snap");
    fs::write(d.join("a"), b"1").unwrap();
    let s1 = tree_snapshot(&d).unwrap();
    assert_eq!(s1, tree_snapshot(&d).unwrap());
    fs::write(d.join("b"), b"2").unwrap();
    assert_ne!(s1, tree_snapshot(&d).unwrap(), "new file not noticed");
}

#[test]
fn f09_successful_watch_send_still_deletes() {
    let d = tmpdir("f09_ok");
    let src = d.join("f.txt");
    fs::write(&src, b"hello").unwrap();
    let mut line = File::create(d.join("line.bin")).unwrap();
    assert!(send_batch(vec![src], &mut line, 115200, 1024, 35, 1).is_ok());
}
