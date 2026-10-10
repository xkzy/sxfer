//! Relay verified received files to another machine with the system `scp`.
//!
//! Only files that already sit in the output directory are forwarded: the
//! receiver writes legacy files via a `.name.id.sxfer-part` temp + rename and
//! authenticated batches are committed from `.sxfer_staging_*` only after
//! verification, so anything visible here is complete and verified.
//! A file is deleted locally only after `scp` exits successfully.

use crate::logmsg;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

const RETRY_AFTER: Duration = Duration::from_secs(10);
/// A file touched more recently than this may still be mid-commit.
const SETTLE: Duration = Duration::from_millis(1000);

/// True for `[user@]host:path` (scp syntax); false for plain paths, including
/// Windows drive paths (`C:\\out`, `C:/out`, `C:`) and anything with a separator before the colon.
pub fn looks_like_scp(s: &str) -> bool {
    let Some((host, _)) = s.split_once(':') else { return false };
    if host.is_empty() || host.contains('/') || host.contains('\\') {
        return false;
    }
    let drive = host.len() == 1 && host.as_bytes()[0].is_ascii_alphabetic();
    !drive
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScpTarget {
    host: String,
    dir: String,
}

impl ScpTarget {
    /// Parse `[user@]host:/remote/dir`. Rejects option-looking values so a
    /// crafted target can never be parsed by ssh/scp as a flag.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (host, dir) = s
            .split_once(':')
            .ok_or("--scp target must look like [user@]host:/remote/dir")?;
        if host.is_empty() || host.starts_with('-') || host.contains(char::is_whitespace) {
            return Err(format!("invalid --scp host '{}'", host));
        }
        let dir = if dir.is_empty() { "." } else { dir };
        Ok(Self {
            host: host.to_string(),
            dir: dir.trim_end_matches('/').to_string(),
        })
    }

    fn remote_path(&self, rel: &str) -> String {
        if self.dir.is_empty() {
            format!("/{}", rel) // target was "host:/"
        } else {
            format!("{}/{}", self.dir, rel)
        }
    }
}

/// POSIX single-quote escaping for the remote `mkdir -p`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Internal receiver bookkeeping that must never be forwarded.
fn is_internal(name: &str) -> bool {
    name.starts_with(".sxfer_") || name.ends_with(".sxfer-part")
}

fn collect(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if is_internal(&name) {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_symlink() {
            continue; // never follow or ship links
        } else if ft.is_dir() {
            collect(&p, base, out);
        } else if ft.is_file() {
            out.push(p);
        }
    }
}

fn rel_string(base: &Path, p: &Path) -> Option<String> {
    let rel = p.strip_prefix(base).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    Some(parts.join("/"))
}

/// File names come from the (untrusted) sender and legacy scp hands the remote
/// path to the remote shell, so only forward names that are inert there.
/// Quoting is not an option: SFTP-mode scp would keep the quotes literally.
fn is_safe_rel(rel: &str) -> bool {
    !rel.is_empty()
        && rel.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+' | '=' | ',' | '@'))
        })
}

const UNSAFE_PREFIX: &str = "unsafe file name";

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("cannot run {:?}: {}", cmd.get_program(), e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn forward_one(
    target: &ScpTarget,
    base: &Path,
    file: &Path,
    made: &mut HashSet<String>,
) -> Result<String, String> {
    let rel = rel_string(base, file).ok_or("path outside output dir")?;
    if !is_safe_rel(&rel) {
        return Err(format!(
            "{} (allowed: A-Z a-z 0-9 . _ - + = , @)",
            UNSAFE_PREFIX
        ));
    }
    let remote = target.remote_path(&rel);
    let remote_parent = remote.rsplit_once('/').map_or(".", |(p, _)| if p.is_empty() { "/" } else { p });
    if !made.contains(remote_parent) {
        run(Command::new("ssh")
            .args(["-o", "BatchMode=yes", "--"])
            .arg(&target.host)
            .arg(format!("mkdir -p -- {}", sh_quote(remote_parent))))?;
        made.insert(remote_parent.to_string());
    }
    run(Command::new("scp")
        .args(["-q", "-o", "BatchMode=yes", "--"])
        .arg(file)
        .arg(format!("{}:{}", target.host, remote)))?;
    Ok(remote)
}

fn prune_empty_dirs(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if is_internal(&name) {
            continue;
        }
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            prune_empty_dirs(&e.path());
            let _ = fs::remove_dir(e.path()); // only succeeds when empty
        }
    }
}

/// One scan; returns how many files are still pending locally.
fn pass(
    target: &ScpTarget,
    base: &Path,
    retry_at: &mut HashMap<PathBuf, Instant>,
    made: &mut HashSet<String>,
    final_pass: bool,
) -> usize {
    let mut files = Vec::new();
    collect(base, base, &mut files);
    files.sort();
    let mut pending = 0;
    for f in files {
        if !final_pass {
            let fresh = fs::metadata(&f)
                .and_then(|m| m.modified())
                .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() < SETTLE)
                .unwrap_or(true);
            if fresh || retry_at.get(&f).map_or(false, |t| Instant::now() < *t) {
                pending += 1;
                continue;
            }
        }
        match forward_one(target, base, &f, made) {
            Ok(remote) => {
                retry_at.remove(&f);
                let shown = rel_string(base, &f).unwrap_or_default();
                match fs::remove_file(&f) {
                    Ok(()) => logmsg(&format!("SCP   {} -> {}:{} (local copy removed)",
                        crate::sanitize_log_str(&shown), target.host, crate::sanitize_log_str(&remote))),
                    Err(e) => logmsg(&format!("SCP   sent {} but could not delete locally: {}",
                        crate::sanitize_log_str(&shown), e)),
                }
            }
            Err(e) => {
                made.clear(); // remote dir may have vanished or the host changed
                let skip = e.starts_with(UNSAFE_PREFIX);
                logmsg(&format!(
                    "SCP   {} {} (kept locally{}): {}",
                    if skip { "SKIP" } else { "FAILED" },
                    crate::sanitize_log_str(&rel_string(base, &f).unwrap_or_default()),
                    if skip { "" } else { ", will retry" },
                    crate::sanitize_log_str(&e)
                ));
                // A rejected name will never become valid: do not retry it.
                let wait = if e.starts_with(UNSAFE_PREFIX) {
                    Duration::from_secs(365 * 24 * 3600)
                } else {
                    RETRY_AFTER
                };
                retry_at.insert(f, Instant::now() + wait);
                pending += 1;
            }
        }
    }
    prune_empty_dirs(base);
    pending
}

pub struct Forwarder {
    done: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

impl Forwarder {
    pub fn start(target: ScpTarget, out_dir: PathBuf) -> Self {
        logmsg(&format!(
            "SCP   forwarding verified files to {}:{} (local copy deleted after success)",
            target.host, target.dir
        ));
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        let handle = thread::spawn(move || {
            let mut retry_at = HashMap::new();
            let mut made = HashSet::new();
            while !d.load(Ordering::Relaxed) {
                pass(&target, &out_dir, &mut retry_at, &mut made, false);
                thread::sleep(Duration::from_millis(500));
            }
            // Receiver finished: flush everything left, ignoring settle/backoff.
            let left = pass(&target, &out_dir, &mut retry_at, &mut made, true);
            if left > 0 {
                logmsg(&format!("SCP   {} file(s) NOT forwarded, left in {}", left, out_dir.display()));
            }
        });
        Self { done, handle }
    }

    pub fn finish(self) {
        self.done.store(true, Ordering::Relaxed);
        let _ = self.handle.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target() {
        let t = ScpTarget::parse("me@box:/data/in/").unwrap();
        assert_eq!(t.host, "me@box");
        assert_eq!(t.remote_path("a/b.dat"), "/data/in/a/b.dat");
        assert_eq!(ScpTarget::parse("box:").unwrap().remote_path("x"), "./x");
        assert_eq!(ScpTarget::parse("box:/").unwrap().remote_path("x"), "/x");
        assert!(ScpTarget::parse("-oProxyCommand=evil:/x").is_err());
        assert!(ScpTarget::parse("nocolon").is_err());
        assert!(ScpTarget::parse(":/x").is_err());
    }

    #[test]
    fn scp_detection() {
        for yes in ["box:/in", "me@box:/in", "me@box:", "10.0.0.2:data", "ab:/x"] {
            assert!(looks_like_scp(yes), "{}", yes);
        }
        for no in ["./recv", "/tmp/x", "recv", "C:\\out", "C:/out", "c:", "dir/sub:x", "..\\a:b", ":x"] {
            assert!(!looks_like_scp(no), "{}", no);
        }
    }

    #[test]
    fn safe_names() {
        assert!(is_safe_rel("a/b-c_d.1+x=y,z@h"));
        for bad in ["", "a b", "a;b", "a`b`", "$(x)", "a'b", "../x", "a//b", "./a", "-x/..", "a\\b", "a\nb", "a|b", "é"] {
            assert!(!is_safe_rel(bad), "{:?}", bad);
        }
    }

    #[test]
    fn quoting_and_internal() {
        assert_eq!(sh_quote("a b'c"), r"'a b'\''c'");
        assert!(is_internal(".sxfer_staging_x"));
        assert!(is_internal(".f.00.sxfer-part"));
        assert!(!is_internal(".bashrc"));
    }
}
