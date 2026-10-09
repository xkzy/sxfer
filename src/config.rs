//! Configuration Engine for sxfer (Linux `/etc/sxfer.conf` & Windows `%APPDATA%\sxfer\sxfer.conf`).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
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
    pub notify: bool,
    // Security & Authentication Layer
    pub sign_key: Option<String>,
    pub verify_key: Option<String>,
    pub require_auth: bool,
    pub max_clock_skew_secs: i64,
    pub replay_cache_file: Option<String>,
}

impl Default for SxferConfig {
    fn default() -> Self {
        #[cfg(windows)]
        let default_port = "COM3".to_string();
        #[cfg(not(windows))]
        let default_port = "/dev/ttyUSB1".to_string();

        #[cfg(windows)]
        let default_dest = {
            let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:".to_string());
            format!(r"{}\Downloads\sxfer", user_profile)
        };
        #[cfg(not(windows))]
        let default_dest = "/var/spool/sxfer/incoming".to_string();

        #[cfg(windows)]
        let default_watch = {
            let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:".to_string());
            format!(r"{}\Downloads\sxfer_outgoing", user_profile)
        };
        #[cfg(not(windows))]
        let default_watch = "/var/spool/sxfer/outgoing".to_string();

        Self {
            role: "receiver".to_string(),
            port: default_port,
            baud: 115200,
            redundancy: 1.0,
            fast_lzma2: true,
            dest_dir: default_dest,
            keep_damaged: false,
            watch_dir: default_watch,
            poll_interval_ms: 100,
            delete_after_send: true,
            notify: true,
            sign_key: None,
            verify_key: None,
            require_auth: false,
            max_clock_skew_secs: 300,
            replay_cache_file: None,
        }
    }
}

impl SxferConfig {
    pub fn default_config_path() -> PathBuf {
        #[cfg(windows)]
        {
            if let Ok(appdata) = std::env::var("APPDATA") {
                PathBuf::from(appdata).join("sxfer").join("sxfer.conf")
            } else {
                PathBuf::from(r"C:\ProgramData\sxfer\sxfer.conf")
            }
        }
        #[cfg(not(windows))]
        {
            let system_path = PathBuf::from("/etc/sxfer.conf");
            if system_path.exists() {
                return system_path;
            }
            if let Ok(home) = std::env::var("HOME") {
                let user_conf = PathBuf::from(home).join(".config/sxfer/sxfer.conf");
                if user_conf.exists() {
                    return user_conf;
                }
            }
            system_path
        }
    }

    pub fn load_default() -> Self {
        let path = Self::default_config_path();
        if path.exists() {
            Self::load_from_file(&path).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Self::parse_str(&content)
    }

    pub fn parse_str(content: &str) -> io::Result<Self> {
        let mut cfg = Self::default();
        let mut current_section = "general".to_string();
        let mut kv_map: HashMap<String, HashMap<String, String>> = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                current_section = line[1..line.len() - 1].trim().to_lowercase();
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_lowercase();
                let mut val = v.trim();
                // strip optional quotes
                if val.len() >= 2
                    && ((val.starts_with('"') && val.ends_with('"'))
                        || (val.starts_with('\'') && val.ends_with('\'')))
                {
                    val = &val[1..val.len() - 1];
                }
                kv_map
                    .entry(current_section.clone())
                    .or_default()
                    .insert(key, val.to_string());
            }
        }

        // Apply general
        if let Some(sec) = kv_map.get("general") {
            if let Some(v) = sec.get("role") {
                cfg.role = v.clone();
            }
            if let Some(v) = sec.get("port") {
                cfg.port = v.clone();
            }
            if let Some(v) = sec.get("baud") {
                if let Ok(b) = v.parse::<u64>() {
                    cfg.baud = b;
                }
            }
            if let Some(v) = sec.get("redundancy") {
                if let Ok(r) = v.parse::<f64>() {
                    if r.is_finite() && (0.0..=100.0).contains(&r) {
                        cfg.redundancy = r;
                    }
                }
            }
            if let Some(v) = sec.get("fast_lzma2") {
                cfg.fast_lzma2 = v.eq_ignore_ascii_case("true") || v == "1";
            }
        }

        // Apply receiver
        if let Some(sec) = kv_map.get("receiver") {
            if let Some(v) = sec.get("dest_dir").or_else(|| sec.get("dest")) {
                cfg.dest_dir = v.clone();
            }
            if let Some(v) = sec.get("port") {
                cfg.port = v.clone();
            }
            if let Some(v) = sec.get("baud") {
                if let Ok(b) = v.parse::<u64>() {
                    cfg.baud = b;
                }
            }
            if let Some(v) = sec.get("keep_damaged") {
                cfg.keep_damaged = v.eq_ignore_ascii_case("true") || v == "1";
            }
            if let Some(v) = sec.get("notify") {
                cfg.notify = v.eq_ignore_ascii_case("true") || v == "1";
            }
        }

        // Apply sender
        if let Some(sec) = kv_map.get("sender") {
            if let Some(v) = sec.get("watch_dir").or_else(|| sec.get("watch")) {
                cfg.watch_dir = v.clone();
            }
            if let Some(v) = sec.get("port") {
                cfg.port = v.clone();
            }
            if let Some(v) = sec.get("baud") {
                if let Ok(b) = v.parse::<u64>() {
                    cfg.baud = b;
                }
            }
            if let Some(v) = sec.get("poll_interval_ms") {
                if let Ok(p) = v.parse::<u64>() {
                    cfg.poll_interval_ms = p;
                }
            }
            if let Some(v) = sec.get("delete_after_send") {
                cfg.delete_after_send = v.eq_ignore_ascii_case("true") || v == "1";
            }
        }

        // Apply security
        if let Some(sec) = kv_map.get("security") {
            if let Some(v) = sec.get("sign_key") {
                if !v.is_empty() {
                    cfg.sign_key = Some(v.clone());
                }
            }
            if let Some(v) = sec.get("verify_key") {
                if !v.is_empty() {
                    cfg.verify_key = Some(v.clone());
                }
            }
            if let Some(v) = sec.get("require_auth") {
                cfg.require_auth = v.eq_ignore_ascii_case("true") || v == "1";
            }
            if let Some(v) = sec.get("max_clock_skew_secs") {
                if let Ok(s) = v.parse::<i64>() {
                    if s > 0 {
                        cfg.max_clock_skew_secs = s;
                    }
                }
            }
            if let Some(v) = sec.get("replay_cache_file") {
                if !v.is_empty() {
                    cfg.replay_cache_file = Some(v.clone());
                }
            }
        }

        Ok(cfg)
    }

    #[allow(dead_code)]
    pub fn generate_default_conf() -> String {
        format!(
            r#"# sxfer Configuration File
# Linux: /etc/sxfer.conf or ~/.config/sxfer/sxfer.conf
# Windows: %APPDATA%\sxfer\sxfer.conf

[general]
role = receiver
port = {port}
baud = 115200
redundancy = 1.0
fast_lzma2 = true

[receiver]
dest_dir = {dest}
keep_damaged = false
notify = true

[sender]
watch_dir = {watch}
poll_interval_ms = 100
delete_after_send = true

[security]
# require_auth = false
# verify_key = /etc/sxfer/trusted_sender.pub
# sign_key = /etc/sxfer/sender_private.key
# max_clock_skew_secs = 300
"#,
            port = if cfg!(windows) {
                "COM3"
            } else {
                "/dev/ttyUSB1"
            },
            dest = if cfg!(windows) {
                r"C:\Downloads\sxfer"
            } else {
                "/var/spool/sxfer/incoming"
            },
            watch = if cfg!(windows) {
                r"C:\Downloads\sxfer_outgoing"
            } else {
                "/var/spool/sxfer/outgoing"
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse_custom() {
        let conf_str = r#"
# Sample sxfer configuration
[general]
role = receiver
port = /dev/ttyUSB1
baud = 921600
redundancy = 1.5
fast_lzma2 = true

[receiver]
dest_dir = /tmp/incoming
keep_damaged = false
notify = true

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
        assert!(cfg.notify);
    }
}
