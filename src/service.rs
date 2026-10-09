//! Linux & Cross-Platform Background Service Daemon with /etc/sxfer.conf and systemd support.

use std::path::Path;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::process::Command;

use crate::config::SxferConfig;
use crate::{do_recv, do_send, logmsg};

pub fn run_daemon(config_path: Option<&Path>) -> Result<(), String> {
    let cfg = if let Some(p) = config_path {
        SxferConfig::load_from_file(p)
            .map_err(|e| format!("Failed to read config file '{}': {}", p.display(), e))?
    } else {
        SxferConfig::load_default()
    };

    logmsg(&format!(
        "DAEMON starting [role={}, port={}, baud={}, redundancy={:.1}]",
        cfg.role, cfg.port, cfg.baud, cfg.redundancy
    ));

    match cfg.role.to_lowercase().as_str() {
        "receiver" | "recv" | "rx" => {
            let mut args = vec![
                "-d".to_string(),
                cfg.port,
                "-b".to_string(),
                cfg.baud.to_string(),
                "-o".to_string(),
                cfg.dest_dir,
            ];
            if cfg.keep_damaged {
                args.push("-k".to_string());
            }
            if let Some(vk) = cfg.verify_key {
                args.push("--verify-key".to_string());
                args.push(vk);
            }
            if cfg.require_auth {
                args.push("--require-auth".to_string());
            }
            if let Some(rc) = cfg.replay_cache_file {
                args.push("--replay-cache".to_string());
                args.push(rc);
            }
            if cfg.max_clock_skew_secs > 0 {
                args.push("--max-clock-skew".to_string());
                args.push(cfg.max_clock_skew_secs.to_string());
            }
            do_recv(&args)
        }
        "sender" | "send" | "tx" | "watch" => {
            let rounds = (cfg.redundancy + 0.5) as usize;
            let rounds = if rounds < 1 { 1 } else { rounds };
            let mut args = vec![
                "-d".to_string(),
                cfg.port,
                "-b".to_string(),
                cfg.baud.to_string(),
                "-r".to_string(),
                rounds.to_string(),
                "-w".to_string(),
                cfg.watch_dir,
            ];
            if let Some(sk) = cfg.sign_key {
                args.push("--sign-key".to_string());
                args.push(sk);
            }
            do_send(&args)
        }
        other => Err(format!(
            "Invalid role '{}' in configuration. Expected 'receiver' or 'sender'/'watch'",
            other
        )),
    }
}

pub fn install_systemd_service() -> Result<(), String> {
    #[cfg(not(unix))]
    {
        return Err(
            "Systemd service installation is only supported on Linux/Unix systems".to_string(),
        );
    }

    #[cfg(unix)]
    {
        let conf_path = Path::new("/etc/sxfer.conf");
        if !conf_path.exists() {
            let default_conf = SxferConfig::generate_default_conf();
            fs::write(conf_path, default_conf)
                .map_err(|e| format!("Failed to write /etc/sxfer.conf (root required): {}", e))?;
            println!("Installed default configuration at /etc/sxfer.conf");
        } else {
            println!("Using existing configuration at /etc/sxfer.conf");
        }

        // Hardened unit: the daemon parses untrusted data off a serial line, so
        // confine it to the configured directories, drop everything it doesn't need,
        // and enforce resource boundaries (MemoryMax, TasksMax, LimitNOFILE, LimitCORE).
        let cfg =
            SxferConfig::load_from_file(conf_path).unwrap_or_else(|_| SxferConfig::load_default());
        let rw_paths = format!("\"{}\" \"{}\"", cfg.dest_dir, cfg.watch_dir);
        if rw_paths.chars().any(|c| c == '\n' || c == '\r') {
            return Err("Refusing to install unit: newline in configured directory".to_string());
        }
        let service_content = format!(
            r#"[Unit]
Description=sxfer High-Speed Unidirectional Serial Transfer Service
After=network.target local-fs.target
Documentation=man:sxfer(1) https://github.com/xkzy/sxfer

[Service]
Type=simple
ExecStart=/usr/local/bin/sxfer daemon --config /etc/sxfer.conf
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryMax=512M
TasksMax=64
LimitNOFILE=1024
LimitCORE=0
DevicePolicy=closed
DeviceAllow=/dev/ttyUSB* rw
DeviceAllow=/dev/ttyS* rw
DeviceAllow=/dev/ttyACM* rw
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
ReadWritePaths={rw}

[Install]
WantedBy=multi-user.target
"#,
            rw = rw_paths
        );

        let unit_path = Path::new("/etc/systemd/system/sxfer.service");
        fs::write(unit_path, service_content).map_err(|e| {
            format!(
                "Failed to write /etc/systemd/system/sxfer.service (root required): {}",
                e
            )
        })?;
        println!("Installed systemd unit at /etc/systemd/system/sxfer.service");

        // Try reloading systemd if systemctl is available
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        println!("\nTo enable and start the service immediately, run:");
        println!("  sudo systemctl enable --now sxfer");
        println!("\nTo view live status and logs:");
        println!("  sudo systemctl status sxfer");
        println!("  journalctl -u sxfer -f\n");

        Ok(())
    }
}
