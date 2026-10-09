//! Windows Native System Tray Service with Notifications, Context Menu, and Background Daemon.

use std::path::Path;

#[cfg(not(windows))]
pub fn run_tray_service(_config_path: Option<&Path>) -> Result<(), String> {
    Err("Windows System Tray mode is only supported on Windows. On Linux, use 'sxfer daemon' or 'sxfer systemd install'.".to_string())
}

#[cfg(windows)]
mod win_tray {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;

    use windows_sys::Win32::Foundation::{
        GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM,
    };
    use windows_sys::Win32::UI::Shell::{
        Shell_NotifyIconW, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        NOTIFYICONDATAW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
        DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, PostQuitMessage, RegisterClassW,
        SetForegroundWindow, TrackPopupMenu, IDI_APPLICATION, MF_DISABLED, MF_SEPARATOR, MF_STRING,
        MSG, TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RIGHTBUTTON, WM_COMMAND, WM_DESTROY,
        WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_USER, WNDCLASSW,
    };

    use crate::config::SxferConfig;
    use crate::service::run_daemon;

    const WM_TRAYICON: u32 = WM_USER + 100;
    const ID_TRAY_STATUS: usize = 2001;
    const ID_TRAY_OPEN_DIR: usize = 2004;
    const ID_TRAY_SETTINGS: usize = 2005;
    const ID_TRAY_EXIT: usize = 2006;

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn run_tray_service_impl(config_path: Option<&Path>) -> Result<(), String> {
        let cfg = if let Some(p) = config_path {
            SxferConfig::load_from_file(p).unwrap_or_default()
        } else {
            SxferConfig::load_default()
        };

        let is_running = Arc::new(AtomicBool::new(true));
        let running_clone = is_running.clone();
        let cfg_path_buf = config_path.map(|p| p.to_path_buf());

        // Spawn background worker thread for daemon
        let daemon_handle = thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                let _ = run_daemon(cfg_path_buf.as_deref());
                thread::sleep(std::time::Duration::from_millis(1000));
            }
        });

        unsafe {
            let class_name = to_wide("SxferTrayWindowClass");
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wnd_proc);
            wc.lpszClassName = class_name.as_ptr();
            wc.hInstance = 0 as HINSTANCE;

            RegisterClassW(&wc);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                to_wide("sxfer tray host").as_ptr(),
                0,
                0,
                0,
                0,
                0,
                0 as HWND,
                0 as _,
                0 as HINSTANCE,
                std::ptr::null(),
            );

            if hwnd == 0 as HWND {
                return Err(format!(
                    "Failed to create tray window handle: {}",
                    GetLastError()
                ));
            }

            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = LoadIconW(0 as HINSTANCE, IDI_APPLICATION);

            let tip = format!("sxfer: Listening on {} @ {} baud", cfg.port, cfg.baud);
            let tip_wide = to_wide(&tip);
            let copy_len = tip_wide.len().min(127);
            nid.szTip[..copy_len].copy_from_slice(&tip_wide[..copy_len]);

            let title_wide = to_wide("sxfer Serial Transfer Service");
            let title_len = title_wide.len().min(63);
            nid.szInfoTitle[..title_len].copy_from_slice(&title_wide[..title_len]);

            let msg_wide = to_wide(&format!(
                "Service started on {}. Incoming files saved to {}",
                cfg.port, cfg.dest_dir
            ));
            let msg_len = msg_wide.len().min(255);
            nid.szInfo[..msg_len].copy_from_slice(&msg_wide[..msg_len]);

            Shell_NotifyIconW(NIM_ADD, &nid);

            // Windows Message Loop
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, 0 as HWND, 0, 0) > 0 {
                DispatchMessageW(&msg);
            }

            Shell_NotifyIconW(NIM_DELETE, &nid);
            is_running.store(false, Ordering::SeqCst);
        }

        let _ = daemon_handle.join();
        Ok(())
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_TRAYICON => {
                let event = (lparam & 0xFFFF) as u32;
                if event == WM_RBUTTONUP || event == WM_LBUTTONDBLCLK {
                    let mut pt: POINT = std::mem::zeroed();
                    GetCursorPos(&mut pt);
                    SetForegroundWindow(hwnd);

                    let hmenu = CreatePopupMenu();
                    let cfg = SxferConfig::load_default();

                    let banner = format!("sxfer: {} @ {} baud", cfg.port, cfg.baud);
                    AppendMenuW(
                        hmenu,
                        MF_STRING | MF_DISABLED,
                        ID_TRAY_STATUS,
                        to_wide(&banner).as_ptr(),
                    );
                    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
                    AppendMenuW(
                        hmenu,
                        MF_STRING,
                        ID_TRAY_OPEN_DIR,
                        to_wide("Open Incoming Folder").as_ptr(),
                    );
                    AppendMenuW(
                        hmenu,
                        MF_STRING,
                        ID_TRAY_SETTINGS,
                        to_wide("Open Config File...").as_ptr(),
                    );
                    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
                    AppendMenuW(
                        hmenu,
                        MF_STRING,
                        ID_TRAY_EXIT,
                        to_wide("Exit sxfer").as_ptr(),
                    );

                    TrackPopupMenu(
                        hmenu,
                        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                        pt.x,
                        pt.y,
                        0,
                        hwnd,
                        std::ptr::null(),
                    );
                    DestroyMenu(hmenu);
                }
                0
            }
            WM_COMMAND => {
                let id = wparam & 0xFFFF;
                match id {
                    ID_TRAY_OPEN_DIR => {
                        let cfg = SxferConfig::load_default();
                        let _ = std::process::Command::new("explorer.exe")
                            .arg(&cfg.dest_dir)
                            .spawn();
                    }
                    ID_TRAY_SETTINGS => {
                        let conf_path = SxferConfig::default_config_path();
                        let _ = std::process::Command::new("notepad.exe")
                            .arg(conf_path.to_string_lossy().as_ref())
                            .spawn();
                    }
                    ID_TRAY_EXIT => {
                        crate::STOP_FLAG.store(true, Ordering::SeqCst);
                        PostQuitMessage(0);
                    }
                    _ => {}
                }
                0
            }
            WM_DESTROY => {
                crate::STOP_FLAG.store(true, Ordering::SeqCst);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

#[cfg(windows)]
pub fn run_tray_service(config_path: Option<&Path>) -> Result<(), String> {
    win_tray::run_tray_service_impl(config_path)
}
