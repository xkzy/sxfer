//! Serial Port & Device I/O Configuration for Linux & Windows.


pub fn auto_chunk_size(baud: u64) -> usize {
    if baud < 500_000 {
        1024
    } else if baud < 2_500_000 {
        2048
    } else {
        64 // 64 bytes optimal for 3Mbaud
    }
}

pub fn baud_to_speed(baud: u64) -> Option<u32> {
    match baud {
        1200 => Some(0o000011),
        2400 => Some(0o000013),
        4800 => Some(0o000014),
        9600 => Some(0o000015),
        19200 => Some(0o000016),
        38400 => Some(0o000017),
        57600 => Some(0o010001),
        115200 => Some(0o010002),
        230400 => Some(0o010003),
        460800 => Some(0o010004),
        500000 => Some(0o010005),
        576000 => Some(0o010006),
        921600 => Some(0o010007),
        1000000 => Some(0o010010),
        1152000 => Some(0o010011),
        1500000 => Some(0o010012),
        2000000 => Some(0o010013),
        3000000 => Some(0o010015),
        _ => None,
    }
}

// =========================================================================
// UNIX IMPLEMENTATION
// =========================================================================
#[cfg(unix)]
mod unix_impl {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::path::Path;
    use super::baud_to_speed;

    #[repr(C)]
    #[derive(Default)]
    struct Termios {
        c_iflag: u32,
        c_oflag: u32,
        c_cflag: u32,
        c_lflag: u32,
        c_line: u8,
        c_cc: [u8; 32],
        c_ispeed: u32,
        c_ospeed: u32,
    }

    extern "C" {
        fn isatty(fd: std::os::raw::c_int) -> std::os::raw::c_int;
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
        fn tcgetattr(fd: std::os::raw::c_int, termios_p: *mut Termios) -> std::os::raw::c_int;
        fn tcsetattr(fd: std::os::raw::c_int, optional_actions: std::os::raw::c_int, termios_p: *const Termios) -> std::os::raw::c_int;
        fn cfmakeraw(termios_p: *mut Termios);
        fn cfsetispeed(termios_p: *mut Termios, speed: u32) -> std::os::raw::c_int;
        fn cfsetospeed(termios_p: *mut Termios, speed: u32) -> std::os::raw::c_int;
        fn tcflush(fd: std::os::raw::c_int, queue_selector: std::os::raw::c_int) -> std::os::raw::c_int;
    }

    const LOCK_EX: std::os::raw::c_int = 2;
    const LOCK_NB: std::os::raw::c_int = 4;

    pub fn lock_device(fd: RawFd, path: &Path) -> std::io::Result<()> {
        unsafe {
            if isatty(fd) != 0 {
                if flock(fd, LOCK_EX | LOCK_NB) != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(11) /* EAGAIN / EWOULDBLOCK */ {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ResourceBusy,
                            format!("Port '{}' is already in use by another active sxfer TX/RX instance (port locked)", path.display()),
                        ));
                    }
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub fn configure_tty(fd: RawFd, baud: u64) -> std::io::Result<()> {
        unsafe {
            if isatty(fd) == 0 {
                return Ok(());
            }

            let speed = baud_to_speed(baud).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Unsupported baud rate: {}", baud))
            })?;

            let mut t = Termios::default();
            if tcgetattr(fd, &mut t) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            cfmakeraw(&mut t);
            t.c_cflag &= !0o000060; // clear CSIZE
            t.c_cflag |= 0o004000 | 0o000200 | 0o000060; // CLOCAL | CREAD | CS8
            t.c_cflag &= !(0o000100 | 0o002000 | 0o000400 | 0o001000 | 0o20000000000); // clear CSTOPB, HUPCL, PARENB, PARODD, CRTSCTS

            t.c_iflag &= !(0o002000 | 0o010000 | 0o004000); // IXON | IXOFF | IXANY
            t.c_cc[6] = 0; // VMIN = 0 (non-blocking with timeout)
            t.c_cc[5] = 2; // VTIME = 2 (200ms timeout)

            cfsetispeed(&mut t, speed);
            cfsetospeed(&mut t, speed);

            if tcsetattr(fd, 0, &t) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            tcflush(fd, 2); // TCIOFLUSH
        }
        Ok(())
    }

    pub fn open_line_send(path: &Path, baud: u64) -> std::io::Result<File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(0o0400) // O_NOCTTY
            .open(path)?;

        lock_device(file.as_raw_fd(), path)?;
        configure_tty(file.as_raw_fd(), baud)?;
        Ok(file)
    }

    pub fn open_line_recv(path: &Path, baud: u64) -> std::io::Result<File> {
        let is_fifo = std::fs::metadata(path)
            .map(|m| {
                use std::os::unix::fs::FileTypeExt;
                m.file_type().is_fifo()
            })
            .unwrap_or(false);

        let mut opts = OpenOptions::new();
        opts.read(true);
        if is_fifo {
            opts.write(true);
        }
        opts.custom_flags(0o0400); // O_NOCTTY
        let file = opts.open(path)?;

        if !is_fifo {
            lock_device(file.as_raw_fd(), path)?;
        }
        configure_tty(file.as_raw_fd(), baud)?;
        Ok(file)
    }

    pub fn flush_tty(file: &File) {
        let _ = file.sync_all();
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
}

#[cfg(unix)]
pub use unix_impl::*;

// =========================================================================
// WINDOWS IMPLEMENTATION
// =========================================================================
#[cfg(windows)]
mod windows_impl {
    use std::ffi::OsStr;
    use std::fs::{File, OpenOptions};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::Path;

    use windows_sys::Win32::Devices::Communication::{
        PurgeComm, SetCommState, SetCommTimeouts, COMMTIMEOUTS, DCB,
        NOPARITY, ONESTOPBIT, PURGE_RXABORT, PURGE_RXCLEAR, PURGE_TXABORT, PURGE_TXCLEAR,
        DTR_CONTROL_ENABLE, RTS_CONTROL_ENABLE,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, GENERIC_READ,
        GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, LockFileEx, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    pub fn normalize_comm_path(path: &Path) -> Vec<u16> {
        let s = path.to_string_lossy();
        let upper = s.to_ascii_uppercase();
        let final_str = if (upper.starts_with("COM") && upper[3..].chars().all(|c| c.is_ascii_digit()))
            || upper.starts_with(r"\\.\")
        {
            if upper.starts_with(r"\\.\") {
                s.to_string()
            } else {
                format!(r"\\.\{}", s)
            }
        } else {
            s.to_string()
        };

        OsStr::new(&final_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn is_comm_port(path: &Path) -> bool {
        let s = path.to_string_lossy().to_ascii_uppercase();
        s.starts_with("COM") || s.starts_with(r"\\.\COM")
    }

    pub fn lock_device(handle: RawHandle, path: &Path) -> std::io::Result<()> {
        if !is_comm_port(path) {
            return Ok(());
        }
        unsafe {
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            let res = LockFileEx(
                handle as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            );
            if res == 0 {
                let err = GetLastError();
                if err == ERROR_LOCK_VIOLATION || err == ERROR_ACCESS_DENIED {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ResourceBusy,
                        format!("Port '{}' is already in use by another active sxfer TX/RX instance (port locked)", path.display()),
                    ));
                }
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(())
    }

    pub fn configure_tty(handle: RawHandle, baud: u64) -> std::io::Result<()> {
        unsafe {
            let h = handle as HANDLE;
            let mut dcb: DCB = std::mem::zeroed();
            dcb.DCBlength = std::mem::size_of::<DCB>() as u32;

            dcb.BaudRate = baud as u32;
            dcb.ByteSize = 8;
            dcb.Parity = NOPARITY;
            dcb.StopBits = ONESTOPBIT;
            dcb.fBinary = 1;
            dcb.fParity = 0;
            dcb.fOutxCtsFlow = 0;
            dcb.fOutxDsrFlow = 0;
            dcb.fDtrControl = DTR_CONTROL_ENABLE as u32;
            dcb.fDsrSensitivity = 0;
            dcb.fTXContinueOnXoff = 1;
            dcb.fOutX = 0;
            dcb.fInX = 0;
            dcb.fErrorChar = 0;
            dcb.fNull = 0;
            dcb.fRtsControl = RTS_CONTROL_ENABLE as u32;
            dcb.fAbortOnError = 0;

            if SetCommState(h, &dcb) == 0 {
                let err = GetLastError();
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }

            let mut timeouts: COMMTIMEOUTS = std::mem::zeroed();
            timeouts.ReadIntervalTimeout = 20;
            timeouts.ReadTotalTimeoutConstant = 200;
            timeouts.ReadTotalTimeoutMultiplier = 0;
            timeouts.WriteTotalTimeoutConstant = 1000;
            timeouts.WriteTotalTimeoutMultiplier = 0;

            if SetCommTimeouts(h, &timeouts) == 0 {
                let err = GetLastError();
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }

            PurgeComm(h, PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
        }
        Ok(())
    }

    pub fn open_line_send(path: &Path, baud: u64) -> std::io::Result<File> {
        if is_comm_port(path) {
            let wide = normalize_comm_path(path);
            unsafe {
                let handle = CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0,
                );
                if handle == INVALID_HANDLE_VALUE {
                    let err = GetLastError();
                    if err == ERROR_ACCESS_DENIED {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ResourceBusy,
                            format!("Port '{}' is already in use by another active sxfer TX/RX instance (port locked)", path.display()),
                        ));
                    }
                    return Err(std::io::Error::from_raw_os_error(err as i32));
                }

                lock_device(handle as RawHandle, path)?;
                configure_tty(handle as RawHandle, baud)?;
                Ok(File::from_raw_handle(handle as RawHandle))
            }
        } else {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?;
            Ok(file)
        }
    }

    pub fn open_line_recv(path: &Path, baud: u64) -> std::io::Result<File> {
        if is_comm_port(path) {
            let wide = normalize_comm_path(path);
            unsafe {
                let handle = CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0,
                );
                if handle == INVALID_HANDLE_VALUE {
                    let err = GetLastError();
                    if err == ERROR_ACCESS_DENIED {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ResourceBusy,
                            format!("Port '{}' is already in use by another active sxfer TX/RX instance (port locked)", path.display()),
                        ));
                    }
                    return Err(std::io::Error::from_raw_os_error(err as i32));
                }

                lock_device(handle as RawHandle, path)?;
                configure_tty(handle as RawHandle, baud)?;
                Ok(File::from_raw_handle(handle as RawHandle))
            }
        } else {
            let file = OpenOptions::new().read(true).open(path)?;
            Ok(file)
        }
    }

    pub fn flush_tty(file: &File) {
        let _ = file.sync_all();
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
}

#[cfg(windows)]
pub use windows_impl::*;
