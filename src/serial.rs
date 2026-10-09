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

#[cfg(unix)]
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
    use super::baud_to_speed;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::path::Path;

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
        fn tcsetattr(
            fd: std::os::raw::c_int,
            optional_actions: std::os::raw::c_int,
            termios_p: *const Termios,
        ) -> std::os::raw::c_int;
        fn cfmakeraw(termios_p: *mut Termios);
        fn cfsetispeed(termios_p: *mut Termios, speed: u32) -> std::os::raw::c_int;
        fn cfsetospeed(termios_p: *mut Termios, speed: u32) -> std::os::raw::c_int;
        fn tcflush(
            fd: std::os::raw::c_int,
            queue_selector: std::os::raw::c_int,
        ) -> std::os::raw::c_int;
    }

    const LOCK_EX: std::os::raw::c_int = 2;
    const LOCK_NB: std::os::raw::c_int = 4;

    pub fn lock_device(fd: RawFd, path: &Path) -> std::io::Result<()> {
        unsafe {
            if isatty(fd) != 0 && flock(fd, LOCK_EX | LOCK_NB) != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(11)
                /* EAGAIN / EWOULDBLOCK */
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ResourceBusy,
                        format!("Port '{}' is already in use by another active sxfer TX/RX instance (port locked)", path.display()),
                    ));
                }
                return Err(err);
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
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unsupported baud rate: {}", baud),
                )
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
    use std::fs::{File, OpenOptions};
    use std::path::Path;
    use std::time::Duration;

    pub fn is_comm_port(path: &Path) -> bool {
        let s = path.to_string_lossy().to_ascii_uppercase();
        s.starts_with("COM") || s.starts_with(r"\\.\COM")
    }

    /// Open a COM port through the `serialport` crate (8N1, no flow control).
    /// serialport opens the device with exclusive sharing, so a second
    /// sxfer instance gets ERROR_ACCESS_DENIED, reported here as ResourceBusy.
    /// The handle is handed back as a plain `File` so callers stay OS-agnostic.
    fn open_comm(path: &Path, baud: u64, timeout_ms: u64) -> std::io::Result<Box<dyn serialport::SerialPort>> {
        let name = path.to_string_lossy().to_string();
        serialport::new(name, baud as u32)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(Duration::from_millis(timeout_ms))
            .open()
            .map_err(|e| {
                let io: std::io::Error = e.into();
                if io.kind() == std::io::ErrorKind::PermissionDenied {
                    std::io::Error::new(
                        std::io::ErrorKind::ResourceBusy,
                        format!("Port '{}' is already in use by another active sxfer TX/RX instance (port locked)", path.display()),
                    )
                } else {
                    io
                }
            })
    }

    struct FileSerialPort(File);
    impl std::io::Read for FileSerialPort {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.0.read(buf) }
    }
    impl std::io::Write for FileSerialPort {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.0.write(buf) }
        fn flush(&mut self) -> std::io::Result<()> { self.0.flush() }
    }
    impl serialport::SerialPort for FileSerialPort {
        fn name(&self) -> Option<String> { None }
        fn baud_rate(&self) -> serialport::Result<u32> { Ok(0) }
        fn data_bits(&self) -> serialport::Result<serialport::DataBits> { Ok(serialport::DataBits::Eight) }
        fn flow_control(&self) -> serialport::Result<serialport::FlowControl> { Ok(serialport::FlowControl::None) }
        fn parity(&self) -> serialport::Result<serialport::Parity> { Ok(serialport::Parity::None) }
        fn stop_bits(&self) -> serialport::Result<serialport::StopBits> { Ok(serialport::StopBits::One) }
        fn timeout(&self) -> Duration { Duration::from_millis(0) }
        fn set_baud_rate(&mut self, _: u32) -> serialport::Result<()> { Ok(()) }
        fn set_data_bits(&mut self, _: serialport::DataBits) -> serialport::Result<()> { Ok(()) }
        fn set_flow_control(&mut self, _: serialport::FlowControl) -> serialport::Result<()> { Ok(()) }
        fn set_parity(&mut self, _: serialport::Parity) -> serialport::Result<()> { Ok(()) }
        fn set_stop_bits(&mut self, _: serialport::StopBits) -> serialport::Result<()> { Ok(()) }
        fn set_timeout(&mut self, _: Duration) -> serialport::Result<()> { Ok(()) }
        fn write_request_to_send(&mut self, _: bool) -> serialport::Result<()> { Ok(()) }
        fn write_data_terminal_ready(&mut self, _: bool) -> serialport::Result<()> { Ok(()) }
        fn read_clear_to_send(&mut self) -> serialport::Result<bool> { Ok(false) }
        fn read_data_set_ready(&mut self) -> serialport::Result<bool> { Ok(false) }
        fn read_ring_indicator(&mut self) -> serialport::Result<bool> { Ok(false) }
        fn read_carrier_detect(&mut self) -> serialport::Result<bool> { Ok(false) }
        fn bytes_to_read(&self) -> serialport::Result<u32> { Ok(0) }
        fn bytes_to_write(&self) -> serialport::Result<u32> { Ok(0) }
        fn clear(&self, _: serialport::ClearBuffer) -> serialport::Result<()> { Ok(()) }
        fn try_clone(&self) -> serialport::Result<Box<dyn serialport::SerialPort>> { Err(serialport::Error::new(serialport::ErrorKind::NoDevice, "Cannot clone")) }
        fn set_break(&self) -> serialport::Result<()> { Ok(()) }
        fn clear_break(&self) -> serialport::Result<()> { Ok(()) }
    }

    pub fn open_line_send(path: &Path, baud: u64) -> std::io::Result<Box<dyn serialport::SerialPort>> {
        if is_comm_port(path) {
            open_comm(path, baud, 1000)
        } else {
            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)?;
            Ok(Box::new(FileSerialPort(f)))
        }
    }

    pub fn open_line_recv(path: &Path, baud: u64) -> std::io::Result<Box<dyn serialport::SerialPort>> {
        if is_comm_port(path) {
            open_comm(path, baud, 200)
        } else {
            let f = OpenOptions::new().read(true).open(path)?;
            Ok(Box::new(FileSerialPort(f)))
        }
    }

}

#[cfg(windows)]
pub use windows_impl::*;
