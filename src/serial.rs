//! Serial Port & Device I/O Configuration.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

pub fn auto_chunk_size(baud: u64) -> usize {
    if baud < 500_000 {
        1024
    } else if baud < 2_500_000 {
        4096
    } else {
        16384
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
        2500000 => Some(0o010014),
        3000000 => Some(0o010015),
        3500000 => Some(0o010016),
        4000000 => Some(0o010017),
        _ => None,
    }
}

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
    fn tcgetattr(fd: std::os::raw::c_int, termios_p: *mut Termios) -> std::os::raw::c_int;
    fn tcsetattr(fd: std::os::raw::c_int, optional_actions: std::os::raw::c_int, termios_p: *const Termios) -> std::os::raw::c_int;
    fn cfmakeraw(termios_p: *mut Termios);
    fn cfsetispeed(termios_p: *mut Termios, speed: u32) -> std::os::raw::c_int;
    fn cfsetospeed(termios_p: *mut Termios, speed: u32) -> std::os::raw::c_int;
    fn tcflush(fd: std::os::raw::c_int, queue_selector: std::os::raw::c_int) -> std::os::raw::c_int;
    fn tcdrain(fd: std::os::raw::c_int) -> std::os::raw::c_int;
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
        t.c_cflag |= 0o004000 | 0o000200 | 0o000060; // CLOCAL | CREAD | CS8
        t.c_cflag &= !(0o000020 | 0o002000 | 0o000400 | 0o001000 | 0o20000000000); // CSTOPB | HUPCL | PARENB | PARODD | CRTSCTS
        t.c_iflag &= !(0o002000 | 0o010000 | 0o004000); // IXON | IXOFF | IXANY
        t.c_cc[6] = 1; // VMIN = 1
        t.c_cc[5] = 0; // VTIME = 0

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

    configure_tty(file.as_raw_fd(), baud)?;
    Ok(file)
}

pub fn open_line_recv(path: &Path, baud: u64) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0o0400) // O_NOCTTY
        .open(path)?;

    configure_tty(file.as_raw_fd(), baud)?;
    Ok(file)
}

pub fn flush_tty(file: &File) {
    unsafe {
        if isatty(file.as_raw_fd()) != 0 {
            tcdrain(file.as_raw_fd());
        }
    }
}
