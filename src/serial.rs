//! Serial Port & Device I/O Configuration.

use serialport::SerialPort;
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

pub fn open_line_send(path: &Path, baud: u64) -> std::io::Result<Box<dyn SerialPort>> {
    let builder = serialport::new(path.to_string_lossy(), baud as u32)
        .timeout(std::time::Duration::from_millis(100));

    match builder.open() {
        Ok(port) => Ok(port),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to open serial port: {}", e),
        )),
    }
}

pub fn open_line_recv(path: &Path, baud: u64) -> std::io::Result<Box<dyn SerialPort>> {
    let builder = serialport::new(path.to_string_lossy(), baud as u32)
        .timeout(std::time::Duration::from_millis(10));

    match builder.open() {
        Ok(port) => Ok(port),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to open serial port: {}", e),
        )),
    }
}

pub fn flush_tty(port: &mut Box<dyn SerialPort>) {
    let _ = port.flush();
}
