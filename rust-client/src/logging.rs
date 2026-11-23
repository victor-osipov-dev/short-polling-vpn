//! Logging: stderr plus a rotating-ish log file used by `spvpn logs` / TUI.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
pub struct TeeWriter {
    file: Option<PathBuf>,
    stderr: bool,
    lock: std::sync::Arc<Mutex<()>>,
}

impl TeeWriter {
    pub fn new(file: Option<PathBuf>, stderr: bool) -> Self {
        Self {
            file,
            stderr,
            lock: std::sync::Arc::new(Mutex::new(())),
        }
    }
}

pub struct GuardedWriter {
    file: Option<std::fs::File>,
    stderr: bool,
    lock: std::sync::Arc<Mutex<()>>,
}

impl Write for GuardedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _guard = self.lock.lock().unwrap();
        if self.stderr {
            let _ = io::stderr().write_all(buf);
        }
        if let Some(file) = &mut self.file {
            let _ = file.write_all(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _guard = self.lock.lock().unwrap();
        if self.stderr {
            let _ = io::stderr().flush();
        }
        if let Some(file) = &mut self.file {
            let _ = file.flush();
        }
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for TeeWriter {
    type Writer = GuardedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        let file = self.file.as_ref().and_then(|path| {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        });
        GuardedWriter {
            file,
            stderr: self.stderr,
            lock: self.lock.clone(),
        }
    }
}

/// Initializes logging. `to_stderr` is disabled while the TUI owns the
/// terminal; the log file keeps receiving everything.
pub fn init(dir: &Path, verbose: bool, to_stderr: bool) {
    let file = dir.join("spvpn.log");
    let filter = if verbose {
        "spvpn=debug,info"
    } else {
        "spvpn=info,warn"
    };
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .with_ansi(false)
        .with_writer(TeeWriter::new(Some(file), to_stderr));
    let _ = subscriber.try_init();
}

/// Returns the last `max` bytes of the log file as text (best effort).
pub fn tail(dir: &Path, max: usize) -> String {
    let path = dir.join("spvpn.log");
    let Ok(meta) = std::fs::metadata(&path) else {
        return String::new();
    };
    let len = meta.len() as usize;
    let start = len.saturating_sub(max);
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(&path) else {
        return String::new();
    };
    if file.seek(SeekFrom::Start(start as u64)).is_err() {
        return String::new();
    }
    let mut buf = String::new();
    let _ = file.read_to_string(&mut buf);
    if start > 0 {
        // Drop a partial first line.
        if let Some(idx) = buf.find('\n') {
            buf.drain(..=idx);
        }
    }
    buf
}

pub fn log_path(dir: &Path) -> PathBuf {
    dir.join("spvpn.log")
}
