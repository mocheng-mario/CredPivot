use crate::error::{AgentError, Result};
use crate::paths::single_writer_lock_path;
use fs2::FileExt;
use std::fs::OpenOptions;
/// Exclusive runtime lock: only one App process may own the agent / sockets.
pub struct SingleWriterLock {
    file: std::fs::File,
}

impl SingleWriterLock {
    pub fn acquire() -> Result<Self> {
        crate::paths::ensure_runtime_dir()?;
        let path = single_writer_lock_path();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { file }),
            Err(_) => Err(AgentError::SingleWriterConflict),
        }
    }

}

impl Drop for SingleWriterLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
