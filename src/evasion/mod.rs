//! Evasion techniques for loader modules.

pub mod syscalls;

use thiserror::Error;

/// Common error type for evasion functions.
#[derive(Debug, Error)]
pub enum EvadeError {
    #[error("failed to load DLL: {0}")]
    LoadFailure(String),
    #[error("memory allocation failure")]
    MemoryAllocationFailure,
    #[error("syscall failed with status: {0:#x}")]
    SyscallFailed(u32),
    #[error("invalid image base")]
    InvalidImageBase,
}
