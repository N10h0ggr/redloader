
pub mod direct;
pub use direct::run_direct_syscall;

pub mod hells_gate;
pub use hells_gate::prepare_direct_syscall;