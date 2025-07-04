
pub mod direct;
pub use direct::run_direct_syscall;

pub mod indirect;
pub use indirect::run_indirect_syscall;

pub mod hallos_gate;
pub use hallos_gate::prepare_direct_syscall;
pub use hallos_gate::prepare_indirect_syscall;