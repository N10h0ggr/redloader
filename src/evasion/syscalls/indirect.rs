use std::arch::global_asm;

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".data",
    "pGate: .quad 0",                 // puntero al stub válido en ntdll

    ".text",
    // ---------- set_gate(void* stub) ----------
    ".global set_gate",
    "set_gate:",
    "    mov [rip + pGate], rcx",     // RCX llega desde Rust → guardar
    "    ret",

    // ---------- run_indirect_syscall(...) ----------
    ".global run_indirect_syscall",
    "run_indirect_syscall:",
    "    mov r11, [rip + pGate]", 
    "    jmp r11", 
);

unsafe extern "C" {
    pub fn set_gate(stub: *const core::ffi::c_void);
    pub fn run_indirect_syscall(...) -> usize;
}