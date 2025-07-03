
use std::arch::global_asm;

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".data",
    "wSystemCall: .long 0x0000",

    ".text",
    ".global set_ssn",
    "set_ssn:",
    "    xor eax, eax",
    "    mov DWORD PTR wSystemCall[rip], eax",
    "    mov eax, ecx",
    "    mov r8d, eax",
    "    mov DWORD PTR wSystemCall[rip], r8d",
    "    ret",

    ".global run_direct_syscall",
    "run_direct_syscall:",
    "    xor r10, r10",                 // r10 = 0
    "    mov rax, rcx",                 // rax = rcx
    "    mov r10, rax",                 // r10 = rax = rcx
    "    mov eax, DWORD PTR wSystemCall[rip]",  // eax = ssn
    "    jmp run",                      // execute 'Run'
    "    xor eax, eax",                 // won't run
    "    xor rcx, rcx",                 // won't run
    "    shl r10, 2",                   // won't run
    "run:",
    "    syscall",                      // syscall
    "    ret"

);

unsafe extern "C" {
    pub fn set_ssn(ssn: usize);
    // The three dots means an undetermined number of parameters
    pub fn run_direct_syscall(...) -> usize;
}