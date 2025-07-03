use std::arch::asm;
use windows::Win32::System::Threading::{PEB, PEB_LDR_DATA, TEB};
use windows::Win32::Foundation::{HMODULE};
use windows::Win32::System::WindowsProgramming::LDR_DATA_TABLE_ENTRY;
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use crate::utils::fast_crc32::{compute_crc32_hash, FastCrc32};

#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut TEB {
    let teb: *mut TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    (*teb).ProcessEnvironmentBlock
}

/// Retrieves the module handle for a given DLL name crc32 hash.
///
/// # Arguments
/// * `dll_name_hash` - The crc32 hash of the DLL name in uppercase for which to get the module handle.
///
/// # Returns
/// * `Option<*const u8>` - The pointer of the module if found, or `None` if not found.
pub unsafe fn get_module_handle_by_hash(dll_name_hash: u32) -> Option<usize> {
    let peb: *const PEB = get_peb();
    let p_ldr: *const PEB_LDR_DATA = (*peb).Ldr;
    let mut p_dte: *const LDR_DATA_TABLE_ENTRY = (*p_ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;

    let crc32 = FastCrc32::new();

    while let Some(p_dte_ref) = p_dte.as_ref() {
        if !p_dte_ref.FullDllName.Buffer.is_null() {
            let dte_name_upper = p_dte_ref.FullDllName.Buffer.to_string().unwrap().to_uppercase();
            let dte_name_hash = crc32.compute_hash(dte_name_upper.as_bytes());
            if dte_name_hash == dll_name_hash {
                return Some(p_dte_ref.Reserved2[0] as _);
            }
        } else { break; }
        // Next element in the linked list
        p_dte = p_dte_ref.Reserved1[0] as *const LDR_DATA_TABLE_ENTRY ;
    }
    None
}
/// Retrieves the module handle for a given DLL name.
///
/// # Arguments
/// * `dll_name_hash` - The DLL name for which to get the module handle.
///
/// # Returns
/// * `Option<*const u8>` - The pointer of the module if found, or `None` if not found.
pub unsafe fn get_module_handle(dll_name: String) -> Option<usize> {
    let dll_name_hash = compute_crc32_hash(dll_name.to_uppercase().as_ref());
    get_module_handle_by_hash(dll_name_hash)
}

/// Retrieves the NT headers for a given module handle.
///
/// # Arguments
/// * `module_handle` - The handle of the module for which to get the NT headers.
///
/// # Returns
/// * `*mut IMAGE_NT_HEADERS` - A pointer to the NT headers of the module, or `ptr::null_mut()` if invalid.
pub unsafe fn get_nt_headers(module_handle: HMODULE) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos_header = module_handle.0 as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D { // Check for 'MZ' magic number
        return None;
    }
    let nt_headers = (module_handle.0 as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt_headers).Signature != 0x00004550 { // Check for 'PE\0\0' signature
        return None;
    }
    Some(nt_headers as *mut IMAGE_NT_HEADERS64)
}

/// Retrieves the export directory for a given module handle.
///
/// # Arguments
/// * `module_handle` - The handle of the module for which to get the export directory.
///
/// # Returns
/// * `Option<*const IMAGE_EXPORT_DIRECTORY>` - A pointer to the export directory, or `None` if not found.
pub unsafe fn get_export_directory(module_handle: HMODULE) -> Option<*const IMAGE_EXPORT_DIRECTORY> {
    let nt_headers = get_nt_headers(module_handle)?;
    if nt_headers.is_null() {
        return None;
    }

    let export_directory_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_directory_rva == 0 {
        return None;
    }
    Some((module_handle.0 as usize + export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY)
}

/// Retrieves the names of all exported functions from a given DLL.
///
/// # Arguments
/// * `dll_name_hash` - The crc32 hash of the DLL name in uppercase for which to get the module handle.
///
/// # Returns
/// * `Vec<String>` - A vector containing the names of all exported functions.
pub unsafe fn get_dll_exported_functions_by_hash(dll_name_hash: usize) -> Vec<String> {
    let mut exported_functions = Vec::new();

    if let Some(module_handle) = get_module_handle_by_hash(dll_name_hash as u32) {
        if let Some(export_directory) = get_export_directory(HMODULE(module_handle as _)) {
            let base_address = module_handle as usize;
            let names_rva = (*export_directory).AddressOfNames;
            let names_count = (*export_directory).NumberOfNames;

            let names = std::slice::from_raw_parts((base_address + names_rva as usize) as *const u32, names_count as usize);
            for i in 0..names_count {
                let name_ptr = (base_address + names[i as usize] as usize) as *const i8;
                let function_name = std::ffi::CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
                exported_functions.push(function_name);
            }
        }
    }

    exported_functions
}

#[cfg(test)]
mod tests {
    use windows::core::{w};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use crate::utils::fast_crc32::FastCrc32;
    use super::*;

    #[test]
    fn test_get_module_handle() {
        let crc32 = FastCrc32::new();

        unsafe {
            let dll_name = w!("NTDLL.DLL");
            let dll_hash = crc32.compute_hash(dll_name.to_string().unwrap().as_bytes());

            // WinAPI handle
            let win_handle = GetModuleHandleW(dll_name).unwrap();
            // Custom handle
            let custom_handle = get_module_handle_by_hash(dll_hash).unwrap() as _;
            // Custom handle using name
            let custom_handle_by_name = get_module_handle(dll_name.to_string().unwrap()).unwrap() as _;

            assert_eq!(win_handle, HMODULE(custom_handle));
            assert_eq!(win_handle, HMODULE(custom_handle_by_name))
        }
    }

    #[test]
    fn test_get_dll_exported_functions_by_hash() {
        let crc32 = FastCrc32::new();

        unsafe {
            let dll_name = w!("non_existent_dll.DLL");
            let dll_hash = crc32.compute_hash(unsafe { dll_name.to_string().expect("Unable to transform PCWSTR to String").to_uppercase() }.as_bytes());

            let exported_functions = get_dll_exported_functions_by_hash(dll_hash as usize);
            assert_eq!(exported_functions.len(), 0);

            let dll_name = w!("NTDLL.DLL");
            let dll_hash = crc32.compute_hash(unsafe { dll_name.to_string().expect("Unable to transform PCWSTR to String").to_uppercase() }.as_bytes());

            let exported_functions = get_dll_exported_functions_by_hash(dll_hash as usize);
            assert_ne!(exported_functions.len(), 0);

            let dll_name = w!("Kernel32.dll");
            let dll_hash = crc32.compute_hash(unsafe { dll_name.to_string().expect("Unable to transform PCWSTR to String").to_uppercase() }.as_bytes());

            let exported_functions = get_dll_exported_functions_by_hash(dll_hash as usize);
            assert_ne!(exported_functions.len(), 0);

            let dll_name = w!("gibberish");
            let dll_hash = crc32.compute_hash(unsafe { dll_name.to_string().expect("Unable to transform PCWSTR to String").to_uppercase() }.as_bytes());

            let exported_functions = get_dll_exported_functions_by_hash(dll_hash as usize);
            assert_eq!(exported_functions.len(), 0);
        }
    }
}