import ctypes as c
from ctypes import wintypes as w

# Define constants
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40

# Define Windows API functions
kernel32 = c.WinDLL('kernel32', use_last_error=True)
user32 = c.WinDLL('user32')

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
OpenProcess.restype = w.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [w.HANDLE, w.LPCVOID, c.c_size_t, w.DWORD, w.DWORD]
VirtualAllocEx.restype = w.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [w.HANDLE, w.LPCVOID,
                               w.LPVOID, c.c_size_t, c.POINTER(c.c_size_t)]
WriteProcessMemory.restype = w.BOOL

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [w.HANDLE, c.c_void_p,
                               c.c_size_t, w.LPVOID, w.LPVOID, w.DWORD, c.c_void_p]
CreateRemoteThread.restype = w.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [w.HANDLE]
CloseHandle.restype = w.BOOL

GetLastError = kernel32.GetLastError
GetLastError.restype = w.DWORD

# Define the function signature for GetModuleHandleW
kernel32.GetModuleHandleW.restype = w.HMODULE
kernel32.GetModuleHandleW.argtypes = [w.LPCWSTR]

# Define the function signature for GetProcAddress
kernel32.GetProcAddress.restype = c.c_void_p
kernel32.GetProcAddress.argtypes = [w.HMODULE, w.LPCSTR]


def get_function_address(module_name, function_name):
    module_handle = kernel32.GetModuleHandleW(module_name)
    if not module_handle:
        raise Exception(
            f"Failed to get module handle for {module_name}. Error code: {GetLastError()}")

    func_address = kernel32.GetProcAddress(
        module_handle, function_name.encode('utf-8'))
    if not func_address:
        raise Exception(
            f"Failed to get function address for {function_name}. Error code: {GetLastError()}")

    return func_address


def inject_code(target_pid, hwnd):
    print(f"Opening process with PID {target_pid}...")

    process_handle = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, target_pid)
    if not process_handle:
        print(f"Failed to open process. Error code: {GetLastError()}.")
        return

    print("Process opened successfully.")

    print("Allocating memory in the target process...")

    alloc_address = VirtualAllocEx(
        process_handle, 0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if not alloc_address:
        print(f"Failed to allocate memory. Error code: {GetLastError()}.")
        CloseHandle(process_handle)
        return

    print(f"Memory allocated at address {alloc_address}.")

    print("Writing code to the allocated memory...")

    try:
        function_address = get_function_address(
            "user32.dll", "SetWindowDisplayAffinity")
    except Exception as e:
        print(f"Error resolving function address: {e}")
        CloseHandle(process_handle)
        return

    hwnd_bytes = c.c_uint(hwnd).value.to_bytes(4, 'little')
    address_bytes = c.c_void_p(function_address).value.to_bytes(8, 'little')

    code = (
        b"\x68" + hwnd_bytes +
        b"\x68\x11\x00\x00\x00" +
        b"\xB8" + address_bytes +
        b"\xFF\xD0" +
        b"\xC3"
    )

    bytes_written = c.c_size_t(0)
    write_success = WriteProcessMemory(
        process_handle, alloc_address, code, len(code), c.byref(bytes_written))
    if not write_success:
        print(f"Failed to write memory. Error code: {GetLastError()}.")
        CloseHandle(process_handle)
        return

    print(f"Bytes written: {bytes_written.value}")
    print(f"Write success: {write_success}")

    print("Code written successfully.")

    print("Creating remote thread in the target process...")

    thread_handle = CreateRemoteThread(
        process_handle, None, 0, alloc_address, None, 0, None)
    if not thread_handle:
        print(f"Failed to create remote thread. Error code: {GetLastError()}.")
        CloseHandle(process_handle)
        return

    print(f"Thread handle: {thread_handle}")
    print("Remote thread created successfully.")

    # Optionally wait for the thread to finish
    result = c.windll.kernel32.WaitForSingleObject(
        thread_handle, 5000)  # 5 seconds timeout
    if result == 0xFFFFFFFF:  # WAIT_FAILED
        print(
            f"Failed to wait for thread completion. Error code: {GetLastError()}.")
    else:
        print("Thread completed.")

    c.windll.kernel32.CloseHandle(thread_handle)
    CloseHandle(process_handle)
    print("Process handle closed.")
