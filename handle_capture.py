import ctypes as c
from ctypes import wintypes as w

# Define constants
WH_MOUSE_LL = 14
WM_LBUTTONDOWN = 0x0201

# Define the MSLLHOOKSTRUCT structure
class MSLLHOOKSTRUCT(c.Structure):
    _fields_ = [
        ("pt", w.POINT),
        ("mouseData", w.DWORD),
        ("dwExtraInfo", c.c_ulong),
        ("flags", w.DWORD),
        ("time", w.DWORD)
    ]

# Define the callback type for the hook
LOW_LEVEL_MOUSE_PROC = c.WINFUNCTYPE(
    c.c_long, c.c_int, c.c_uint, c.POINTER(MSLLHOOKSTRUCT)
)

# Load the user32 and kernel32 libraries
user32 = c.WinDLL('user32', use_last_error=True)
kernel32 = c.WinDLL('kernel32', use_last_error=True)

# Variable to hold the result
captured_hwnd_pid = None

# Define the hook callback function
def mouse_hook_callback(nCode, wParam, lParam):
    global captured_hwnd_pid
    if nCode >= 0 and wParam == WM_LBUTTONDOWN:
        print("Left mouse button clicked")
        # Extract window handle
        pt = w.POINT()
        user32.GetCursorPos(c.byref(pt))
        hwnd = user32.WindowFromPoint(pt)
        if hwnd:
            # Retrieve process ID from window handle
            pid = w.DWORD()
            user32.GetWindowThreadProcessId(hwnd, c.byref(pid))
            captured_hwnd_pid = (hwnd, pid.value)

            # Stop processing further hooks
            c.windll.user32.PostQuitMessage(0)
    return user32.CallNextHookEx(None, nCode, wParam, lParam)

def set_mouse_hook():
    hook_proc = LOW_LEVEL_MOUSE_PROC(mouse_hook_callback)
    hook_id = user32.SetWindowsHookExW(WH_MOUSE_LL, hook_proc, None, 0)
    if not hook_id:
        raise RuntimeError(f'Failed to set hook. Error code: {c.GetLastError()}')

    global captured_hwnd_pid
    captured_hwnd_pid = None
    try:
        msg = w.MSG()
        while user32.GetMessageW(c.byref(msg), None, 0, 0) != 0:
            user32.TranslateMessage(c.byref(msg))
            user32.DispatchMessageW(c.byref(msg))
            if captured_hwnd_pid:
                break
    except Exception as e:
        print(f"An error occurred during message processing: {e}")
    finally:
        if hook_id:
            user32.UnhookWindowsHookEx(hook_id)
    
    return captured_hwnd_pid

def capture_window_handle_and_pid(option):
    print("Set up the hook. Click on the window you want to capture.")
    hwnd_pid = set_mouse_hook()
    if hwnd_pid:
        hwnd, pid = hwnd_pid
        print(f"Captured Window Handle: {hwnd}")
        print(f"Captured Process ID: {pid}")
        return hwnd, pid
    else:
        print("No window was captured.")
        return None, None
