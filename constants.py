import ctypes
from ctypes.wintypes import DWORD, HANDLE, LPVOID

SIZE_T = ctypes.c_size_t

# --- Constants ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# --- Threat Signatures ---
SUSPICIOUS_PATTERNS = {
    "NOP Sled (Potential Shellcode)": b"\x90\x90\x90\x90\x90\x90\x90\x90",
    "INT3 Breakpoints": b"\xCC\xCC\xCC\xCC",
}

# --- Windows API Structures ---
class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationBase", LPVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]

# --- API Setup ---
kernel32 = ctypes.windll.kernel32
OpenProcess = kernel32.OpenProcess
VirtualQueryEx = kernel32.VirtualQueryEx
CloseHandle = kernel32.CloseHandle
ReadProcessMemory = kernel32.ReadProcessMemory

OpenProcess.restype = HANDLE
OpenProcess.argtypes = [DWORD, ctypes.c_bool, DWORD]

VirtualQueryEx.restype = SIZE_T
VirtualQueryEx.argtypes = [HANDLE, LPVOID, ctypes.POINTER(MemoryBasicInformation), SIZE_T]

CloseHandle.restype = ctypes.c_bool
CloseHandle.argtypes = [HANDLE]

ReadProcessMemory.restype = ctypes.c_bool
ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]