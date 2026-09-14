import ctypes
from ctypes.wintypes import DWORD, HANDLE, LPVOID

SIZE_T = ctypes.c_size_t

# --- Process Access Flags ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# --- Memory Allocation & State Flags ---
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# --- Memory Protection Flags ---
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

# All protection flags granting code execution privileges
EXECUTABLE_PROTECTIONS = (
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
)

# --- Threat Signatures ---
SUSPICIOUS_PATTERNS = {
    # Match a 16-byte contiguous NOP sled to suppress false positives from short padding
    "NOP Sled (Potential Shellcode)": b"\x90" * 16,

    # INT3 (0xCC) omitted: JIT engines frequently use 0xCC for alignment padding
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
OpenProcess.restype = HANDLE
OpenProcess.argtypes = [DWORD, ctypes.c_bool, DWORD]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.restype = SIZE_T
VirtualQueryEx.argtypes = [HANDLE, LPVOID, ctypes.POINTER(MemoryBasicInformation), SIZE_T]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = ctypes.c_bool
CloseHandle.argtypes = [HANDLE]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = ctypes.c_bool
ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
