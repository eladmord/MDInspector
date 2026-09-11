import ctypes
import os
from ctypes.wintypes import DWORD

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

def run_injector():
    print("=== Advanced Mock Payload Injector ===")
    pid = os.getpid()
    print(f"[*] Current Process PID: {pid}")

    kernel32 = ctypes.windll.kernel32
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p

    VirtualProtect = kernel32.VirtualProtect
    VirtualProtect.restype = ctypes.c_bool
    VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, DWORD, ctypes.POINTER(DWORD)]

    print("\nSelect Injection Technique:")
    print("1. Classic RWX Injection (PAGE_EXECUTE_READWRITE)")
    print("2. Modern W^X Bypass (Alloc RW -> Write Shellcode -> Flip to RX)")
    choice = input("Enter choice (1 or 2): ").strip()

    initial_protect = PAGE_EXECUTE_READWRITE if choice == "1" else PAGE_READWRITE
    allocated_memory = VirtualAlloc(0, 1024, MEM_COMMIT | MEM_RESERVE, initial_protect)

    if not allocated_memory:
        print("[!] Allocation failed.")
        return

    print(f"[+] Memory allocated at: {hex(allocated_memory)}")

    # פיילוד דמה: NOP Sled ולאחריו INT3
    mock_shellcode = b"\x90" * 16 + b"\xCC" * 16
    ctypes.memmove(allocated_memory, mock_shellcode, len(mock_shellcode))
    print(f"[+] Written {len(mock_shellcode)} bytes of mock shellcode.")

    if choice == "2":
        old_protect = DWORD()
        success = VirtualProtect(allocated_memory, 1024, PAGE_EXECUTE_READ, ctypes.byref(old_protect))
        if success:
            print("[+] VirtualProtect applied: Protection successfully changed from RW to RX!")
        else:
            print("[!] VirtualProtect failed.")

    print("\n>>> Run 'python main.py -p " + str(pid) + "' in another terminal. <<<")
    input("\nPress Enter to release memory and exit...")

if __name__ == "__main__":
    run_injector()