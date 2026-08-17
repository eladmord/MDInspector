import ctypes
import os

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000


def create_rwx_memory():
    print("=== Dummy RWX Memory Allocator & Injector ===")

    pid = os.getpid()
    print(f"[*] Target Process PID: {pid}")

    kernel32 = ctypes.windll.kernel32
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p

    print("[*] Requesting Windows to allocate 1KB of RWX memory...")
    allocated_memory = VirtualAlloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

    if not allocated_memory:
        print("[!] Error: Failed to allocate memory.")
        return

    print(f"[+] RWX memory allocated successfully at: {hex(allocated_memory)}")

    # Inject simulated payload: NOP sled (0x90) followed by INT3 Breakpoints (0xCC)
    fake_shellcode = b"\x90" * 16 + b"\xCC" * 16
    ctypes.memmove(allocated_memory, fake_shellcode, len(fake_shellcode))
    print(f"[+] Injected {len(fake_shellcode)} bytes of mock payload (NOPs + INT3) into memory.")

    print("\n>>> Run the scanner in another terminal against this PID. <<<")
    input("\nPress Enter after scanning to release memory and exit...")


if __name__ == "__main__":
    create_rwx_memory()