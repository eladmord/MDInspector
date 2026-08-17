import ctypes
import os
from constants import (
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PAGE_EXECUTE_READWRITE,
    MEM_COMMIT, MEM_PRIVATE, MEM_IMAGE, MEM_MAPPED,
    MemoryBasicInformation, SUSPICIOUS_PATTERNS,
    OpenProcess, VirtualQueryEx, CloseHandle, ReadProcessMemory, SIZE_T
)


def scan_rwx_memory(pid):
    print(f"[*] Attempting to open handle to process {pid}...")

    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

    if not h_process:
        print(f"[!] Error: Could not open process {pid}.")
        print("    Tip: Ensure the PID is correct and the script is running with Administrative privileges.")
        return

    print(f"[+] Handle established: {h_process}")
    print("[*] Initiating memory space enumeration...\n")

    address = 0
    mbi = MemoryBasicInformation()
    mbi_size = ctypes.sizeof(mbi)
    findings = []

    while VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size):

        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE:
            base_addr = hex(mbi.BaseAddress if mbi.BaseAddress else 0)
            region_size = mbi.RegionSize

            memory_type_str = "UNKNOWN"
            is_highly_suspicious = False

            if mbi.Type == MEM_PRIVATE:
                memory_type_str = "MEM_PRIVATE (Unbacked)"
                is_highly_suspicious = True
            elif mbi.Type == MEM_IMAGE:
                memory_type_str = "MEM_IMAGE (Backed)"
            elif mbi.Type == MEM_MAPPED:
                memory_type_str = "MEM_MAPPED"

            print(f"[!] RWX Region Found: {base_addr} | Size: {region_size} Bytes")
            print(f"    --> Memory Type: {memory_type_str}")

            if is_highly_suspicious:
                print("    [*] Commencing memory dump...")
                buffer = ctypes.create_string_buffer(region_size)
                bytes_read = SIZE_T(0)

                success = ReadProcessMemory(
                    h_process, ctypes.c_void_p(mbi.BaseAddress), buffer, region_size, ctypes.byref(bytes_read)
                )

                if success:
                    print(f"    [+] Successfully read {bytes_read.value} Bytes.")

                    if buffer.raw[:2] == b"MZ":
                        print("    [!!!] CRITICAL: 'MZ' PE Header detected! (Reflective PE/DLL Injection)")

                    for pattern_name, pattern_bytes in SUSPICIOUS_PATTERNS.items():
                        if pattern_bytes in buffer.raw:
                            print(f"    [!!!] SIGNATURE MATCH: {pattern_name} detected in memory!")

                    # --- Dump to Disk ---
                    os.makedirs("dumps", exist_ok=True)
                    dump_filename = f"dump_PID{pid}_{base_addr}.bin"
                    dump_path = os.path.join("dumps", dump_filename)

                    with open(dump_path, "wb") as f:
                        f.write(buffer.raw)
                    print(f"    [v] Raw memory dumped to disk: {dump_path}\n")
                else:
                    print("    [-] Failed to read memory.\n")

            findings.append({
                "BaseAddress": base_addr,
                "Size": region_size,
                "Suspicious": is_highly_suspicious
            })

        address += mbi.RegionSize

    print(f"[*] Scan completed. Total RWX regions identified: {len(findings)}")
    CloseHandle(h_process)
    print("[-] Process handle closed.")