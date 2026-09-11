import ctypes
import os
import math
from collections import Counter
from constants import (
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE,
    EXECUTABLE_PROTECTIONS, MemoryBasicInformation,
    SUSPICIOUS_PATTERNS, OpenProcess, VirtualQueryEx,
    CloseHandle, ReadProcessMemory, SIZE_T
)

MAX_DUMP_SIZE = 50 * 1024 * 1024  # 50MB MAX DUMP


def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy


def get_protection_name(protect_val):
    base_protect = protect_val & 0xFF
    names = {
        0x10: "PAGE_EXECUTE",
        0x20: "PAGE_EXECUTE_READ",
        0x40: "PAGE_EXECUTE_READWRITE",
        0x80: "PAGE_EXECUTE_WRITECOPY"
    }
    return names.get(base_protect, f"0x{protect_val:X}")


def scan_process_memory(pid, quiet=False):
    if not quiet:
        print(f"[*] Opening target process: PID {pid}")

    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

    if not h_process:
        if not quiet:
            print(f"[!] Access Denied or Invalid PID ({pid}).")
        return []

    if not quiet:
        print(f"[+] Process handle obtained: {h_process}")
        print("[*] Walking virtual memory address space...\n")

    address = 0
    mbi = MemoryBasicInformation()
    mbi_size = ctypes.sizeof(mbi)
    findings = []

    try:
        while VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size):
            if mbi.RegionSize == 0:
                break

            is_executable = (mbi.Protect & 0xFF) in EXECUTABLE_PROTECTIONS

            if mbi.State == MEM_COMMIT and is_executable:
                base_addr_int = mbi.BaseAddress if mbi.BaseAddress else 0
                base_addr_hex = hex(base_addr_int)
                protect_str = get_protection_name(mbi.Protect)
                is_unbacked = (mbi.Type == MEM_PRIVATE)
                is_rwx = ((mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE)

                # אם זה אזור מגובה קובץ ובמצב שקט - דלג
                if quiet and not is_unbacked:
                    address += mbi.RegionSize
                    continue

                severity = "SUSPICIOUS (Unbacked Executable - RX)"
                if is_rwx:
                    severity = "CRITICAL (Unbacked Executable - RWX)"

                if is_unbacked:
                    read_size = min(mbi.RegionSize, MAX_DUMP_SIZE)
                    buffer = ctypes.create_string_buffer(read_size)
                    bytes_read = SIZE_T(0)

                    success = ReadProcessMemory(
                        h_process, ctypes.c_void_p(base_addr_int), buffer, read_size, ctypes.byref(bytes_read)
                    )

                    if success and bytes_read.value > 0:
                        payload = buffer.raw[:bytes_read.value]
                        entropy = calculate_entropy(payload)
                        has_mz = payload[:2] == b"MZ"
                        matched_signatures = [name for name, sig in SUSPICIOUS_PATTERNS.items() if sig in payload]

                        is_high_entropy = entropy > 6.5
                        has_known_signatures = has_mz or len(matched_signatures) > 0

                        should_dump = is_high_entropy or has_known_signatures

                        # == הסינון החכם ==
                        # אם אנחנו במצב שקט וזה כנראה רק דפדפן (JIT) - שותקים ועוברים הלאה
                        if quiet and not should_dump:
                            address += mbi.RegionSize
                            continue

                        # מכאן והלאה - אנחנו מדפיסים כי מצאנו איום אמיתי (או שאנחנו במצב סריקה של PID בודד)
                        if quiet:
                            print(f"\n[!!!] REAL THREAT DETECTED IN PID: {pid} [!!!]")

                        print(f"[!] Executable Region: {base_addr_hex} | Size: {mbi.RegionSize} bytes")
                        print(f"    --> Protection: {protect_str}")
                        print(f"    --> Memory Type: MEM_PRIVATE (Unbacked)")
                        print(f"    --> Threat Assessment: {severity}")

                        if not should_dump:
                            print(
                                f"    [i] Low Entropy ({entropy:.2f}) & No Signatures -> Classified as legitimate JIT. Skipping dump.\n")
                        else:
                            if mbi.RegionSize > MAX_DUMP_SIZE and not quiet:
                                print(
                                    f"    [!] Warning: Region too large. Limiting dump to first {MAX_DUMP_SIZE} bytes.")

                            print(f"    [+] Successfully read {bytes_read.value} bytes.")
                            print(f"    [i] Shannon Entropy: {entropy:.2f}/8.00", end="")
                            print(" (HIGH - Possible Packed/Encrypted Code!)" if is_high_entropy else " (LOW)")

                            if has_mz:
                                print("    [!!!] ALERT: Injected PE Header ('MZ') detected!")

                            for sig in matched_signatures:
                                print(f"    [!!!] SIGNATURE MATCH: {sig}")

                            os.makedirs("dumps", exist_ok=True)
                            dump_path = os.path.join("dumps", f"dump_PID{pid}_{base_addr_hex}.bin")
                            with open(dump_path, "wb") as f:
                                f.write(payload)
                            print(f"    [v] Artifact dumped to: {dump_path}\n")

                        # נוסיף לממצאים רק דברים שהחלטנו לא להתעלם מהם
                        findings.append(
                            {"Address": base_addr_hex, "Size": mbi.RegionSize, "Type": mbi.Type, "Dumped": should_dump})
                    else:
                        if not quiet:
                            print(f"[!] Executable Region: {base_addr_hex} | Size: {mbi.RegionSize} bytes")
                            print("    [-] Failed to read memory buffer.\n")
                else:
                    if not quiet:
                        print(f"[!] Executable Region: {base_addr_hex} | Size: {mbi.RegionSize} bytes")
                        print(f"    --> Protection: {protect_str}")
                        print("    --> Memory Type: MEM_IMAGE / MAPPED")

            address += mbi.RegionSize

    except Exception as err:
        if not quiet:
            print(f"[!] Error during memory inspection: {err}")
    finally:
        CloseHandle(h_process)
        if not quiet:
            print("[-] Target handle safely released.")

    if not quiet:
        print(f"[*] Scan finished. Executable regions analyzed: {len(findings)}")

    return findings