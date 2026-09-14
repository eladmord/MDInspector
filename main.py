import argparse
import ctypes
from ctypes import wintypes
from scanner import scan_process_memory


def get_all_pids():
    """Retrieves all active Process IDs using the Windows API (EnumProcesses)"""
    psapi = ctypes.WinDLL('psapi')

    # Allocate an array large enough to hold active PIDs (up to 1024 processes)
    array_size = 1024
    process_ids = (wintypes.DWORD * array_size)()
    bytes_returned = wintypes.DWORD()

    if not psapi.EnumProcesses(ctypes.byref(process_ids), ctypes.sizeof(process_ids), ctypes.byref(bytes_returned)):
        print("[!] Failed to enumerate processes.")
        return []

    # Calculate the actual number of PIDs returned
    num_processes = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
    return [process_ids[i] for i in range(num_processes) if process_ids[i] != 0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MDInspector: Windows Process Memory Injection & Unbacked Code Scanner",
        epilog="Examples:\n  python main.py -p 1234\n  python main.py --all",
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pid", type=int, help="Target Process PID to scan")
    group.add_argument("-a", "--all", action="store_true", help="Scan all running processes (Quiet Mode)")

    args = parser.parse_args()

    print("=== MDInspector: Memory Forensics & Anomaly Detector ===")

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        print("[!] Warning: Non-admin privileges detected. Many processes will return Access Denied.\n")

    if args.pid:
        scan_process_memory(args.pid, quiet=False)
    elif args.all:
        print("[*] Initiating system-wide scan across all active processes...")
        print("[*] Running in Quiet Mode: Only anomalies (Unbacked Executable Memory) will be reported.\n")

        pids = get_all_pids()
        suspicious_processes = 0

        for pid in pids:
            # Pass quiet=True to suppress background noise during system sweep
            findings = scan_process_memory(pid, quiet=True)
            if any(f.get("Type") == 0x20000 for f in findings):  # 0x20000 = MEM_PRIVATE
                suspicious_processes += 1

        print(f"\n[*] System-wide scan complete. Scanned {len(pids)} processes.")
        if suspicious_processes == 0:
            print("[v] No memory anomalies detected system-wide.")
        else:
            print(f"[!] Found anomalies in {suspicious_processes} processes. Check the 'dumps' directory.")
