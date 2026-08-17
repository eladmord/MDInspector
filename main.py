import argparse
import ctypes
from scanner import scan_rwx_memory

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced Windows Memory Scanner: Detects unbacked executable memory and injected payloads.",
        epilog="Example usage: python main.py --pid 1234",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "-p", "--pid",
        type=int,
        required=True,
        help="The Process ID (PID) of the target process to scan."
    )

    args = parser.parse_args()

    print("=== Windows Memory Dump & Anomaly Inspector ===")

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        print("[!] WARNING: Script is not running with Administrative privileges.")
        print("    OpenProcess may fail with Access Denied (Error 5) for certain processes.\n")

    # Execute the scanner module
    scan_rwx_memory(args.pid)