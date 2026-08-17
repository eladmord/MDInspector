import ctypes
import os

PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000


def create_rwx_memory():
    print("=== Dummy RWX Memory Allocator & Injector ===")

    pid = os.getpid()
    print(f"[*] PID של תהליך המטרה: {pid}")

    kernel32 = ctypes.windll.kernel32
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.restype = ctypes.c_void_p

    print("[*] מבקש מ-Windows להקצות 1KB של זיכרון RWX...")
    allocated_memory = VirtualAlloc(0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

    if not allocated_memory:
        print("[!] שגיאה בהקצאת הזיכרון.")
        return

    print(f"[+] זיכרון RWX הוקצה בהצלחה בכתובת: {hex(allocated_memory)}")

    # ==========================================
    # השלב החדש: כתיבת ה-"Shellcode" לזיכרון
    # ==========================================
    # ניצור רצף בתים שמדמה NOP Sled (0x90) ואחריו Breakpoints (0xCC)
    fake_shellcode = b"\x90" * 16 + b"\xCC" * 16

    # נעתיק את הבתים לתוך כתובת הזיכרון שהקצינו
    ctypes.memmove(allocated_memory, fake_shellcode, len(fake_shellcode))
    print(f"[+] הוזרקו {len(fake_shellcode)} Bytes של 'Shellcode' מזויף (NOPs + INT3) אל תוך הזיכרון.")

    print("\n>>> עבור כעת לסקריפט mem_scanner.py, הרץ אותו, והזן את ה-PID שלמעלה. <<<")
    input("\n(לאחר הסריקה) לחץ Enter כדי לשחרר את הזיכרון ולסגור את התוכנית...")


if __name__ == "__main__":
    create_rwx_memory()