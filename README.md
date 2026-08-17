# MDInspector (Memory Dump & Anomaly Inspector) 🔍

MDInspector is a lightweight, proof-of-concept Windows memory scanner written in Python. It is designed to detect and extract advanced memory-resident threats, such as Fileless Malware, Shellcode, and Reflective DLL Injections, by interacting directly with the Windows Kernel via the Win32 API.

## 🧠 Core Architecture & Methodology

Unlike traditional static antivirus scanners that rely on disk-based file signatures, MDInspector hunts for anomalies dynamically in the Random Access Memory (RAM). It leverages `ctypes` to bridge Python with `kernel32.dll` and enumerates the virtual memory space of a target process.

The detection engine relies on identifying **Unbacked Executable Memory**:
* **RWX Permissions**: Locates memory pages explicitly allocated with `PAGE_EXECUTE_READWRITE` (0x40).
* **MEM_PRIVATE State**: Cross-references the RWX pages to ensure they are `MEM_PRIVATE` (unbacked by a physical file on disk), which is a high-confidence indicator of Process Injection (e.g., via `VirtualAllocEx`).
* **Pattern Matching & Extraction**: Utilizes `ReadProcessMemory` to dump the suspicious region, searching for `MZ` headers (Reflective PE Injection) or NOP Sleds / INT3 traps (Shellcode execution).

## ⚙️ Features
* **Virtual Memory Enumeration**: Rapidly maps committed memory regions using `VirtualQueryEx`.
* **Heuristic Anomaly Detection**: Flags memory that violates the W^X (Write XOR Execute) security mitigation.
* **Signature Scanning**: Scans raw bytes in memory for known malicious patterns.
* **Automated Evidence Dumping**: Automatically extracts flagged memory regions into `.bin` files for offline reverse engineering and forensic analysis.

## 🚀 Usage

### Prerequisites
* Python 3.x
* Windows OS
* Administrative privileges (Required to obtain `PROCESS_VM_READ` handles via `OpenProcess` for elevated processes).

### Running the Scanner
Use the Command Line Interface (CLI) to attach the scanner to a target process:

```cmd
python main.py --pid <Target_PID>
```

### Testing the Engine (Dummy Injector)
To safely test the scanner without deploying real malware, a self-injecting dummy script is provided. It allocates an unbacked RWX memory region and writes a fake NOP Sled + INT3 payload.

1. Run the injector script:
   ```cmd
   python tests/dummy_injector.py
   ```
2. Note the generated PID.
3. Open a new terminal and run the scanner against that PID:
   ```cmd
   python main.py --pid <PID>
   ```
4. Check the `dumps/` folder for the extracted `.bin` memory dump.

## ⚠️ Disclaimer
This tool was developed for educational and research purposes only, focusing on Windows Internals, defensive engineering, and Incident Response methodologies.