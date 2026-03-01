# PE Import Analyzer: A Practical Guide for Malware Analysts and Reverse Engineers

*How to quickly understand what a Windows executable does—before you run it.*

**PE Import Analyzer** has grown into a **powerful, production-ready tool**: it doesn’t just list imports—it classifies every API by risk (Dangerous, Suspicious, Uncommon, Common), detects **suspicious combinations** of APIs and DLLs (e.g. classic injection, persistence, keylogging), and covers **100 DLLs** with **1,500+ API descriptions** based on Microsoft documentation. All in one command, no execution required.

---

## Table of Contents

1. [Why Import Tables Matter](#why-import-tables-matter)
2. [What You'll Need](#what-youll-need)
3. [Installation (Under a Minute)](#installation-under-a-minute)
4. [First Run: One Command, One Report](#first-run-one-command-one-report)
5. [What Makes It Powerful](#what-makes-it-powerful)
6. [Testing on Real Samples](#testing-on-real-samples)
7. [Output Formats: When to Use Which](#output-formats-when-to-use-which)
8. [Dangerous-API Categories and Risk Classification](#dangerous-api-categories-and-risk-classification)
9. [Suspicious Combination Detection](#suspicious-combination-detection)
10. [Handy Options](#handy-options)
11. [Limitations and Tips](#limitations-and-tips)
12. [Wrap-Up](#wrap-up)

---

## Why Import Tables Matter

When you pick up an unknown `.exe` in a sandbox or during an incident, one of the first questions is: **what does it do?** Disassembly is powerful but slow. Strings can hint at behavior. The **import table** sits in the sweet spot: it lists the Windows APIs the binary intends to call—file access, registry, network, process injection, crypto—without executing a single instruction.

**PE Import Analyzer** automates that and goes further: it parses the PE, resolves each import to a short description (based on Microsoft docs), **classifies every API by risk level**, and **flags suspicious combinations** (e.g. VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) so you see not just *what* is imported but *how risky* it is and *what patterns* it matches. In this guide we’ll install it, run it on real samples, and read the results like a analyst.

---

## What You’ll Need

- **Python 3.8+**
- **LIEF** (`pip install lief`) — the library that parses PE files
- A Windows PE file to analyze (or the samples below)

---

## Installation (Under a Minute)

```bash
git clone https://github.com/anpa1200/PE-Import-Analyzer.git
cd PE-Import-Analyzer
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

That’s it. No heavy IDE, no commercial tools.

---

## First Run: One Command, One Report

For a quick overview, non-interactive mode is best: no prompts, output goes to a file.

```bash
python3 PE-Import-Analyzer.py sample.exe --html --dangerous --no-prompt -o report.html
```

- `--html` — produce a readable HTML report (you can also use `--txt` or `--json`).
- `--dangerous` — include a section that flags suspicious APIs (injection, persistence, crypto, etc.).
- `--no-prompt` — no interactive questions; ideal for scripts and automation.
- `-o report.html` — output path.

Open `report.html` in a browser. You’ll see:

1. **Summary** — total DLLs, total imports, count of dangerous/suspicious APIs, and number of suspicious patterns.
2. **Per-DLL sections** — each imported DLL with a one-line explanation and a **full** table of every imported function (no truncation by default) with a **short description** and a **Risk** column: **Dangerous**, **Suspicious**, **Uncommon**, or **Common**.
3. **Suspicious patterns detected** — a table of **matched behavioral patterns** (e.g. “Classic process injection”, “Thread context hijacking”, “Registry persistence”) with **severity colors**: **red** (high), **orange** (medium), **yellow** (low). Each row shows confidence, pattern name, description, and the APIs or DLLs involved.
4. **Most dangerous / suspicious functions** — a dedicated table of high-risk APIs (e.g. `CreateRemoteThread`, `WriteProcessMemory`, `RegSetValueExA`) with categories.

Unknown DLLs are never hidden: they appear with “No description available” and their full import list. The tool supports **delay-load imports** too (shown as `DLL (delay-load)`).

---

## What Makes It Powerful

- **100 DLLs, 1,500+ API descriptions** — Kernel32, User32, Advapi32, Ntdll, Winsock, WinINet, WinHTTP, WinCred, DbgHelp, NetAPI, WTSAPI, UserEnv, Shell, ImageHlp, BCrypt, NCrypt, RPC, URLMon, DNS, WFP, Event Log, Wintrust, CryptSP, MSI, WinMM, UXTheme, DWM, GDI+, RpcRt4, WlanAPI, WinUSB, HID, AMSI, AppHelp, ESE, CLFS, Offline Files, and many more. Descriptions are based on **Microsoft documentation**.
- **Four-level risk classification** — Every API is tagged as **Dangerous**, **Suspicious**, **Uncommon**, or **Common**. You see at a glance which imports are high risk (injection, persistence, crypto, evasion) and which are merely noteworthy (e.g. process enumeration, hooks).
- **Suspicious combination detection** — The tool runs a **rule engine** over the full import set. Rules match both **A and W API variants** (e.g. RegCreateKeyExA/W), so you don’t miss patterns. It detects: classic process injection, thread context hijacking, registry and service persistence, keylogging (SetWindowsHookEx + GetKeyState/GetAsyncKeyState), dynamic API resolution, network C2 (WinINet), anti-debug/timing, memory protection changes (VirtualAlloc + VirtualProtect), file mapping injection, and more. In the HTML report, each pattern is **color-coded by severity**: red (high), orange (medium), yellow (low).
- **Full report by default** — Every API is listed (no “…and more” truncation) unless you cap with `--limit N`. Ideal for complete audits.
- **HTML, text, JSON, and LLM prompt** — Human-readable reports, machine-readable JSON (with `risk_class` per API and `suspicious_patterns[]`), and an **LLM-ready prompt** (`--llm`) you can paste into ChatGPT, Claude, or similar for a natural-language assessment.

---

## Testing on Real Samples

I ran the tool on three samples from a local malware corpus:

| Sample       | Size   | Result        | DLLs | Imports | Flagged dangerous |
|-------------|--------|---------------|------|---------|--------------------|
| malware1.exe | ~86 KB | ✅ Parsed      | 4    | 48      | 14                 |
| malware2.exe | ~550 KB| ✅ Parsed      | 13   | 338     | 16                 |
| malware3.exe | ~105 KB| ❌ Not valid PE| —    | —       | —                  |

*malware3.exe* was rejected as “Not a valid PE file” (exit code 4). That can mean a packed binary, a .NET assembly, or a non-PE file with an `.exe` extension—so the tool correctly refuses to misinterpret it.

### Sample 1: malware1.exe — Injection and Crypto

Summary from the JSON report:

- **4 DLLs**, **48 imports**, **14** APIs flagged as dangerous.

Notable dangerous APIs:

- **Process / injection:** `CreateProcessA`, `OpenProcess`, `GetThreadContext`, `SetThreadContext`, `ResumeThread`, `TerminateProcess`, `WriteProcessMemory`, `VirtualAllocEx`
- **Dynamic loading:** `GetProcAddress`, `LoadLibraryA`
- **Crypto:** `CryptEncrypt`, `CryptDecrypt`
- **Persistence / config:** `RegOpenKeyExA`
- **Evasion / timing:** `Sleep`

This pattern (process creation, thread context, remote memory write, and crypto) is classic for **process injection or hollowing** and possible **payload decryption**. On this sample, the tool’s **suspicious-pattern detection** fires on **Thread context hijacking** (high confidence) and **Process termination capability** (medium), so you get both the raw API list and an explicit risk assessment in seconds.

### Sample 2: malware2.exe — Broader Footprint

- **13 DLLs**, **338 imports**, **16** dangerous.

Here you see more UI and system APIs (e.g. GDI, common dialogs), plus:

- **Registry persistence:** `RegCreateKeyExA`, `RegOpenKeyExA`, `RegSetValueExA`
- **Memory / evasion:** `VirtualAlloc`, `VirtualProtect`, `SetUnhandledExceptionFilter`, `SetWindowsHookExA`
- **Dynamic resolution:** `GetProcAddress`, `LoadLibraryA`, `GetModuleHandleA`
- **Timing / anti-debug:** `GetTickCount`, `QueryPerformanceCounter`

So you get a clear signal: **persistence via registry**, possible **anti-debug / anti-analysis**, and **hook-based or memory manipulation**. Again, no execution required.

---

## Output Formats: When to Use Which

- **HTML** — best for human review: open in a browser, share with colleagues, or screenshot for reports. Includes a summary block, full import list per DLL, and severity-colored suspicious patterns (red/orange/yellow).
- **TXT** — same content, plain text; good for logs and terminals.
- **LLM prompt** (`--llm`) — a single, copy-paste-ready block for ChatGPT, Claude, or other LLMs. It includes an analysis instruction, summary, full imports with risk tags and short descriptions, suspicious patterns, and dangerous APIs, then asks the model for a short assessment (benign/suspicious/malicious and main indicators). Output defaults to `{filename}_prompt.txt` with `--no-prompt`, or use `-o prompt.txt`.
- **JSON** — for automation: ingest into SIEM, run stats, or build your own dashboards. The JSON includes:
  - `dlls[]` with name, explanation, and per-API entries: **name**, **explanation**, and **risk_class** (dangerous/suspicious/uncommon/common)
  - **suspicious_patterns[]** — each matched pattern with id, name, description, confidence, apis_involved, dlls_involved
  - `dangerous_functions[]` with **category** (e.g. `injection_and_memory`, `persistence_and_registry`)
  - `summary` (total DLLs, total imports, dangerous count, **suspicious_patterns_count**)

Example for automation:

```bash
python3 PE-Import-Analyzer.py sample.exe --json --dangerous --no-prompt -o report.json -q
# Then: your_script.py report.json
```




---

## Dangerous-API Categories and Risk Classification

Every API in the report is assigned a **risk class**:

- **Dangerous** — High-risk: injection (e.g. `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`), process/thread control (`CreateProcess`, `OpenProcess`, `TerminateProcess`, `SetThreadContext`), persistence (`RegCreateKeyEx`, `RegSetValueEx`, `CreateService`), network/C2 (`InternetOpen`, `HttpSendRequest`, `WSAConnect`), crypto (`CryptEncrypt`, `CryptDecrypt`), evasion (`GetProcAddress`, `LoadLibrary`, `SetUnhandledExceptionFilter`, `IsDebuggerPresent`), file/system (`CreateFile`, `NtCreateFile`). These are grouped in categories (injection_and_memory, process_and_thread, persistence_and_registry, network_and_c2, crypto_and_evasion, file_and_system).
- **Suspicious** — Often abused: process/snapshot APIs (`CreateToolhelp32Snapshot`, `Process32First`/`Next`), `DuplicateHandle`, `GetThreadContext`/`SetThreadContext`, hooks (`SetWindowsHookEx`), key state (`GetAsyncKeyState`), and similar.
- **Uncommon** — Rare in benign apps: many **Nt*** APIs, `RtlGenRandom`, `IsDebuggerPresent`, etc.
- **Common** — Everything else (normal file I/O, string ops, etc.).

So you can quickly answer: “Does it touch the registry? Does it use classic injection APIs? Is this API dangerous or just uncommon?”

---

## Suspicious Combination Detection

The tool doesn’t stop at single-API risk. It runs **combination rules** over the full import set and reports when **multiple APIs or DLLs** appear together in a way that suggests a known technique:

| Pattern | Example APIs / DLLs | Confidence |
|--------|---------------------|------------|
| Classic process injection | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | high |
| Thread context hijacking | GetThreadContext, SetThreadContext, VirtualAllocEx | high |
| Registry persistence | RegCreateKeyEx, RegSetValueEx, RegOpenKeyEx | medium |
| Service persistence | OpenSCManagerA, CreateServiceA, StartService | high |
| Keylogging / hooks | SetWindowsHookEx, GetAsyncKeyState | high |
| Dynamic API resolution | LoadLibrary, GetProcAddress | medium |
| Network C2 (WinINet) | InternetOpenA, InternetConnectA, HttpSendRequestA | medium |
| Anti-debug / timing | IsDebuggerPresent, GetTickCount | medium |
| Process termination | OpenProcess, TerminateProcess | medium |
| Keylogging / key state | SetWindowsHookEx, GetKeyState | high |
| Memory protection + alloc | VirtualAlloc, VirtualProtect | medium |
| Exception filter + memory | SetUnhandledExceptionFilter, VirtualProtect | medium |
| Dynamic resolution + memory | LoadLibrary, GetProcAddress, VirtualAlloc | medium |
| Suspicious DLL set | kernel32 + advapi32 + ws2_32 | low |

In the HTML report, each pattern row is **color-coded by severity**: **red** (high), **orange** (medium), **yellow** (low). Rules match both A and W API variants (e.g. RegCreateKeyExA or RegCreateKeyExW). So you get not only “it imports WriteProcessMemory” but “it matches the **classic process injection** pattern.” That’s what makes the tool powerful for triage.

---

## Handy Options

- `--llm` — output an LLM-ready prompt (paste into ChatGPT/Claude). Saved as `{name}_prompt.txt` with `--no-prompt` unless `-o` is set.
- `--limit N` — cap the number of APIs shown per DLL at N (default: no limit; full report).
- `--no-delay-load` — skip delay-loaded imports (by default they’re included and labeled “(delay-load)”).
- `-q` — quiet: only errors to stderr; no “Output saved to …” message.
- `-v` — verbose logging.
- `--version` — print version and exit.

Exit codes: `0` = success, `2` = file not found, `3` = permission denied, `4` = not a valid PE, `5` = output write error. That makes it easy to use in scripts and pipelines.

---

## Limitations and Tips

- **Packed or obfuscated binaries** — the import table may be stripped or minimal; the tool will still report what’s there (or reject the file if it’s not a valid PE). Combine with dynamic analysis and unpacking when needed.
- **Delay-load and dynamic resolution** — many samples resolve APIs at runtime via `GetProcAddress` / `LoadLibrary`. The tool highlights those; the rest of the behavior still needs runtime or disassembly.
- **Not a substitute for execution analysis** — import analysis is a fast **triaging** step. Use it to decide what to run in a sandbox and what to dig into in a disassembler.

---

## Wrap-Up

**PE Import Analyzer** is now a **powerful, production-ready tool**: it gives you a fast, readable map of what a Windows executable is *capable* of doing from its import table—**100 DLLs**, **1,500+ API descriptions** (Microsoft-docs based), **four-level risk classification** (Dangerous/Suspicious/Uncommon/Common), and **automatic detection of suspicious API/DLL combinations** (injection, persistence, keylogging, C2, anti-debug, and more). Reports are **full by default** (all APIs, no truncation), and the HTML report uses **severity colors** (red/orange/yellow) for suspicious patterns. You can also export an **LLM-ready prompt** (`--llm`) to paste into ChatGPT or Claude for a short verdict. It correctly rejects non-PE files and supports delay-load imports and full CLI automation.

If you’re doing malware triage, incident response, or reverse engineering on Windows binaries, add this to your first steps—right after hashing and strings—and before you run anything in a sandbox.

- **Repo:** [github.com/anpa1200/PE-Import-Analyzer](https://github.com/anpa1200/PE-Import-Analyzer)
- **Requirements:** Python 3.8+, LIEF
- **License:** MIT

*Stay safe, and analyze before you execute.*
