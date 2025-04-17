# PE Import Analyzer 🔍

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![LIEF Parser](https://img.shields.io/badge/LIEF-Parser-orange.svg)](https://lief.quarkslab.com/)

A command-line utility to analyze the import table of PE files. Provides detailed DLL descriptions, API function explanations, and flexible output formats (HTML or plain text). Ideal for **malware analysts**, **reverse engineers**, and **forensic investigators**.

---

## 🔍 Features

- **Import Table Extraction**: Uses LIEF to parse PE files and extract all imported DLLs and their functions.
- **DLL Summaries**: Built-in explanations for core Windows DLLs (e.g., `kernel32.dll`, `user32.dll`, `advapi32.dll`, `ntdll.dll`, `ws2_32.dll`, `wininet.dll`, etc.).
- **API Explanations**: Up to 20 common API calls per DLL with concise descriptions.
- **Placeholder Expansion**: Automatically pads each DLL’s API list to a minimum of 100 entries if needed.
- **Dangerous Function Flagging**: Optionally include a section for known suspicious or high-risk API calls.
- **HTML & Plain Text Output**: Interactive prompt to choose the output format and filename (default `<basename>.html` or `<basename>.txt`).
- **Customizable**: Easily extend the `dll_api_explanations` dictionary with additional DLLs and APIs.

---

## 📦 Installation

```bash
# Download the script
the script
curl -O https://raw.githubusercontent.com/anpa1200/PE-Import-Analyzer/main/PE-Import-Analyzer.py

# (Optional) Clone the repository for examples and LICENSE
git clone https://github.com/anpa1200/PE-Import-Analyzer.git && cd PE-Import-Analyzer

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install lief
```bash
# Download the script
curl -O https://raw.githubusercontent.com/anpa1200/Malware_analysis/main/PE-Import-Analyzer.py

# (Optional) Clone the repository for examples and LICENSE
git clone https://github.com/anpa1200/Malware_analysis.git && cd Malware_analysis

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install lief
```  
*Note: No additional packages required beyond LIEF.*

---

## 🚀 Usage

```bash
python3 PE-Import-Analyzer.py <path_to_pe_file> [--html] [--dangerous]
```

- `<path_to_pe_file>`: Path to the target PE file.
- `--html`: Generate a styled HTML report (default is plain text).
- `--dangerous`: Include functions flagged as potentially dangerous (e.g., process/thread manipulation, cryptographic, injection APIs).

### Interactive Steps
1. Launch the script with required arguments.
2. When prompted, confirm whether to include dangerous functions.
3. Choose output format (HTML or TXT).
4. Specify output filename or accept the default.
5. View the generated report in your terminal or browser.

---

## 🛠️ Function Reference

| Function                          | Description                                                                                   |
| --------------------------------- | --------------------------------------------------------------------------------------------- |
| `extend_apis(dll_dict, target)`   | Ensures each DLL has at least `target` APIs by adding placeholders.                           |
| `dll_api_explanations`            | Nested dict mapping DLL names to explanation + API descriptions.                              |
| `parse_imports(file_path)`        | (Internal) Uses LIEF to extract the import table from the PE binary.                          |
| `format_text_report(info, apis)`  | Renders a plain text summary of DLLs and API calls.                                           |
| `format_html_report(info, apis)`  | Generates an HTML table with DLL and API details.                                             |
| `prompt_user_options()`           | Interactive CLI prompts for dangerous APIs, output format, and filename.                     |
| `main()`                          | Orchestrates argument parsing, import extraction, user prompts, and file writing.             |

---

## 🛠️ Example

```bash
$ python3 Import_Extraction.py samples/malware.exe --html --dangerous
Include dangerous API functions? (yes/no): yes
Output format? (html/txt): html
Output file (default: malware_imports.html): report.html
Report generated: report.html
Include dangerous API functions? (yes/no): yes
Output format? (html/txt): html
Output file (default: malware_imports.html): report.html
Report generated: report.html
```

### Example Text Report

```txt
--- Import Table Analysis ---
DLL: kernel32.dll
  - CreateFile        : Creates or opens a file, device, or I/O resource and returns a handle.
  - ReadFile          : Reads data from an open file or I/O device into a buffer.
  ... (up to 20 functions)

DLL: user32.dll
  - CreateWindowEx    : Creates an overlapped, pop-up, or child window with extended styles.
  - DefWindowProc     : Provides default processing for window messages not handled by the window procedure.
  ... (up to 20 functions)

[Additional DLL sections]
--------------------------
```

### Example HTML Report

Below is how the report table will render in the browser or GitHub README:

| DLL            | Function         | Description                                                                                      |
|--------------- | ---------------- | ------------------------------------------------------------------------------------------------ |
| **kernel32.dll** | CreateFile       | Creates or opens a file, device, or I/O resource and returns a handle.                           |
|                | ReadFile         | Reads data from an open file or I/O device into a buffer.                                       |
| **user32.dll**   | CreateWindowEx   | Creates a window with extended styles for UI elements.                                          |
|                | DefWindowProc    | Default processing for window messages not handled by the application.                          |
| **advapi32.dll** | RegOpenKeyExA    | Opens a registry key with extended options (ANSI version).                                       |
|                | OpenSCManagerA   | Opens a handle to the Service Control Manager database.                                          |

---

## 🔗 Dependencies

- **Python** 3.7+
- **LIEF**: `pip install lief`

---

## 🤝 Contributing

Contributions and enhancements are welcome! To add support for more DLLs or APIs:
1. Fork the repo.
2. Update `dll_api_explanations` in `Import_Extraction.py`.
3. Submit a Pull Request.

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

