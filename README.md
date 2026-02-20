# PE Import Analyzer 🔍

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![LIEF Parser](https://img.shields.io/badge/LIEF-Parser-orange.svg)](https://lief.quarkslab.com/)

A command-line utility to analyze the import table of PE files. Provides detailed DLL descriptions, API function explanations, and flexible output formats (HTML, plain text, JSON). Ideal for **malware analysts**, **reverse engineers**, and **forensic investigators**.

---

## 🔍 Features

- **Import Table Extraction**: Uses [LIEF](https://lief.quarkslab.com/) to parse PE files and extract all imported DLLs and their functions.
- **Delay-Load Imports**: Optional parsing of delay-load import table (LIEF 0.12+); shown as `DLL_NAME (delay-load)`.
- **DLL Summaries**: Built-in explanations for core Windows DLLs (e.g. `kernel32.dll`, `user32.dll`, `advapi32.dll`, `ntdll.dll`, `ws2_32.dll`, `wininet.dll`, and more).
- **API Explanations**: Case-insensitive lookup; per-DLL limit (default 20) or `--all-apis` for full lists.
- **All DLLs Included**: Unknown DLLs are no longer skipped; they appear with “No description available” and full API lists.
- **Dangerous Function Flagging**: Optional section for high-risk APIs, with categories (injection, persistence, network/C2, crypto/evasion, etc.). Expanded list for malware and hardening analysis.
- **Multiple Output Formats**: HTML (styled report), plain text, and JSON (for scripting and tooling).
- **Non-Interactive Mode**: Use `--no-prompt` with `--html`/`--txt`/`--json`, `--dangerous`, and `-o FILE` for automation.
- **Robustness**: File existence and readability checks; clear errors for non-PE or corrupt files.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/anpa1200/PE-Import-Analyzer.git && cd PE-Import-Analyzer

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

*Requires only **LIEF** (`lief>=0.14.0`) and Python 3.8+.*

### Development

```bash
pip install -e ".[dev]"   # lief + pytest
pytest tests/ -v           # run tests (CLI tests need lief)
```

---

## 🚀 Usage

```bash
python3 PE-Import-Analyzer.py <path_to_pe_file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--html` | Output HTML report. |
| `--txt` | Output plain text report. |
| `--json` | Output JSON (for scripting). |
| `--dangerous` | Include dangerous/suspicious API section. |
| `--no-dangerous` | Exclude dangerous API section. |
| `-o FILE`, `--output FILE` | Output file path. |
| `--no-prompt` | Non-interactive: use defaults and CLI flags only. |
| `--all-apis` | Show all APIs per DLL (default: first 20). |
| `--no-delay-load` | Skip delay-load import table. |
| `-q`, `--quiet` | Minimal output (errors only). |
| `-v`, `--verbose` | Verbose logging. |
| `--version` | Show version and exit. |

### Examples

**Interactive (prompts for format and options):**
```bash
python3 PE-Import-Analyzer.py sample.exe
```

**Non-interactive, HTML report with dangerous APIs:**
```bash
python3 PE-Import-Analyzer.py sample.exe --html --dangerous --no-prompt -o report.html
```

**JSON for tooling:**
```bash
python3 PE-Import-Analyzer.py sample.exe --json --no-prompt -o report.json
```

**Full API list, text and HTML:**
```bash
python3 PE-Import-Analyzer.py sample.exe --txt --html --all-apis --no-prompt
```

---

## Exit codes

| Code | Meaning        |
|------|----------------|
| 0    | Success        |
| 2    | File not found |
| 3    | Permission denied |
| 4    | Invalid or corrupt PE |
| 5    | Output write error |

## 🛠️ Function Reference

| Function | Description |
|----------|-------------|
| `extract_and_sort_imports(file_path, include_delay_load=True)` | Parses PE and returns DLL → sorted list of imports; optional delay-load. |
| `get_api_explanation(dll_info, api_name)` | Case-insensitive API explanation lookup. |
| `generate_text_output(...)` | Plain text report. |
| `generate_html_output(...)` | HTML report. |
| `generate_json_output(...)` | JSON structure with summary and dangerous categories. |
| `dll_api_explanations` | Nested dict: DLL name → `explanation` + `apis`. |
| `DANGEROUS_API_LIST` | Dict of categories → list of dangerous API names (lowercase). |

---

## 📄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
