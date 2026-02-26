#!/usr/bin/env python3
"""
PE Import Analyzer — Extract and analyze PE import tables with DLL/API explanations.

Parses PE files via LIEF, extracts import (and optional delay-load) tables, and produces
HTML, text, or JSON reports. Supports non-interactive use and dangerous-API flagging.
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import sys
from typing import Any

import lief

from dll_explanations import (
    DEFAULT_EXPLANATION,
    _dangerous_with_category,
    dll_api_explanations,
    dangerous_functions,
    get_api_risk_class,
    detect_suspicious_combinations,
)

__version__ = "2.0.0"
LOG = logging.getLogger(__name__)

def get_api_explanation(
    dll_info: dict[str, Any] | None, api_name: str
) -> str | None:
    """Return explanation for api_name from dll_info['apis'], case-insensitive, or None."""
    if not dll_info or "apis" not in dll_info:
        return None
    key_lower = api_name.lower()
    apis = dll_info["apis"]
    if key_lower in apis:
        return apis[key_lower]
    for k, v in apis.items():
        if k.lower() == key_lower:
            return v
    return None


# --- Import Extraction Function ---
def extract_and_sort_imports(
    file_path: str, include_delay_load: bool = True
) -> dict[str, list[str]]:
    """Parse the PE file and extract its import table (and optionally delay-load imports).
       Returns a dictionary with DLL names as keys and sorted lists of imported functions as values.
       Delay-loaded DLLs appear as 'DLL_NAME (delay-load)'."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Cannot read file: {file_path}")

    try:
        binary = lief.parse(file_path)
    except Exception as e:
        raise ValueError(f"Failed to parse PE file: {e}") from e

    if not binary or not isinstance(binary, lief.PE.Binary):
        raise ValueError("Not a valid PE file.")

    imports_by_dll = {}
    for imp in binary.imports:
        dll_name = imp.name or "UNKNOWN_DLL"
        if dll_name not in imports_by_dll:
            imports_by_dll[dll_name] = []
        for entry in imp.entries:
            func = entry.name if entry.name else f"Ordinal_{entry.ordinal}"
            imports_by_dll[dll_name].append(func)

    # Delay-load imports (LIEF 0.12+)
    if include_delay_load and hasattr(binary, "delay_imports") and binary.delay_imports:
        for dimp in binary.delay_imports:
            dll_name = (dimp.name or "UNKNOWN_DLL") + " (delay-load)"
            if dll_name not in imports_by_dll:
                imports_by_dll[dll_name] = []
            for entry in dimp.entries:
                func = entry.name if entry.name else f"Ordinal_{entry.ordinal}"
                imports_by_dll[dll_name].append(func)

    for dll in imports_by_dll:
        imports_by_dll[dll].sort(key=str.lower)
    sorted_imports = {dll: imports_by_dll[dll] for dll in sorted(imports_by_dll, key=str.lower)}
    return sorted_imports

# --- Text Output Generation Function ---
def generate_text_output(
    sorted_imports: dict[str, list[str]],
    nested_dict: dict[str, Any],
    dangerous_set: set[str],
    max_apis_per_dll: int | None = None,
    suspicious_patterns: list | None = None,
) -> str:
    if suspicious_patterns is None:
        suspicious_patterns = detect_suspicious_combinations(sorted_imports)
    lines = []
    for dll, functions in sorted_imports.items():
        key = dll.lower().replace(" (delay-load)", "")
        lines.append(f"{dll}:")
        dll_info = nested_dict.get(key)
        explanation = dll_info["explanation"] if dll_info else "No description available."
        lines.append(f"    DLL Explanation: {explanation}")
        count = 0
        for api in sorted(functions, key=str.lower):
            risk = get_api_risk_class(api)
            expl = get_api_explanation(dll_info, api) if dll_info else None
            tag = f" [{risk.upper()}]" if risk != "common" else ""
            if expl and expl != DEFAULT_EXPLANATION:
                lines.append(f"    {api}{tag}: {expl}")
            else:
                lines.append(f"    {api}{tag}")
            count += 1
            if max_apis_per_dll is not None and count >= max_apis_per_dll:
                if len(functions) > max_apis_per_dll:
                    lines.append(f"    ... and {len(functions) - max_apis_per_dll} more")
                break
        lines.append("")
    if suspicious_patterns:
        lines.append("--- Suspicious patterns detected ---")
        for p in suspicious_patterns:
            lines.append(f"  [{p['confidence'].upper()}] {p['name']}: {p['description']}")
            if p.get("apis_involved"):
                lines.append(f"    APIs: {', '.join(p['apis_involved'])}")
            if p.get("dlls_involved"):
                lines.append(f"    DLLs: {', '.join(p['dlls_involved'])}")
        lines.append("")
    if dangerous_set:
        lines.append("Most Dangerous/Suspicious Functions:")
        for func in sorted(dangerous_set, key=str.lower):
            explanation = None
            for dll_data in nested_dict.values():
                explanation = get_api_explanation(dll_data, func)
                if explanation and explanation != DEFAULT_EXPLANATION:
                    break
            if explanation and explanation != DEFAULT_EXPLANATION:
                lines.append(f"    {func}: {explanation}")
            else:
                lines.append(f"    {func}")
    return "\n".join(lines)


# --- LLM-ready prompt output (paste into ChatGPT, Claude, etc.) ---
def generate_llm_prompt_output(
    sorted_imports: dict[str, list[str]],
    nested_dict: dict[str, Any],
    dangerous_set: set[str],
    file_path: str = "",
    max_apis_per_dll: int | None = None,
    suspicious_patterns: list | None = None,
) -> str:
    """Generate a single text block suitable for pasting as an LLM prompt (e.g. for malware analysis)."""
    if suspicious_patterns is None:
        suspicious_patterns = detect_suspicious_combinations(sorted_imports)
    total_dlls = len(sorted_imports)
    total_imports = sum(len(f) for f in sorted_imports.values())

    lines = [
        "Analyze the following Windows PE executable import table for malicious or suspicious behavior.",
        "Consider: injection, persistence, keylogging, C2, anti-debug, credential access, and evasion.",
        "",
        "--- Summary ---",
        f"File: {file_path or '(unknown)'}",
        f"Total DLLs: {total_dlls}  |  Total imports: {total_imports}  |  Dangerous/suspicious APIs: {len(dangerous_set)}  |  Suspicious patterns: {len(suspicious_patterns)}",
        "",
        "--- Imports by DLL (API [risk]: explanation) ---",
    ]
    for dll, functions in sorted_imports.items():
        key = dll.lower().replace(" (delay-load)", "")
        dll_info = nested_dict.get(key)
        explanation = (dll_info["explanation"] if dll_info else "No description available.")
        lines.append(f"\n{dll}: {explanation}")
        count = 0
        for api in sorted(functions, key=str.lower):
            risk = get_api_risk_class(api)
            expl = get_api_explanation(dll_info, api) if dll_info else None
            tag = f" [{risk}]" if risk != "common" else ""
            expl_str = f" — {expl}" if expl and expl != DEFAULT_EXPLANATION else ""
            lines.append(f"  • {api}{tag}{expl_str}")
            count += 1
            if max_apis_per_dll is not None and count >= max_apis_per_dll:
                if len(functions) > max_apis_per_dll:
                    lines.append(f"  • ... and {len(functions) - max_apis_per_dll} more")
                break
    if suspicious_patterns:
        lines.append("")
        lines.append("--- Suspicious patterns detected ---")
        for p in suspicious_patterns:
            apis_dlls = ", ".join(p.get("apis_involved", []) + p.get("dlls_involved", []))
            lines.append(f"  [{p['confidence']}] {p['name']}: {p['description']}")
            if apis_dlls:
                lines.append(f"    APIs/DLLs: {apis_dlls}")
    if dangerous_set:
        lines.append("")
        lines.append("--- Most dangerous/suspicious APIs ---")
        for func in sorted(dangerous_set, key=str.lower):
            explanation = None
            for dll_data in nested_dict.values():
                explanation = get_api_explanation(dll_data, func)
                if explanation and explanation != DEFAULT_EXPLANATION:
                    break
            expl_str = f" — {explanation}" if explanation and explanation != DEFAULT_EXPLANATION else ""
            lines.append(f"  • {func}{expl_str}")
    lines.append("")
    lines.append("--- End of data ---")
    lines.append("Provide a short assessment: likely benign, suspicious, or malicious, and the main behavioral indicators.")
    return "\n".join(lines)


# --- HTML Output Generation Function ---
def generate_html_output(
    sorted_imports: dict[str, list[str]],
    nested_dict: dict[str, Any],
    dangerous_set: set[str],
    max_apis_per_dll: int | None = None,
    suspicious_patterns: list | None = None,
) -> str:
    if suspicious_patterns is None:
        suspicious_patterns = detect_suspicious_combinations(sorted_imports)
    total_dlls = len(sorted_imports)
    total_imports = sum(len(f) for f in sorted_imports.values())
    html_lines = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "<meta charset=\"UTF-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
        "<title>PE Import Analysis</title>",
        "<style>",
        "body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }",
        "h1 { color: #0f3460; border-bottom: 2px solid #e94560; padding-bottom: 8px; }",
        "h2 { color: #e94560; margin-top: 24px; }",
        "table { border-collapse: collapse; width: 95%; max-width: 900px; margin: 12px 0; background: #16213e; border-radius: 8px; overflow: hidden; }",
        "th, td { border: 1px solid #0f3460; padding: 10px 12px; text-align: left; }",
        "th { background: #0f3460; color: #eee; }",
        "tr:nth-child(even) { background: #1a1a2e; }",
        "tr:hover { background: #0f3460; }",
        ".danger { background: #2d1b1b !important; } .danger th { background: #8b0000; }",
        ".risk-Dangerous { color: #ff6b6b; font-weight: bold; }",
        ".risk-Suspicious { color: #ffa94d; }",
        ".risk-Uncommon { color: #74c0fc; }",
        ".pattern-high { background: #3d1a1a !important; border-left: 4px solid #e63946; } .pattern-high td:first-child { color: #ff6b6b; font-weight: bold; }",
        ".pattern-medium { background: #3d2a15 !important; border-left: 4px solid #e67700; } .pattern-medium td:first-child { color: #ffa94d; font-weight: bold; }",
        ".pattern-low { background: #3d3d1a !important; border-left: 4px solid #d4a500; } .pattern-low td:first-child { color: #e6d44d; font-weight: bold; }",
        "p { max-width: 900px; line-height: 1.5; }",
        ".meta { color: #888; font-size: 0.9em; margin-bottom: 20px; }",
        ".summary { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 16px; max-width: 900px; margin-bottom: 24px; }",
        ".summary table { width: auto; }",
        ".summary td { border: none; padding: 4px 16px 4px 0; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>PE Import Analysis</h1>",
        "<p class=\"meta\">Generated by PE-Import-Analyzer</p>",
        "<div class=\"summary\"><table><tr><td><strong>Total DLLs</strong></td><td>" + str(total_dlls) + "</td></tr>",
        "<tr><td><strong>Total imports</strong></td><td>" + str(total_imports) + "</td></tr>",
        "<tr><td><strong>Dangerous / suspicious APIs</strong></td><td>" + str(len(dangerous_set)) + "</td></tr>",
        "<tr><td><strong>Suspicious patterns detected</strong></td><td>" + str(len(suspicious_patterns)) + "</td></tr></table></div>",
    ]
    for dll, functions in sorted_imports.items():
        key = dll.lower().replace(" (delay-load)", "")
        dll_info = nested_dict.get(key)
        explanation = (dll_info["explanation"] if dll_info else "No description available.")
        html_lines.append(f"<h2>{html.escape(dll)}</h2>")
        html_lines.append(f"<p><strong>DLL Explanation:</strong> {html.escape(explanation)}</p>")
        html_lines.append("<table>")
        html_lines.append("<tr><th>API Function</th><th>Risk</th><th>Explanation</th></tr>")
        count = 0
        for api in sorted(functions, key=str.lower):
            risk = get_api_risk_class(api)
            expl = get_api_explanation(dll_info, api) if dll_info else None
            expl_str = html.escape(expl) if expl and expl != DEFAULT_EXPLANATION else ""
            risk_span = f"<span class=\"risk-{risk}\">{risk}</span>" if risk != "common" else "common"
            html_lines.append(f"<tr><td>{html.escape(api)}</td><td>{risk_span}</td><td>{expl_str}</td></tr>")
            count += 1
            if max_apis_per_dll is not None and count >= max_apis_per_dll:
                if len(functions) > max_apis_per_dll:
                    html_lines.append(f"<tr><td colspan=\"3\"><em>... and {len(functions) - max_apis_per_dll} more</em></td></tr>")
                break
        html_lines.append("</table>")
    if suspicious_patterns:
        html_lines.append("<h2>Suspicious patterns detected</h2>")
        html_lines.append("<table>")
        html_lines.append("<tr><th>Confidence</th><th>Pattern</th><th>Description</th><th>APIs / DLLs</th></tr>")
        for p in suspicious_patterns:
            conf_class = f"pattern-{p['confidence']}"
            apis_dlls = ", ".join(p.get("apis_involved", []) + p.get("dlls_involved", []))
            html_lines.append(f"<tr class=\"{conf_class}\"><td>{html.escape(p['confidence'])}</td><td>{html.escape(p['name'])}</td><td>{html.escape(p['description'])}</td><td>{html.escape(apis_dlls)}</td></tr>")
        html_lines.append("</table>")
    if dangerous_set:
        html_lines.append("<h2>Most Dangerous / Suspicious Functions</h2>")
        html_lines.append("<table class=\"danger\">")
        html_lines.append("<tr><th>API Function</th><th>Explanation</th></tr>")
        for func in sorted(dangerous_set, key=str.lower):
            explanation = None
            for dll_data in nested_dict.values():
                explanation = get_api_explanation(dll_data, func)
                if explanation and explanation != DEFAULT_EXPLANATION:
                    break
            expl_str = html.escape(explanation) if explanation and explanation != DEFAULT_EXPLANATION else ""
            html_lines.append(f"<tr><td>{html.escape(func)}</td><td>{expl_str}</td></tr>")
        html_lines.append("</table>")
    html_lines.append("</body></html>")
    return "\n".join(html_lines)


# --- JSON Output Generation Function ---
def generate_json_output(
    sorted_imports: dict[str, list[str]],
    nested_dict: dict[str, Any],
    dangerous_set: set[str],
    suspicious_patterns: list | None = None,
) -> str:
    """Produce a JSON-serializable structure for scripting and tooling."""
    if suspicious_patterns is None:
        suspicious_patterns = detect_suspicious_combinations(sorted_imports)
    key_lower = lambda s: s.lower().replace(" (delay-load)", "")
    out = {
        "dlls": [],
        "dangerous_functions": [],
        "suspicious_patterns": suspicious_patterns,
        "summary": {
            "total_dlls": len(sorted_imports),
            "total_imports": sum(len(f) for f in sorted_imports.values()),
            "dangerous_count": len(dangerous_set),
            "suspicious_patterns_count": len(suspicious_patterns),
        },
    }
    for dll, functions in sorted_imports.items():
        key = key_lower(dll)
        dll_info = nested_dict.get(key)
        explanation = (dll_info["explanation"] if dll_info else "No description available.")
        apis = []
        for api in sorted(functions, key=str.lower):
            expl = get_api_explanation(dll_info, api) if dll_info else None
            risk = get_api_risk_class(api)
            apis.append({"name": api, "explanation": expl or "", "risk_class": risk})
        out["dlls"].append({
            "name": dll,
            "explanation": explanation,
            "is_delay_load": "(delay-load)" in dll,
            "apis": apis,
        })
    for func in sorted(dangerous_set, key=str.lower):
        category = _dangerous_with_category.get(func.lower(), "")
        explanation = None
        for dll_data in nested_dict.values():
            explanation = get_api_explanation(dll_data, func)
            if explanation and explanation != DEFAULT_EXPLANATION:
                break
        out["dangerous_functions"].append({
            "name": func,
            "category": category,
            "explanation": explanation or "",
        })
    return json.dumps(out, indent=2, ensure_ascii=False)


# --- Main Function ---
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and analyze PE import tables with DLL/API explanations. Supports HTML, text, and JSON output.",
        prog="PE-Import-Analyzer",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("file_path", nargs="?", help="Path to the PE file")
    parser.add_argument("--html", action="store_true", help="Output HTML report")
    parser.add_argument("--txt", action="store_true", help="Output plain text report")
    parser.add_argument("--json", action="store_true", help="Output JSON (for scripting)")
    parser.add_argument("--llm", action="store_true", help="Output LLM-ready prompt (paste into ChatGPT, Claude, etc.)")
    parser.add_argument("--dangerous", action="store_true", help="Include dangerous/suspicious API section")
    parser.add_argument("--no-dangerous", action="store_true", help="Exclude dangerous API section (default if not --dangerous)")
    parser.add_argument("-o", "--output", metavar="FILE", help="Output file path")
    parser.add_argument("--no-prompt", action="store_true", help="Non-interactive: use defaults and CLI flags only")
    parser.add_argument("--all-apis", action="store_true", help="Show all APIs per DLL (default: already all; kept for compatibility)")
    parser.add_argument("--limit", type=int, default=None, metavar="N", help="Cap APIs per DLL at N (default: no limit = full report)")
    parser.add_argument("--no-delay-load", action="store_true", help="Skip delay-load import table")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (errors only)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO),
        format="%(message)s" if not args.verbose else "%(levelname)s: %(message)s",
    )
    if args.file_path is None:
        parser.error("the following arguments are required: file_path")

    try:
        sorted_imports = extract_and_sort_imports(
            args.file_path,
            include_delay_load=not args.no_delay_load,
        )
    except FileNotFoundError as e:
        LOG.error("%s", e)
        sys.exit(2)
    except PermissionError as e:
        LOG.error("%s", e)
        sys.exit(3)
    except ValueError as e:
        LOG.error("%s", e)
        sys.exit(4)

    dangerous_found = set()
    for dll, functions in sorted_imports.items():
        for api in functions:
            if api.lower() in dangerous_functions:
                dangerous_found.add(api)

    # Output format and options
    output_html = args.html
    output_txt = args.txt
    output_json = args.json
    output_llm = args.llm
    include_dangerous = args.dangerous
    no_prompt = args.no_prompt
    max_apis = args.limit  # None = full report (all APIs per DLL); --limit N to cap

    if not no_prompt and not (output_html or output_txt or output_json or output_llm):
        output_html = input("Save output as HTML? (y/n): ").strip().lower() == "y"
        output_txt = not output_html
    if not output_html and not output_txt and not output_json and not output_llm:
        output_txt = True

    if not no_prompt and not args.dangerous and not args.no_dangerous:
        include_dangerous = input("Include dangerous/suspicious functions? (y/n): ").strip().lower() == "y"

    base_name = os.path.splitext(os.path.basename(args.file_path))[0]
    dangerous_set = dangerous_found if include_dangerous else set()

    llm_content = None
    if output_llm:
        llm_content = generate_llm_prompt_output(
            sorted_imports, dll_api_explanations, dangerous_set,
            file_path=args.file_path, max_apis_per_dll=max_apis,
        )

    # Build list of (output_path, content) when not using -o
    if args.output:
        if output_json:
            outputs = [(args.output, generate_json_output(sorted_imports, dll_api_explanations, dangerous_found))]
        elif output_html:
            outputs = [(args.output, generate_html_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis))]
        elif output_llm:
            outputs = [(args.output, llm_content)]
        else:
            outputs = [(args.output, generate_text_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis))]
    else:
        if no_prompt:
            outputs = []
            if output_json:
                outputs.append((f"{base_name}.json", generate_json_output(sorted_imports, dll_api_explanations, dangerous_found)))
            if output_html:
                outputs.append((f"{base_name}.html", generate_html_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis)))
            if output_txt:
                outputs.append((f"{base_name}.txt", generate_text_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis)))
            if output_llm:
                outputs.append((f"{base_name}_prompt.txt", llm_content))
            if not outputs:
                outputs = [(f"{base_name}.txt", generate_text_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis))]
        else:
            default_ext = ".json" if output_json else (".html" if output_html else ("_prompt.txt" if output_llm else ".txt"))
            default_filename = f"{base_name}{default_ext}"
            file_name = input(f"Enter output file (default: {default_filename}): ").strip() or default_filename
            if output_json:
                content = generate_json_output(sorted_imports, dll_api_explanations, dangerous_found)
            elif output_html:
                content = generate_html_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis)
            elif output_llm:
                content = llm_content
            else:
                content = generate_text_output(sorted_imports, dll_api_explanations, dangerous_set, max_apis_per_dll=max_apis)
            outputs = [(file_name, content)]

    try:
        for path, content in outputs:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            if not args.quiet:
                LOG.info("Output saved to %s", path)
    except OSError as e:
        LOG.error("Error writing output: %s", e)
        sys.exit(5)

if __name__ == "__main__":
    main()
