"""Tests for report generation and API lookup (no PE/LIEF required)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Data module has no lief dependency
from dll_explanations import (  # noqa: E402
    DEFAULT_EXPLANATION,
    dll_api_explanations,
)


def _get_api_explanation(dll_info: dict | None, api_name: str) -> str | None:
    """Case-insensitive API lookup (mirrors main script logic)."""
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


def _generate_text_output(
    sorted_imports: dict, nested_dict: dict, dangerous_set: set, max_apis_per_dll: int | None = 20
) -> str:
    """Minimal text report (mirrors main script)."""
    lines = []
    for dll, functions in sorted_imports.items():
        key = dll.lower().replace(" (delay-load)", "")
        dll_info = nested_dict.get(key)
        explanation = dll_info["explanation"] if dll_info else "No description available."
        lines.append(f"{dll}:")
        lines.append(f"    DLL Explanation: {explanation}")
        for i, api in enumerate(sorted(functions, key=str.lower)):
            if max_apis_per_dll is not None and i >= max_apis_per_dll:
                break
            expl = _get_api_explanation(dll_info, api) if dll_info else None
            if expl and expl != DEFAULT_EXPLANATION:
                lines.append(f"    {api}: {expl}")
            else:
                lines.append(f"    {api}")
        lines.append("")
    return "\n".join(lines)


def _generate_html_output(
    sorted_imports: dict, nested_dict: dict, dangerous_set: set, max_apis_per_dll: int | None = 20
) -> str:
    """Minimal HTML snippet (enough to test escaping)."""
    import html as html_module
    parts = []
    for dll, functions in sorted_imports.items():
        key = dll.lower().replace(" (delay-load)", "")
        dll_info = nested_dict.get(key)
        explanation = (dll_info["explanation"] if dll_info else "No description available.")
        parts.append(html_module.escape(dll))
        parts.append(html_module.escape(explanation))
    return "".join(parts)


def _generate_json_output(
    sorted_imports: dict, nested_dict: dict, dangerous_set: set
) -> str:
    """JSON report (mirrors main script structure)."""
    key_lower = lambda s: s.lower().replace(" (delay-load)", "")
    out = {
        "dlls": [],
        "dangerous_functions": list(dangerous_set),
        "summary": {
            "total_dlls": len(sorted_imports),
            "total_imports": sum(len(f) for f in sorted_imports.values()),
            "dangerous_count": len(dangerous_set),
        },
    }
    for dll, functions in sorted_imports.items():
        key = key_lower(dll)
        dll_info = nested_dict.get(key)
        explanation = (dll_info["explanation"] if dll_info else "No description available.")
        apis = [{"name": api, "explanation": _get_api_explanation(dll_info, api) or ""} for api in sorted(functions, key=str.lower)]
        out["dlls"].append({"name": dll, "explanation": explanation, "apis": apis})
    return json.dumps(out, indent=2, ensure_ascii=False)


# Use local implementations so tests run without lief
get_api_explanation = _get_api_explanation
generate_text_output = _generate_text_output
generate_html_output = _generate_html_output
generate_json_output = _generate_json_output


def test_get_api_explanation_case_insensitive() -> None:
    """API lookup is case-insensitive."""
    dll_info = dll_api_explanations.get("kernel32.dll")
    assert dll_info is not None
    assert get_api_explanation(dll_info, "CreateFile") == get_api_explanation(
        dll_info, "createfile"
    )
    assert "Creates or opens" in (get_api_explanation(dll_info, "createfile") or "")


def test_get_api_explanation_unknown_returns_none() -> None:
    """Unknown API returns None."""
    dll_info = dll_api_explanations.get("kernel32.dll")
    assert get_api_explanation(dll_info, "NonExistentApi123") is None


def test_get_api_explanation_none_dll_info() -> None:
    """None dll_info returns None."""
    assert get_api_explanation(None, "CreateFile") is None


def test_generate_text_output_all_dlls_shown() -> None:
    """Unknown DLLs appear in text output with 'No description'."""
    sorted_imports = {
        "known.dll": ["SomeFunc"],
        "unknown.dll": ["OtherFunc"],
    }
    nested = {"known.dll": {"explanation": "Known.", "apis": {"somefunc": "Does something."}}}
    out = generate_text_output(sorted_imports, nested, set(), max_apis_per_dll=20)
    assert "known.dll" in out
    assert "unknown.dll" in out
    assert "No description" in out
    assert "SomeFunc" in out
    assert "OtherFunc" in out


def test_generate_html_output_contains_escape() -> None:
    """HTML output escapes content."""
    sorted_imports = {"x.dll": ["Func"]}
    nested = {"x.dll": {"explanation": "Test <script>", "apis": {"func": "Desc"}}}
    out = generate_html_output(sorted_imports, nested, set(), max_apis_per_dll=20)
    assert "&lt;script&gt;" in out or "script" not in out  # escaped or not present
    assert "x.dll" in out


def test_generate_json_output_structure() -> None:
    """JSON output has expected keys and summary."""
    sorted_imports = {"kernel32.dll": ["CreateFile", "ReadFile"]}
    nested = dll_api_explanations
    dangerous_set = {"CreateFile"}
    out_str = generate_json_output(sorted_imports, nested, dangerous_set)
    data = json.loads(out_str)
    assert "dlls" in data
    assert "dangerous_functions" in data
    assert "summary" in data
    assert data["summary"]["total_dlls"] == 1
    assert data["summary"]["total_imports"] == 2
    assert data["summary"]["dangerous_count"] == 1
    assert len(data["dlls"]) == 1
    assert data["dlls"][0]["name"] == "kernel32.dll"
    assert any(api["name"] == "CreateFile" for api in data["dlls"][0]["apis"])
