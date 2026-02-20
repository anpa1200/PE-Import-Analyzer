# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-02-20

### Added

- **Data/code split**: DLL and API explanation data moved to `dll_explanations.py` for maintainability and smaller main script.
- **JSON output**: `--json` for machine-readable reports with summary and dangerous-API categories.
- **Delay-load imports**: Optional parsing of delay-load import table (LIEF); shown as `DLL (delay-load)`. Use `--no-delay-load` to disable.
- **Full CLI**: `--html`, `--txt`, `--json`, `--dangerous`, `--no-dangerous`, `-o`, `--no-prompt`, `--all-apis`, `--no-delay-load`, `-q`, `-v`, `--version`.
- **Non-interactive mode**: `--no-prompt` for scripting and CI.
- **Dangerous-API categories**: Expanded list with categories (injection, persistence, network/C2, crypto/evasion, file/system) and JSON category field.
- **Logging**: Optional `-v`/`--verbose` and `-q`/`--quiet`; errors go to stderr with distinct exit codes.
- **Type hints**: Public functions annotated for IDE and static checking.
- **Tests**: `tests/test_analyzer.py` (report logic, no LIEF) and `tests/test_cli.py` (CLI, requires LIEF).
- **Packaging**: `pyproject.toml` with metadata, dependencies, and optional dev deps (pytest).
- **Exit codes**: 2 = file not found, 3 = permission denied, 4 = invalid PE, 5 = write error.

### Fixed

- **All DLLs in report**: Unknown DLLs were previously omitted; they now appear with "No description available" and full API list.
- **Case-insensitive API lookup**: Mixed-case API names (e.g. `OpenSCManagerA`) now match explanations correctly.
- **Placeholder bloat**: Removed the unused "extend to 100 APIs per DLL" logic.

### Changed

- **HTML report**: Dark theme and clearer styling; dangerous section highlighted.
- **Default behavior**: Without `--no-prompt`, interactive prompts unchanged; with `--no-prompt`, defaults to `.txt` and derived filename.
- **README**: Updated usage, options, and examples; duplicate installation block removed.

## [1.x] - Earlier

- Initial release: PE import extraction with LIEF, DLL/API explanations, HTML and text output, dangerous-API flagging.
