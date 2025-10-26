## Purpose

These instructions help an AI code agent be productive in the detect-secrets repo. Focus on the
core components, local conventions, test/build workflows, and concrete code locations where
changes typically belong.

## Big picture (what this project does)

- detect-secrets scans code for potential secrets, produces a JSON-compatible baseline, and
  provides CLI tools: `detect-secrets` (scan), `detect-secrets-hook` (pre-commit blocking), and
  `detect-secrets audit` (label baseline results). See `README.md` for usage examples.

## Key components & where to look

- Engine & orchestration: `detect_secrets/core/` — scanning, baseline handling, and plugin init.
- Global settings: `detect_secrets/settings.py` — Settings singleton, `default_settings()` and
  `transient_settings()` context managers. Use these when testing or running programmatic scans.
- Plugin interface: `detect_secrets/plugins/base.py` — subclass `RegexBasedDetector`,
  `LineBased` or `FileBased` detectors. `secret_type` and `json()` are important for baseline
  compatibility.
- Built-in detectors: `detect_secrets/plugins/` — examples of detectors and verification logic
  (e.g. `high_entropy_strings.py`, `aws.py`). Use these as canonical examples for new plugins.
- Filters: `detect_secrets/filters/` — filters are referenced by import path or `file://` URL and are
  configured via the Settings object (see `settings.configure_filters`).
- Tests & helpers: `testing/` and `tests/` — test fixtures, custom filter/plugin helpers live in
  `testing/` and unit tests are in `tests/`.

## Project-specific conventions & patterns

- Settings are global via a cached singleton. Prefer `transient_settings({...})` when running
  isolated changes so caches are cleared and restored.

- Filters are configured by import path strings (e.g.
  `detect_secrets.filters.heuristic.is_sequential_string`) or by file URLs `file:///path/to.py::func`.
  Filters must accept injectable variables — see `settings.get_filters()` which attaches
  `function.injectable_variables`.

- Plugins in baselines are stored as a list of dicts with a `name` key (see
  `Settings.configure_plugins`) — if you change `secret_type` or plugin class names, note
  it will affect baseline compatibility.

## Developer workflows (commands to run)

- Run the test suite (recommended via tox):

  tox  # runs envlist from `tox.ini` (py39..py313, mypy)

  Quick local run without tox:

  python -m pytest --strict tests

- Coverage and CI thresholds (enforced in `tox.ini`):
  - coverage for `tests/*` must be >= 99%
  - coverage for `testing/*` must be 100%
  - coverage for `detect_secrets/*` must be >= 95%

- Run type checking (mypy):

  tox -e mypy

- Pre-commit hooks: configured in `.github` and installed with `pre-commit install` or via
  `tox -e venv` which creates a `venv` env and installs hooks. CI runs `pre-commit run --all-files`.

## How to add a detector or filter (quick checklist)

1. Add a new detector under `detect_secrets/plugins/` by subclassing `RegexBasedDetector` or
   `BasePlugin` (see `plugins/base.py`). Set a stable `secret_type` and implement `analyze_string`
   (or `analyze_line`).
2. Add tests under `tests/plugins/` and helper fixtures in `testing/` if needed.
3. Run `python -m pytest tests/plugins` and ensure coverage thresholds remain satisfied.
4. If the detector needs runtime configuration, ensure it can be referenced via the baseline
   structure (name + optional args) and documented in `README.md` or `docs/`.

## Useful code examples (where to change behavior)

- To temporarily change which plugins run in a script or test, use `transient_settings` in
  `detect_secrets/settings.py` (example in README under "More Advanced Configuration").

- Verification hooks live in plugin classes (`verify` / `format_scan_result`) and rely on
  `detect_secrets.constants.VerifiedResult` and the `detect_secrets.filters` settings.

## Integration points & CI

- CI uses GitHub Actions (`.github/workflows/ci.yml`) and enforces tox-based testing and
  coverage thresholds. Packaging metadata and bumpversion configuration live in `setup.cfg`.

## What an AI agent should avoid changing

- Do not rename an existing plugin class or change `secret_type` without adding a migration
  note: older baselines rely on the name and JSON fields.
- Avoid modifying coverage thresholds or CI logic without explicit reviewer sign-off — these
  are intentionally strict.

## If something's unclear, iterate

Leave a concise PR or comment that references the exact files changed (path + function/class)
and ask for the maintainer to point to intended behavior. If you'd like, I can iterate on this
file to add more repo-specific examples — tell me which areas you'd like expanded.
