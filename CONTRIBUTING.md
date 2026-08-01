# Contributing to Host & Network Hardener

Thanks for your interest in improving this project. Please read the
[Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)
first — we expect every participant to treat others with respect.

## Reporting bugs

- Search [open issues](https://github.com/aBadRoy/Host-Network-Hardener-/issues) first.
- Include the tool version (`python main.py --version`), your OS/Python version,
  the exact command you ran and the full error output.

## Suggesting features

Open an issue describing the problem you want to solve. Explain the use case and
how the feature should behave before proposing a specific implementation.

## Setting up for development

```bash
git clone https://github.com/aBadRoy/Host-Network-Hardener-.git
cd Host-Network-Hardener-
python -m pip install -e ".[dev]"
```

## Running the tests and lints

```bash
# Full test suite
python -m pytest

# Lint (unused imports, undefined names)
python -m pyflakes hardener main.py lab_mock.py conftest.py tests

# Compile check
python -m py_compile main.py lab_mock.py conftest.py hardener/*.py tests/*.py
```

All tests must pass and pyflakes must report no issues before a pull request is merged.

## Code style

- Target **Python 3.9+**; avoid syntax introduced after 3.9.
- Keep modules focused: one concern per file inside `hardener/`.
- Never print raw remote banners directly — always pass output through
  `utils.sanitize_text()` so unusual encodings cannot crash the tool.
- Do not add comments that restate what the code does.
- Add a test in `tests/` for any new behavior or bug fix.

## Testing network features

`lab_mock.py` starts a local mock target on `127.0.0.1` so the full scanning
pipeline can be exercised without touching external systems:

```bash
# Terminal 1
python lab_mock.py

# Terminal 2
python main.py -t 127.0.0.1 -p 8080,2222,2121,2323,6379,13306,15432,8443 --authorized
```

> ⚠️ The tool performs active network scanning. Only run it against systems you
> own or have explicit written permission to test.

## Pull request checklist

- [ ] Tests pass: `python -m pytest`
- [ ] Pyflakes clean: `python -m pyflakes hardener main.py lab_mock.py conftest.py tests`
- [ ] New behavior covered by tests
- [ ] `CHANGELOG.md` updated under *Unreleased*

## Commit messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) style,
e.g. `fix:`, `feat:`, `docs:`, `test:`, `ci:`.
