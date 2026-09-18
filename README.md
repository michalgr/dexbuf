# dexbuf

> **Fast, 0-copy, and complete Dalvik Executable (DEX) reader built on Python's Buffer protocol and typed dataclasses.**

[![CI](https://github.com/michalgr/dexbuf/actions/workflows/ci.yml/badge.svg)](https://github.com/michalgr/dexbuf/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://docs.python.org/3.14/)

---

## Vision & Philosophy

`dexbuf` is an in-place, zero-copy Dalvik Executable (DEX) parser and bytecode reader engineered for Python 3.14+. Operating directly on objects satisfying `collections.abc.Buffer` (`memoryview`, `mmap`, `bytes`), `dexbuf` navigates binary tables in-place without upfront deserialization or intermediate byte copying.

- **Fast & 0-Copy**: Slices `memoryview` buffers directly. Byte allocations are strictly deferred until materializing leaf values (strings, dataclasses).
- **Tiered Architecture**:
  - **Low-Level Spec Representation**: Maps 1:1 to structures in the official [Android DEX Format Specification](https://source.android.com/docs/core/runtime/dex-format).
  - **REPL / Scripting API**: High-level, ergonomic domain views for interactive inspection and analysis in a Python REPL.
- **Modern Python**: Built with `struct`, `typing`, frozen slotted `dataclasses`, and native deferred evaluation (PEP 649).
- **Hermetic Testing via Nix**: No precompiled `.dex` binary files are checked into git. Test fixtures dynamically compile Java sources using `javac` and `d8` provided by a Nix environment.

---

## Development & Tooling

`dexbuf` uses modern, high-performance tooling managed via [`uv`](https://github.com/astral-sh/uv) and [Nix](https://nixos.org).

### Prerequisites
- Python `>=3.14`
- [`uv`](https://github.com/astral-sh/uv)

### Nix Shell (Dynamic DEX Tooling)
To enter a development environment with `uv`, JDK (`javac`), and Android SDK build-tools (`d8`):

```bash
# Using Nix flakes:
nix develop

# Or classic nix-shell:
nix-shell
```

### Common Commands

```bash
# Synchronize environment
uv sync

# Run test suite
uv run pytest

# Format and lint
uv run ruff check .
uv run ruff format --check .

# Static type checking
uv run pyrefly
```

---

## Specification Reference

`dexbuf` structures directly mirror the official Android runtime specifications:
- [Dalvik Executable (DEX) Format](https://source.android.com/docs/core/runtime/dex-format)
- [Dalvik Bytecode Instruction Formats](https://source.android.com/docs/core/runtime/instruction-formats)

---

## License

MIT License.
