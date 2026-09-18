# Agent Rules & Guidelines for `dexbuf`

This document defines core principles, architectural guidelines, and tooling conventions for contributors and AI agents working on `dexbuf`.

---

## 1. Core Principles

- **Fast, 0-Copy & Complete DEX Parser**:
  - All public entry points accepting DEX data must type-hint against `collections.abc.Buffer`.
  - Internally, wrap buffers in `memoryview` and navigate data in-place without intermediate byte copies.
  - Slicing a `memoryview` produces child views without heap allocations; allocations are strictly deferred until materializing leaf values (e.g., Python `str` or decoded dataclass records).
  - Use `struct.unpack_from` and in-place cursor traversal for numeric unpacking.
- **Tiered API (REPL-Friendly)**:
  - **Low-level spec representation**: 1:1 mapping to Dalvik Executable binary structures with zero transformation overhead.
  - **High-level REPL/scripting view**: Ergonomic, lazy domain views (classes, methods, fields, instructions) built on top of low-level records.
- **Organic Layout Documentation**:
  - Do not pre-specify or hypothesize struct layouts ahead of time.
  - Data structure definitions and layout documentation will be born in the process as each component is implemented.
- **Spec Traceability**:
  - Whenever implementing a structure or parser mirroring the DEX specification, link directly to the relevant section of the official [Android DEX Format Specification](https://source.android.com/docs/core/runtime/dex-format).

---

## 2. Technology Stack & Python Features

- **Runtime Target**: Python `>=3.14` exclusively.
- **Python 3.14 Features**:
  - Rely on **PEP 649 native deferred annotation evaluation**. Do **not** use `from __future__ import annotations` (which triggers legacy stringification).
  - Annotate all attributes and variables explicitly.
- **Data Modeling**:
  - Use `@dataclass(slots=True, frozen=True)` for immutable spec records.
  - Use `struct.Struct` for binary unpacking.
  - Use `typing` primitives (generics, protocols, `typing.Self`) without `Any`.

---

## 3. Tooling & Development Workflow

- **Project Management**: Use `uv` exclusively for environment synchronization and execution (`uv sync`, `uv run pytest`, `uv run ruff check`).
- **Code Formatting & Linting**: Use `ruff` with line length 100.
- **Static Type Checking**: Use `pyrefly` strict checking.
- **Testing (`pytest`) & Dynamic Compilation**:
  - **Do NOT check in precompiled `.dex` binary files** to git.
  - Use **Nix** (`flake.nix` / `shell.nix`) to provide a hermetic environment containing `javac` (JDK) and `d8` (Android SDK build-tools).
  - Tests dynamically compile minimal Java sources or construct synthetic byte sequences to test parser behaviors.
- **No Machine-Specific Paths in Tracked Files**:
  - Never write absolute paths (e.g. `/Users/...` or `file:///...`) into repository files or documentation. Use relative markdown links or code spans.
