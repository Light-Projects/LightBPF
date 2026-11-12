# Contributing to LightPacket

First off, **thank you** for taking the time to contribute! 

LightPacket is maintained by a **solo developer**, which means every bug report, pull request, documentation fix, and test run on an unusual OS makes a real difference. You don't need to be a networking or `ctypes` expert to help. Curiosity and care are plenty.

This document explains how the project is organized, how to get a development environment running, and where you can jump in.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [About the Project](#about-the-project)
- [Project Architecture](#project-architecture)
- [Good First Issues](#good-first-issues)
- [Development Setup](#development-setup)
- [Testing and the OS Matrix](#testing-and-the-os-matrix)
- [Submitting Changes](#submitting-changes)
- [Coding Guidelines](#coding-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Security Issues](#security-issues)
- [License](#license)

---

## Code of Conduct

Be kind, be patient, and assume good intent. This is a small project and we want it to stay a friendly place for beginners and experts alike. Harassment, personal attacks, or discriminatory behavior won't be tolerated.

## About the Project

The repository contains two closely related components:

- **LightPacket**: a cross-platform Python library for raw packet crafting, sniffing, and manipulation. It supports **Linux, Windows, Unix Like-Systems, macOS, FreeBSD, NetBSD, OpenBSD, and DragonFlyBSD**.
- **LightBPF**: a zero-dependency, pure-Python classic BPF (cBPF) compiler. It turns human-readable filters such as `tcp port 80` into bytecode that can be attached directly to the kernel, and acts as a fallback when `libpcap` is not installed.

Both are licensed under **MPL-2.0**.

## Project Architecture

LightPacket leans heavily on `ctypes` to talk to C-level system APIs (`AF_PACKET`, BPF devices, Npcap, and `libpcap`). The filter pipeline in LightBPF is a classic compiler front-to-back flow:

```
 "tcp port 80"
      │
      ▼
 ┌─────────┐    ┌─────────┐    ┌──────────┐    ┌──────────────────┐
 │  Lexer  │ ─▶ │ Parser  │ ─▶ │ Compiler │ ─▶ │ ctypes Sockets   │
 └─────────┘    └─────────┘    └──────────┘    └──────────────────┘
  tokens         AST            cBPF bytecode   attach filter &
                                                read/write frames
```

| Stage | What it does |
|-------|--------------|
| **Lexer** | Breaks the filter string into tokens (keywords, numbers, addresses, operators). |
| **Parser** | Builds an abstract syntax tree (AST) from the tokens, handling precedence and primitives like `tcp`, `port`, `host`. |
| **Compiler** | Walks the AST and emits cBPF instructions (jumps, loads, returns). |
| **ctypes Sockets** | Platform-specific socket layers that open raw sockets or BPF devices, attach the compiled program (or hand the filter to `libpcap` / Npcap), and send/receive frames. |

> **Heads-up:** The socket layer is where most platform quirks live. Struct layouts, alignment, pointer lifetimes, and differences between BSD `bpf` and Linux `AF_PACKET` are the usual suspects when something misbehaves, so please take extra care when touching `ctypes` definitions.

## Good First Issues

Not sure where to start? Here are some friendly entry points:

-  **Documentation**: improve the README, add usage examples, write docstrings, or clarify the filter syntax LightBPF supports.
-  **Add EtherTypes / protocol definitions**: extend the protocol tables with new EtherTypes (and their headers, if you're feeling adventurous), with a test for each.
-  **Test on different operating systems**: run the test suite on a platform you have access to (especially NetBSD, DragonFlyBSD, or an older macOS/Windows version) and report what works and what doesn't.
-  **Expand test coverage**: add tests for filter expressions, malformed packets, and edge cases.
-  **Triage issues**: reproduce reported bugs and add details like OS version, Python version, and `libpcap` version.

Look for issues labeled `good first issue` or `help wanted`. If you want to work on something, leave a quick comment so we don't duplicate effort.

## Development Setup

### Prerequisites

- **Python 3.8+**
- **Git**
- **Root / Administrator privileges** for tests that open real raw sockets
- **`libpcap`** (Linux/macOS/BSD) or **Npcap** (Windows) for testing the `libpcap` backend. LightBPF itself has no dependencies, but you'll want `libpcap` available to compare behavior.

### 1. Fork and clone

```bash
git clone https://github.com/Light-Projects/LightPacket.git
cd LightPacket
git remote add upstream https://github.com/Light-Projects/LightPacket.git
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
pip install pytest               # or your preferred test runner
```

### 3. Install the native dependencies

| OS | Command |
|----|---------|
| **Debian / Ubuntu** | `sudo apt install libpcap-dev tcpdump` |
| **Fedora / RHEL** | `sudo dnf install libpcap-devel tcpdump` |
| **Arch** | `sudo pacman -S libpcap tcpdump` |
| **macOS** | `libpcap` ships with the OS; optionally `brew install libpcap` |
| **FreeBSD / OpenBSD / NetBSD / DragonFlyBSD** | `libpcap` is part of the base system on most; otherwise install via `pkg` / `pkg_add` / `pkgin` |
| **Windows** | Install [Npcap](https://npcap.com/) (enable *WinPcap API-compatible mode* if prompted) |

> `tcpdump` is handy for comparing filter output against LightBPF's bytecode (`tcpdump -d "tcp port 80"`).

### 4. Run the tests

```bash
# Tests that don't need privileges
pytest

# Tests that open raw sockets (need elevated privileges)
sudo -E env "PATH=$PATH" pytest      # Linux / macOS / BSD
# Windows: run your terminal as Administrator
```

> **Be careful when running as root.** Raw sockets can send arbitrary traffic. Test on an isolated network, loopback, or a VM whenever possible, and never against systems you don't own or have permission to test.

## Testing and the OS Matrix

LightPacket targets **seven operating systems**, and platform differences are the single biggest source of bugs. Before opening a PR, please:

1. Run the test suite on **at least one** OS you have access to and note which one in your PR.
2. If your change touches the **socket layer or `ctypes` structs**, think through how it behaves on other platforms (struct padding, endianness, `sizeof` differences, BSD vs. Linux semantics).
3. If you can, test on **both a Linux system and a BSD-family system**.

| Platform | Backends | Notes |
|----------|----------|-------|
| Linux | `AF_PACKET`, `libpcap` | Needs `CAP_NET_RAW` or root |
| Windows | Npcap | Needs Administrator, Npcap installed |
| macOS | BPF devices, `libpcap` | Needs root or access to `/dev/bpf*` |
| FreeBSD | BPF devices, `libpcap` | Needs root or access to `/dev/bpf*` |
| NetBSD | BPF devices, `libpcap` | Needs root or access to `/dev/bpf*` |
| OpenBSD | BPF devices, `libpcap` | Needs root or access to `/dev/bpf*` |
| DragonFlyBSD | BPF devices, `libpcap` | Needs root or access to `/dev/bpf*` |

Don't have all seven? **That's completely fine.** Say what you tested and what you couldn't, and we'll work out the rest together (for example, via VMs or community testers).

### Tips for good tests

- Prefer **pure unit tests** (no privileges, no network) for the Lexer, Parser, and Compiler. These run everywhere.
- Compare compiled LightBPF bytecode against known-good output (e.g. from `tcpdump -d`) when adding filter features.
- Mark tests that need root/Administrator or a specific OS so they skip cleanly elsewhere.

## Submitting Changes

1. **Open an issue first** for anything substantial, so we can agree on direction before you invest time.
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/short-description
   ```
3. **Make focused changes.** Small, single-purpose PRs are much easier to review than large ones.
4. **Add or update tests and docs** for your change.
5. **Run the tests** on your OS and mention it in the PR.
6. **Open a pull request** and fill out the description: what changed, why, and how you tested it.

Since this is a solo-maintained project, reviews may take a few days. Thanks in advance for your patience! A friendly ping after a week is always welcome.

### Commit messages

Clear and descriptive is the goal. Something like:

```
Add EtherType definition for LLDP

- Add constant and header parser
- Add unit test with a captured frame
```

## Coding Guidelines

- **Python 3.8+ compatible**: avoid syntax and stdlib features newer than 3.8.
- **LightBPF stays zero-dependency.** Please don't add third-party imports to it.
- Follow **PEP 8** and keep lines reasonably short.
- Add **type hints** and **docstrings** to public functions and classes.
- With **`ctypes`**:
  - Always declare `argtypes` and `restype` for foreign functions. Defaults can silently truncate pointers on 64-bit systems.
  - Double-check struct field order, sizes, and padding per platform.
  - Keep references to buffers alive for as long as C code may use them.
  - Validate lengths before slicing or casting packet data. Never trust sizes from the wire.
- Avoid unbounded loops when parsing packet data; always make sure parsing makes forward progress.

## Reporting Bugs

Please [open an issue](https://github.com/Light-Projects/LightPacket/issues) and include:

- LightPacket and/or LightBPF version
- Operating system and version
- Python version (`python --version`)
- `libpcap` / Npcap version, if relevant
- Steps to reproduce, expected behavior, and actual behavior
- Tracebacks, or crash output / core dump details for segfaults

**Is it a security vulnerability?** Please **do not** open a public issue. See [SECURITY.md](SECURITY.md) instead.

## Security Issues

Because LightPacket operates with elevated privileges, crashes and parser hangs can have security implications. If you believe you've found one, follow the private disclosure process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Mozilla Public License 2.0 (MPL-2.0)](LICENSE), the same license as the project.

---

Thank you again for helping make LightPacket better. Happy hacking! 