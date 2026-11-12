# Security Policy

Thank you for helping keep LightBPF and its users safe. 

LightBPF compiles filter expressions into bytecode that is attached to the kernel, usually by programs running with elevated privileges. A flaw in the compiler can therefore have real consequences, and we take security reports seriously.

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [What Counts as a Vulnerability](#what-counts-as-a-vulnerability)
- [Out of Scope](#out-of-scope)
- [Response Process](#response-process)
- [Safe Harbor](#safe-harbor)

---

## Supported Versions

| Component | Supported Versions |
|-----------|--------------------|
| **LightBPF** | v1.1.0 and newer   |

Older versions are **not** actively supported. Please upgrade and confirm the issue still reproduces before reporting.

If you use LightBPF through [LightPacket](https://github.com/Light-Projects/LightPacket), note that LightPacket v1.0.0 and newer are the supported releases on that side.

## Reporting a Vulnerability

> ### Please do **NOT** open a public GitHub issue, pull request, or discussion for security vulnerabilities.
>
> Public reports can put users at risk before a fix is available.

Report vulnerabilities **privately** by email:

- **lightscanframework@gmail.com**

Suggested subject line: `[SECURITY] LightBPF: short description`

Please include as much of the following as you can:

- LightBPF version, Python version, and operating system
- A clear description of the issue and its potential impact
- The **exact filter string** (or input) that triggers it
- Step-by-step reproduction instructions or a small script
- Observed vs. expected behavior (crash output, hang details, or the incorrect bytecode produced)
- Any suggested fix or mitigation

## Threat Model

**Filters are compiled into kernel-attached programs.** LightBPF takes a filter string and produces cBPF bytecode that the operating system runs against every packet on a socket. If the bytecode doesn't do what the filter says, traffic can be wrongly accepted or dropped.

**Filter strings may be untrusted.** Applications may build filters from user input, configuration files, or network-facing APIs. The Lexer, Parser, and Compiler must handle hostile or malformed input safely.

**The host process is often privileged.** LightBPF is typically used together with raw sockets, which require root/Administrator (or `CAP_NET_RAW`). A crash or hang in that process affects a high-value target.

**Zero dependencies means a small, auditable surface.** LightBPF is pure Python with no third-party code. The only native boundary is the thin `ctypes` layer used to attach programs to the kernel, which is where memory-safety mistakes (struct misalignment, wrong argument types, buffer lifetime) can cause crashes such as segmentation faults.

Given this, we treat the following as **high priority**:

- **Denial of Service in the compiler pipeline**: infinite loops in the Lexer or Parser, unbounded recursion, or exponential time or memory use triggered by a crafted filter (for example, deeply nested parentheses or very long boolean chains).
- **Incorrect bytecode generation**: filters that compile to programs which don't match the documented semantics in a security-relevant way (for example, an `and`/`or`/`not` precedence error, a wrong offset or mask, or a jump that lands on the wrong instruction).
- **Invalid or oversized programs**: output that exceeds cBPF limits (such as program length or the single-byte conditional jump range) without being detected, causing silent truncation, wrap-around, or kernel rejection.
- **Crashes and memory-safety issues** in the `ctypes` attachment layer, including segmentation faults from misaligned structures or invalid pointers.

A crash or hang in a privileged process is a **security issue**, not merely a stability bug. If in doubt, report it privately.

## What Counts as a Vulnerability

Examples of reports we want to hear about:

- A filter string that makes the Lexer, Parser, or Compiler hang or consume unbounded CPU or memory
- A filter that compiles to bytecode with semantics different from what was requested
- Integer overflow or wrap-around in jump offsets, constants, or program length
- A crafted filter that causes an interpreter crash (not just a Python exception)
- Platform-specific crashes in the socket-attachment code
- Error handling that swallows a compilation failure and silently attaches a wrong or empty program

## Out of Scope

The following are generally **not** considered vulnerabilities in LightBPF:

- Anything requiring an attacker to *already* have root/Administrator access on the host
- Clean, expected Python exceptions raised for invalid filter syntax
- Vulnerabilities in the OS kernel's BPF implementation, `Libpcap`, `Npcap`, or other third-party software (please report those upstream)
- Issues only present in unsupported versions
- Applications that pass untrusted filter strings *by design* without any validation or limits, when LightBPF itself behaves as documented. A hang or crash in LightBPF on such input is still in scope, however.

Not sure whether something qualifies? **Email us**; we'd rather hear about it.

## Response Process

LightBPF is maintained by a solo developer, so timelines are best-effort:

| Step | Target |
|------|--------|
| Acknowledgement of your report | Within **5 business days** |
| Initial assessment and severity rating | Within **10 business days** |
| Fix or mitigation for high-severity issues | As quickly as possible, with updates along the way |
| Public disclosure | Coordinated with you after a fix is released |

We follow **coordinated disclosure** and ask for a reasonable window (typically up to **90 days**) before public disclosure. With your permission, we'll credit you in the release notes and advisory.

When a fix is ready, we will:

1. Release a patched version of LightBPF
2. Publish a GitHub Security Advisory (and request a CVE where appropriate)
3. Describe the impact, affected versions, and upgrade steps

## Safe Harbor

We support good-faith security research. If you make a genuine effort to follow this policy (avoid privacy violations, don't disrupt systems or networks you don't own, and give us time to respond), we will not pursue or support legal action against you for your research.

Please test only on systems and networks that you own or have explicit permission to test.

---

Thank you for helping us keep LightBPF secure! 