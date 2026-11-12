# Security Policy

Thank you for helping keep LightPacket and its users safe. 

LightPacket is a raw packet crafting and sniffing library that runs with elevated privileges. That makes security reports especially important to us, and we take them seriously.

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [What Counts as a Vulnerability](#what-counts-as-a-vulnerability)
- [Out of Scope](#out-of-scope)
- [Response Process](#response-process)
- [Safe Harbor](#safe-harbor)
- [Responsible Use](#responsible-use)

---

## Supported Versions

Only the following versions receive security fixes:

| Component | Supported Versions |
|-----------|-------------------|
| **LightPacket** | v1.0.0 and newer  |
| **LightBPF** | v1.1.0 and newer  |

Older versions are **not** actively supported. If you are running one, please upgrade before reporting, and check whether the issue still reproduces on a supported release.

## Reporting a Vulnerability

> ### Please do **NOT** open a public GitHub issue, pull request, or discussion for security vulnerabilities.
>
> Public reports can put users at risk before a fix is available.

Instead, report vulnerabilities **privately** by email:

- **lightscanframework@gmail.com**

Suggested subject line: `[SECURITY] LightPacket: short description`

To help us triage quickly, please include as much of the following as you can:

- Affected component (LightPacket, LightBPF, or both) and version
- Operating system and version, Python version, and `Libpcap` / `Npcap` version
- A clear description of the issue and its potential impact
- Step-by-step reproduction instructions
- A proof of concept, such as a crafted packet (hex dump or `.pcap`), filter string, or script
- Crash output, tracebacks, or core dump details, if applicable
- Any suggested fix or mitigation

If you'd like to send sensitive attachments, let us know in your first email and we'll arrange a suitable method.

## Threat Model

Understanding how LightPacket is used helps explain how we rate severity.

**Raw sockets need privileges.** To open raw sockets, BPF devices, or Npcap handles, LightPacket must typically run as **root** (Linux/macOS/BSD), with `CAP_NET_RAW`, or as **Administrator** (Windows). Processes with these privileges are high-value targets: a bug that crashes or hijacks them can affect the entire host.

**Packet data is untrusted input.** Anything received from the network, including frames, headers, options, and length fields, may be crafted by an attacker. LightPacket's parsers and the socket layer must handle hostile or malformed data safely.

**`ctypes` removes Python's safety net.** Because LightPacket binds directly to C-level APIs (`AF_PACKET`, BPF devices, Npcap, `libpcap`), mistakes such as struct misalignment, wrong `argtypes`/`restype`, bad buffer sizes, or freed memory can cause memory corruption or crashes that pure Python code would never produce.

Given this, we consider the following **high-priority vulnerabilities**:

- **Crashes (e.g. segmentation faults)** caused by `ctypes` misalignment, incorrect struct layouts, invalid pointer handling, or buffer mismanagement, particularly when triggered by received packets or crafted filter input.
- **Denial of Service via infinite loops or unbounded resource use** in the packet parser, filter compiler, or capture loop (e.g. a malformed header that causes the parser to never make progress, or a field that triggers excessive memory allocation).
- **Memory safety issues** such as out-of-bounds reads/writes, use-after-free, or buffer overflows in the `ctypes` layer.
- **Privilege-related flaws**, such as anything that could allow an unprivileged party to influence behavior of a privileged LightPacket process in unintended ways.

A crash or hang in a process holding raw-socket privileges is a **security issue**, not just a stability bug. Please report it privately even if you aren't sure it's exploitable.

## What Counts as a Vulnerability

Examples of reports we want to hear about:

- A crafted packet that makes a sniffer crash, hang, or consume unbounded CPU or memory
- A malformed BPF filter string that crashes the compiler or emits **incorrect bytecode** that bypasses the intended filter in a way that could be security-relevant
- Out-of-bounds access when parsing protocol headers
- Incorrect handling of length, offset, or count fields from the wire
- Unsafe temporary file, device, or handle usage in the platform socket layers
- Platform-specific crashes (for example, only on one BSD or on Windows) that can be triggered remotely or by crafted input

## Out of Scope

The following are generally **not** considered vulnerabilities in LightPacket:

- Behavior that requires an attacker to *already* have root/Administrator access on the machine
- Misuse of the library to send traffic the user intended to send (crafting packets is the library's purpose)
- Vulnerabilities in third-party dependencies such as `libpcap`, Npcap, or the operating system (please report those upstream), though we welcome a heads-up if LightPacket can mitigate them
- Issues only present in unsupported versions
- Reports without a plausible security impact (ordinary bugs can be filed as public issues)

If you're unsure which category your finding falls into, **email us**. We'd rather hear about it.

## Response Process

LightPacket is maintained by a solo developer, so timelines are best-effort, but here is what you can expect:

| Step | Target |
|------|--------|
| Acknowledgement of your report | Within **5 business days** |
| Initial assessment and severity rating | Within **10 business days** |
| Fix or mitigation for high-severity issues | As quickly as possible; we'll keep you updated |
| Public disclosure | Coordinated with you after a fix is released |

We follow **coordinated disclosure**: we ask that you give us a reasonable window (typically up to **90 days**) to investigate and release a fix before any public disclosure. We're happy to credit you in the release notes and advisory unless you prefer to remain anonymous.

When a fix is ready, we will:

1. Release patched versions of the affected component(s)
2. Publish a GitHub Security Advisory (and request a CVE where appropriate)
3. Describe the impact, affected versions, and upgrade steps

## Safe Harbor

We support good-faith security research. If you make a genuine effort to follow this policy (avoid privacy violations, don't disrupt systems or networks you don't own, and give us time to respond), we will not pursue or support legal action against you for your research.

Please test only against systems and networks that you own or have explicit permission to test.

## Responsible Use

LightPacket is a powerful tool for network engineering, education, testing, and security research. Please use it responsibly, and only on networks and systems you are authorized to work with. Running as root and sending raw traffic can disrupt networks, so test in isolated environments such as VMs or loopback interfaces whenever possible.

---

Thank you for helping us keep LightPacket secure! 