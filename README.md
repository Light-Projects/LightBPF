## LightBPF is part of LightPacket Library so for imports in this example you will find it always starts with LightPacket

# LightBPF: Pure-Python Berkeley Packet Filter (cBPF) Engine

**LightBPF** is a standalone, pure-Python Berkeley Packet Filter engine for packet sniffing, inspection, and network security applications. It tokenizes, parses, compiles, disassembles, and emulates classic BPF (cBPF / pcap-filter) bytecode with zero native C dependencies.

```
+------------------+         +------------------+         +----------------------+
|   Filter Text    |         |   Token Stream   |         | Abstract Syntax Tree |
|  "tcp port 80"   | ----->  | [IP-PROTO, tcp], | ----->  |  KeywordFilterNode   |
|                  | (Lexer) | [KEYWORD, port]  | (Parser)|   (port=80, tcp)     |
+------------------+         +------------------+         +----------------------+
                                                                     |
                                                                     | (Compiler)
                                                                     v
                                                          +----------------------+
                                                          |  cBPF Machine Code   |
                                                          | (List[Instruction])  |
                                                          +----------------------+
                                                              /              \
                                                             /                \
                                                            v                  v
                                                  +------------------+   +-------------------+
                                                  | Linux Raw Socket |   | Pure-Python VM    |
                                                  | SO_ATTACH_FILTER |   |   (BpfEmulator)   |
                                                  +------------------+   +-------------------+
```

---

## Table of Contents

1. [Key Features](#key-features)
2. [Quick Start Guide](#quick-start-guide)
   - [Compiling a Filter](#compiling-a-filter)
   - [Offline Packet Filtering (BpfEmulator)](#offline-packet-filtering-bpfemulator)
   - [Attaching to Linux Raw Sockets](#attaching-to-linux-raw-sockets)
   - [Disassembling Bytecode](#disassembling-bytecode)
3. [Supported Filter Syntax Cheat Sheet](#supported-filter-syntax-cheat-sheet)
4. [Architecture & Pipeline](#architecture--pipeline)
   - [The Classic BPF (cBPF) Virtual Machine](#the-classic-bpf-cbpf-virtual-machine)
   - [Instruction Structure (struct bpf_insn)](#instruction-structure-struct-bpf_insn)
5. [Developer Deep-Dive: Stage 1 — Lexer (`Lexer.py`)](#developer-deep-dive-stage-1--lexer-lexerpy)
   - [Tokenizer Mechanics](#tokenizer-mechanics)
   - [Token Reference Table](#token-reference-table)
6. [Developer Deep-Dive: Stage 2 — Parser (`Parser.py`)](#developer-deep-dive-stage-2--parser-parserpy)
   - [Grammar & Operator Precedence](#grammar--operator-precedence)
   - [Abstract Syntax Tree (AST) Reference](#abstract-syntax-tree-ast-reference)
7. [Developer Deep-Dive: Stage 3 — Compiler (`Compiler.py`)](#developer-deep-dive-stage-3--compiler-compilerpy)
   - [Short-Circuit Boolean Control Flow](#short-circuit-boolean-control-flow)
   - [Relative Jump Resolution & Jump Threading](#relative-jump-resolution--jump-threading)
   - [Register Spilling via Scratch Memory (M[0..15])](#register-spilling-via-scratch-memory-m015)
   - [Dynamic IPv4 IHL Tracking (BPF_MSH)](#dynamic-ipv4-ihl-tracking-bpf_msh)
   - [VLAN 802.1Q Handling](#vlan-8021q-handling)
   - [Bitmask Optimization (BPF_JSET)](#bitmask-optimization-bpf_jset)
8. [Worked Examples & Disassembly Traces](#worked-examples--disassembly-traces)
   - [Example 1: `tcp and port 80`](#example-1-tcp-and-port-80)
   - [Example 2: `tcp[13] & 2 != 0` (TCP SYN)](#example-2-tcp13--2--0-tcp-syn)
   - [Example 3: `host 192.168.1.1`](#example-3-host-19216811)
   - [Example 4: `vlan 100`](#example-4-vlan-100)
   - [Example 5: `(ip[0] & 0xf) * 4 > 20`](#example-5-ip0--0xf--4--20)
9. [Verification & Testing](#verification--testing)
10. [Opcode & Constant Reference](#opcode--constant-reference)

---

## Key Features

- **100% Pure Python**: Runs everywhere without needing `libpcap`, `gcc`, or external tools installed.
- **Full cBPF Instruction Coverage**: Complete support for classes, addressing modes, arithmetic/bitwise operations, and jump branches.
- **Dual-Stack Networking**: Handles both IPv4 (with dynamic IHL header offsets) and IPv6 (multi-word 128-bit checks).
- **Rich Protocol & Filter Support**: Protocols (`tcp`, `udp`, `icmp`, `arp`, `vlan`, `mpls`), network filters (`host`, `net`, `port`, `portrange`), byte access (`tcp[13]`, `ip[2:2]`), and pseudo-fields (`tcpflags`, `icmptype`).
- **Scratch Memory Spilling**: Uses cBPF registers `M[0..15]` to compile nested mathematical expressions on both sides of comparisons.
- **Peephole Jump Optimization**: Automatically flattens jump chains via jump threading.
- **Integrated VM Emulator**: Execute BPF filters on raw byte packets in unit tests or user-space applications without root privileges.
- **Standard Serialization**: Export to Linux kernel `struct sock_fprog` or 8-byte raw machine instruction streams.

---

## Quick Start Guide

### Compiling a Filter

```python
from LightPacket.LightBPF.Compiler import BpfCompiler

# Compile a classic filter string directly into cBPF bytecode
instructions = BpfCompiler.compile_str("tcp port 80 and src host 192.168.1.10")

print(f"Compiled into {len(instructions)} BPF instructions:")
for i, insn in enumerate(instructions):
    print(f"  [{i:02d}] {insn}")
```

### Offline Packet Filtering (`BpfEmulator`)

You can execute filters directly on raw bytes in Python:

```python
from LightPacket.LightBPF.Compiler import BpfCompiler, BpfEmulator

filter_code = BpfCompiler.compile_str("tcp[tcpflags] & tcp-syn != 0")

raw_packet = b"..."  # raw Ethernet frame bytes

# Returns captured length (> 0) if matched, 0 if rejected
match_len = BpfEmulator.execute(filter_code, raw_packet)

if match_len > 0:
    print(f"Matched! Captured {match_len} bytes.")
else:
    print("Rejected.")
```

### Attaching to Linux Raw Sockets

Attach compiled filters straight to a Linux AF_PACKET raw socket with `SO_ATTACH_FILTER`:

```python
import socket
from LightPacket.LightBPF.Compiler import BpfCompiler

# 1. Open raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind(("eth0", 0))

# 2. Compile and package into ctypes sock_fprog
instructions = BpfCompiler.compile_str("tcp and port 443")
fprog = BpfCompiler.to_fprog(instructions)

# 3. Attach in kernel space
SO_ATTACH_FILTER = 26
sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
```

### Disassembling Bytecode

Print human-readable cBPF assembly formatted like `tcpdump -d`:

```python
from LightPacket.LightBPF.Compiler import BpfCompiler, disassemble

insns = BpfCompiler.compile_str("ip and (port 80 or port 443)")
print(disassemble(insns))
```

---

## Supported Filter Syntax Cheat Sheet

| Category | Filter Examples | Description |
|---|---|---|
| **Protocols** | `ip`, `ip6`, `tcp`, `udp`, `icmp`, `arp`, `vlan`, `mpls`, `ether` | Standalone protocol verification |
| **Hosts** | `host 192.168.1.1`<br>`src host 10.0.0.1`<br>`dst host fe80::1`<br>`ether host aa:bb:cc:dd:ee:ff` | Match IPv4, IPv6 (4 words), or MAC address |
| **Networks** | `net 10.0.0.0/8`<br>`src net 192.168.1.0/24`<br>`net 10.0.0.0 mask 255.0.0.0`<br>`ip6 net 2001:db8::/32` | CIDR and netmask matching |
| **Ports** | `port 80`<br>`tcp dst port 443`<br>`udp port 53`<br>`src port http`<br>`portrange 1000-2000` | Port, port range, and service name resolution |
| **Byte Access** | `tcp[13] & 2 != 0`<br>`ip[2:2] > 500`<br>`ether[12:2] == 0x0800`<br>`tcp[tcpflags] & tcp-syn != 0` | Arbitrary byte/half/word extraction |
| **Header Length** | `(ip[0] & 0xf) * 4 > 20` | Dynamic IPv4 IHL calculations |
| **Packet Size** | `len > 100`, `less 64`, `greater 1500` | Frame size checks via `BPF_LEN` |
| **Broadcast / Multicast** | `broadcast`<br>`multicast` | Ethernet broadcast and multicast bit checks |
| **VLAN / MPLS** | `vlan`, `vlan 100`<br>`mpls`, `mpls 500` | Tag presence and ID/label extraction |
| **Protocol Numbers** | `ip proto 6`, `ip proto tcp`, `ether proto 0x0800` | Layer 3/4 protocol inspection |
| **Boolean Logic** | `tcp and port 80`<br>`tcp or udp`<br>`not port 22`<br>`(tcp or udp) and not dst port 53` | Short-circuit boolean combinations |

---

## Architecture & Pipeline

### The Classic BPF (cBPF) Virtual Machine

cBPF is a 32-bit register machine designed specifically for in-kernel packet filtering:

```
+----------------------------------------------------------------+
|                   cBPF Virtual Machine Registers               |
|                                                                |
|  [ Register A ] (32-bit Accumulator)                           |
|    - Holds results of packet loads, arithmetic, and tests      |
|                                                                |
|  [ Register X ] (32-bit Index Register)                        |
|    - Used for indexed packet addressing: packet[X + k]         |
|    - Second operand for ALU operations                         |
|                                                                |
|  [ Memory M[0..15] ] (16 Scratch Words)                        |
|    - Register spill space for complex nested expressions       |
|                                                                |
|  [ Program Counter (PC) ]                                      |
+----------------------------------------------------------------+
```

### Instruction Structure (`struct bpf_insn`)

Every instruction is exactly 8 bytes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          code (16)            |    jt (8)     |    jf (8)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            k (32)                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **`code`** (16 bits): Opcode encoding class, size modifier, and addressing mode/ALU operator.
- **`jt`** (8 bits): Jump-true relative offset (number of instructions to skip forward if comparison succeeds).
- **`jf`** (8 bits): Jump-false relative offset (number of instructions to skip forward if comparison fails).
- **`k`** (32 bits): Multi-purpose value (packet offset, immediate constant, or scratch index).

---

## Developer Deep-Dive: Stage 1 — Lexer (`Lexer.py`)

The `BpfLexer` turns a raw filter string into a list of typed `Token` tuples: `(type, value)`.

### Tokenizer Mechanics
- **Regex Ordering**: The tokenizer runs a single compiled regex with named groups. Specific tokens (such as MAC addresses and IPv6 with colons) take precedence over general words and symbols.
- **Normalization**: Operators like `&&`, `||`, and `!` are normalized directly into `and`, `or`, and `not`.
- **Named Constants**: TCP flags (`tcp-syn`, `tcp-ack`, `tcp-fin`) and ICMP types (`icmp-echo`, `icmp-echoreply`) are resolved directly into integer `NUMBER` tokens at lex time.

### Token Reference Table

| Token Type | Examples | Produced From |
|---|---|---|
| `NUMBER` | `'80'`, `'2048'`, `'2'` | Integer digits, hex (`0x0800`), named constants (`tcp-syn` $\rightarrow$ `2`) |
| `IPV4` | `'192.168.1.1'` | Standard dotted-quad IPv4 |
| `IPV4_CIDR` | `'10.0.0.0/8'` | Dotted-quad with prefix |
| `IPV6` | `'fe80::1'` | Colon-delimited hex address |
| `IPV6_CIDR` | `'2001:db8::/32'` | Colon-hex with prefix |
| `MAC` | `'aa:bb:cc:dd:ee:ff'` | 6 hex pairs with colons |
| `RANGE` | `'1000-2000'` | Port range syntax |
| `IP-PROTOCOL` | `'tcp'`, `'udp'`, `'icmp'`, `'gre'` | IP protocol names |
| `ETHERTYPE` | `'ip'`, `'ip6'`, `'arp'`, `'vlan'` | Link-layer protocol names |
| `KEYWORD` | `'host'`, `'port'`, `'net'`, `'src'`, `'dst'` | Filter keywords |
| `FIELD` | `'tcpflags'`, `'icmptype'` | Named protocol fields |
| `REL_OP` | `'=='`, `'!='`, `'>'`, `'>='`, `'<'`, `'<='` | Comparison operators |
| `MATH_OP` | `'+'`, `'-'`, `'*'`, `'/'`, `'%'`, `'&'`, `'\|'`, `'^'`, `'<<'`, `'>>'` | Arithmetic and bitwise operators |

---

## Developer Deep-Dive: Stage 2 — Parser (`Parser.py`)

The `BpfParser` implements a **recursive descent** parser that turns the token stream into an Abstract Syntax Tree (AST).

### Grammar & Operator Precedence

Precedence is enforced through tiered grammar methods (lowest to highest):

```
expr_or        := expr_and  ( 'or'  expr_and )*
expr_and       := expr_not  ( 'and' expr_not )*
expr_not       := 'not' expr_not | expr_primary
expr_primary   := '(' expr_or ')' | qualifier_rule | expr_relation
expr_relation  := expr_bitor ( REL_OP expr_bitor )?
expr_bitor     := expr_bitxor ( '|'  expr_bitxor )*
expr_bitxor    := expr_bitand ( '^'  expr_bitand )*
expr_bitand    := expr_shift  ( '&'  expr_shift )*
expr_shift     := expr_add    ( ('<<'|'>>') expr_add )*
expr_add       := expr_mult   ( ('+'|'-') expr_mult )*
expr_mult      := expr_atom   ( ('*'|'/'|'%') expr_atom )*
```

### Abstract Syntax Tree (AST) Reference

```python
# Boolean Operations
BinaryOpNode(left: ASTNode, op: str, right: ASTNode)
UnaryOpNode(op: str, expr: ASTNode)

# Protocols & Qualifiers
ProtocolNode(name: str, proto_num: Optional[int] = None)
KeywordFilterNode(
    keyword: str,
    value: Any = None,
    direction: Optional[str] = None,   # 'src' | 'dst' | 'src or dst' | 'src and dst'
    protocol: Optional[str] = None,    # 'tcp' | 'ip6' | 'ether' ...
    value_type: Optional[str] = None,  # 'ipv4' | 'ipv6' | 'mac' | 'cidr4' | 'cidr6' | 'number' | 'range' | 'name'
    mask: Optional[str] = None         # for 'net X mask Y'
)

# Packet Access & Values
ByteAccessNode(protocol: str, offset: ASTNode, size: int = 1)
LengthNode()                           # 'len' operand
NumberNode(value: int)
LiteralNode(value: str, kind: str)
FieldNode(name: str)                   # 'tcpflags', 'icmptype'
```

---

## Developer Deep-Dive: Stage 3 — Compiler (`Compiler.py`)

The `BpfCompiler` walks the AST and emits classic BPF instructions.

### Short-Circuit Boolean Control Flow

All boolean sub-expressions compile with two symbolic jump targets: `true_target` and `false_target`.

- **`A and B`**: `A` compiles with `true_target = label_B` and `false_target = overall_false`. If `A` passes, it falls into `B`. If `A` fails, it immediately jumps to `overall_false`.
- **`A or B`**: `A` compiles with `true_target = overall_true` and `false_target = label_B`. If `A` passes, it immediately short-circuits to `overall_true`.
- **`not A`**: Swaps the true and false branch targets of `A`.

### Relative Jump Resolution & Jump Threading

In cBPF, relative jump offsets specify how many instructions to skip **past the next instruction**:

$$\text{offset} = \text{target\_index} - (\text{current\_index} + 1)$$

Before computing final numeric offsets, the compiler executes **Jump Threading (Peephole Optimization)**:
If a jump target points to an unconditional jump (`ja target_2`), the compiler rewrites the jump to target `target_2` directly, eliminating wasted jump hops.

### Register Spilling via Scratch Memory (`M[0..15]`)

cBPF only has two general registers: Accumulator `A` and Index `X`. When compiling complex binary operations where both the left and right operands are expressions (e.g. `(ip[0] & 0xf) * 4 == (tcp[12] >> 4) * 4`):

1. Right operand compiles into Register `A`.
2. Emits `st M[scratch]` to store the right operand in scratch memory.
3. Left operand compiles into Register `A`.
4. Emits `ldx M[scratch]` to load the right operand into Register `X`.
5. Emits the ALU or comparison operation using Register `X` (`BPF_X`).

### Dynamic IPv4 IHL Tracking (`BPF_MSH`)

IPv4 headers can vary in length between 20 and 60 bytes due to optional fields. To locate transport-layer headers (TCP/UDP) reliably without hardcoding an offset:

```python
self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, 14))
```

The `BPF_MSH` opcode computes:
$$X = 4 \times (\text{packet}[14] \ \& \ \text{0x0F})$$
storing the exact byte length of the IPv4 header into Register `X`.
Subsequent transport-layer loads use indexed addressing (`BPF_IND`):
- Source Port: `ldh [x + 14]`
- Destination Port: `ldh [x + 16]`

### VLAN 802.1Q Handling

An 802.1Q tagged frame has the following layout:

```
Byte 12..13: TPID (0x8100)
Byte 14..15: TCI (Bits 15-13: Priority, Bit 12: DEI, Bits 11-0: 12-bit VLAN ID)
```

For `vlan 100`:
1. `ldh [12]` $\rightarrow$ Verify EtherType is `0x8100`.
2. `ldh [14]` $\rightarrow$ Load 16-bit TCI.
3. `and #0x0fff` $\rightarrow$ Mask out Priority and DEI to isolate the 12-bit VLAN ID.
4. `jeq #100` $\rightarrow$ Match target VLAN ID.

### Bitmask Optimization (`BPF_JSET`)

When testing specific bitflags (e.g. `tcp[13] & 2 != 0` or `tcp[tcpflags] & tcp-syn != 0`), the compiler optimizes this pattern into a single `BPF_JSET` jump instruction:

```
ldb [x + 27]             ; Load TCP flags byte
jset #2 jt ACCEPT jf REJECT
```

This tests `(A & 2) != 0` in a single hardware cycle.

---

## Worked Examples & Disassembly Traces

### Example 1: `tcp and port 80`

```python
insns = BpfCompiler.compile_str("tcp and port 80")
print(disassemble(insns))
```

```
(000) ldh [12]                  ; Load EtherType
(001) jeq #0x800 jt 2 jf 9      ; Is IPv4?
(002) ldb [23]                  ; Load IP Protocol byte
(003) jeq #6 jt 4 jf 9          ; Is TCP (6)?
(004) ldxb 4*([14]&0xf)         ; Load IPv4 Header Length into X
(005) ldh [x + 14]              ; Load TCP Source Port
(006) jeq #80 jt 8 jf 7         ; Is src port 80? (If yes, accept)
(007) ldh [x + 16]              ; Load TCP Destination Port
(008) jeq #80 jt 10 jf 9        ; Is dst port 80? (If yes, accept; else reject)
(009) ret #0                    ; REJECT (Return 0)
(010) ret #262144               ; ACCEPT (Return max buffer)
```

---

### Example 2: `tcp[13] & 2 != 0` (TCP SYN)

```python
insns = BpfCompiler.compile_str("tcp[13] & 2 != 0")
print(disassemble(insns))
```

```
(000) ldxb 4*([14]&0xf)         ; X = IPv4 IHL
(001) ldb [x + 27]              ; Load byte 13 of TCP (14 + 13 = 27)
(002) jset #2 jt 4 jf 3         ; Test bit 2 (SYN flag)
(003) ret #0                    ; REJECT
(004) ret #262144               ; ACCEPT
```

---

### Example 3: `host 192.168.1.1`

```python
insns = BpfCompiler.compile_str("host 192.168.1.1")
print(disassemble(insns))
```

```
(000) ldh [12]                  ; Load EtherType
(001) jeq #0x800 jt 2 jf 5      ; Is IPv4?
(002) ld [26]                   ; Load Source IP
(003) jeq #0xc0a80101 jt 6 jf 4 ; Matches 192.168.1.1?
(004) ld [30]                   ; Load Destination IP
(005) jeq #0xc0a80101 jt 6 jf 5 ; Matches 192.168.1.1?
(006) ret #0                    ; REJECT
(007) ret #262144               ; ACCEPT
```

---

### Example 4: `vlan 100`

```python
insns = BpfCompiler.compile_str("vlan 100")
print(disassemble(insns))
```

```
(000) ldh [12]                  ; Load EtherType
(001) jeq #0x8100 jt 2 jf 5     ; Is 802.1Q VLAN?
(002) ldh [14]                  ; Load TCI (Tag Control Information)
(003) and #0xfff                ; Mask out Priority & DEI to get 12-bit VID
(004) jeq #100 jt 6 jf 5        ; Is VID == 100?
(005) ret #0                    ; REJECT
(006) ret #262144               ; ACCEPT
```

---

### Example 5: `(ip[0] & 0xf) * 4 > 20`

Checks if the IPv4 packet contains IP Options (IHL > 20 bytes):

```python
insns = BpfCompiler.compile_str("(ip[0] & 0xf) * 4 > 20")
print(disassemble(insns))
```

```
(000) ldb [14]                  ; Load byte 0 of IP header
(001) and #15                   ; Mask lower 4 bits (IHL)
(002) mul #4                    ; Multiply by 4 (header length in bytes)
(003) jgt #20 jt 5 jf 4         ; Is header length > 20?
(004) ret #0                    ; REJECT
(005) ret #262144               ; ACCEPT
```

---

## Verification & Testing

The engine is validated through two test suites covering unit tests, emulation tests, and native C libpcap cross-verification:

```bash
pytest tests/test_bpf.py tests/test_lightbpf.py -v
```

### What is tested:
1. **Lexer & Parser**: Operator precedence, token classification, strict mode, syntax errors.
2. **Bytecode Compilation**: Opcode correctness, backpatching, jump offsets, and disassembly.
3. **Emulator Verification (`BpfEmulator`)**: Real packet matching and rejection across IPv4, IPv6, ARP, VLAN, and MPLS packets.
4. **Native C Libpcap Cross-Verification**: If `libpcap.so` is present on the host, tests execute each compiled filter through native C `bpf_filter()` to guarantee 100% bytecode compatibility with libpcap/tcpdump.

---

## Opcode & Constant Reference

### Instruction Classes (`code & 0x07`)
| Constant | Hex | Description |
|---|---|---|
| `BPF_LD` | `0x00` | Load into Register A |
| `BPF_LDX` | `0x01` | Load into Register X |
| `BPF_ST` | `0x02` | Store Register A into `M[k]` |
| `BPF_STX` | `0x03` | Store Register X into `M[k]` |
| `BPF_ALU` | `0x04` | Arithmetic or Bitwise operation on A |
| `BPF_JMP` | `0x05` | Jump operation |
| `BPF_RET` | `0x06` | Return from filter |
| `BPF_MISC` | `0x07` | Register transfer (`tax`, `txa`) |

### Addressing Modes (`code & 0xe0`)
| Constant | Hex | Description |
|---|---|---|
| `BPF_IMM` | `0x00` | Immediate constant `k` |
| `BPF_ABS` | `0x20` | Absolute packet byte offset `packet[k]` |
| `BPF_IND` | `0x40` | Indexed packet offset `packet[X + k]` |
| `BPF_MEM` | `0x60` | Scratch memory word `M[k]` |
| `BPF_LEN` | `0x80` | Packet length |
| `BPF_MSH` | `0xa0` | Load $4 \times (\text{packet}[k] \ \& \ \text{0x0F})$ into X |

### ALU Operations (`code & 0xf0`)
| Constant | Hex | Operation |
|---|---|---|
| `BPF_ADD` | `0x00` | `A = A + operand` |
| `BPF_SUB` | `0x10` | `A = A - operand` |
| `BPF_MUL` | `0x20` | `A = A * operand` |
| `BPF_DIV` | `0x30` | `A = A / operand` |
| `BPF_OR` | `0x40` | `A = A \| operand` |
| `BPF_AND` | `0x50` | `A = A & operand` |
| `BPF_LSH` | `0x60` | `A = A << operand` |
| `BPF_RSH` | `0x70` | `A = A >> operand` |
| `BPF_NEG` | `0x80` | `A = -A` |
| `BPF_MOD` | `0x90` | `A = A % operand` |
| `BPF_XOR` | `0xa0` | `A = A ^ operand` |

### Jump Operations (`code & 0xf0`)
| Constant | Hex | Jump Condition |
|---|---|---|
| `BPF_JA` | `0x00` | Unconditional jump |
| `BPF_JEQ` | `0x10` | Jump if `A == operand` |
| `BPF_JGT` | `0x20` | Jump if `A > operand` |
| `BPF_JGE` | `0x30` | Jump if `A >= operand` |
| `BPF_JSET` | `0x40` | Jump if `(A & operand) != 0` |
