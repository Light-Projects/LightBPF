# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Classic BPF (cBPF) bytecode compiler.

Translates the AST produced by ``LightBPF.Parser`` into cBPF instructions
compatible with libpcap / tcpdump.

Pipeline (compile_str):
    text   --Lexer-->   tokens
    tokens' --Parser-->  AST
    AST    --BpfCompiler-->  instructions (with symbolic labels)
    instructions --assemble/backpatch-->  numeric instructions
    numeric instructions --Peephole.optimize-->  final program

The false-target threading invariant:

    Every byte-access instruction (`tcp[13]`, `ip[0]`, ...) is compiled
    inside a boolean context that supplies a symbolic `false_target`.
    On any protocol mismatch (EtherType wrong, transport proto wrong,
    non-first fragment for transport), control jumps directly to that
    `false_target` — never to a fabricated value. This keeps the guard's
    mismatch path indistinguishable from any other "this predicate failed"
    path, so all callers behave correctly without special-casing.
"""
import socket
import ipaddress
import struct
from typing import List, Optional, Tuple, Dict, Any, Union

from LightPacket.LightBPF.CompilerSet.Instruction import Instruction
from LightPacket.LightBPF.CompilerSet.Opcode import (
    BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC,
    BPF_W, BPF_H, BPF_B,
    BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH,
    BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH,
    BPF_TAX, BPF_MOD, BPF_XOR,
    BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
    BPF_K, BPF_X, BPF_MAX_BUF_LEN,
)
from LightPacket.LightBPF.CompilerSet import Peephole
from LightPacket.LightBPF.CompilerSet import Shortcut
try:
    from LightPacket.LightBPF.Lexer import BpfLexer
    from LightPacket.LightBPF.Parser import (
        BpfParser, ASTNode, BinaryOpNode, UnaryOpNode, ProtocolNode,
        KeywordFilterNode, ByteAccessNode, LengthNode, NumberNode,
        LiteralNode, FieldNode,
    )
    from LightPacket.LightBPF.Ethertype import ETHERTYPE_KEYWORDS
except ImportError:
    from LightBPF.Lexer import BpfLexer          # type: ignore
    from LightBPF.Parser import (                 # type: ignore
        BpfParser, ASTNode, BinaryOpNode, UnaryOpNode, ProtocolNode,
        KeywordFilterNode, ByteAccessNode, LengthNode, NumberNode,
        LiteralNode, FieldNode,
    )
    #from LightBPF.Ethertype import ETHERTYPE_KEYWORDS


# ----------------------------------------------------------------------
# Lookup tables
# ----------------------------------------------------------------------
ETHERTYPE_MAP = ETHERTYPE_KEYWORDS

COMMON_SERVICES: Dict[str, int] = {
    "echo": 7, "discard": 9, "ftp-data": 20, "ftp": 21, "ssh": 22,
    "telnet": 23, "smtp": 25, "time": 37, "nameserver": 42, "nicname": 43,
    "domain": 53, "dns": 53, "bootps": 67, "bootpc": 68, "tftp": 69,
    "gopher": 70, "finger": 79, "http": 80, "www": 80, "kerberos": 88,
    "pop2": 109, "pop3": 110, "sunrpc": 111, "auth": 113, "sftp": 115,
    "nntp": 119, "ntp": 123, "netbios-ns": 137, "netbios-dgm": 138,
    "netbios-ssn": 139, "imap": 143, "snmp": 161, "snmptrap": 162,
    "bgp": 179, "ldap": 389, "https": 443, "microsoft-ds": 445,
    "ldaps": 636, "rsync": 873, "imaps": 993, "pop3s": 995,
    "openvpn": 1194, "mysql": 3306, "rdp": 3389, "postgresql": 5432,
    "http-alt": 8080, "squid": 3128,
}

FIELD_OFFSETS: Dict[str, Tuple[int, int]] = {
    "tcpflags":  (13, 1),
    "icmptype":  (0, 1),
    "icmpcode":  (1, 1),
    "icmp6type": (0, 1),
    "icmp6code": (1, 1),
}

_TRANSPORT_PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "sctp": 132, "icmp6": 58,"igmp": 2}
_IPV4_ONLY_TRANSPORT = {"icmp","igmp"}
_IPV6_ONLY_TRANSPORT = {"icmp6"}


# ----------------------------------------------------------------------
class BpfCompiler:
    """Classic BPF bytecode compiler."""

    def __init__(self, linktype: int = 1):
        self.instructions: List[Union[Instruction, str]] = []
        self._label_counter = 0
        self._scratch_counter = 0
        self._parsed_upper = False
        self.EXPLICIT = None
        self.sip = False
        self.E_P_OFFSET = 12
        self.linktype = linktype

        self.n40_or_20 = 0

        self.VLAN_ID_OFF = 14

        self.IPv4_PROTO_OFF = 23
        self.IPv6_PROTO_OFF = 20

        self.PORT_FIELD_SRC = 14
        self.PORT_FIELD_DST = 16

        self.IPv4_H_ST = 14
        self.IPv6_H_ST = 20

        self.IPv4_FRAG = 20

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def compile(self, ast_root: ASTNode, optimize: bool = True, linktype: int = 1) -> List[Instruction]:
        self.instructions = []
        self._label_counter = 0
        self._scratch_counter = 0
        self.linktype = linktype
        self._compile_bool(ast_root, "ACCEPT", "REJECT")
        code = self._assemble_and_backpatch("ACCEPT", "REJECT")
        if optimize:
            code = Peephole.optimize(code)
        return code

    @classmethod
    def compile_str(cls, filter_string: str, optimize: bool = True) -> List[Instruction]:
        filter = Shortcut.str_shortcut(filter_string)
        tokens = BpfLexer(filter).tokenize()
        ast = BpfParser(tokens).parse()
        return cls().compile(ast, optimize=optimize)

    @staticmethod
    def to_bytes(instructions: List[Instruction]) -> bytes:
        return b"".join(i.to_bytes() for i in instructions)

    # ------------------------------------------------------------------
    # Label / scratch helpers
    # ------------------------------------------------------------------
    def _new_label(self, prefix: str = "L") -> str:
        self._label_counter += 1
        return f"{prefix}_{self._label_counter}"

    def _emit(self, instr: Instruction) -> None:
        self.instructions.append(instr)

    def _emit_label(self, name: str) -> None:
        self.instructions.append(f"LABEL:{name}")

    def _alloc_scratch(self) -> int:
        idx = self._scratch_counter
        self._scratch_counter += 1
        if idx >= 16:
            raise RuntimeError("Exceeded maximum BPF scratch memory registers (16)")
        return idx

    def _free_scratch(self) -> None:
        if self._scratch_counter > 0:
            self._scratch_counter -= 1

    # ------------------------------------------------------------------
    # Boolean expressions
    # ------------------------------------------------------------------
    def _compile_bool(self, node: ASTNode, true_target: str, false_target: str) -> None:
        if isinstance(node, BinaryOpNode):
            if node.op == "and":
                nxt = self._new_label("and")
                self._compile_bool(node.left, nxt, false_target)
                self._emit_label(nxt)
                self._compile_bool(node.right, true_target, false_target)
            elif node.op == "or":
                nxt = self._new_label("or")
                self._compile_bool(node.left, true_target, nxt)
                self._emit_label(nxt)
                self._compile_bool(node.right, true_target, false_target)
            elif node.op in ("==", "!=", ">", ">=", "<", "<="):
                self._compile_comparison(node, true_target, false_target)
            elif node.op == "&":
                self._compile_bitwise_bool(node, true_target, false_target)
            else:
                self._compile_value(node, false_target)
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                                       false_target, true_target, 0))
            return

        if isinstance(node, UnaryOpNode) and node.op == "not":
            self._compile_bool(node.expr, false_target, true_target)
            return

        if isinstance(node, ProtocolNode):
            self._compile_protocol(node, true_target, false_target)
            return

        if isinstance(node, KeywordFilterNode):
            self._compile_keyword(node, true_target, false_target)
            return

        if isinstance(node, ByteAccessNode):
            self._compile_value(node, false_target)
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                                   false_target, true_target, 0))
            return

        if isinstance(node, FieldNode):
            raise NotImplementedError(
                f"Standalone pseudo-field '{node.name}' is not valid; "
                f"use it inside a byte access, e.g. tcp[{node.name}]"
            )

        if isinstance(node, (NumberNode, LengthNode)):
            self._compile_value(node)
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                                   false_target, true_target, 0))
            return

        raise NotImplementedError(f"Unsupported boolean AST node: {type(node).__name__}")

    def _compile_bitwise_bool(self, node: BinaryOpNode,
                              true_target: str, false_target: str) -> None:
        if isinstance(node.right, NumberNode):
            self._compile_value(node.left, false_target)
            self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K,
                                   true_target, false_target, node.right.value))
        else:
            scratch = self._alloc_scratch()
            self._compile_value(node.right, false_target)
            self._emit(Instruction(BPF_ST, 0, 0, scratch))
            self._compile_value(node.left, false_target)
            self._emit(Instruction(BPF_LDX | BPF_MEM, 0, 0, scratch))
            self._free_scratch()
            self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_X,
                                   true_target, false_target, 0))

    def _compile_comparison(self, node: BinaryOpNode,
                            true_target: str, false_target: str) -> None:
        # Constant division-by-zero is rejected inside _compile_arithmetic
        # when it recurses into the offending subtree; no guard is needed here.

        # Idiomatic bitmask test: (expr & mask) != 0 / == 0 / > / >=
        if (isinstance(node.left, BinaryOpNode) and node.left.op == "&"
                and isinstance(node.right, NumberNode) and node.right.value == 0
                and isinstance(node.left.right, NumberNode)):
            mask = node.left.right.value
            self._compile_value(node.left.left, false_target)
            if node.op in ("!=", ">"):
                self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K,
                                       true_target, false_target, mask))
            elif node.op == "==":
                self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K,
                                       false_target, true_target, mask))
            elif node.op == ">=":
                self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))
            return

        if isinstance(node.right, NumberNode):
            self._compile_value(node.left, false_target)
            val = node.right.value
            if node.op == "==":
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, val))
            elif node.op == "!=":
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, false_target, true_target, val))
            elif node.op == ">":
                self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_K, true_target, false_target, val))
            elif node.op == ">=":
                self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_K, true_target, false_target, val))
            elif node.op == "<":
                self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_K, false_target, true_target, val))
            elif node.op == "<=":
                self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_K, false_target, true_target, val))
        else:
            scratch = self._alloc_scratch()
            self._compile_value(node.right, false_target)
            self._emit(Instruction(BPF_ST, 0, 0, scratch))
            self._compile_value(node.left, false_target)
            self._emit(Instruction(BPF_LDX | BPF_MEM, 0, 0, scratch))
            self._free_scratch()
            if node.op == "==":
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_X, true_target, false_target, 0))
            elif node.op == "!=":
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_X, false_target, true_target, 0))
            elif node.op == ">":
                self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_X, true_target, false_target, 0))
            elif node.op == ">=":
                self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_X, true_target, false_target, 0))
            elif node.op == "<":
                self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_X, false_target, true_target, 0))
            elif node.op == "<=":
                self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_X, false_target, true_target, 0))

    # ------------------------------------------------------------------
    # Protocol checks
    # ------------------------------------------------------------------
    def _compile_protocol(self, node: ProtocolNode,
                          true_target: str, false_target: str) -> None:
        name = node.name.lower()
        if self.linktype == 1:
            if name in ("ether", "link"):
                self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))
                return

            if name in ETHERTYPE_MAP.keys():
                ethertype = ETHERTYPE_MAP.get(name, 0x0800)
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ethertype))

                if ethertype in (0x0800, 0x86DD):
                    self.EXPLICIT = ethertype
                    self.sip = True
                self._parsed_upper = True
                return

            if name == "vlan":
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                ok = self._new_label("vlan_ok")
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, ok, 0x8100))
                self._emit_label(ok)
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 0x88a8))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 0x9100))
                return

            if name == "mpls":
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                ok = self._new_label("mpls_ok")
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, ok, 0x8847))
                self._emit_label(ok)
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 0x8848))
                return

            if name in BpfLexer.IP_PROTOCOLS:
                proto_num = BpfLexer.IP_PROTOCOLS[name]
            elif node.proto_num is not None:
                proto_num = node.proto_num
            else:
                raise NotImplementedError(f"Unsupported protocol: '{name}'")

            if name == "icmp":
                if self.sip == False:
                    check = self._new_label("ip4")
                    self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check, false_target, 0x0800))
                    self._emit_label(check)
                self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv4_PROTO_OFF))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 1))
                return

            if name == "icmp6":
                if self.sip == False:
                    check = self._new_label("ip6")
                    self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check, false_target, 0x86DD))
                    self._emit_label(check)
                self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 20))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 58))
                return

            if self.EXPLICIT == 0x0800:
                self._compile_transport_ipv4(proto_num, true_target, false_target)
            elif self.EXPLICIT == 0x86DD:
                self._compile_transport_ipv6(proto_num, true_target, false_target)
            else:
                self._compile_dual_stack_transport(proto_num, true_target, false_target,
                                                   with_x_offset=False)
        else:
            raise NotImplementedError(f"Unsupported linktype: '{self.linktype}'")

    def _compile_transport_ipv4(self, proto_num, true_target, false_target,
                                with_x_offset=False):
        """IPv4-only transport protocol check.

        Verifies EtherType == 0x0800 and IP protocol == proto_num.
        On the port path (with_x_offset=True) also rejects non-first
        IPv4 fragments before loading X.

        with_x_offset=False: jumps to true_target on match (standalone
                             protocol check, e.g. filter "tcp").
        with_x_offset=True:  loads X with the transport-header offset
                             (IHL via BPF_MSH) and falls through to the
                             caller's next instruction.
        """

        after_ether = self._new_label("ip4_after_ether")

        #self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12))
        #self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, after_ether, false_target, 0x0800))
        self._emit_label(after_ether)

        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv4_PROTO_OFF))

        if not with_x_offset:
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                                   true_target, false_target, proto_num))
            return

        after_proto = self._new_label("ip4_after_proto")
        first_frag = self._new_label("ip4_first_frag")

        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                               after_proto, false_target, proto_num))
        self._emit_label(after_proto)
        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.IPv4_FRAG))
        self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K,
                               false_target, first_frag, 0x1FFF))
        self._emit_label(first_frag)
        self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.PORT_FIELD_SRC))

    def _compile_transport_ipv6(self, proto_num, true_target, false_target,
                                with_x_offset=False):
        """IPv6-only transport protocol check.

        Verifies EtherType == 0x86DD and next-header == proto_num, with a
        fragment-header traversal for the Fragment extension header (44).

        with_x_offset=False: jumps to true_target on match.
        with_x_offset=True:  loads X = 40 (fixed IPv6 header length) and
                             falls through to the caller's next instruction.
        """
        after_ether = self._new_label("ip6_after_ether")
        frag_check = self._new_label("ip6_frag_check")
        frag_ok = self._new_label("ip6_frag_ok")

        if with_x_offset:
            match_target = self._new_label("ip6_after_nh")
        else:
            match_target = true_target

        #self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, 12))
        #self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, after_ether, false_target, 0x86DD))
        self._emit_label(after_ether)
        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv6_PROTO_OFF))

        # Direct next-header match, or fall through to fragment-header path.
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                               match_target, frag_check, proto_num))
        self._emit_label(frag_check)
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, frag_ok, false_target, 44))
        self._emit_label(frag_ok)
        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 54))
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K,
                               match_target, false_target, proto_num))

        if with_x_offset:
            self._emit_label(match_target)
            self._emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, 40))


    def _compile_dual_stack_transport(self, proto_num: int,
                                      true_target: str, false_target: str,
                                      with_x_offset: bool) -> None:
        """Shared IPv4/IPv6 protocol check.

        If `with_x_offset` is True, on a successful match the code sets
        X to the byte offset of the transport header (IHL for IPv4, 40
        for IPv6) and falls through to `transport_ready`; used by port
        filters and byte access. If False, on a successful match the
        code jumps straight to `true_target`; used by standalone protocol
        checks (e.g. filter "tcp").
        """

        self.sip = True

        ip4_ok = self._new_label("ip4_ok")
        ip6_ok = self._new_label("ip6_ok")
        check_ip4 = self._new_label("ip4_chk")
        check_ip6 = self._new_label("ip6_chk")
        transport_ready = self._new_label("transport_ready") if with_x_offset else None

        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check_ip4, check_ip6, 0x0800))

        # ---- IPv4 ----
        self._emit_label(check_ip4)
        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv4_PROTO_OFF))
        ip4_match = ip4_ok if with_x_offset else true_target
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, proto_num))
        first_frag = self._new_label("ip4_first_frag")


        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.IPv4_FRAG))
        self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K,
                               false_target, first_frag, 0x1FFF))
        self._emit_label(first_frag)
        self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.PORT_FIELD_SRC))

        #if with_x_offset:
        #    self._emit_label(ip4_ok)
        #    first_frag = self._new_label("ip4_frag_ok")
        #    self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.IPv4_FRAG))
        #    self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K,
        #                           false_target, first_frag, 0x1FFF))
        #    self._emit_label(first_frag)
        #    self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.PORT_FIELD_SRC))
        #    self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, transport_ready))

        self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, ip4_match))


        # ---- IPv6 ----
        self._emit_label(check_ip6)
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x86DD))
        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv6_PROTO_OFF))
        # Direct match
        #ip6_match = ip6_ok if with_x_offset else true_target
        #check_frag = self._new_label("ip6_frag_chk")
        load = self._new_label("load")
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, load, false_target, proto_num))
        # Fragment-header chain
        #self._emit_label(check_frag)
        #frag_ok = self._new_label("ip6_frag_ok")
        #self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, frag_ok, false_target, 44))
        #self._emit_label(frag_ok)
        self._emit_label(load)
        self._emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, 40))


        #self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 54))
        #self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_match, false_target, proto_num))
        #if with_x_offset:
        #    self._emit_label(ip6_ok)
        #    self._emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, 40))
        #    self._emit_label(transport_ready)

    # ------------------------------------------------------------------
    # Keyword filters
    # ------------------------------------------------------------------
    def _compile_keyword(self, node: KeywordFilterNode,
                         true_target: str, false_target: str) -> None:
        kw = node.keyword
        if kw == "host":
            self._compile_host_filter(node, true_target, false_target)
        elif kw == "net":
            self._compile_net_filter(node, true_target, false_target)
        elif kw == "port":
            self._compile_port_filter(node, true_target, false_target)
        elif kw == "portrange":
            self._compile_portrange_filter(node, true_target, false_target)
        elif kw in ("less", "greater"):
            self._compile_length_filter(node, true_target, false_target)
        elif kw == "broadcast":
            self._compile_broadcast_filter(true_target, false_target)
        elif kw == "multicast":
            self._compile_multicast_filter(true_target, false_target)
        elif kw in ("proto", "protochain"):
            self._compile_proto_filter(node, true_target, false_target)
        elif kw == "vlan":
            self._compile_vlan_filter(node, true_target, false_target)
        elif kw == "mpls":
            self._compile_mpls_filter(node, true_target, false_target)
        elif kw in ("inbound", "outbound"):
            raise NotImplementedError(
                f"'{kw}' requires socket metadata and cannot be compiled to cBPF"
            )
        elif kw == "gateway":
            raise NotImplementedError(
                "'gateway' is not supported: it requires the host's MAC address, "
                "which is not resolvable at filter-compile time"
            )
        else:
            raise NotImplementedError(f"Unsupported keyword filter: '{kw}'")

    # --- host ---
    def _compile_host_filter(self, node: KeywordFilterNode,
                             true_target: str, false_target: str) -> None:
        vtype = node.value_type
        direction = node.direction

        if vtype == "ipv4":
            ip_int = struct.unpack("!I", socket.inet_aton(node.value))[0]
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x0800))
            if direction == "src":
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 26))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))
            elif direction == "dst":
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 30))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))
            elif direction == "src and dst":
                chk = self._new_label("chk_dst")
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 26))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, ip_int))
                self._emit_label(chk)
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 30))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))
            else:
                chk = self._new_label("chk_dst")
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 26))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, chk, ip_int))
                self._emit_label(chk)
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 30))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))

        elif vtype == "ipv6":
            words = struct.unpack("!IIII", ipaddress.IPv6Address(node.value).packed)
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x86DD))

            def match(base_off, m_true, m_false):
                w0 = self._new_label("w0")
                w1 = self._new_label("w1")
                w2 = self._new_label("w2")
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, w0, m_false, words[0]))
                self._emit_label(w0)
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + 4))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, w1, m_false, words[1]))
                self._emit_label(w1)
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + 8))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, w2, m_false, words[2]))
                self._emit_label(w2)
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + 12))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, m_true, m_false, words[3]))

            if direction == "src":
                match(22, true_target, false_target)
            elif direction == "dst":
                match(38, true_target, false_target)
            elif direction == "src and dst":
                chk = self._new_label("chk_dst")
                match(22, chk, false_target)
                self._emit_label(chk)
                match(38, true_target, false_target)
            else:
                chk = self._new_label("chk_dst")
                match(22, true_target, chk)
                self._emit_label(chk)
                match(38, true_target, false_target)

        elif vtype == "mac":
            mac_bytes = bytes.fromhex(node.value.replace(":", "").replace("-", ""))
            w0 = struct.unpack("!I", mac_bytes[:4])[0]
            h1 = struct.unpack("!H", mac_bytes[4:6])[0]

            def match(base_off, m_true, m_false):
                p1 = self._new_label("mac1")
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, p1, m_false, w0))
                self._emit_label(p1)
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, base_off + 4))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, m_true, m_false, h1))

            if direction == "src":
                match(6, true_target, false_target)
            elif direction == "dst":
                match(0, true_target, false_target)
            elif direction == "src and dst":
                chk = self._new_label("chk_src")
                match(0, chk, false_target)
                self._emit_label(chk)
                match(6, true_target, false_target)
            else:
                chk = self._new_label("chk_src")
                match(0, true_target, chk)
                self._emit_label(chk)
                match(6, true_target, false_target)

        elif vtype == "name":
            try:
                resolved = socket.gethostbyname(node.value)
            except OSError:
                raise ValueError(f"Could not resolve host name: '{node.value}'")
            clone = KeywordFilterNode(
                keyword=node.keyword, value=resolved,
                direction=node.direction, protocol=node.protocol,
                value_type="ipv4", mask=node.mask,
            )
            self._compile_host_filter(clone, true_target, false_target)
        else:
            raise NotImplementedError(f"Unsupported host value type: '{vtype}'")

    # --- net ---
    def _compile_net_filter(self, node: KeywordFilterNode,
                            true_target: str, false_target: str) -> None:
        direction = node.direction

        if node.value_type in ("cidr4", "ipv4") or node.mask is not None:
            if node.mask:
                net = ipaddress.IPv4Network(f"{node.value}/{node.mask}", strict=False)
            elif "/" in str(node.value):
                net = ipaddress.IPv4Network(node.value, strict=False)
            else:
                parts = str(node.value).split(".")
                if len(parts) == 4:
                    first = int(parts[0])
                    prefix = 8 if first < 128 else 16 if first < 192 else 24 if first < 224 else 32
                else:
                    prefix = len(parts) * 8
                padded = parts + ["0"] * (4 - len(parts))
                net = ipaddress.IPv4Network(f"{'.'.join(padded)}/{prefix}", strict=False)

            net_int = int(net.network_address)
            mask_int = int(net.netmask)

            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x0800))

            def match(offset, m_true, m_false):
                self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset))
                if mask_int != 0xFFFFFFFF:
                    self._emit(Instruction(BPF_ALU | BPF_AND | BPF_K, 0, 0, mask_int))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, m_true, m_false, net_int))

            if direction == "src":
                match(26, true_target, false_target)
            elif direction == "dst":
                match(30, true_target, false_target)
            elif direction == "src and dst":
                chk = self._new_label("chk_dst")
                match(26, chk, false_target)
                self._emit_label(chk)
                match(30, true_target, false_target)
            else:
                chk = self._new_label("chk_dst")
                match(26, true_target, chk)
                self._emit_label(chk)
                match(30, true_target, false_target)

        elif node.value_type == "cidr6":
            net6 = ipaddress.IPv6Network(node.value, strict=False)
            net_words = struct.unpack("!IIII", net6.network_address.packed)
            mask_words = struct.unpack("!IIII", net6.netmask.packed)

            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x86DD))

            def match(base_off, m_true, m_false):
                labels = [self._new_label(f"net6_w{i}") for i in range(3)]
                for i in range(4):
                    nxt = labels[i] if i < 3 else m_true
                    nw, mw = net_words[i], mask_words[i]
                    if mw == 0:
                        self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, nxt))
                    else:
                        self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + i * 4))
                        if mw != 0xFFFFFFFF:
                            self._emit(Instruction(BPF_ALU | BPF_AND | BPF_K, 0, 0, mw))
                        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, nxt, m_false, nw))
                    if i < 3:
                        self._emit_label(labels[i])

            if direction == "src":
                match(22, true_target, false_target)
            elif direction == "dst":
                match(38, true_target, false_target)
            elif direction == "src and dst":
                chk = self._new_label("chk_dst")
                match(22, chk, false_target)
                self._emit_label(chk)
                match(38, true_target, false_target)
            else:
                chk = self._new_label("chk_dst")
                match(22, true_target, chk)
                self._emit_label(chk)
                match(38, true_target, false_target)
        else:
            raise NotImplementedError(f"Unsupported net type: '{node.value_type}'")

    # --- port / portrange ---
    def _resolve_port(self, val: Any) -> int:
        if isinstance(val, int):
            return val
        s = str(val).lower()
        if s.isdigit():
            return int(s)
        if s in COMMON_SERVICES:
            return COMMON_SERVICES[s]
        try:
            return socket.getservbyname(s)
        except OSError:
            raise ValueError(f"Unknown service or port: '{val}'")

    def _compile_port_filter(self, node: KeywordFilterNode,
                             true_target: str, false_target: str) -> None:
        port_num = self._resolve_port(node.value)
        direction = node.direction
        proto = node.protocol.lower() if node.protocol else None

        if self.sip == False:
            self._setup_transport_layer(proto, false_target)

        if direction == "src":
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.PORT_FIELD_SRC))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))
        elif direction == "dst":
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.PORT_FIELD_DST))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))
        elif direction == "src and dst":
            chk = self._new_label("chk_dst")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.PORT_FIELD_SRC))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, port_num))
            self._emit_label(chk)
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.PORT_FIELD_DST))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))
        else:
            chk = self._new_label("chk_dst")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.PORT_FIELD_SRC))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, chk, port_num))
            self._emit_label(chk)
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.PORT_FIELD_DST))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))

    def _compile_portrange_filter(self, node: KeywordFilterNode,
                                  true_target: str, false_target: str) -> None:
        lo, hi = int(node.value[0]), int(node.value[1])
        direction = node.direction
        proto = node.protocol.lower() if node.protocol else None

        self._setup_transport_layer(proto, false_target)

        def check(offset, m_true, m_false):
            chk_hi = self._new_label("chk_hi")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, offset))
            self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_K, chk_hi, m_false, lo))
            self._emit_label(chk_hi)
            self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_K, m_false, m_true, hi))

        if direction == "src":
            check(self.PORT_FIELD_SRC, true_target, false_target)
        elif direction == "dst":
            check(self.PORT_FIELD_DST, true_target, false_target)
        elif direction == "src and dst":
            chk = self._new_label("chk_dst")
            check(self.PORT_FIELD_SRC, chk, false_target)
            self._emit_label(chk)
            check(self.PORT_FIELD_DST, true_target, false_target)
        else:
            chk = self._new_label("chk_dst")
            check(self.PORT_FIELD_SRC, true_target, chk)
            self._emit_label(chk)
            check(self.PORT_FIELD_DST, true_target, false_target)

    # --- transport setup (used by port / portrange / byte access) ---
    def _setup_transport_layer(self, proto: Optional[str], false_target: str) -> None:
        if proto in _IPV6_ONLY_TRANSPORT:
            num = _TRANSPORT_PROTO_NUM[proto]
            chk = self._new_label("is_ip6")
            ok = self._new_label("ip6_ok")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, 0x86DD))
            self._emit_label(chk)
            self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv6_H_ST))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, num))
            self._emit_label(ok)
            self._emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, 40))
            return

        if proto in _IPV4_ONLY_TRANSPORT:
            num = _TRANSPORT_PROTO_NUM[proto]
            chk = self._new_label("is_ip4")
            ok = self._new_label("ip4_ok")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, 0x0800))
            self._emit_label(chk)
            self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, false_target, self.IPv4_PROTO_OFF))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, num))
            self._emit_label(ok)


            first_frag = self._new_label("first_frag")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.IPv4_FRAG))
            self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, 0x1FFF))
            self._emit_label(first_frag)
            self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.IPv4_H_ST))

            return

        num = _TRANSPORT_PROTO_NUM.get(proto) if proto else None

        ip4_ok = self._new_label("ip4_ok")
        ip6_ok = self._new_label("ip6_ok")
        transport_ready = self._new_label("transport_ready")
        check_ip6 = self._new_label("chk_ip6")
        check_ip4 = self._new_label("chk_ip4")

        if self.EXPLICIT not in (None, 0x0800, 0x86DD):
            # Non-IP ethertype asserted earlier — the upper layers can't match.
            self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, false_target))
            return


        if self._parsed_upper == False:
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))

        if self.EXPLICIT is None or self.EXPLICIT == 0x0800:

            if self._parsed_upper == False:
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check_ip4, check_ip6, 0x0800))

            # ---- IPv4 ----
            self._emit_label(check_ip4)
            if num is not None:
                self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv4_PROTO_OFF))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, false_target, num))
            else:
                if self._parsed_upper == False:
                    is_udp = self._new_label("is_udp4")
                    self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv4_PROTO_OFF))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, is_udp, 6))
                    self._emit_label(is_udp)
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, false_target, 17))
            self._emit_label(ip4_ok)
            first_frag = self._new_label("first_frag")
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.IPv4_FRAG))
            self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, 0x1FFF))
            self._emit_label(first_frag)
            self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.IPv4_H_ST))
            self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, transport_ready))

        if self.EXPLICIT is None or self.EXPLICIT == 0x86DD:
            # ---- IPv6 ----

            self._emit_label(check_ip6)

            if self._parsed_upper == False:
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x86DD))


            if num is not None:
                self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv6_H_ST))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, false_target, num))
            else:
                if self._parsed_upper == False:
                    is_udp6 = self._new_label("is_udp6")
                    self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv6_H_ST))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, is_udp6, 6))
                    self._emit_label(is_udp6)
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, false_target, 17))

            self._emit_label(ip6_ok)
            self._emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, 40))

        self._emit_label(transport_ready)
        self.sip = True

    # --- length / broadcast / multicast ---
    def _compile_length_filter(self, node: KeywordFilterNode,
                               true_target: str, false_target: str) -> None:
        val = int(node.value)
        self._emit(Instruction(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0))
        if node.keyword == "less":
            self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_K, false_target, true_target, val))
        else:
            self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_K, true_target, false_target, val))

    def _compile_broadcast_filter(self, true_target: str, false_target: str) -> None:
        part = self._new_label("bcast1")
        self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0))
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, part, false_target, 0xFFFFFFFF))
        self._emit_label(part)
        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, 4))
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 0xFFFF))

    def _compile_multicast_filter(self, true_target: str, false_target: str) -> None:
        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 0))
        self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, true_target, false_target, 0x01))

    # --- vlan / mpls ---
    def _compile_vlan_filter(self, node: KeywordFilterNode,
                             true_target: str, false_target: str) -> None:
        ok = self._new_label("vlan_ok")
        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
        self.E_P_OFFSET += 4
        self.IPv4_FRAG += 4
        self.IPv4_PROTO_OFF += 4
        self.IPv4_H_ST += 4
        self.IPv6_H_ST += 4
        self.IPv6_PROTO_OFF += 4
        self.PORT_FIELD_SRC += 4
        self.PORT_FIELD_DST += 4
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, 0, 0x8100))
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, 0, 0x88a8))
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, 0x9100))
        self._emit_label(ok)
        if node.value is not None:
            vid = int(node.value)
            self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.VLAN_ID_OFF))
            self._emit(Instruction(BPF_ALU | BPF_AND | BPF_K, 0, 0, 0x0FFF))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, vid))
        else:
            self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))
        self.VLAN_ID_OFF += 4

    def _compile_mpls_filter(self, node: KeywordFilterNode,
                             true_target: str, false_target: str) -> None:
        ok = self._new_label("mpls_ok")
        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
        self.E_P_OFFSET += 4
        self.IPv4_FRAG += 4
        self.IPv4_PROTO_OFF += 4
        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, 0x8847))
        #self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, 0x8848))
        self._emit_label(ok)
        if node.value is not None:
            label = int(node.value)
            self._emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, 14))
            self._emit(Instruction(BPF_ALU | BPF_RSH | BPF_K, 0, 0, 12))
            self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, label))
        else:
            self._emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))

    # --- proto ---
    def _compile_proto_filter(self, node: KeywordFilterNode,
                              true_target: str, false_target: str) -> None:
        val = node.value
        num: Optional[int] = None
        if isinstance(val, str):
            lv = val.lower()
            if self.linktype == 1:
                if lv in ETHERTYPE_MAP:
                    num = ETHERTYPE_MAP[lv]
                else:
                    try:
                        num = int(lv, 0)
                    except ValueError:
                        num = None
                self._parsed_upper = True
                if num in (0x0800, 0x86DD):
                    self.EXPLICIT = num
        elif isinstance(val, int):
            if self.linktype == 1:
                num = val
                self._parsed_upper = True
                if num in (0x0800, 0x86DD):
                    self.EXPLICIT = num
        if num is None:
            raise ValueError(f"Cannot resolve protocol '{val}'")

        link = (node.protocol or "").lower()
        if self.linktype == 1:
            if link in ("ether", "link"):
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))
            elif link in ("ip6", "ipv6"):
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x86DD))
                if node.protocol is not None:
                    self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 20))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))
            else:
                popo = node.value
                if popo in ("ip6", "ipv6"):
                    self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x86DD))
                    if node.protocol is not None:
                        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 20))
                        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))
                elif popo in ETHERTYPE_MAP.keys():
                    self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_MAP.get(popo)))
                else:
                    self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                    self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, 0x0800))
                    if node.protocol is not None:
                        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, 23))
                        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))

    # ------------------------------------------------------------------
    # Value expressions
    # ------------------------------------------------------------------
    def _compile_value(self, node: ASTNode, false_target: Optional[str] = None) -> None:
        if isinstance(node, NumberNode):
            self._emit(Instruction(BPF_LD | BPF_IMM, 0, 0, node.value))
        elif isinstance(node, LengthNode):
            self._emit(Instruction(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0))
        elif isinstance(node, FieldNode):
            raise NotImplementedError(
                f"Field '{node.name}' can only be used inside a byte access "
                f"(e.g. tcp[{node.name}])"
            )
        elif isinstance(node, ByteAccessNode):
            if false_target is None:
                raise NotImplementedError(
                    "Byte access must appear inside a boolean context "
                    "(comparison, bitmask test, or standalone predicate)"
                )
            self._compile_byte_access(node, false_target)
        elif isinstance(node, BinaryOpNode):
            self._compile_arithmetic(node, false_target)
        elif isinstance(node, LiteralNode):
            if node.kind == "ipv4":
                ip_int = struct.unpack("!I", socket.inet_aton(node.value))[0]
                self._emit(Instruction(BPF_LD | BPF_IMM, 0, 0, ip_int))
            else:
                raise NotImplementedError(
                    f"Literal of kind '{node.kind}' cannot be used as a value"
                )
        else:
            raise NotImplementedError(f"Unsupported value node: {type(node).__name__}")

    def _compile_byte_access(self, node: ByteAccessNode, false_target: str) -> None:
        size_flag = BPF_B if node.size == 1 else (BPF_H if node.size == 2 else BPF_W)
        proto = node.protocol.lower()

        offset_val: Optional[int] = None
        if isinstance(node.offset, NumberNode):
            offset_val = node.offset.value
        elif isinstance(node.offset, FieldNode):
            offset_val, _ = FIELD_OFFSETS.get(node.offset.name, (0, 1))

        # --- ether / link: no protocol guard ---
        if self.linktype == 1:
            if proto in ("ether", "link"):
                if offset_val is not None:
                    self._emit(Instruction(BPF_LD | size_flag | BPF_ABS, 0, 0, offset_val))
                else:
                    self._compile_value(node.offset, false_target)
                    self._emit(Instruction(BPF_MISC | BPF_TAX, 0, 0, 0))
                    self._emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 0))
                return

            # --- IP / IPv6 network-layer access ---
            if proto in ("ip", "ip4", "ipv4", "ip6", "ipv6"):

                ethertype = 0x0800 if proto in ("ip", "ip4", "ipv4") else 0x86DD
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ethertype))

                if offset_val is not None:
                    self._emit(Instruction(BPF_LD | size_flag | BPF_ABS, 0, 0, self.IPv4_H_ST + offset_val))
                else:
                    self._compile_value(node.offset, false_target)
                    self._emit(Instruction(BPF_ALU | BPF_ADD | BPF_K, 0, 0, self.IPv4_H_ST))
                    self._emit(Instruction(BPF_MISC | BPF_TAX, 0, 0, 0))
                    self._emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 0))
                return

            # --- transport-layer access ---
            if proto in _TRANSPORT_PROTO_NUM:
                if self.sip == True:
                    if self.EXPLICIT == 0x0800:
                        self._emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.IPv4_PROTO_OFF))
                        self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, _TRANSPORT_PROTO_NUM.get(proto)))
                        first_frag = self._new_label("first_frag")
                        self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.IPv4_FRAG))
                        self._emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, 0x1FFF))
                        self._emit_label(first_frag)
                        self._emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.IPv4_H_ST))
                    elif self.EXPLICIT == 0x86DD:
                        self._emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, 40))

                else:
                    self._setup_transport_layer(proto, false_target)

                if offset_val is not None:
                    self._emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 14 + offset_val))
                else:
                    scratch = self._alloc_scratch()
                    self._emit(Instruction(BPF_STX, 0, 0, scratch))
                    self._compile_value(node.offset, false_target)
                    self._emit(Instruction(BPF_ALU | BPF_ADD | BPF_K, 0, 0, 14))
                    self._emit(Instruction(BPF_LDX | BPF_MEM, 0, 0, scratch))
                    self._free_scratch()
                    self._emit(Instruction(BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0))
                    self._emit(Instruction(BPF_MISC | BPF_TAX, 0, 0, 0))
                    self._emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 0))
                return

            if proto in ETHERTYPE_MAP.keys():
                ethertype = ETHERTYPE_MAP.get(proto)
                self._emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.E_P_OFFSET))
                self._emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ethertype))
                if offset_val is not None:
                    self._emit(Instruction(BPF_LD | size_flag | BPF_ABS, 0, 0, 14 + offset_val))
                return

        raise NotImplementedError(f"Unsupported byte access protocol: '{proto}'")

    def _compile_arithmetic(self, node: BinaryOpNode, false_target: Optional[str]) -> None:
        alu = {
            "+": BPF_ADD, "-": BPF_SUB, "*": BPF_MUL, "/": BPF_DIV,
            "%": BPF_MOD, "&": BPF_AND, "|": BPF_OR,  "^": BPF_XOR,
            "<<": BPF_LSH, ">>": BPF_RSH,
        }
        if node.op not in alu:
            raise NotImplementedError(f"Unsupported arithmetic operator: '{node.op}'")
        if (node.op in ("/", "%")
                and isinstance(node.right, NumberNode) and node.right.value == 0):
            raise ValueError("Division by zero in filter expression")

        op_code = alu[node.op]
        if isinstance(node.right, NumberNode):
            self._compile_value(node.left, false_target)
            self._emit(Instruction(BPF_ALU | op_code | BPF_K, 0, 0, node.right.value))
        else:
            scratch = self._alloc_scratch()
            self._compile_value(node.right, false_target)
            self._emit(Instruction(BPF_ST, 0, 0, scratch))
            self._compile_value(node.left, false_target)
            self._emit(Instruction(BPF_LDX | BPF_MEM, 0, 0, scratch))
            self._free_scratch()
            self._emit(Instruction(BPF_ALU | op_code | BPF_X, 0, 0, 0))

    # ------------------------------------------------------------------
    # Assembler / backpatch
    # ------------------------------------------------------------------
    def _assemble_and_backpatch(self, true_label: str, false_label: str) -> List[Instruction]:
        label_map: Dict[str, int] = {}
        clean: List[Instruction] = []

        for item in self.instructions:
            if isinstance(item, str) and item.startswith("LABEL:"):
                label_map[item[6:]] = len(clean)
            elif isinstance(item, Instruction):
                clean.append(item)

        label_map[true_label] = len(clean)
        clean.append(Instruction(BPF_RET | BPF_K, 0, 0, BPF_MAX_BUF_LEN))
        label_map[false_label] = len(clean)
        clean.append(Instruction(BPF_RET | BPF_K, 0, 0, 0))

        def resolve(idx: int) -> int:
            seen = set()
            while 0 <= idx < len(clean) and idx not in seen:
                seen.add(idx)
                insn = clean[idx]
                if (insn.code & 0x07) == BPF_JMP and (insn.code & 0xf0) == BPF_JA \
                        and isinstance(insn.k, str):
                    idx = label_map[insn.k]
                else:
                    break
            return idx

        for i, insn in enumerate(clean):
            if (insn.code & 0x07) != BPF_JMP:
                continue
            if (insn.code & 0xf0) == BPF_JA:
                if isinstance(insn.k, str):
                    insn.k = resolve(label_map[insn.k]) - (i + 1)
            else:
                if isinstance(insn.jt, str):
                    insn.jt = resolve(label_map[insn.jt]) - (i + 1)
                if isinstance(insn.jf, str):
                    insn.jf = resolve(label_map[insn.jf]) - (i + 1)
                if not (0 <= insn.jt <= 255):
                    raise ValueError(
                        f"Conditional-jump true offset {insn.jt} at insn {i} exceeds 8-bit range"
                    )
                if not (0 <= insn.jf <= 255):
                    raise ValueError(
                        f"Conditional-jump false offset {insn.jf} at insn {i} exceeds 8-bit range"
                    )
        return clean