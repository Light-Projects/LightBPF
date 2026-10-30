# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Classic BPF (cBPF) bytecode compiler Next-Generation (LightBPF).

Modular compiler design with pluggable link-type handlers.
"""

import socket
import ipaddress
import struct
from typing import List, Optional, Dict, Any, Union, Type

from LightPacket.LightBPF.CompilerSet.Instruction import Instruction
from LightPacket.LightBPF.CompilerSet.Opcode import (
    BPF_LD, BPF_LDX, BPF_ST, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC,
    BPF_W, BPF_H, BPF_B,
    BPF_IMM, BPF_MEM, BPF_LEN,
    BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH,
    BPF_TAX, BPF_MOD, BPF_XOR,
    BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
    BPF_K, BPF_X, BPF_MAX_BUF_LEN,
)
from LightPacket.LightBPF.Constants import (
    DLT_EN10MB, FIELD_OFFSETS, COMMON_SERVICES
)
from LightPacket.LightBPF.CompilerSet import Peephole
from LightPacket.LightBPF.CompilerSet import Shortcut
from LightPacket.LightBPF.CompilerSet.LinkLayers.BaseLinkType import BaseLinkType
from LightPacket.LightBPF.CompilerSet.LinkLayers.Ethernet import EthernetLinkType

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
    from LightBPF.Ethertype import ETHERTYPE_KEYWORDS  # type: ignore


class BpfCompilerNG:
    """Extensible classic BPF bytecode compiler."""

    # Global registry for Data Link Types
    _LINKTYPE_REGISTRY: Dict[int, Type[BaseLinkType]] = {
        DLT_EN10MB: EthernetLinkType,
    }

    @classmethod
    def register_link_type(cls, linktype: int, handler_cls: Type[BaseLinkType]) -> None:
        """Register a new link-type handler class for a given DLT code."""
        cls._LINKTYPE_REGISTRY[linktype] = handler_cls

    def __init__(self, linktype: int = DLT_EN10MB,
                 interface: Optional[str] = None,
                 host_mac: Optional[str] = None,
                 host_ip: Optional[str] = None):
        self.instructions: List[Union[Instruction, str]] = []
        self._label_counter = 0
        self._scratch_counter = 0
        self.parsed_upper = False
        self.explicit_ethertype: Optional[int] = None
        self.sip = False
        self.linktype = linktype

        self.interface = interface
        self.host_mac = host_mac
        self.host_ip = host_ip

        # Instantiate link-layer handler
        self._link_handler: Optional[BaseLinkType] = None
        self._set_link_handler(linktype)

    def _set_link_handler(self, linktype: int) -> None:
        if linktype not in self._LINKTYPE_REGISTRY:
            raise NotImplementedError(
                f"Unsupported linktype: '{linktype}'. Available linktypes: {list(self._LINKTYPE_REGISTRY.keys())}"
            )
        self.linktype = linktype
        self._link_handler = self._LINKTYPE_REGISTRY[linktype](self)

    @property
    def link_handler(self) -> BaseLinkType:
        if self._link_handler is None:
            self._set_link_handler(self.linktype)
        return self._link_handler  # type: ignore

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def compile(self, ast_root: ASTNode, optimize: bool = True,
                linktype: Optional[int] = None,
                interface: Optional[str] = None,
                host_mac: Optional[str] = None,
                host_ip: Optional[str] = None) -> List[Instruction]:
        self.instructions = []
        self._label_counter = 0
        self._scratch_counter = 0
        self.parsed_upper = False
        self.explicit_ethertype = None
        self.sip = False

        if linktype is not None:
            self._set_link_handler(linktype)
        if interface is not None:
            self.interface = interface
        if host_mac is not None:
            self.host_mac = host_mac
        if host_ip is not None:
            self.host_ip = host_ip

        self.link_handler.reset()

        self._compile_bool(ast_root, "ACCEPT", "REJECT")
        code = self._assemble_and_backpatch("ACCEPT", "REJECT")
        if optimize:
            code = Peephole.optimize(code)
        return code

    @classmethod
    def compile_str(cls, filter_string: str, optimize: bool = True,
                    linktype: int = DLT_EN10MB,
                    interface: Optional[str] = None,
                    host_mac: Optional[str] = None,
                    host_ip: Optional[str] = None) -> List[Instruction]:
        filter_exp = Shortcut.str_shortcut(filter_string)
        tokens = BpfLexer(filter_exp).tokenize()
        ast = BpfParser(tokens).parse()
        compiler = cls(linktype=linktype, interface=interface, host_mac=host_mac, host_ip=host_ip)
        return compiler.compile(ast, optimize=optimize)

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
            self.link_handler.compile_protocol(node, true_target, false_target)
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
    # Keyword dispatch to link-type handler
    # ------------------------------------------------------------------
    def _compile_keyword(self, node: KeywordFilterNode,
                         true_target: str, false_target: str) -> None:
        kw = node.keyword
        if kw == "host":
            self.link_handler.compile_host(node, true_target, false_target)
        elif kw == "net":
            self.link_handler.compile_net(node, true_target, false_target)
        elif kw == "port":
            self.link_handler.compile_port(node, true_target, false_target)
        elif kw == "portrange":
            self.link_handler.compile_portrange(node, true_target, false_target)
        elif kw in ("less", "greater"):
            self._compile_length_filter(node, true_target, false_target)
        elif kw == "broadcast":
            self.link_handler.compile_broadcast(true_target, false_target)
        elif kw == "multicast":
            self.link_handler.compile_multicast(true_target, false_target)
        elif kw in ("proto", "protochain"):
            self.link_handler.compile_proto(node, true_target, false_target)
        elif kw == "vlan":
            self.link_handler.compile_vlan(node, true_target, false_target)
        elif kw == "mpls":
            self.link_handler.compile_mpls(node, true_target, false_target)
        elif kw == "inbound":
            self.link_handler.compile_inbound(true_target, false_target)
        elif kw == "outbound":
            self.link_handler.compile_outbound(true_target, false_target)
        elif kw == "gateway":
            raise NotImplementedError(
                "'gateway' is not supported: it requires routing neighbor resolution "
                "which is not expressible in static cBPF"
            )
        else:
            raise NotImplementedError(f"Unsupported keyword filter: '{kw}'")

    def _compile_length_filter(self, node: KeywordFilterNode,
                               true_target: str, false_target: str) -> None:
        val = int(node.value)
        self._emit(Instruction(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0))
        if node.keyword == "less":
            self._emit(Instruction(BPF_JMP | BPF_JGT | BPF_K, false_target, true_target, val))
        else:
            self._emit(Instruction(BPF_JMP | BPF_JGE | BPF_K, true_target, false_target, val))

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
            self.link_handler.compile_byte_access(node, false_target)
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


# Alias for backward-compatible naming
BpfCompiler = BpfCompilerNG
