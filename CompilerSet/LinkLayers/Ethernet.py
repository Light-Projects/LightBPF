# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Ethernet (DLT_EN10MB = 1) Link-Layer compiler implementation for LightBPF.

Encapsulates:
- Ethernet frame header offsets (DA, SA, Type/Length)
- Inbound and Outbound directional filtering based on host MAC address
- IPv4 / IPv6 header traversal, fragmentation checks, and port offsets
- VLAN (802.1Q / 802.1ad) and MPLS tag offset shifts
- Transport protocol and byte-level indexing
"""

import socket
import struct
import ipaddress
from typing import Optional, Any, TYPE_CHECKING

try:
    from LightBPF.CompilerSet.Instruction import Instruction
    from LightBPF.CompilerSet.Opcode import (
        BPF_LD, BPF_LDX, BPF_ALU, BPF_JMP,
        BPF_W, BPF_H, BPF_B, BPF_MISC, BPF_STX,
        BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM,
        BPF_ADD, BPF_AND, BPF_RSH, BPF_TAX,
        BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
        BPF_K, BPF_X, BPF_MSH,
    )
    from LightBPF.Constants import (
        DLT_EN10MB, IPV4_FRAG_MASK,
        ETH_DST_OFF, ETH_SRC_OFF, ETH_TYPE_OFF, ETH_HLEN,
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_PPPOE_SESS,
        ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD, ETHERTYPE_VLAN_9100,
        ETHERTYPE_MPLS_UC, ETHERTYPE_MPLS_MC,
        IPV4_PROTO_OFF, IPV4_FRAG_OFF, IPV4_SRC_OFF, IPV4_DST_OFF,
        IPV6_PROTO_OFF, IPV6_SRC_OFF, IPV6_DST_OFF, IPV6_HLEN, IPV6_FRAG_NEXT_HDR_OFF,
        IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_FRAGMENT,
        IPV4_ONLY_PROTOCOLS, IPV6_ONLY_PROTOCOLS,
        VLAN_VID_MASK, FIELD_OFFSETS, COMMON_SERVICES, PPPOES_PROTO_OFF
    )
    from LightBPF.Ethertype import ETHERTYPE_KEYWORDS, PPP_PROTOCOLS
    from LightBPF.CompilerSet.LinkLayers.BaseLinkType import BaseLinkType
except:
    from LightPacket.LightBPF.CompilerSet.Instruction import Instruction
    from LightPacket.LightBPF.CompilerSet.Opcode import (
        BPF_LD, BPF_LDX, BPF_ALU, BPF_JMP,
        BPF_W, BPF_H, BPF_B, BPF_MISC, BPF_STX,
        BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM,
        BPF_ADD, BPF_AND, BPF_RSH, BPF_TAX,
        BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
        BPF_K, BPF_X, BPF_MSH,
    )
    from LightPacket.LightBPF.Constants import (
        DLT_EN10MB, IPV4_FRAG_MASK,
        ETH_DST_OFF, ETH_SRC_OFF, ETH_TYPE_OFF, ETH_HLEN,
        ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_PPPOE_SESS,
        ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD, ETHERTYPE_VLAN_9100,
        ETHERTYPE_MPLS_UC, ETHERTYPE_MPLS_MC,
        IPV4_PROTO_OFF, IPV4_FRAG_OFF, IPV4_SRC_OFF, IPV4_DST_OFF,
        IPV6_PROTO_OFF, IPV6_SRC_OFF, IPV6_DST_OFF, IPV6_HLEN, IPV6_FRAG_NEXT_HDR_OFF,
        IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_FRAGMENT,
        IPV4_ONLY_PROTOCOLS, IPV6_ONLY_PROTOCOLS,
        VLAN_VID_MASK, FIELD_OFFSETS, COMMON_SERVICES, PPPOES_PROTO_OFF
    )
    from LightPacket.LightBPF.Ethertype import ETHERTYPE_KEYWORDS, PPP_PROTOCOLS
    from LightPacket.LightBPF.CompilerSet.LinkLayers.BaseLinkType import BaseLinkType

if TYPE_CHECKING:
    try:
        from LightBPF.CompilerSet.Compiler import BpfCompilerNG
        from LightBPF.Parser import (
            ProtocolNode, KeywordFilterNode, ByteAccessNode
        )
    except:
        from LightPacket.LightBPF.CompilerSet.Compiler import BpfCompilerNG
        from LightPacket.LightBPF.Parser import (
            ProtocolNode, KeywordFilterNode, ByteAccessNode
        )


class EthernetLinkType(BaseLinkType):
    """Handler for standard 10/100/1000/10000+ Mb/s Ethernet frames (DLT_EN10MB = 1)."""
    # interface

    linktype = DLT_EN10MB
    name = "Ethernet (DLT_EN10MB)"

    def __init__(self, compiler: "BpfCompilerNG"):
        super().__init__(compiler)
        self.reset()

    def reset(self) -> None:
        """Reset layer offsets to standard untagged Ethernet baseline."""
        self.e_p_offset = ETH_TYPE_OFF     # 12
        self.vlan_id_off = ETH_HLEN        # 14
        self.ipv4_proto_off = IPV4_PROTO_OFF # 23
        self.ipv6_proto_off = IPV6_PROTO_OFF # 20
        self.ipv4_src_off = IPV4_SRC_OFF
        self.ipv4_dst_off = IPV4_DST_OFF
        self.pppoes_proto_off = PPPOES_PROTO_OFF # 20
        self.ipv4_h_st = ETH_HLEN          # 14
        self.ipv6_h_st = IPV6_PROTO_OFF    # 20
        self.ipv6_src_off = IPV6_SRC_OFF
        self.ipv6_dst_off = IPV6_DST_OFF
        self.ipv4_frag = IPV4_FRAG_OFF     # 20
        self.port_field_src = ETH_HLEN     # 14
        self.port_field_dst = 16
        self.is_pppoe_active = False
        self.eth_al = False

    # ------------------------------------------------------------------
    # Protocols
    # ------------------------------------------------------------------
    def compile_protocol(self, node: "ProtocolNode", true_target: str, false_target: str) -> None:
        name = node.name.lower()
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        if name in ("ether", "link"):
            emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))
            return

        if name in ETHERTYPE_KEYWORDS:
            ethertype = ETHERTYPE_KEYWORDS[name]
            if self.is_pppoe_active:
                if name in ("ip", "ip4", "ipv4"):
                    proto_val = 0x0021
                elif name in ("ip6", "ipv6"):
                    proto_val = 0x0057
                elif name in PPP_PROTOCOLS:
                    proto_val = PPP_PROTOCOLS[name]
                else:
                    proto_val = ethertype

                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, proto_val))
                if proto_val in (0x0021, 0x0057):
                    self.compiler.explicit_ethertype = ETHERTYPE_IPV4 if proto_val == 0x0021 else ETHERTYPE_IPV6
                    self.compiler.sip = True
                self.compiler.parsed_upper = True
                return

            if not self.eth_al:
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))

            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ethertype))
            self.eth_al = True

            if ethertype in (ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_PPPOE_SESS):
                if self.compiler.explicit_ethertype is None:
                    self.compiler.explicit_ethertype = ethertype
                else:
                    self.compiler.explicit_ethertype = 90909090909090
                self.compiler.sip = True
            self.compiler.parsed_upper = True
            return

        if name == "vlan":
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            ok = new_label("vlan_ok")
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, ok, ETHERTYPE_VLAN_8021Q))
            self.compiler._emit_label(ok)
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ETHERTYPE_VLAN_8021AD))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ETHERTYPE_VLAN_9100))
            return

        if name == "mpls":
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            ok = new_label("mpls_ok")
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, ok, ETHERTYPE_MPLS_UC))
            self.compiler._emit_label(ok)
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ETHERTYPE_MPLS_MC))
            return

        try:
            from LightBPF.Lexer import BpfLexer
        except ImportError:
            from LightPacket.LightBPF.Lexer import BpfLexer

        if name in BpfLexer.IP_PROTOCOLS:
            proto_num = BpfLexer.IP_PROTOCOLS[name]
        elif name in PPP_PROTOCOLS and self.compiler.explicit_ethertype == ETHERTYPE_PPPOE_SESS:
            proto_num = PPP_PROTOCOLS[name]
        elif node.proto_num is not None:
            proto_num = node.proto_num
        else:
            raise NotImplementedError(f"Unsupported protocol: '{name}'")

        if name == "icmp":
            if not self.compiler.sip:
                check = new_label("ip4")
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check, false_target, ETHERTYPE_IPV4))
                self.compiler._emit_label(check)
            emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, IPPROTO_ICMP))
            return

        if name == "icmp6":
            if not self.compiler.sip:
                check = new_label("ip6")
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check, false_target, ETHERTYPE_IPV6))
                self.compiler._emit_label(check)
            emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_proto_off))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, IPPROTO_ICMPV6))
            return

        if name in IPV4_ONLY_PROTOCOLS or self.compiler.explicit_ethertype == ETHERTYPE_IPV4:
            self._compile_transport_ipv4(proto_num, true_target, false_target, with_x_offset=False)
        elif name in IPV6_ONLY_PROTOCOLS or self.compiler.explicit_ethertype == ETHERTYPE_IPV6:
            self._compile_transport_ipv6(proto_num, true_target, false_target, with_x_offset=False)
        elif self.compiler.explicit_ethertype == ETHERTYPE_PPPOE_SESS:
            self._compile_transport_pppoes(proto_num, true_target, false_target, with_x_offset=False)
        else:
            self._compile_dual_stack_transport(proto_num, true_target, false_target, with_x_offset=False)

    def _compile_transport_pppoes(self, proto_num: int, true_target: str, false_target: str,
                                with_x_offset: bool = False) -> None:
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        after_ether = new_label("pppoes_after_ether")
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, after_ether, false_target, ETHERTYPE_PPPOE_SESS))
        self.compiler._emit_label(after_ether)

        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.pppoes_proto_off))

        if not with_x_offset:
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, proto_num))
            return

    def _compile_transport_ipv4(self, proto_num: int, true_target: str, false_target: str,
                                with_x_offset: bool = False) -> None:
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        after_ether = new_label("ip4_after_ether")

        if not self.compiler.parsed_upper:
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, after_ether, false_target, ETHERTYPE_IPV4))
            self.compiler._emit_label(after_ether)

        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))

        if not with_x_offset:
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, proto_num))
            return

        after_proto = new_label("ip4_after_proto")
        first_frag = new_label("ip4_first_frag")
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, after_proto, false_target, proto_num))
        self.compiler._emit_label(after_proto)
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.ipv4_frag))
        emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, IPV4_FRAG_MASK))
        self.compiler._emit_label(first_frag)
        emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.port_field_src))

    def _compile_transport_ipv6(self, proto_num: int, true_target: str, false_target: str,
                                with_x_offset: bool = False) -> None:
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        after_ether = new_label("ip6_after_ether")
        frag_check = new_label("ip6_frag_check")
        frag_ok = new_label("ip6_frag_ok")
        match_target = new_label("ip6_after_nh") if with_x_offset else true_target

        if not self.compiler.parsed_upper:
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, after_ether, false_target, ETHERTYPE_IPV6))
            self.compiler._emit_label(after_ether)

        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_proto_off))

        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, match_target, frag_check, proto_num))
        self.compiler._emit_label(frag_check)
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, frag_ok, false_target, IPPROTO_FRAGMENT))
        self.compiler._emit_label(frag_ok)
        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, IPV6_FRAG_NEXT_HDR_OFF))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, match_target, false_target, proto_num))

        if with_x_offset:
            self.compiler._emit_label(match_target)
            emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, IPV6_HLEN))

    def _compile_dual_stack_transport(self, proto_num: int, true_target: str, false_target: str,
                                      with_x_offset: bool = False) -> None:
        self.compiler.sip = True
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        check_ip4 = new_label("ip4_chk")
        check_ip6 = new_label("ip6_chk")
        ip4_match = true_target
        load_ip6 = new_label("ip6_load")

        proto_v4 = 0x0021 if self.is_pppoe_active else ETHERTYPE_IPV4
        proto_v6 = 0x0057 if self.is_pppoe_active else ETHERTYPE_IPV6

        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check_ip4, check_ip6, proto_v4))

        # IPv4
        self.compiler._emit_label(check_ip4)
        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, proto_num))
        first_frag = new_label("ip4_first_frag")
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.ipv4_frag))
        emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, IPV4_FRAG_MASK))
        self.compiler._emit_label(first_frag)
        emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.port_field_src))
        emit(Instruction(BPF_JMP | BPF_JA, 0, 0, ip4_match))

        # IPv6
        self.compiler._emit_label(check_ip6)
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, proto_v6))
        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_proto_off))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, load_ip6, false_target, proto_num))
        self.compiler._emit_label(load_ip6)
        emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, IPV6_HLEN))

    # ------------------------------------------------------------------
    # Host filter
    # ------------------------------------------------------------------
    def compile_host(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        vtype = node.value_type
        direction = node.direction
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        if vtype == "ipv4":
            ip_int = struct.unpack("!I", socket.inet_aton(node.value))[0]
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV4))

            if direction == "src":
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, self.ipv4_src_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))
            elif direction == "dst":
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, self.ipv4_dst_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))
            elif direction == "src and dst":
                chk = new_label("chk_dst")
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, self.ipv4_src_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, ip_int))
                self.compiler._emit_label(chk)
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, self.ipv4_dst_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))
            else:  # src or dst (default)
                chk = new_label("chk_dst")
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, self.ipv4_src_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, chk, ip_int))
                self.compiler._emit_label(chk)
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, self.ipv4_dst_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, ip_int))

        elif vtype == "ipv6":
            words = struct.unpack("!IIII", ipaddress.IPv6Address(node.value).packed)
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV6))

            def match(base_off: int, m_true: str, m_false: str):
                w0 = new_label("w0")
                w1 = new_label("w1")
                w2 = new_label("w2")
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, w0, m_false, words[0]))
                self.compiler._emit_label(w0)
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + 4))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, w1, m_false, words[1]))
                self.compiler._emit_label(w1)
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + 8))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, w2, m_false, words[2]))
                self.compiler._emit_label(w2)
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + 12))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, m_true, m_false, words[3]))

            if direction == "src":
                match(self.ipv6_src_off, true_target, false_target)
            elif direction == "dst":
                match(self.ipv6_dst_off, true_target, false_target)
            elif direction == "src and dst":
                chk = new_label("chk_dst")
                match(self.ipv6_src_off, chk, false_target)
                self.compiler._emit_label(chk)
                match(self.ipv6_dst_off, true_target, false_target)
            else:
                chk = new_label("chk_dst")
                match(self.ipv6_src_off, true_target, chk)
                self.compiler._emit_label(chk)
                match(self.ipv6_dst_off, true_target, false_target)

        elif vtype == "mac":
            mac_clean = node.value.replace(":", "").replace("-", "")
            mac_bytes = bytes.fromhex(mac_clean)
            w0 = struct.unpack("!I", mac_bytes[:4])[0]
            h1 = struct.unpack("!H", mac_bytes[4:6])[0]

            def match_mac(base_off: int, m_true: str, m_false: str):
                p1 = new_label("mac1")
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, p1, m_false, w0))
                self.compiler._emit_label(p1)
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, base_off + 4))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, m_true, m_false, h1))

            if direction == "src":
                match_mac(ETH_SRC_OFF, true_target, false_target)
            elif direction == "dst":
                match_mac(ETH_DST_OFF, true_target, false_target)
            elif direction == "src and dst":
                chk = new_label("chk_src")
                match_mac(ETH_DST_OFF, chk, false_target)
                self.compiler._emit_label(chk)
                match_mac(ETH_SRC_OFF, true_target, false_target)
            else:
                chk = new_label("chk_src")
                match_mac(ETH_DST_OFF, true_target, chk)
                self.compiler._emit_label(chk)
                match_mac(ETH_SRC_OFF, true_target, false_target)

        elif vtype == "name":
            try:
                resolved = socket.gethostbyname(node.value)
            except OSError:
                raise ValueError(f"Could not resolve host name: '{node.value}'")

            try:
                from LightBPF.Parser import KeywordFilterNode
            except ImportError:
                from LightPacket.LightBPF.Parser import KeywordFilterNode

            clone = KeywordFilterNode(
                keyword=node.keyword, value=resolved,
                direction=node.direction, protocol=node.protocol,
                value_type="ipv4", mask=node.mask,
            )
            self.compile_host(clone, true_target, false_target)
        else:
            raise NotImplementedError(f"Unsupported host value type: '{vtype}'")

    # ------------------------------------------------------------------
    # Net filter
    # ------------------------------------------------------------------
    def compile_net(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        direction = node.direction
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        if node.value_type in ("cidr4", "ipv4") or node.mask is not None:
            if node.mask:
                net = ipaddress.IPv4Network(f"{node.value}/{node.mask}", strict=False)
            elif "/" in str(node.value):
                net = ipaddress.IPv4Network(node.value, strict=False)
            else:
                parts = str(node.value).split(".")
                prefix = 8 if int(parts[0]) < 128 else 16 if int(parts[0]) < 192 else 24 if int(parts[0]) < 224 else 32
                padded = parts + ["0"] * (4 - len(parts))
                net = ipaddress.IPv4Network(f"{'.'.join(padded)}/{prefix}", strict=False)

            net_int = int(net.network_address)
            mask_int = int(net.netmask)

            if not self.compiler.parsed_upper:
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV4))

            def match_net4(offset: int, m_true: str, m_false: str):
                emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, offset))
                if mask_int != 0xFFFFFFFF:
                    emit(Instruction(BPF_ALU | BPF_AND | BPF_K, 0, 0, mask_int))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, m_true, m_false, net_int))

            if direction == "src":
                match_net4(self.ipv4_src_off, true_target, false_target)
            elif direction == "dst":
                match_net4(self.ipv4_dst_off, true_target, false_target)
            elif direction == "src and dst":
                chk = new_label("chk_dst")
                match_net4(self.ipv4_src_off, chk, false_target)
                self.compiler._emit_label(chk)
                match_net4(self.ipv4_dst_off, true_target, false_target)
            else:
                chk = new_label("chk_dst")
                match_net4(self.ipv4_src_off, true_target, chk)
                self.compiler._emit_label(chk)
                match_net4(self.ipv4_dst_off, true_target, false_target)

        elif node.value_type == "cidr6":
            net6 = ipaddress.IPv6Network(node.value, strict=False)
            net_words = struct.unpack("!IIII", net6.network_address.packed)
            mask_words = struct.unpack("!IIII", net6.netmask.packed)

            if not self.compiler.parsed_upper:
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV6))

            def match_net6(base_off: int, m_true: str, m_false: str):
                labels = [new_label(f"net6_w{i}") for i in range(3)]
                for i in range(4):
                    nxt = labels[i] if i < 3 else m_true
                    nw, mw = net_words[i], mask_words[i]
                    if mw == 0:
                        emit(Instruction(BPF_JMP | BPF_JA, 0, 0, nxt))
                    else:
                        emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, base_off + i * 4))
                        if mw != 0xFFFFFFFF:
                            emit(Instruction(BPF_ALU | BPF_AND | BPF_K, 0, 0, mw))
                        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, nxt, m_false, nw))
                    if i < 3:
                        self.compiler._emit_label(labels[i])

            if direction == "src":
                match_net6(self.ipv6_src_off, true_target, false_target)
            elif direction == "dst":
                match_net6(self.ipv6_dst_off, true_target, false_target)
            elif direction == "src and dst":
                chk = new_label("chk_dst")
                match_net6(self.ipv6_src_off, chk, false_target)
                self.compiler._emit_label(chk)
                match_net6(self.ipv6_dst_off, true_target, false_target)
            else:
                chk = new_label("chk_dst")
                match_net6(self.ipv6_src_off, true_target, chk)
                self.compiler._emit_label(chk)
                match_net6(self.ipv6_dst_off, true_target, false_target)
        else:
            raise NotImplementedError(f"Unsupported net type: '{node.value_type}'")

    # ------------------------------------------------------------------
    # Port & Portrange
    # ------------------------------------------------------------------
    def compile_port(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        port_num = self._resolve_port(node.value)
        direction = node.direction
        proto = node.protocol.lower() if node.protocol else None
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        if not self.compiler.sip or self.compiler.parsed_upper:
            self._setup_transport_layer(proto, false_target)

        if direction == "src":
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.port_field_src))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))
        elif direction == "dst":
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.port_field_dst))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))
        elif direction == "src and dst":
            chk = new_label("chk_dst")
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.port_field_src))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, port_num))
            self.compiler._emit_label(chk)
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.port_field_dst))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))
        else:
            chk = new_label("chk_dst")
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.port_field_src))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, chk, port_num))
            self.compiler._emit_label(chk)
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, self.port_field_dst))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, port_num))

    def compile_portrange(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        lo, hi = int(node.value[0]), int(node.value[1])
        direction = node.direction
        proto = node.protocol.lower() if node.protocol else None
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        self._setup_transport_layer(proto, false_target)

        def check_range(offset: int, m_true: str, m_false: str):
            chk_hi = new_label("chk_hi")
            emit(Instruction(BPF_LD | BPF_H | BPF_IND, 0, 0, offset))
            emit(Instruction(BPF_JMP | BPF_JGE | BPF_K, chk_hi, m_false, lo))
            self.compiler._emit_label(chk_hi)
            emit(Instruction(BPF_JMP | BPF_JGT | BPF_K, m_false, m_true, hi))

        if direction == "src":
            check_range(self.port_field_src, true_target, false_target)
        elif direction == "dst":
            check_range(self.port_field_dst, true_target, false_target)
        elif direction == "src and dst":
            chk = new_label("chk_dst")
            check_range(self.port_field_src, chk, false_target)
            self.compiler._emit_label(chk)
            check_range(self.port_field_dst, true_target, false_target)
        else:
            chk = new_label("chk_dst")
            check_range(self.port_field_src, true_target, chk)
            self.compiler._emit_label(chk)
            check_range(self.port_field_dst, true_target, false_target)

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

    def _setup_transport_layer(self, proto: Optional[str], false_target: str) -> None:
        try:
            from LightBPF.Lexer import BpfLexer
        except ImportError:
            from LightPacket.LightBPF.Lexer import BpfLexer

        proto_map = BpfLexer.IP_PROTOCOLS
        emit = self.compiler._emit
        new_label = self.compiler._new_label

        if proto in IPV6_ONLY_PROTOCOLS:
            num = proto_map[proto]
            chk = new_label("is_ip6")
            ok = new_label("ip6_ok")
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, ETHERTYPE_IPV6))
            self.compiler._emit_label(chk)
            emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_h_st))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, num))
            self.compiler._emit_label(ok)
            emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, IPV6_HLEN))
            return

        if proto in IPV4_ONLY_PROTOCOLS:
            num = proto_map[proto]
            chk = new_label("is_ip4")
            ok = new_label("ip4_ok")
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, chk, false_target, ETHERTYPE_IPV4))
            self.compiler._emit_label(chk)
            emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, false_target, self.ipv4_proto_off))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, num))
            self.compiler._emit_label(ok)

            first_frag = new_label("first_frag")
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.ipv4_frag))
            emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, IPV4_FRAG_MASK))
            self.compiler._emit_label(first_frag)
            emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.ipv4_h_st))
            return

        num = proto_map.get(proto) if proto else None
        ip4_ok = new_label("ip4_ok")
        ip6_ok = new_label("ip6_ok")
        transport_ready = new_label("transport_ready")
        check_ip6 = new_label("chk_ip6")
        check_ip4 = new_label("chk_ip4")

        if self.compiler.explicit_ethertype not in (None, ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            emit(Instruction(BPF_JMP | BPF_JA, 0, 0, false_target))
            return

        if not self.compiler.parsed_upper:
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))

        if self.compiler.explicit_ethertype is None or self.compiler.explicit_ethertype == ETHERTYPE_IPV4:
            if not self.compiler.parsed_upper:
                proto_expected = 0x0021 if self.is_pppoe_active else ETHERTYPE_IPV4
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, check_ip4, check_ip6, proto_expected))

            self.compiler._emit_label(check_ip4)
            if num is not None:
                emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, false_target, num))
            else:
                if not self.compiler.parsed_upper:
                    is_udp = new_label("is_udp4")
                    emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, is_udp, 6)) # TCP
                    self.compiler._emit_label(is_udp)
                    is_sctp = new_label("is_sctp")
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, is_sctp, 17)) # UDP
                    self.compiler._emit_label(is_sctp)
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip4_ok, false_target, 132)) # SCTP

            self.compiler._emit_label(ip4_ok)
            first_frag = new_label("first_frag")
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.ipv4_frag))
            emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, IPV4_FRAG_MASK))
            self.compiler._emit_label(first_frag)
            emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.ipv4_h_st))
            emit(Instruction(BPF_JMP | BPF_JA, 0, 0, transport_ready))

        if self.compiler.explicit_ethertype is None or self.compiler.explicit_ethertype == ETHERTYPE_IPV6:
            self.compiler._emit_label(check_ip6)
            if not self.compiler.parsed_upper:
                proto_ip6 = 0x0057 if self.is_pppoe_active else ETHERTYPE_IPV6
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, proto_ip6))

            if num is not None:
                emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_h_st))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, false_target, num))
            else:
                if not self.compiler.parsed_upper:
                    is_udp6 = new_label("is_udp6")
                    emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_h_st))
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, is_udp6, 6))
                    self.compiler._emit_label(is_udp6)
                    is_sctp6 = new_label("is_sctp6")
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, is_sctp6, 17))
                    self.compiler._emit_label(is_sctp6)
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ip6_ok, false_target, 132))

            self.compiler._emit_label(ip6_ok)
            emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, IPV6_HLEN))

        self.compiler._emit_label(transport_ready)
        self.compiler.sip = True

    # ------------------------------------------------------------------
    # Broadcast & Multicast
    # ------------------------------------------------------------------
    def compile_broadcast(self, true_target: str, false_target: str) -> None:
        emit = self.compiler._emit
        part = self.compiler._new_label("bcast1")
        emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, ETH_DST_OFF))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, part, false_target, 0xFFFFFFFF))
        self.compiler._emit_label(part)
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, ETH_DST_OFF + 4))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, 0xFFFF))

    def compile_multicast(self, true_target: str, false_target: str) -> None:
        emit = self.compiler._emit
        # In Ethernet, the least significant bit of the first byte of dst MAC indicates multicast
        emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, ETH_DST_OFF))
        emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, true_target, false_target, 0x01))

    # ------------------------------------------------------------------
    # Proto, VLAN & MPLS
    # ------------------------------------------------------------------
    def compile_proto(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        val = node.value
        num: Optional[int] = None
        emit = self.compiler._emit

        if isinstance(val, str):
            lv = val.lower()
            if lv in ETHERTYPE_KEYWORDS:
                num = ETHERTYPE_KEYWORDS[lv]
            else:
                try:
                    num = int(lv, 0)
                except ValueError:
                    num = None
            self.compiler.parsed_upper = True
            if num in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
                self.compiler.explicit_ethertype = num
        elif isinstance(val, int):
            num = val
            self.compiler.parsed_upper = True
            if num in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
                self.compiler.explicit_ethertype = num

        if num is None:
            raise ValueError(f"Cannot resolve protocol '{val}'")

        link = (node.protocol or "").lower()
        if link in ("ether", "link"):
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))
        elif link in ("ip6", "ipv6"):
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV6))
            if node.protocol is not None:
                emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_proto_off))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))
        else:
            popo = node.value
            if popo in ("ip6", "ipv6"):
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV6))
                if node.protocol is not None:
                    emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv6_proto_off))
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))
            elif popo in ETHERTYPE_KEYWORDS:
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_KEYWORDS[popo]))
            else:
                emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
                emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ETHERTYPE_IPV4))
                if node.protocol is not None:
                    emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, num))

    def compile_vlan(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        emit = self.compiler._emit
        ok = self.compiler._new_label("vlan_ok")
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))

        self.e_p_offset += 4
        self.ipv4_frag += 4
        self.ipv4_proto_off += 4
        self.ipv4_dst_off += 4
        self.ipv4_src_off += 4
        self.ipv6_src_off += 4
        self.ipv6_dst_off += 4
        self.ipv4_h_st += 4
        self.ipv6_h_st += 4
        self.ipv6_proto_off += 4
        self.port_field_src += 4
        self.port_field_dst += 4

        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, 0, ETHERTYPE_VLAN_8021Q))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, 0, ETHERTYPE_VLAN_8021AD))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, ETHERTYPE_VLAN_9100))
        self.compiler._emit_label(ok)

        if node.value is not None:
            vid = int(node.value)
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.vlan_id_off))
            emit(Instruction(BPF_ALU | BPF_AND | BPF_K, 0, 0, VLAN_VID_MASK))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, vid))
        else:
            emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))
        self.vlan_id_off += 4

    def compile_mpls(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        emit = self.compiler._emit
        ok = self.compiler._new_label("mpls_ok")
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))

        self.e_p_offset += 4
        self.ipv4_frag += 4
        self.ipv4_proto_off += 4
        self.ipv4_dst_off += 4
        self.ipv4_src_off += 4

        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, ETHERTYPE_MPLS_UC))
        self.compiler._emit_label(ok)
        if node.value is not None:
            label = int(node.value)
            emit(Instruction(BPF_LD | BPF_W | BPF_ABS, 0, 0, ETH_HLEN))
            emit(Instruction(BPF_ALU | BPF_RSH | BPF_K, 0, 0, 12))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, label))
        else:
            emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))

    def compile_pppoes(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        emit = self.compiler._emit
        ok = self.compiler._new_label("pppoes_ok")
        emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
        emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, ok, false_target, ETHERTYPE_PPPOE_SESS))
        self.compiler._emit_label(ok)

        # Check session ID if specified (offset e_p_offset + 4 is Session ID in PPPoE header)
        if node.value is not None:
            sess_id = int(node.value)
            sess_offset = self.e_p_offset + 4
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, sess_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, true_target, false_target, sess_id))
        else:
            emit(Instruction(BPF_JMP | BPF_JA, 0, 0, true_target))

        # Shift offsets past PPPoE (6 bytes) + PPP Protocol (2 bytes) = 8 bytes
        PPPOES_SHIFT = 8
        self.e_p_offset += PPPOES_SHIFT
        self.ipv4_frag += PPPOES_SHIFT
        self.ipv4_proto_off += PPPOES_SHIFT
        self.ipv4_h_st += PPPOES_SHIFT
        self.ipv6_h_st += PPPOES_SHIFT
        self.ipv6_proto_off += PPPOES_SHIFT
        self.port_field_src += PPPOES_SHIFT
        self.port_field_dst += PPPOES_SHIFT
        self.pppoes_proto_off += PPPOES_SHIFT
        self.ipv4_dst_off += PPPOES_SHIFT
        self.ipv4_src_off += PPPOES_SHIFT
        self.ipv6_src_off += PPPOES_SHIFT
        self.ipv6_dst_off += PPPOES_SHIFT
        self.is_pppoe_active = True

    # ------------------------------------------------------------------
    # Byte Access
    # ------------------------------------------------------------------
    def compile_byte_access(self, node: "ByteAccessNode", false_target: str) -> None:
        try:
            from LightBPF.Parser import NumberNode, FieldNode
            from LightBPF.Lexer import BpfLexer
        except ImportError:
            from LightPacket.LightBPF.Parser import NumberNode, FieldNode
            from LightPacket.LightBPF.Lexer import BpfLexer

        size_flag = BPF_B if node.size == 1 else (BPF_H if node.size == 2 else BPF_W)
        proto = node.protocol.lower()
        emit = self.compiler._emit

        offset_val: Optional[int] = None
        if isinstance(node.offset, NumberNode):
            offset_val = node.offset.value
        elif isinstance(node.offset, FieldNode):
            offset_val, _ = FIELD_OFFSETS.get(node.offset.name, (0, 1))

        # 1. ether / link
        if proto in ("ether", "link"):
            if offset_val is not None:
                emit(Instruction(BPF_LD | size_flag | BPF_ABS, 0, 0, offset_val))
            else:
                self.compiler._compile_value(node.offset, false_target)
                emit(Instruction(BPF_MISC | BPF_TAX, 0, 0, 0))
                emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 0))
            return

        # 2. IP / IPv6
        if proto in ("ip", "ip4", "ipv4", "ip6", "ipv6"):
            ethertype = ETHERTYPE_IPV4 if proto in ("ip", "ip4", "ipv4") else ETHERTYPE_IPV6
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ethertype))

            if offset_val is not None:
                emit(Instruction(BPF_LD | size_flag | BPF_ABS, 0, 0, self.ipv4_h_st + offset_val))
            else:
                self.compiler._compile_value(node.offset, false_target)
                emit(Instruction(BPF_ALU | BPF_ADD | BPF_K, 0, 0, self.ipv4_h_st))
                emit(Instruction(BPF_MISC | BPF_TAX, 0, 0, 0))
                emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 0))
            return

        # 3. Transport protocols
        transport_map = BpfLexer.IP_PROTOCOLS
        if proto in transport_map:
            if self.compiler.sip:
                if self.compiler.explicit_ethertype == ETHERTYPE_IPV4:
                    emit(Instruction(BPF_LD | BPF_B | BPF_ABS, 0, 0, self.ipv4_proto_off))
                    emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, transport_map[proto]))
                    first_frag = self.compiler._new_label("first_frag")
                    emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.ipv4_frag))
                    emit(Instruction(BPF_JMP | BPF_JSET | BPF_K, false_target, first_frag, IPV4_FRAG_MASK))
                    self.compiler._emit_label(first_frag)
                    emit(Instruction(BPF_LDX | BPF_B | BPF_MSH, 0, 0, self.ipv4_h_st))
                elif self.compiler.explicit_ethertype == ETHERTYPE_IPV6:
                    emit(Instruction(BPF_LDX | BPF_IMM, 0, 0, IPV6_HLEN))
            else:
                self._setup_transport_layer(proto, false_target)

            if offset_val is not None:
                emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, ETH_HLEN + offset_val))
            else:
                scratch = self.compiler._alloc_scratch()
                emit(Instruction(BPF_STX, 0, 0, scratch))
                self.compiler._compile_value(node.offset, false_target)
                emit(Instruction(BPF_ALU | BPF_ADD | BPF_K, 0, 0, ETH_HLEN))
                emit(Instruction(BPF_LDX | BPF_MEM, 0, 0, scratch))
                self.compiler._free_scratch()
                emit(Instruction(BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0))
                emit(Instruction(BPF_MISC | BPF_TAX, 0, 0, 0))
                emit(Instruction(BPF_LD | size_flag | BPF_IND, 0, 0, 0))
            return

        # 4. EtherType keyword byte access
        if proto in ETHERTYPE_KEYWORDS:
            ethertype = ETHERTYPE_KEYWORDS[proto]
            emit(Instruction(BPF_LD | BPF_H | BPF_ABS, 0, 0, self.e_p_offset))
            emit(Instruction(BPF_JMP | BPF_JEQ | BPF_K, 0, false_target, ethertype))
            if offset_val is not None:
                emit(Instruction(BPF_LD | size_flag | BPF_ABS, 0, 0, ETH_HLEN + offset_val))
            return

        raise NotImplementedError(f"Unsupported byte access protocol: '{proto}'")

    def save_state(self) -> tuple:
        return (
            self.e_p_offset, self.vlan_id_off, self.ipv4_proto_off,
            self.ipv6_proto_off, self.pppoes_proto_off, self.ipv4_h_st,
            self.ipv6_h_st, self.ipv4_frag, self.port_field_src,
            self.port_field_dst, self.is_pppoe_active, self.eth_al
        )

    def restore_state(self, state: tuple) -> None:
        (self.e_p_offset, self.vlan_id_off, self.ipv4_proto_off,
         self.ipv6_proto_off, self.pppoes_proto_off, self.ipv4_h_st,
         self.ipv6_h_st, self.ipv4_frag, self.port_field_src,
         self.port_field_dst, self.is_pppoe_active, self.eth_al) = state
