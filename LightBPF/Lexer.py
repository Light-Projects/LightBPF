# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import re
import ipaddress
from typing import NamedTuple, List


class Token(NamedTuple):
    type: str
    value: str


class BpfLexer:
    """Lexer for classic BPF (pcap-filter) expressions.

    Token types:
      NUMBER, HEX, IPV4, IPV6, MAC, IPV4_CIDR, IPV6_CIDR,
      DLT, ETHERTYPE, IP-PROTOCOL, PROTO_QUAL, KEYWORD, LOGICAL,
      MATH_OP, REL_OP, SYMBOL, IDENTIFIER
    """

    IP_PROTOCOLS = {
        "hopopt": 0, "icmp": 1, "igmp": 2, "ggp": 3, "ipv4": 4, "st": 5, "tcp": 6,
        "cbt": 7, "egp": 8, "igp": 9, "bbn-rcc-mon": 10, "nvp-ii": 11, "pup": 12,
        "argus": 13, "emcon": 14, "xnet": 15, "chaos": 16, "udp": 17, "mux": 18,
        "dcn-meas": 19, "hmp": 20, "prm": 21, "xns-idp": 22, "trunk-1": 23,
        "trunk-2": 24, "leaf-1": 25, "leaf-2": 26, "rdp": 27, "irtp": 28,
        "iso-tp4": 29, "netblt": 30, "mfe-nsp": 31, "merit-inp": 32, "dccp": 33,
        "3pc": 34, "idpr": 35, "xtp": 36, "ddp": 37, "idpr-cmtp": 38, "tp++": 39,
        "il": 40, "ipv6": 41, "sdrp": 42, "ipv6-route": 43, "ipv6-frag": 44,
        "idrp": 45, "rsvp": 46, "gre": 47, "dsr": 48, "bna": 49, "esp": 50,
        "ah": 51, "i-nlsp": 52, "swipe": 53, "narp": 54, "mobile": 55, "tlsp": 56,
        "skip": 57, "ipv6-icmp": 58, "ipv6-nonxt": 59, "ipv6-opts": 60,
        "any-host-internal": 61, "cftp": 62, "any-local-network": 63,
        "sat-expak": 64, "kryptolan": 65, "rvd": 66, "ippc": 67,
        "any-distributed-fs": 68, "sat-mon": 69, "visa": 70, "ipcv": 71,
        "cpnx": 72, "cphb": 73, "wsn": 74, "pvp": 75, "br-sat-mon": 76,
        "sun-nd": 77, "wb-mon": 78, "wb-expak": 79, "iso-ip": 80, "vmtp": 81,
        "secure-vmtp": 82, "vines": 83, "ttp": 84, "iptm": 84, "nsfnet-igp": 85,
        "dgp": 86, "tcf": 87, "eigrp": 88, "ospfigp": 89, "sprite-rpc": 90,
        "larp": 91, "mtp": 92, "ax.25": 93, "ipip": 94, "micp": 95, "scc-sp": 96,
        "etherip": 97, "encap": 98, "any-private-encryption": 99, "gmtp": 100,
        "ifmp": 101, "pnni": 102, "pim": 103, "aris": 104, "scps": 105,
        "qnx": 106, "a/n": 107, "ipcomp": 108, "snp": 109, "compaq-peer": 110,
        "ipx-in-ip": 111, "vrrp": 112, "pgm": 113, "any-0-hop": 114, "l2tp": 115,
        "ddx": 116, "iatp": 117, "stp": 118, "srp": 119, "uti": 120, "smp": 121,
        "sm": 122, "ptp": 123, "isis": 124, "fire": 125, "crtp": 126, "crudp": 127,
        "sscopmce": 128, "iplt": 129, "sps": 130, "pipe": 131, "sctp": 132,
        "fc": 133, "rsvp-e2e-ignore": 134, "mobility-header": 135, "udplite": 136,
        "mpls-in-ip": 137, "manet": 138, "hip": 139, "shim6": 140, "wesp": 141,
        "rohc": 142, "ethernet": 143,
        "experimentation-1": 253, "experimentation-2": 254, "reserved": 255
    }

    ETHERTYPE_KEYWORDS = {
        "ip": 0x0800, "ip4": 0x0800,
        "ip6": 0x86DD,
        "arp": 0x0806, "rarp": 0x8035,
        "vlan": 0x8100, "mpls": 0x8847,
        "pppoed": 0x8863, "pppoes": 0x8864,
    }

    # Link-layer qualifiers usable as ether[..], wlan[..], etc.
    DLT_LINKS = {"ether": 1, "wlan": 105, "ppp": 9, "fddi": 10, "tr": 6,
                 "slip": 8, "link": 1}

    # Protocol names that pcap treats specially (checked before IP_PROTOCOLS)
    PROTO_QUALIFIERS = {"tcp", "udp", "icmp", "icmp6", "sctp"}

    KEYWORDS = {
        "host", "port", "net", "mask", "src", "dst", "portrange",
        "inbound", "outbound", "less", "greater", "gateway",
        "broadcast", "multicast", "proto", "protochain", "len",
        "vlan", "mpls",
    }
    LOGICAL_OPS = {"and", "or", "not"}

    ARITHMETIC_OPS = {"+", "-", "*", "/", "%"}
    BITWISE_OPS = {"&", "|", "^", "<<", ">>"}
    RELATIONAL_OPS = {"==", "!=", ">", ">=", "<", "<=", "="}
    STRUCTURAL_SYMBOLS = {"[", "]", "(", ")", ":"}

    # Named constants usable inside expressions (tcp[tcpflags] & tcp-syn)
    NAMED_CONSTANTS = {
        "tcp-fin": 0x01, "tcp-syn": 0x02, "tcp-rst": 0x04, "tcp-push": 0x08,
        "tcp-ack": 0x10, "tcp-urg": 0x20, "tcp-ece": 0x40, "tcp-cwr": 0x80,
        "icmp-echoreply": 0, "icmp-unreach": 3, "icmp-sourcequench": 4,
        "icmp-redirect": 5, "icmp-echo": 8, "icmp-routeradvert": 9,
        "icmp-routersolicit": 10, "icmp-timxceed": 11, "icmp-paramprob": 12,
        "icmp-tstamp": 13, "icmp-tstampreply": 14, "icmp-ireq": 15,
        "icmp-ireqreply": 16, "icmp-maskreq": 17, "icmp-maskreply": 18,
    }
    # Pseudo-fields usable as tcp[tcpflags], icmp[icmptype]
    FIELD_NAMES = {"tcpflags", "icmptype", "icmpcode", "icmp6type", "icmp6code"}

    def __init__(self, filter_string: str):
        self.text = filter_string

        # Order matters: longest / most specific alternatives first.
        self.tokenizer_regex = re.compile(
            # MAC: aa:bb:cc:dd:ee:ff
            r'(?P<MAC>\b[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}\b)|'
            # IPv6 (with optional /prefix): must contain at least two ':'
            r'(?P<IPV6>(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\.\d{1,3}){0,3}(?:/\d{1,3})?)|'
            # IPv4 (with optional /prefix)
            r'(?P<IPV4>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)|'
            # Hex number
            r'(?P<HEX>0[xX][0-9a-fA-F]+)|'
            # Port range: 1000-2000
            r'(?P<RANGE>\d+-\d+)|'
            # Words (protocols, keywords, names with - . _)
            r'(?P<WORD>[a-zA-Z0-9_][a-zA-Z0-9_\-\.]*)|'
            r'(?P<LOGIC_SYM>&&|\|\|)|'
            r'(?P<REL_OP>!=|==|>=|<=|>(?!>)|<(?!<)|=)|'
            r'(?P<MATH_OP><<|>>|&|\||\^|\+|-|\*|/|%)|'
            r'(?P<NOT_SYM>!)|'
            r'(?P<SYMBOL>[\[\]\(\):])|'
            r'(?P<WS>\s+)|'
            r'(?P<UNKNOWN>.)'
        )

    def tokenize(self, strict: bool = True) -> List[Token]:
        tokens: List[Token] = []
        for m in self.tokenizer_regex.finditer(self.text):
            kind, value = m.lastgroup, m.group()

            if kind == 'WS':
                continue
            if kind == 'MAC':
                tokens.append(Token('MAC', value.lower()))
            elif kind == 'IPV6':
                tokens.append(self._classify_ipv6(value))
            elif kind == 'IPV4':
                tokens.append(self._classify_ipv4(value))
            elif kind == 'RANGE':
                tokens.append(Token('RANGE', value))
            elif kind == 'HEX':
                tokens.append(Token('NUMBER', str(int(value, 16))))
            elif kind == 'LOGIC_SYM':
                tokens.append(Token('LOGICAL', 'and' if value == '&&' else 'or'))
            elif kind == 'NOT_SYM':
                tokens.append(Token('LOGICAL', 'not'))
            elif kind in ('SYMBOL', 'REL_OP', 'MATH_OP'):
                tokens.append(Token(kind, '==' if value == '=' else value))
            elif kind == 'WORD':
                tokens.append(self._classify_word(value))
            elif kind == 'UNKNOWN':
                if strict:
                    raise SyntaxError(f"Lexer Error: Unknown character '{value}' at {m.start()}")
        return tokens

    # ------------------------------------------------------------------
    @staticmethod
    def _classify_ipv4(value: str) -> Token:
        try:
            if '/' in value:
                ipaddress.IPv4Network(value, strict=False)
                return Token('IPV4_CIDR', value)
            ipaddress.IPv4Address(value)
            return Token('IPV4', value)
        except ValueError:
            raise SyntaxError(f"Lexer Error: Invalid IPv4 address '{value}'")

    @staticmethod
    def _classify_ipv6(value: str) -> Token:
        try:
            if '/' in value:
                ipaddress.IPv6Network(value, strict=False)
                return Token('IPV6_CIDR', value)
            ipaddress.IPv6Address(value)
            return Token('IPV6', value)
        except ValueError:
            raise SyntaxError(f"Lexer Error: Invalid IPv6 address '{value}'")

    def _classify_word(self, word: str) -> Token:
        lw = word.lower()
        if lw in self.LOGICAL_OPS:
            return Token('LOGICAL', lw)
        if lw in self.NAMED_CONSTANTS:
            return Token('NUMBER', str(self.NAMED_CONSTANTS[lw]))
        if lw in self.FIELD_NAMES:
            return Token('FIELD', lw)
        if lw in self.DLT_LINKS:
            return Token('DLT', lw)
        if lw in self.PROTO_QUALIFIERS:
            return Token('IP-PROTOCOL', lw)
        # vlan / mpls act as both keyword and ethertype; parser disambiguates
        if lw in ("vlan", "mpls"):
            return Token('KEYWORD', lw)
        if lw in self.ETHERTYPE_KEYWORDS:
            return Token('ETHERTYPE', lw)
        if lw in self.IP_PROTOCOLS:
            return Token('IP-PROTOCOL', lw)
        if lw in self.KEYWORDS:
            return Token('KEYWORD', lw)
        if word.isdigit():
            return Token('NUMBER', word)
        return Token('IDENTIFIER', word)