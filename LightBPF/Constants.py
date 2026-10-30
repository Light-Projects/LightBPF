# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Named protocol, DLT, and packet offset constants for LightBPF.

Eliminates magic numbers and magic strings throughout the compiler,
disassembler, and link-type modules.
"""

from typing import Dict, Tuple

# ----------------------------------------------------------------------
# Data Link Types (DLT) - standard libpcap values
# ----------------------------------------------------------------------
DLT_NULL = 0             # BSD loopback
DLT_EN10MB = 1           # Ethernet (10Mb, 100Mb, 1Gb, 10Gb, etc.)
DLT_IEEE802 = 6          # Token Ring
DLT_ARCNET = 7           # ARCNET
DLT_SLIP = 8             # SLIP
DLT_PPP = 9              # PPP
DLT_FDDI = 10            # FDDI
DLT_RAW = 12             # Raw IP (no link header)
DLT_LOOP = 108           # OpenBSD loopback
DLT_LINUX_SLL = 113      # Linux "cooked" capture encapsulation
DLT_IEEE802_11 = 105     # IEEE 802.11 wireless
DLT_IEEE802_11_RADIO = 127 # 802.11 plus radiotap header

# ----------------------------------------------------------------------
# Standard EtherType values (16-bit)
# ----------------------------------------------------------------------
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_RARP = 0x8035
ETHERTYPE_VLAN_8021Q = 0x8100
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_MPLS_UC = 0x8847
ETHERTYPE_MPLS_MC = 0x8848
ETHERTYPE_PPPOE_DISC = 0x8863
ETHERTYPE_PPPOE_SESS = 0x8864
ETHERTYPE_VLAN_8021AD = 0x88A8  # QinQ / 802.1ad Service VLAN
ETHERTYPE_VLAN_9100 = 0x9100

VLAN_ETHERTYPES = (ETHERTYPE_VLAN_8021Q, ETHERTYPE_VLAN_8021AD, ETHERTYPE_VLAN_9100)
MPLS_ETHERTYPES = (ETHERTYPE_MPLS_UC, ETHERTYPE_MPLS_MC)

# ----------------------------------------------------------------------
# IP Protocol numbers (8-bit)
# ----------------------------------------------------------------------
IPPROTO_IP = 0
IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
IPPROTO_IPIP = 4
IPPROTO_TCP = 6
IPPROTO_EGP = 8
IPPROTO_PUP = 12
IPPROTO_UDP = 17
IPPROTO_DCCP = 33
IPPROTO_IPV6 = 41
IPPROTO_ROUTING = 43
IPPROTO_FRAGMENT = 44
IPPROTO_RSVP = 46
IPPROTO_GRE = 47
IPPROTO_ESP = 50
IPPROTO_AH = 51
IPPROTO_ICMPV6 = 58
IPPROTO_NONE = 59
IPPROTO_DSTOPTS = 60
IPPROTO_IGRP = 88
IPPROTO_OSPF = 89
IPPROTO_PIM = 103
IPPROTO_VRRP = 112
IPPROTO_SCTP = 132

# Protocols that only exist natively in IPv4 or IPv6
IPV4_ONLY_PROTOCOLS = {"icmp", "igmp", "igrp", "pup"}
IPV6_ONLY_PROTOCOLS = {"icmp6", "ipv6-route", "ipv6-nonxt", "ipv6-opts"}

# ----------------------------------------------------------------------
# Common Header Offsets & Lengths for Ethernet (DLT_EN10MB = 1)
# ----------------------------------------------------------------------
ETH_DST_OFF = 0
ETH_SRC_OFF = 6
ETH_TYPE_OFF = 12
ETH_HLEN = 14

VLAN_TAG_LEN = 4
VLAN_VID_MASK = 0x0FFF
MPLS_LABEL_LEN = 4

# Fixed IPv4 Offsets from start of Ethernet frame (standard 14-byte Ethernet header)
IPV4_HLEN_MIN = 20
IPV4_VER_IHL_OFF = 14      # Offset 14: Version (4 bits) + IHL (4 bits)
IPV4_TOS_OFF = 15
IPV4_LEN_OFF = 16
IPV4_ID_OFF = 18
IPV4_FRAG_OFF = 20         # Flags (3 bits) + Fragment Offset (13 bits)
IPV4_TTL_OFF = 22
IPV4_PROTO_OFF = 23
IPV4_CHKSUM_OFF = 24
IPV4_SRC_OFF = 26
IPV4_DST_OFF = 30

IPV4_FRAG_MASK = 0x1FFF     # Mask to extract fragment offset (non-first fragment check)

# Fixed IPv6 Offsets from start of Ethernet frame
IPV6_HLEN = 40
IPV6_VER_TC_FL_OFF = 14
IPV6_PLEN_OFF = 18
IPV6_PROTO_OFF = 20        # Next Header offset
IPV6_HLIM_OFF = 21
IPV6_SRC_OFF = 22          # 16-byte source IPv6 (offsets 22..37)
IPV6_DST_OFF = 38          # 16-byte dest IPv6 (offsets 38..53)

IPV6_FRAG_HDR_LEN = 8
IPV6_FRAG_NEXT_HDR_OFF = 54 # When fragment header follows IPv6 directly at 14+40=54

# Transport layer offsets relative to transport base
TRANSPORT_SRC_PORT_OFF = 0
TRANSPORT_DST_PORT_OFF = 2

# Special pseudo-field offsets for AST ByteAccess / FieldNode
FIELD_OFFSETS: Dict[str, Tuple[int, int]] = {
    "tcpflags":  (13, 1),
    "icmptype":  (0, 1),
    "icmpcode":  (1, 1),
    "icmp6type": (0, 1),
    "icmp6code": (1, 1),
}

# ----------------------------------------------------------------------
# Well-known service port mappings
# ----------------------------------------------------------------------
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
