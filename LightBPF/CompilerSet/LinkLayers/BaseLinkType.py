# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Abstract base class for Data Link Type (DLT) handlers in LightBPF.

Every link layer (Ethernet, Linux Cooked SLL, Null/Loopback, Raw IP, etc.)
inherits from BaseLinkType and implements the compilation logic for link,
network, and transport layer filters.
"""

from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from LightPacket.LightBPF.CompilerSet.Compiler import BpfCompilerNG
    from LightPacket.LightBPF.Parser import (
        ProtocolNode, KeywordFilterNode, ByteAccessNode
    )


class BaseLinkType(ABC):
    """Abstract interface for a specific data link type (DLT)."""

    linktype: int = 1
    name: str = "BaseLinkType"

    def __init__(self, compiler: "BpfCompilerNG"):
        self.compiler = compiler

    @abstractmethod
    def reset(self) -> None:
        """Reset link-specific offsets and state before compiling a new expression."""
        pass

    @abstractmethod
    def compile_protocol(self, node: "ProtocolNode", true_target: str, false_target: str) -> None:
        """Compile a standalone protocol check (e.g. 'ip', 'tcp', 'arp')."""
        pass

    @abstractmethod
    def compile_host(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile a host address filter ('host 1.2.3.4', 'ether host ...', etc.)."""
        pass

    @abstractmethod
    def compile_net(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile a network CIDR filter ('net 192.168.1.0/24', etc.)."""
        pass

    @abstractmethod
    def compile_port(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile a port filter ('port 80', 'src port 53', etc.)."""
        pass

    @abstractmethod
    def compile_portrange(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile a port range filter ('portrange 1000-2000')."""
        pass

    @abstractmethod
    def compile_broadcast(self, true_target: str, false_target: str) -> None:
        """Compile a broadcast filter ('broadcast')."""
        pass

    @abstractmethod
    def compile_multicast(self, true_target: str, false_target: str) -> None:
        """Compile a multicast filter ('multicast')."""
        pass

    @abstractmethod
    def compile_inbound(self, true_target: str, false_target: str) -> None:
        """Compile an inbound filter ('inbound')."""
        pass

    @abstractmethod
    def compile_outbound(self, true_target: str, false_target: str) -> None:
        """Compile an outbound filter ('outbound')."""
        pass

    @abstractmethod
    def compile_proto(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile a protocol-number or proto keyword filter ('proto 6', etc.)."""
        pass

    @abstractmethod
    def compile_vlan(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile a VLAN encapsulation filter ('vlan', 'vlan 100')."""
        pass

    @abstractmethod
    def compile_mpls(self, node: "KeywordFilterNode", true_target: str, false_target: str) -> None:
        """Compile an MPLS encapsulation filter ('mpls', 'mpls 100')."""
        pass

    @abstractmethod
    def compile_byte_access(self, node: "ByteAccessNode", false_target: str) -> None:
        """Compile protocol byte access (e.g. 'ip[0]', 'tcp[13]')."""
        pass
