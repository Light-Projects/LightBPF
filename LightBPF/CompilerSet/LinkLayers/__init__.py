# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""LinkLayer registration and exports for LightBPF."""

from LightPacket.LightBPF.CompilerSet.LinkLayers.BaseLinkType import BaseLinkType
from LightPacket.LightBPF.CompilerSet.LinkLayers.Ethernet import EthernetLinkType

__all__ = ["BaseLinkType", "EthernetLinkType"]
