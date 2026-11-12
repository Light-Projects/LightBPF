# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Single cBPF instruction.

Fields mirror `struct bpf_insn`:
    code  - 16-bit opcode (class | size | mode | op)
    jt    - true-target offset (int) or symbolic label (str, pre-backpatch)
    jf    - false-target offset (int) or symbolic label (str, pre-backpatch)
    k     - immediate / offset / scratch index (int) or label (str)
"""
from dataclasses import dataclass
import struct
from typing import Union


@dataclass
class Instruction:
    code: int
    jt: Union[int, str]
    jf: Union[int, str]
    k: Union[int, str]

    def to_bytes(self) -> bytes:
        jt = self.jt if isinstance(self.jt, int) else 0
        jf = self.jf if isinstance(self.jf, int) else 0
        k = self.k if isinstance(self.k, int) else 0
        return struct.pack("HBBI", self.code, jt, jf, k & 0xFFFFFFFF)

    def __repr__(self) -> str:
        k_repr = f"0x{self.k:x}" if isinstance(self.k, int) else str(self.k)
        return (f"Instruction(code=0x{self.code:02x}, "
                f"jt={self.jt}, jf={self.jf}, k={k_repr})")