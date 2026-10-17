# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""ctypes bindings for struct sock_fprog / struct bpf_insn.

Used for SO_ATTACH_FILTER on Linux. The returned sock_fprog keeps a
reference to its backing ctypes array so the buffer is not GC'd while
the kernel holds the pointer.
"""
import ctypes
from typing import List
from LightPacket.LightBPF.CompilerSet.Instruction import Instruction


class bpf_insn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class sock_fprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(bpf_insn)),
    ]


def to_fprog(instructions: List[Instruction]) -> sock_fprog:
    """Package a compiled program as a struct sock_fprog.

    The ctypes backing array is attached to the returned object as
    `_insn_arr` so it stays alive for the lifetime of the fprog.
    """
    arr_type = bpf_insn * len(instructions)
    insn_arr = arr_type()
    for idx, instr in enumerate(instructions):
        insn_arr[idx].code = instr.code
        insn_arr[idx].jt = instr.jt if isinstance(instr.jt, int) else 0
        insn_arr[idx].jf = instr.jf if isinstance(instr.jf, int) else 0
        insn_arr[idx].k = (instr.k if isinstance(instr.k, int) else 0) & 0xFFFFFFFF
    fprog = sock_fprog(len(instructions),
                       ctypes.cast(insn_arr, ctypes.POINTER(bpf_insn)))
    fprog._insn_arr = insn_arr  # type: ignore[attr-defined]
    return fprog