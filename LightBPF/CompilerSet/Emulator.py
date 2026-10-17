# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Pure-Python cBPF virtual machine.

Executes a compiled program against raw packet bytes and returns the
captured length (0 = reject).
"""
import struct
from typing import List
from LightPacket.LightBPF.CompilerSet.Instruction import Instruction
from LightPacket.LightBPF.CompilerSet.Opcode import (
    BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC,
    BPF_W, BPF_H ,BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH,
    BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH,
    BPF_NEG, BPF_MOD, BPF_XOR,
    BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
    BPF_X, BPF_TAX, BPF_TXA, BPF_A,
)


class BpfEmulator:
    """Interprets cBPF bytecode against a raw packet."""

    @staticmethod
    def execute(instructions: List[Instruction], packet: bytes) -> int:
        A = 0
        X = 0
        M = [0] * 16
        pc = 0
        pkt_len = len(packet)

        def read(off: int, sz: int) -> int:
            if off < 0 or off + sz > pkt_len:
                return 0
            if sz == 1:
                return packet[off]
            if sz == 2:
                return struct.unpack("!H", packet[off:off + 2])[0]
            return struct.unpack("!I", packet[off:off + 4])[0]

        while 0 <= pc < len(instructions):
            insn = instructions[pc]
            cls = insn.code & 0x07
            size = insn.code & 0x18
            mode = insn.code & 0xe0
            op = insn.code & 0xf0
            src = insn.code & 0x08
            sz_bytes = 4 if size == BPF_W else (2 if size == BPF_H else 1)

            if cls == BPF_LD:
                if mode == BPF_IMM:
                    A = insn.k & 0xFFFFFFFF
                elif mode == BPF_ABS:
                    if insn.k + sz_bytes > pkt_len:
                        return 0
                    A = read(insn.k, sz_bytes)
                elif mode == BPF_IND:
                    if X + insn.k + sz_bytes > pkt_len:
                        return 0
                    A = read(X + insn.k, sz_bytes)
                elif mode == BPF_MEM:
                    A = M[insn.k] if 0 <= insn.k < 16 else 0
                elif mode == BPF_LEN:
                    A = pkt_len
                pc += 1

            elif cls == BPF_LDX:
                if mode == BPF_IMM:
                    X = insn.k & 0xFFFFFFFF
                elif mode == BPF_MEM:
                    X = M[insn.k] if 0 <= insn.k < 16 else 0
                elif mode == BPF_LEN:
                    X = pkt_len
                elif mode == BPF_MSH:
                    if insn.k >= pkt_len:
                        return 0
                    X = 4 * (packet[insn.k] & 0x0F)
                pc += 1

            elif cls == BPF_ST:
                if 0 <= insn.k < 16:
                    M[insn.k] = A & 0xFFFFFFFF
                pc += 1

            elif cls == BPF_STX:
                if 0 <= insn.k < 16:
                    M[insn.k] = X & 0xFFFFFFFF
                pc += 1

            elif cls == BPF_ALU:
                val = X if src == BPF_X else insn.k
                if op == BPF_ADD:
                    A = (A + val) & 0xFFFFFFFF
                elif op == BPF_SUB:
                    A = (A - val) & 0xFFFFFFFF
                elif op == BPF_MUL:
                    A = (A * val) & 0xFFFFFFFF
                elif op == BPF_DIV:
                    if val == 0: return 0
                    A = (A // val) & 0xFFFFFFFF
                elif op == BPF_MOD:
                    if val == 0: return 0
                    A = (A % val) & 0xFFFFFFFF
                elif op == BPF_AND:
                    A = (A & val) & 0xFFFFFFFF
                elif op == BPF_OR:
                    A = (A | val) & 0xFFFFFFFF
                elif op == BPF_XOR:
                    A = (A ^ val) & 0xFFFFFFFF
                elif op == BPF_LSH:
                    A = (A << (val & 31)) & 0xFFFFFFFF
                elif op == BPF_RSH:
                    A = (A >> (val & 31)) & 0xFFFFFFFF
                elif op == BPF_NEG:
                    A = (-A) & 0xFFFFFFFF
                pc += 1

            elif cls == BPF_JMP:
                if op == BPF_JA:
                    pc += 1 + insn.k
                else:
                    val = X if src == BPF_X else insn.k
                    if op == BPF_JEQ:
                        cond = (A == val)
                    elif op == BPF_JGT:
                        cond = (A > val)
                    elif op == BPF_JGE:
                        cond = (A >= val)
                    elif op == BPF_JSET:
                        cond = ((A & val) != 0)
                    else:
                        return 0
                    pc += 1 + (insn.jt if cond else insn.jf)

            elif cls == BPF_RET:
                if mode == BPF_A:
                    return A
                return insn.k

            elif cls == BPF_MISC:
                if op == BPF_TAX:
                    X = A
                elif op == BPF_TXA:
                    A = X
                pc += 1
            else:
                return 0
        return 0