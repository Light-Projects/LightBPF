# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""cBPF disassembler (tcpdump-style) and C-struct-literal dumper."""
from typing import List
from LightPacket.LightBPF.CompilerSet.Instruction import Instruction
from LightPacket.LightBPF.CompilerSet.Opcode import (
    BPF_LD, BPF_LDX, BPF_ST, BPF_STX, BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC,
    BPF_W, BPF_H, BPF_B, BPF_IMM, BPF_ABS, BPF_IND, BPF_MEM, BPF_LEN, BPF_MSH,
    BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH,
    BPF_NEG, BPF_MOD, BPF_XOR,
    BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET,
    BPF_X, BPF_TAX, BPF_A,
)

_ALU_NAMES = {
    BPF_ADD: "add", BPF_SUB: "sub", BPF_MUL: "mul", BPF_DIV: "div",
    BPF_MOD: "mod", BPF_AND: "and", BPF_OR: "or", BPF_XOR: "xor",
    BPF_LSH: "lsh", BPF_RSH: "rsh", BPF_NEG: "neg",
}
_JMP_NAMES = {BPF_JEQ: "jeq", BPF_JGT: "jgt", BPF_JGE: "jge", BPF_JSET: "jset"}
_SIZE_NAMES = {BPF_W: "w", BPF_H: "h", BPF_B: "b"}


def disassemble(instructions: List[Instruction]) -> str:
    lines = []
    for i, insn in enumerate(instructions):
        cls = insn.code & 0x07
        size = insn.code & 0x18
        mode = insn.code & 0xe0
        op = insn.code & 0xf0
        src = insn.code & 0x08
        sz = _SIZE_NAMES.get(size, "")

        if cls == BPF_LD:
            if mode == BPF_IMM:
                text = f"ld   #{insn.k}"
            elif mode == BPF_ABS:
                text = f"ld{sz}   [{insn.k}]"
            elif mode == BPF_IND:
                text = f"ld{sz}   [x + {insn.k}]"
            elif mode == BPF_MEM:
                text = f"ld   M[{insn.k}]"
            elif mode == BPF_LEN:
                text = "ld   #len"
            else:
                text = f"ld   mode=0x{mode:x}"
        elif cls == BPF_LDX:
            if mode == BPF_MSH:
                text = f"ldxb   4*([{insn.k}]&0xf)"
            elif mode == BPF_IMM:
                text = f"ldx   #{insn.k}"
            elif mode == BPF_MEM:
                text = f"ldx   M[{insn.k}]"
            elif mode == BPF_LEN:
                text = "ldx    #len"
            else:
                text = f"ldx   mode=0x{mode:x}"
        elif cls == BPF_ST:
            text = f"st   M[{insn.k}]"
        elif cls == BPF_STX:
            text = f"stx   M[{insn.k}]"
        elif cls == BPF_ALU:
            name = _ALU_NAMES.get(op, "alu")
            operand = "x" if src == BPF_X else f"#{insn.k}"
            text = f"{name}   {operand}"
        elif cls == BPF_JMP:
            if op == BPF_JA:
                text = f"ja   {i + 1 + insn.k}"
            else:
                name = _JMP_NAMES.get(op, "jmp")
                operand = "x" if src == BPF_X else f"#{hex(int(insn.k))}"
                text = f"{name}   {operand}  jt {i + 1 + insn.jt}   jf {i + 1 + insn.jf}"
        elif cls == BPF_RET:
            text = "ret   a" if mode == BPF_A else f"ret   #{hex(int(insn.k))}"
        elif cls == BPF_MISC:
            text = "tax" if op == BPF_TAX else "txa"
        else:
            text = f"raw   0x{insn.code:02x}"

        lines.append(f"({i:03d}) {text}")
    return "\n".join(lines)


def c_str_style(instructions: List[Instruction]) -> None:
    """Print instructions as C struct-literal initialisers."""
    for ins in instructions:
        jt = hex(ins.jt) if isinstance(ins.jt, int) else repr(ins.jt)
        jf = hex(ins.jf) if isinstance(ins.jf, int) else repr(ins.jf)
        k = hex(ins.k) if isinstance(ins.k, int) else repr(ins.k)
        print(f'{{ {hex(ins.code):5},{jt:>4},{jf:>4},{k:>10} }}')