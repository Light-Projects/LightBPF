# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Classic BPF (cBPF) opcode constants.

Values are from the Linux kernel <linux/filter.h> and BSD <net/bpf.h>.
"""

# Instruction classes (code & 0x07)
BPF_LD   = 0x00
BPF_LDX  = 0x01
BPF_ST   = 0x02
BPF_STX  = 0x03
BPF_ALU  = 0x04
BPF_JMP  = 0x05
BPF_RET  = 0x06
BPF_MISC = 0x07

# Size modifiers (code & 0x18)
BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10

# Addressing modes (code & 0xe0)
BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xa0

# ALU ops (code & 0xf0)
BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR  = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xa0

# Jump ops (code & 0xf0)
BPF_JA   = 0x00
BPF_JEQ  = 0x10
BPF_JGT  = 0x20
BPF_JGE  = 0x30
BPF_JSET = 0x40

# Source operand (code & 0x08)
BPF_K = 0x00
BPF_X = 0x08

# Misc ops (code & 0xf8)
BPF_TAX = 0x00
BPF_TXA = 0x80

# Return-mode selector
BPF_A = 0x10

# Default snaplen (matches libpcap)
BPF_MAX_BUF_LEN = 0x40000


def insn_class(code): return code & 0x07
def insn_size(code):  return code & 0x18
def insn_mode(code):  return code & 0xe0
def insn_op(code):    return code & 0xf0
def insn_src(code):   return code & 0x08