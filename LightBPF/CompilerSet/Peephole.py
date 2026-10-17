# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Instruction-level peephole optimizations for cBPF programs.

Runs on a fully-assembled program (labels already resolved to numeric
offsets). Three passes, applied in order:

  1. ``_remove_noop_jumps``  - delete unconditional `ja +0` no-ops.
  2. ``_thread_jumps``       - redirect every jump whose target is an
                               unconditional `ja` to the ja's own target.
                               Removes the intermediate hop.
  3. ``_eliminate_dead_code`` - remove instructions unreachable from the
                               entry point.

All passes preserve semantics: they only remove work or short-circuit
jumps that would have executed anyway.
"""
from typing import List,Set
from LightPacket.LightBPF.CompilerSet.Instruction import Instruction
from LightPacket.LightBPF.CompilerSet.Opcode import BPF_JMP, BPF_JA, BPF_RET, insn_class, insn_op


def optimize(code: List[Instruction]) -> List[Instruction]:
    code = _remove_noop_jumps(code)
    code = _thread_jumps(code)
    code = _eliminate_dead_code(code)
    # Dead-code removal may have exposed new jump-thread opportunities.
    code = _thread_jumps(code)
    return code

# ----------------------------------------------------------------------
def _jump_targets(code: List[Instruction]) -> Set[int]:
    targets: Set[int] = {0}
    n = len(code)
    for i, insn in enumerate(code):
        if insn_class(insn.code) != BPF_JMP:
            continue
        if insn_op(insn.code) == BPF_JA:
            targets.add(i + 1 + insn.k)
        else:
            targets.add(i + 1 + insn.jt)
            targets.add(i + 1 + insn.jf)
    return {t for t in targets if 0 <= t < n}

def _remap_jumps(code: List[Instruction],
                 orig_code: List[Instruction],
                 old_to_new: dict,
                 removed: Set[int]) -> None:
    """Rewrite all jumps in `code` using an index mapping from orig_code."""
    n = len(orig_code)
    kept_new_indices = []
    kept_orig_indices = []
    for old_i, new_i in old_to_new.items():
        kept_new_indices.append(new_i)
        kept_orig_indices.append(old_i)
    # invert for convenience
    new_to_old = {new_i: old_i for old_i, new_i in old_to_new.items()}

    def next_kept(idx: int) -> int:
        while idx < n and idx in removed:
            idx += 1
        return idx

    for new_i, insn in enumerate(code):
        old_i = new_to_old[new_i]
        orig = orig_code[old_i]
        cls = insn_class(orig.code)
        if cls != BPF_JMP:
            continue
        if insn_op(orig.code) == BPF_JA:
            tgt = next_kept(old_i + 1 + orig.k)
            insn.k = old_to_new.get(tgt, tgt) - (new_i + 1)
        else:
            tgt_t = next_kept(old_i + 1 + orig.jt)
            tgt_f = next_kept(old_i + 1 + orig.jf)
            insn.jt = old_to_new.get(tgt_t, tgt_t) - (new_i + 1)
            insn.jf = old_to_new.get(tgt_f, tgt_f) - (new_i + 1)


def _apply_removals(code: List[Instruction],
                    removed: Set[int]) -> List[Instruction]:
    if not removed:
        return code
    old_to_new = {}
    new_code = []
    for i, insn in enumerate(code):
        if i in removed:
            continue
        old_to_new[i] = len(new_code)
        new_code.append(insn)
    _remap_jumps(new_code, code, old_to_new, removed)
    return new_code


# ----------------------------------------------------------------------
# Pass 1: no-op jumps
# ----------------------------------------------------------------------
def _remove_noop_jumps(code: List[Instruction]) -> List[Instruction]:
    """Delete `ja +0` instructions (they jump to their own successor)."""
    removed = set()
    for i, insn in enumerate(code):
        if (insn_class(insn.code) == BPF_JMP
                and insn_op(insn.code) == BPF_JA
                and isinstance(insn.k, int)
                and insn.k == 0):
            removed.add(i)
    return _apply_removals(code, removed)


# ----------------------------------------------------------------------
# Pass 2: jump threading
# ----------------------------------------------------------------------
def _thread_jumps(code: List[Instruction]) -> List[Instruction]:
    """Retarget jumps that point at an unconditional `ja`."""
    n = len(code)
    if n == 0:
        return code

    def resolve(t: int) -> int:
        seen = set()
        while 0 <= t < n and t not in seen:
            seen.add(t)
            insn = code[t]
            if insn_class(insn.code) == BPF_JMP and insn_op(insn.code) == BPF_JA:
                t = t + 1 + insn.k
            else:
                break
        return t

    for i, insn in enumerate(code):
        if insn_class(insn.code) != BPF_JMP:
            continue
        if insn_op(insn.code) == BPF_JA:
            tgt = i + 1 + insn.k
            new_tgt = resolve(tgt)
            if new_tgt != tgt:
                insn.k = new_tgt - (i + 1)
        else:
            tgt = i + 1 + insn.jt
            new_tgt = resolve(tgt)
            if new_tgt != tgt:
                insn.jt = new_tgt - (i + 1)
            tgt = i + 1 + insn.jf
            new_tgt = resolve(tgt)
            if new_tgt != tgt:
                insn.jf = new_tgt - (i + 1)
    return code


# ----------------------------------------------------------------------
# Pass 3: dead-code elimination
# ----------------------------------------------------------------------
def _eliminate_dead_code(code: List[Instruction]) -> List[Instruction]:
    """Remove instructions unreachable from the entry point."""
    n = len(code)
    if n == 0:
        return code

    reachable = [False] * n
    stack = list(_jump_targets(code))
    while stack:
        pc = stack.pop()
        if pc < 0 or pc >= n or reachable[pc]:
            continue
        reachable[pc] = True
        insn = code[pc]
        cls = insn_class(insn.code)
        if cls == BPF_JMP:
            if insn_op(insn.code) == BPF_JA:
                stack.append(pc + 1 + insn.k)
            else:
                stack.append(pc + 1 + insn.jt)
                stack.append(pc + 1 + insn.jf)
                stack.append(pc + 1)
        elif cls == BPF_RET:
            continue  # terminal
        else:
            stack.append(pc + 1)

    if all(reachable):
        return code
    removed = {i for i, r in enumerate(reachable) if not r}
    return _apply_removals(code, removed)