#!/usr/bin/env python3
"""
BIVAR: Binary Vulnerability Variant Analyzer
Security Semantic Analyzer module.

Identifies security-relevant patterns in binary diffs.
"""

import re
from collections import defaultdict


# Instruction normalization patterns
REGISTER_PATTERN = re.compile(r'\b(r\d+[sd]?|e\d+[sd]?|[abcd][xl]|sp|bp|si|di)\b', re.IGNORECASE)
HEX_IMM_PATTERN = re.compile(r'\b0x[0-9a-f]+\b', re.IGNORECASE)
MEMORY_PATTERN = re.compile(r'\[([a-z0-9+*]+)\]', re.IGNORECASE)


def normalize_instruction(mnemonic, operands):
    """
    Normalize an instruction for comparison.
    Returns (normalized_mnemonic, normalized_operands, features_dict)
    """
    mn = mnemonic.lower()
    op = operands

    # Normalize registers: all become REG
    op_norm = REGISTER_PATTERN.sub('REG', op)

    # Normalize hex immediates: keep value but mark as IMM
    def replace_imm(match):
        val = int(match.group(0), 16)
        return f'IMM({val})'
    op_norm = HEX_IMM_PATTERN.sub(replace_imm, op_norm)

    # Normalize memory accesses
    def replace_mem(match):
        inner = match.group(1)
        # Simplify: [base + offset] -> [BASE+OFF]
        return '[MEM]'
    op_norm = MEMORY_PATTERN.sub(replace_mem, op_norm)

    # Extract features
    features = {
        'is_cmp': mn in ('cmp', 'test'),
        'is_conditional_branch': mn.startswith('j') and mn != 'jmp',
        'is_unconditional_branch': mn == 'jmp',
        'is_call': mn == 'call',
        'is_return': mn in ('ret', 'retn'),
        'is_memory_write': mn in ('mov', 'movq', 'movl') and '[' in op and not op.strip().startswith('['),
        'has_hex_imm': bool(HEX_IMM_PATTERN.search(op)),
        'has_memory': bool(MEMORY_PATTERN.search(op)),
        'mnemonic': mn,
        'operands': op_norm,
        'raw_operands': op,
    }

    return mn, op_norm, features


def find_guard_patterns(instructions):
    """
    Find guard patterns: CMP followed by conditional branch.
    Returns list of guard patterns.
    """
    guards = []

    for i in range(len(instructions) - 1):
        mn, ops, feat = instructions[i]

        if feat['is_cmp']:
            # Look ahead for conditional branch
            for j in range(i + 1, min(i + 5, len(instructions))):
                next_mn, next_ops, next_feat = instructions[j]

                if next_feat['is_conditional_branch']:
                    # Found a guard pattern!
                    guard = {
                        'cmp_index': i,
                        'branch_index': j,
                        'cmp_instruction': (mn, ops),
                        'branch_instruction': (next_mn, next_ops),
                        'branch_type': next_mn,
                        'condition': infer_condition(mn, ops, next_mn),
                    }
                    guards.append(guard)
                    break

                if next_feat['is_unconditional_branch'] or next_feat['is_call']:
                    break

    return guards


def infer_condition(cmp_mn, cmp_ops, branch_mn):
    """
    Infer what condition this guard is checking.
    """
    branch = branch_mn.lower()

    # Map branch mnemonics to conditions
    branch_conditions = {
        'je': 'equal (== 0)',
        'jz': 'equal (== 0)',
        'jne': 'not equal (!= 0)',
        'jnz': 'not equal (!= 0)',
        'jb': 'below (unsigned <)',
        'jl': 'less (signed <)',
        'jbe': 'below or equal (unsigned <=)',
        'jle': 'less or equal (signed <=)',
        'ja': 'above (unsigned >)',
        'jg': 'greater (signed >)',
        'jae': 'above or equal (unsigned >=)',
        'jge': 'greater or equal (signed >=)',
    }

    return branch_conditions.get(branch, branch)


def classify_security_guard(guard, context_instructions):
    """
    Classify whether a guard pattern is likely a security check.
    Returns classification dict.
    """
    cmp_mn, cmp_ops = guard['cmp_instruction']
    branch_mn, branch_ops = guard['branch_instruction']

    # Heuristics for security check classification
    score = 0
    reasons = []

    # Heuristic 1: Comparing with a small immediate (likely size check)
    if 'IMM(' in cmp_ops:
        # Extract the immediate value
        imm_match = re.search(r'IMM\((\d+)\)', cmp_ops)
        if imm_match:
            imm_val = int(imm_match.group(1))
            # Common sizes: 4, 8, 16, 20, 32, 40, 48, 52, 56
            common_sizes = [4, 8, 12, 16, 20, 24, 32, 40, 48, 52, 56, 64]
            if imm_val in common_sizes or imm_val < 256:
                score += 2
                reasons.append(f'compares with small immediate {imm_val} (likely size check)')

    # Heuristic 2: Test instruction (null check)
    if cmp_mn == 'test':
        score += 3
        reasons.append('test instruction (likely NULL pointer check)')

    # Heuristic 3: Conditional branch goes to a function that looks like error handling
    # (We don't have full CFG, so this is weak for now)

    # Heuristic 4: Compare two registers (likely bounds check)
    if 'REG' in cmp_ops and ',' in cmp_ops and 'IMM' not in cmp_ops:
        score += 1
        reasons.append('comparing two registers (likely bounds/range check)')

    # Determine category
    category = 'UNKNOWN'
    if score >= 5:
        if cmp_mn == 'test':
            category = 'NULL_CHECK'
        elif 'IMM(' in cmp_ops:
            category = 'LENGTH_CHECK'
        else:
            category = 'BOUNDS_CHECK'
    elif score >= 3:
        if cmp_mn == 'test':
            category = 'NULL_CHECK_CANDIDATE'
        elif 'IMM(' in cmp_ops:
            category = 'LENGTH_CHECK_CANDIDATE'
        else:
            category = 'GUARD_CANDIDATE'

    return {
        'category': category,
        'score': score,
        'reasons': reasons,
        'guard': guard,
    }


def analyze_function_security(old_instructions, new_instructions):
    """
    Full security analysis of a function diff.
    """
    # Normalize both instruction lists
    old_norm = []
    for inst in old_instructions:
        if len(inst) == 3:
            addr, mnem, ops = inst
            mn, op_norm, feat = normalize_instruction(mnem, ops)
            old_norm.append((mn, op_norm, feat))

    new_norm = []
    for inst in new_instructions:
        if len(inst) == 3:
            addr, mnem, ops = inst
            mn, op_norm, feat = normalize_instruction(mnem, ops)
            new_norm.append((mn, op_norm, feat))

    # Find guard patterns in new version
    new_guards = find_guard_patterns(new_norm)

    # Find guard patterns in old version
    old_guards = find_guard_patterns(old_norm)

    # Guards that are only in new version = added security checks
    added_guards = []
    for guard in new_guards:
        # Simple heuristic: if this guard wasn't in old version, it's added
        # (More sophisticated: compare normalized guards)
        added_guards.append(guard)

    # Classify each added guard
    security_findings = []
    for guard in added_guards:
        classification = classify_security_guard(guard, new_norm)
        if classification['category'] != 'UNKNOWN':
            security_findings.append(classification)

    result = {
        'old_guard_count': len(old_guards),
        'new_guard_count': len(new_guards),
        'added_guards': len(added_guards),
        'security_findings': security_findings,
    }

    return result


if __name__ == '__main__':
    import sys
    import json
    import subprocess
    import re

    # Quick test
    test_instructions = [
        (0x401200, 'cmp', 'rax, 0x1f'),
        (0x401204, 'jb', '0x401220'),
        (0x401206, 'mov', 'rax, [rdi+0x20]'),
    ]

    print("Testing guard pattern detection...")
    result = analyze_function_security(test_instructions, test_instructions)
    print(json.dumps(result, indent=2))
