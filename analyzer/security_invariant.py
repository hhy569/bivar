#!/usr/bin/env python3
"""
BIVAR: Security Invariant IR Module.

Translates detected security checks into structured security invariants.
"""

import json
import re


class SecurityInvariant:
    """
    Represents a security invariant extracted from a patch.
    """
    
    def __init__(self, invariant_type):
        self.type = invariant_type  # LENGTH_CHECK / NULL_CHECK / INTEGER_OVERFLOW
        self.subject = None          # What is being checked (pointer / buffer / value)
        self.condition = None        # The condition that must hold
        self.guard_instruction = None # The CMP/TEST instruction
        self.branch_instruction = None # The conditional branch
        self.failure_path = None     # Where the branch goes on failure
        self.protected_operation = None # What operation is protected
        self.confidence = 0.0
        self.evidence = []
    
    def to_dict(self):
        return {
            'type': self.type,
            'subject': self.subject,
            'condition': self.condition,
            'guard_instruction': self.guard_instruction,
            'branch_instruction': self.branch_instruction,
            'failure_path': self.failure_path,
            'protected_operation': self.protected_operation,
            'confidence': self.confidence,
            'evidence': self.evidence
        }
    
    def __str__(self):
        return f"SecurityInvariant({self.type}: {self.condition})"


def extract_length_invariant(guard, instructions, context_start, context_end):
    """
    Extract a length-check security invariant from a guard pattern.
    """
    invariant = SecurityInvariant('LENGTH_CHECK')
    
    cmp_mnem, cmp_ops = guard['cmp_instruction']
    branch_mnem, branch_ops = guard['branch_instruction']
    
    # Parse the comparison
    # Typical: cmp length, required_size
    parts = [p.strip() for p in cmp_ops.split(',')]
    
    if len(parts) == 2:
        invariant.subject = parts[0]
        invariant.condition = f"{parts[0]} >= {parts[1]}"
        invariant.evidence.append(f"Compare {parts[0]} with {parts[1]}")
    
    invariant.guard_instruction = f"{cmp_mnem} {cmp_ops}"
    invariant.branch_instruction = f"{branch_mnem} {branch_ops}"
    
    # Infer failure path
    if branch_mnem in ('jb', 'jl', 'jb', 'jae'):
        invariant.failure_path = "reject/early return"
        invariant.evidence.append("Conditional branch to error path")
    
    # Look for protected operation after the guard
    # (memory access that follows the guard)
    invariant.protected_operation = "raw struct/buffer access"
    
    invariant.confidence = 0.8
    
    return invariant


def extract_null_invariant(guard, instructions, context_start, context_end):
    """
    Extract a null-check security invariant from a guard pattern.
    """
    invariant = SecurityInvariant('NULL_CHECK')
    
    cmp_mnem, cmp_ops = guard['cmp_instruction']
    branch_mnem, branch_ops = guard['branch_instruction']
    
    # Test rax, rax / cmp rax, 0
    parts = [p.strip() for p in cmp_ops.split(',')]
    
    invariant.subject = parts[0] if parts else 'pointer'
    invariant.condition = f"{invariant.subject} != NULL"
    invariant.evidence.append(f"{cmp_mnem} checks if {invariant.subject} is null")
    
    invariant.guard_instruction = f"{cmp_mnem} {cmp_ops}"
    invariant.branch_instruction = f"{branch_mnem} {branch_ops}"
    invariant.failure_path = "reject/early return (null)"
    invariant.protected_operation = "pointer dereference"
    
    invariant.confidence = 0.9
    
    return invariant


def extract_integer_invariant(guard, instructions, context_start, context_end):
    """
    Extract an integer-overflow security invariant from a guard pattern.
    """
    invariant = SecurityInvariant('INTEGER_OVERFLOW_CHECK')
    
    cmp_mnem, cmp_ops = guard['cmp_instruction']
    branch_mnem, branch_ops = guard['branch_instruction']
    
    invariant.subject = 'arithmetic_result'
    invariant.condition = "arithmetic operation did not overflow"
    invariant.evidence.append(f"{cmp_mnem} detects overflow condition")
    invariant.evidence.append("Branch rejects on overflow")
    
    invariant.guard_instruction = f"{cmp_mnem} {cmp_ops}"
    invariant.branch_instruction = f"{branch_mnem} {branch_ops}"
    invariant.failure_path = "reject on overflow"
    invariant.protected_operation = "array index / memory offset calculation"
    
    invariant.confidence = 0.85
    
    return invariant


def extract_security_invariant(guard, instructions, context_start, context_end):
    """
    Main function: extract security invariant from a guard pattern.
    """
    cmp_mnem, cmp_ops = guard['cmp_instruction']
    
    # Classify the type
    if cmp_mnem == 'test':
        # Likely null check
        invariant = extract_null_invariant(guard, instructions, context_start, context_end)
    elif 'cmp' in cmp_mnem and any(x in cmp_ops for x in ['length', 'size', 'buf', 'data']):
        # Likely length check
        invariant = extract_length_invariant(guard, instructions, context_start, context_end)
    elif any(x in cmp_ops for x in ['overflow', 'carry', 'jc', 'jo']):
        # Likely integer overflow check
        invariant = extract_integer_invariant(guard, instructions, context_start, context_end)
    else:
        # Generic guard
        invariant = SecurityInvariant('GENERIC_GUARD')
        invariant.condition = "conditional guard detected"
        invariant.confidence = 0.5
    
    return invariant


def analyze_invariants_from_diff(old_insts, new_insts, differences):
    """
    Analyze a function diff to extract all security invariants.
    """
    invariants = []
    
    # Look for added guard patterns in the new version
    # (Simplified: we just look for CMP + conditional branch pairs)
    
    added_insts = []
    for d in differences:
        if d['type'] == 'added':
            added_insts.append(d['instruction'])
    
    # Find guard patterns in added instructions
    for i in range(len(added_insts) - 1):
        mn, ops = added_insts[i]
        
        if mn in ('cmp', 'test'):
            for j in range(i + 1, min(i + 5, len(added_insts))):
                next_mn, next_ops = added_insts[j]
                if next_mn.startswith('j') and next_mn != 'jmp':
                    # Found a guard pattern!
                    guard = {
                        'cmp_instruction': (mn, ops),
                        'branch_instruction': (next_mn, next_ops)
                    }
                    
                    invariant = extract_security_invariant(
                        guard, new_insts, i, j
                    )
                    invariants.append(invariant)
                    break
    
    return invariants


if __name__ == '__main__':
    # Quick test
    from security_semantic import analyze_function_security
    
    # Test with a simple example
    test_new = [
        (0x401200, 'cmp', 'rax, 0x1f'),
        (0x401204, 'jb', '0x401220'),
        (0x401206, 'mov', 'rax, [rdi+0x20]'),
    ]
    
    print("Testing invariant extraction...")
    print("Sample instructions:")
    for addr, mnem, ops in test_new:
        print(f"  0x{addr:x}: {mnem} {ops}")
    
    # Create a mock guard
    guard = {
        'cmp_instruction': ('cmp', 'rax, 0x1f'),
        'branch_instruction': ('jb', '0x401220')
    }
    
    invariant = extract_security_invariant(guard, test_new, 0, 1)
    print("\nExtracted invariant:")
    print(json.dumps(invariant.to_dict(), indent=2))
