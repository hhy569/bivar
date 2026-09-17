#!/usr/bin/env python3
"""
BIVAR: Binary Vulnerability Variant Analyzer
Diff Engine module.

Does instruction-level and basic-block-level diff between two functions.
"""

import re
from collections import defaultdict


def parse_instructions(asm_text):
    """
    Parse objdump output into structured instructions.
    Returns list of (address, mnemonic, operands) tuples.
    """
    instructions = []
    
    for line in asm_text.split('\n'):
        # Match: "  401234:	55                   	push   rbp"
        match = re.match(r'^\s+([0-9a-f]+):\s*([0-9a-f]{2,})\s+(\w+)\s*(.*)?$', line)
        if match:
            addr = int(match.group(1), 16)
            mnemonic = match.group(3)
            operands = match.group(4).strip() if match.group(4) else ''
            instructions.append((addr, mnemonic, operands))
    
    return instructions


def extract_function_asm(binary_path, function_name):
    """
    Extract assembly for a specific function from objdump output.
    """
    import subprocess
    
    result = subprocess.run(
        ['objdump', '-d', '-C', binary_path],
        capture_output=True,
        text=True
    )
    
    # Find the function
    lines = result.stdout.split('\n')
    in_function = False
    asm_lines = []
    
    for line in lines:
        # Match function start
        func_match = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if func_match:
            if function_name in func_match.group(2):
                in_function = True
                continue
            elif in_function:
                break
        
        if in_function:
            asm_lines.append(line)
    
    return '\n'.join(asm_lines)


def diff_functions(old_asm, new_asm):
    """
    Do instruction-level diff between two functions.
    Returns: list of differences.
    """
    old_insts = parse_instructions(old_asm)
    new_insts = parse_instructions(new_asm)
    
    # Simple LCS-based diff
    # For now, use a simpler approach: compare normalized instruction sequences
    
    # Normalize: remove addresses, keep mnemonic + normalized operands
    old_norm = []
    for addr, mnem, ops in old_insts:
        # Normalize operands: remove hex addresses
        norm_ops = re.sub(r'0x[0-9a-f]+', 'ADDR', ops)
        norm_ops = re.sub(r'\[rdi\+0x[0-9a-f]+\]', '[rdi+OFF]', norm_ops)
        old_norm.append((mnem, norm_ops))
    
    new_norm = []
    for addr, mnem, ops in new_insts:
        norm_ops = re.sub(r'0x[0-9a-f]+', 'ADDR', ops)
        norm_ops = re.sub(r'\[rdi\+0x[0-9a-f]+\]', '[rdi+OFF]', norm_ops)
        new_norm.append((mnem, norm_ops))
    
    # Find differences
    differences = []
    
    # Use simple alignment: find first difference, then find re-sync point
    i = j = 0
    while i < len(old_norm) and j < len(new_norm):
        if old_norm[i] == new_norm[j]:
            i += 1
            j += 1
        else:
            # Found a difference
            # Try to find re-sync in next few instructions
            found_resync = False
            for skip_i in range(1, 10):
                for skip_j in range(1, 10):
                    if (i + skip_i < len(old_norm) and 
                        j + skip_j < len(new_norm) and
                        old_norm[i + skip_i] == new_norm[j + skip_j]):
                        # Removed instructions (in old but not in new)
                        for k in range(skip_i):
                            differences.append({
                                'type': 'removed',
                                'old_index': i + k,
                                'instruction': old_norm[i + k]
                            })
                        # Added instructions (in new but not in old)
                        for k in range(skip_j):
                            differences.append({
                                'type': 'added',
                                'new_index': j + k,
                                'instruction': new_norm[j + k]
                            })
                        i += skip_i
                        j += skip_j
                        found_resync = True
                        break
                if found_resync:
                    break
            
            if not found_resync:
                # Can't re-sync, just mark current as modified
                differences.append({
                    'type': 'modified',
                    'old': old_norm[i],
                    'new': new_norm[j]
                })
                i += 1
                j += 1
    
    # Handle remaining instructions
    while i < len(old_norm):
        differences.append({
            'type': 'removed',
            'old_index': i,
            'instruction': old_norm[i]
        })
        i += 1
    
    while j < len(new_norm):
        differences.append({
            'type': 'added',
            'new_index': j,
            'instruction': new_norm[j]
        })
        j += 1
    
    return differences


def detect_security_checks(differences):
    """
    Analyze differences to detect added security checks.
    """
    security_checks = []
    
    # Look for added CMP followed by conditional jump
    added_insts = [d for d in differences if d['type'] == 'added']
    
    for i, diff in enumerate(added_insts):
        mnem, ops = diff['instruction']
        
        # Check for CMP instruction
        if mnem in ('cmp', 'test'):
            # Look ahead for conditional jump
            for j in range(i+1, min(i+5, len(added_insts))):
                next_mnem, next_ops = added_insts[j]['instruction']
                if next_mnem.startswith('j') and next_mnem not in ('jmp',):
                    # This is a security check!
                    check_type = classify_check(mnem, ops, next_mnem, next_ops)
                    security_checks.append({
                        'type': 'SECURITY_CHECK_ADDED',
                        'check_type': check_type,
                        'cmp_instruction': (mnem, ops),
                        'branch_instruction': (next_mnem, next_ops),
                        'position': i
                    })
                    break
    
    return security_checks


def classify_check(cmp_mnem, cmp_ops, branch_mnem, branch_ops):
    """
    Classify what kind of security check this is.
    """
    ops_lower = cmp_ops.lower()
    
    # Length check: comparing packet/buffer length
    if any(term in ops_lower for term in ['len', 'size', 'buf', 'data']):
        return 'LENGTH_CHECK'
    
    # Null check: test register for zero
    if cmp_mnem == 'test' and branch_mnem in ('je', 'jz'):
        return 'NULL_CHECK'
    
    # Bounds check: comparing index with size
    if any(term in ops_lower for term in ['index', 'offset', 'count']):
        return 'BOUNDS_CHECK'
    
    # Default
    return 'GUARD_CHECK'


def analyze_function_diff(old_binary, new_binary, function_name):
    """
    Full analysis of a changed function.
    """
    print(f"  Analyzing {function_name}...")
    
    # Extract asm
    print("    Extracting old function...")
    old_asm = extract_function_asm(old_binary, function_name)
    
    print("    Extracting new function...")
    new_asm = extract_function_asm(new_binary, function_name)
    
    # Diff
    print("    Diffing instructions...")
    differences = diff_functions(old_asm, new_asm)
    
    # Detect security checks
    print("    Detecting security checks...")
    security_checks = detect_security_checks(differences)
    
    result = {
        'function': function_name,
        'old_instruction_count': len(parse_instructions(old_asm)),
        'new_instruction_count': len(parse_instructions(new_asm)),
        'differences': differences,
        'added_count': len([d for d in differences if d['type'] == 'added']),
        'removed_count': len([d for d in differences if d['type'] == 'removed']),
        'security_checks': security_checks
    }
    
    return result


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) != 4:
        print("Usage: diff_engine.py <old_binary> <new_binary> <function_name>")
        sys.exit(1)
    
    old_bin = sys.argv[1]
    new_bin = sys.argv[2]
    func_name = sys.argv[3]
    
    result = analyze_function_diff(old_bin, new_bin, func_name)
    
    print("\n=== Results ===")
    print(f"Function: {result['function']}")
    print(f"Old instructions: {result['old_instruction_count']}")
    print(f"New instructions: {result['new_instruction_count']}")
    print(f"Added: {result['added_count']}")
    print(f"Removed: {result['removed_count']}")
    
    if result['security_checks']:
        print("\nSecurity Checks Detected:")
        for check in result['security_checks']:
            print(f"  Type: {check['check_type']}")
            print(f"    CMP: {check['cmp_instruction']}")
            print(f"    Branch: {check['branch_instruction']}")
    
    # Save results
    with open('diff_results.json', 'w') as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nResults saved to diff_results.json")
