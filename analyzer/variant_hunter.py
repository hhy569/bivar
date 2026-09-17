#!/usr/bin/env python3
"""
BIVAR: Variant Hunter Module.

After identifying a security patch, search for similar unpatched variants
in the same binary.
"""

import re
import subprocess
from collections import defaultdict


def get_all_functions(binary_path):
    """
    Extract all functions with their instructions from a binary.
    """
    result = subprocess.run(
        ['objdump', '-d', '-C', binary_path],
        capture_output=True,
        text=True
    )
    
    functions = {}
    current_func = None
    current_instructions = []
    
    for line in result.stdout.split('\n'):
        # Match function start
        func_match = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if func_match:
            if current_func:
                functions[current_func] = current_instructions
            current_func = func_match.group(2)
            current_instructions = []
            continue
        
        # Match instruction
        inst_match = re.match(r'^\s+[0-9a-f]+:\s*.*\s+(\w+)\s*(.*)?$', line)
        if inst_match and current_func:
            mnem = inst_match.group(1).lower()
            ops = inst_match.group(2).strip() if inst_match.group(2) else ''
            current_instructions.append((mnem, ops))
    
    if current_func:
        functions[current_func] = current_instructions
    
    return functions


def has_security_guard(instructions):
    """
    Check if a function has its own security guard (CMP + conditional branch).
    """
    for i in range(len(instructions) - 1):
        mnem, ops = instructions[i]
        
        if mnem in ('cmp', 'test'):
            # Look ahead for conditional branch
            for j in range(i + 1, min(i + 5, len(instructions))):
                next_mnem, next_ops = instructions[j]
                if next_mnem.startswith('j') and next_mnem != 'jmp':
                    return True
    
    return False


def calls_guarded_function(instructions, guarded_functions):
    """
    Check if this function calls any of the guarded functions.
    If so, it inherits the guard (if the call returns a pointer/object).
    """
    for mnem, ops in instructions:
        if mnem == 'call':
            # Check if it calls one of the guarded functions
            for guarded_func in guarded_functions:
                if guarded_func in ops:
                    return guarded_func
    
    return None


def has_raw_struct_access(instructions):
    """
    Check if this function does raw struct/memory access.
    """
    memory_access_count = 0
    
    for mnem, ops in instructions:
        if '[' in ops and mnem in ('mov', 'movl', 'movq'):
            memory_access_count += 1
    
    return memory_access_count > 0


def hunt_variants(binary_path, patched_function, patched_semantic='LENGTH_CHECK'):
    """
    Main variant hunting function.
    
    patched_function: The function that was patched (has the guard)
    patched_semantic: Type of security check (LENGTH_CHECK / NULL_CHECK / INTEGER_CHECK)
    """
    print(f"Variant Hunter: Searching for {patched_semantic} variants")
    print(f"Patched function: {patched_function}")
    
    # Get all functions
    print("  Extracting functions...")
    functions = get_all_functions(binary_path)
    print(f"  Found {len(functions)} functions")
    
    # Find the patched function
    patched_funcs = [f for f in functions.keys() if patched_function in f]
    if not patched_funcs:
        print(f"  ERROR: Patched function not found!")
        return []
    
    patched_func_name = patched_funcs[0]
    print(f"  Patched function identified: {patched_func_name}")
    
    # Classify all functions
    results = {
        'patched': [],
        'inherited_guard': [],
        'suspicious': [],
        'unrelated': []
    }
    
    for func_name, instructions in functions.items():
        # Skip the patched function itself
        if func_name == patched_func_name:
            results['patched'].append(func_name)
            continue
        
        # Check if it has its own guard
        if has_security_guard(instructions):
            results['patched'].append(func_name)
            continue
        
        # Check if it calls the patched function (inherits guard)
        called = calls_guarded_function(instructions, [patched_func_name])
        if called:
            results['inherited_guard'].append({
                'function': func_name,
                'inherits_from': called
            })
            continue
        
        # Check if it does raw struct access (potential variant)
        if has_raw_struct_access(instructions):
            results['suspicious'].append(func_name)
            continue
        
        # Otherwise unrelated
        results['unrelated'].append(func_name)
    
    return results


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) != 3:
        print("Usage: variant_hunter.py <binary> <patched_function_substring>")
        sys.exit(1)
    
    binary = sys.argv[1]
    patched_func = sys.argv[2]
    
    results = hunt_variants(binary, patched_func)
    
    print("\n=== Variant Hunt Results ===")
    print(f"Patched (has own guard): {len(results['patched'])}")
    for f in results['patched']:
        print(f"  - {f}")
    
    print(f"\nInherited Guard (depends on patched function): {len(results['inherited_guard'])}")
    for item in results['inherited_guard']:
        print(f"  - {item['function']} (from {item['inherits_from']})")
    
    print(f"\nSuspicious (raw access, no guard): {len(results['suspicious'])}")
    for f in results['suspicious'][:10]:
        print(f"  - {f}")
    if len(results['suspicious']) > 10:
        print(f"  ... and {len(results['suspicious']) - 10} more")
    
    print(f"\nUnrelated: {len(results['unrelated'])}")
    
    # Save
    with open('variant_hunt_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to variant_hunt_results.json")
