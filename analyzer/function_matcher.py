#!/usr/bin/env python3
"""
BIVAR: Binary Vulnerability Variant Analyzer
Function matching module.

Uses simple hashing-based function matching between two ELF binaries.
"""

import subprocess
import re
from collections import defaultdict


def get_objdump_functions(binary_path):
    """
    Extract functions from an ELF binary using objdump.
    Returns a dict: function_name -> {start_addr, end_addr, size, instructions}
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
        # Match function start: "0000000000401234 <function_name>:"
        func_match = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if func_match:
            if current_func:
                functions[current_func] = {
                    'start_addr': current_start,
                    'end_addr': current_end,
                    'size': current_end - current_start,
                    'instructions': current_instructions
                }
            
            current_start = int(func_match.group(1), 16)
            current_func = func_match.group(2)
            current_instructions = []
            current_end = current_start
            continue
        
        # Match instruction: "  401234:	55                   	push   rbp"
        inst_match = re.match(r'^\s+([0-9a-f]+):\t', line)
        if inst_match and current_func:
            addr = int(inst_match.group(1), 16)
            current_end = addr
            current_instructions.append(line.strip())
    
    # Don't forget the last function
    if current_func:
        functions[current_func] = {
            'start_addr': current_start,
            'end_addr': current_end,
            'size': current_end - current_start,
            'instructions': current_instructions
        }
    
    return functions


def hash_function(func_data):
    """
    Compute a simple hash of a function's instructions for matching.
    Uses normalized instruction sequence (ignoring addresses).
    """
    normalized = []
    for inst in func_data['instructions']:
        # Remove addresses, keep only mnemonics and operands pattern
        # Simple normalization: remove hex addresses
        normalized_inst = re.sub(r'0x[0-9a-f]+', 'ADDR', inst)
        normalized.append(normalized_inst)
    
    return hash(tuple(normalized))


def match_functions(old_funcs, new_funcs, size_tolerance=0.1):
    """
    Match functions between old and new binary.
    Returns a list of (old_name, new_name, status) tuples.
    Status: 'unchanged', 'modified', 'added', 'removed'
    """
    matches = []
    
    # First, try exact name match
    old_names = set(old_funcs.keys())
    new_names = set(new_funcs.keys())
    
    matched_old = set()
    matched_new = set()
    
    # Exact name matches
    for name in old_names & new_names:
        old_hash = hash_function(old_funcs[name])
        new_hash = hash_function(new_funcs[name])
        
        if old_hash == new_hash:
            matches.append((name, name, 'unchanged'))
        else:
            matches.append((name, name, 'modified'))
        matched_old.add(name)
        matched_new.add(name)
    
    # Added functions (in new but not in old)
    for name in new_names - matched_new:
        matches.append((None, name, 'added'))
    
    # Removed functions (in old but not in new)
    for name in old_names - matched_old:
        matches.append((name, None, 'removed'))
    
    return matches


def analyze_differences(old_binary, new_binary):
    """
    Main analysis function.
    Returns a dict with analysis results.
    """
    print(f"Analyzing: {old_binary} vs {new_binary}")
    
    print("  Extracting functions from old binary...")
    old_funcs = get_objdump_functions(old_binary)
    print(f"  Found {len(old_funcs)} functions")
    
    print("  Extracting functions from new binary...")
    new_funcs = get_objdump_functions(new_binary)
    print(f"  Found {len(new_funcs)} functions")
    
    print("  Matching functions...")
    matches = match_functions(old_funcs, new_funcs)
    
    # Categorize
    unchanged = [m for m in matches if m[2] == 'unchanged']
    modified = [m for m in matches if m[2] == 'modified']
    added = [m for m in matches if m[2] == 'added']
    removed = [m for m in matches if m[2] == 'removed']
    
    results = {
        'old_binary': old_binary,
        'new_binary': new_binary,
        'old_func_count': len(old_funcs),
        'new_func_count': len(new_funcs),
        'unchanged_count': len(unchanged),
        'modified_count': len(modified),
        'added_count': len(added),
        'removed_count': len(removed),
        'modified_functions': [(m[0], m[1]) for m in modified],
        'added_functions': [m[1] for m in added],
        'removed_functions': [m[0] for m in removed],
    }
    
    return results


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) != 3:
        print("Usage: function_matcher.py <old_binary> <new_binary>")
        sys.exit(1)
    
    old_bin = sys.argv[1]
    new_bin = sys.argv[2]
    
    results = analyze_differences(old_bin, new_bin)
    
    print("\n=== Results ===")
    print(f"Old binary functions: {results['old_func_count']}")
    print(f"New binary functions: {results['new_func_count']}")
    print(f"Unchanged: {results['unchanged_count']}")
    print(f"Modified: {results['modified_count']}")
    print(f"Added: {results['added_count']}")
    print(f"Removed: {results['removed_count']}")
    
    if results['modified_functions']:
        print("\nModified functions:")
        for old, new in results['modified_functions'][:10]:
            print(f"  {old} -> {new}")
    
    # Save results
    with open('analysis_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to analysis_results.json")
