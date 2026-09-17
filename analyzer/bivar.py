#!/usr/bin/env python3
"""
BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer
Main entry point.

Usage: python3 bivar.py <old_binary> <new_binary>
"""

import sys
import json
import subprocess
import re

# Import our modules
from function_matcher import get_objdump_functions, hash_function, match_functions
from diff_engine import parse_instructions, extract_function_asm, diff_functions, detect_security_checks
from security_semantic import analyze_function_security


def main():
    if len(sys.argv) != 3:
        print("Usage: bivar.py <old_binary> <new_binary>")
        sys.exit(1)
    
    old_bin = sys.argv[1]
    new_bin = sys.argv[2]
    
    print("=" * 60)
    print("BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer")
    print("=" * 60)
    print()
    
    # Step 1: Function matching
    print("[Step 1] Function Matching...")
    old_funcs = get_objdump_functions(old_bin)
    new_funcs = get_objdump_functions(new_bin)
    matches = match_functions(old_funcs, new_funcs)
    
    unchanged = [m for m in matches if m[2] == 'unchanged']
    modified = [m for m in matches if m[2] == 'modified']
    added = [m for m in matches if m[2] == 'added']
    removed = [m for m in matches if m[2] == 'removed']
    
    print(f"  Old binary: {len(old_funcs)} functions")
    print(f"  New binary: {len(new_funcs)} functions")
    print(f"  Unchanged: {len(unchanged)}")
    print(f"  Modified: {len(modified)}")
    print(f"  Added: {len(added)}")
    print(f"  Removed: {len(removed)}")
    print()
    
    if not modified:
        print("No modified functions found.")
        return
    
    # Step 2: Analyze each modified function
    print("[Step 2] Analyzing Modified Functions...")
    
    all_results = []
    
    for old_name, new_name, status in modified:
        print(f"\n  Function: {old_name}")
        
        # Extract asm
        old_asm = extract_function_asm(old_bin, old_name)
        new_asm = extract_function_asm(new_bin, new_name)
        
        old_insts = parse_instructions(old_asm)
        new_insts = parse_instructions(new_asm)
        
        print(f"    Old instructions: {len(old_insts)}")
        print(f"    New instructions: {len(new_insts)}")
        
        # Instruction diff
        differences = diff_functions(old_asm, new_asm)
        added_count = len([d for d in differences if d['type'] == 'added'])
        removed_count = len([d for d in differences if d['type'] == 'removed'])
        
        print(f"    Added instructions: {added_count}")
        print(f"    Removed instructions: {removed_count}")
        
        # Security semantic analysis
        security_result = analyze_function_security(old_insts, new_insts)
        
        if security_result['security_findings']:
            print(f"\n    Security Findings:")
            for finding in security_result['security_findings']:
                print(f"      Category: {finding['category']}")
                print(f"      Score: {finding['score']}")
                for reason in finding['reasons']:
                    print(f"        - {reason}")
        
        func_result = {
            'function': old_name,
            'old_instruction_count': len(old_insts),
            'new_instruction_count': len(new_insts),
            'added_count': added_count,
            'removed_count': removed_count,
            'security_findings': security_result['security_findings'],
        }
        
        all_results.append(func_result)
    
    # Step 3: Summary
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print()
    
    total_security_findings = sum(len(r['security_findings']) for r in all_results)
    
    print(f"Modified functions analyzed: {len(modified)}")
    print(f"Security findings detected: {total_security_findings}")
    
    for r in all_results:
        if r['security_findings']:
            print(f"\n  {r['function']}:")
            for finding in r['security_findings']:
                print(f"    - {finding['category']} (score: {finding['score']})")
    
    # Save results
    output = {
        'old_binary': old_bin,
        'new_binary': new_bin,
        'function_stats': {
            'old_total': len(old_funcs),
            'new_total': len(new_funcs),
            'unchanged': len(unchanged),
            'modified': len(modified),
            'added': len(added),
            'removed': len(removed),
        },
        'modified_functions': all_results,
    }
    
    with open('bivar_results.json', 'w') as f:
        json.dump(output, f, indent=2, default=str)
    
    print()
    print(f"Full results saved to bivar_results.json")


if __name__ == '__main__':
    main()
