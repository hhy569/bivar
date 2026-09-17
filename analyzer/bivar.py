#!/usr/bin/env python3
"""
BIVAR v1.0: Binary Patch-Guided Vulnerability Variant Analyzer

A complete binary patch analysis framework that:
1. Matches functions between two binary versions
2. Diffs modified functions at instruction level
3. Classifies security check semantics
4. Extracts security invariants
5. Analyzes patch completeness
6. Hunts for unpatched variants

Usage:
    python3 bivar.py <old_binary> <new_binary> [options]

Options:
    --output FILE    Output report file (default: bivar_report.json)
    --html FILE      Generate HTML report
    --verbose        Verbose output
    --benchmark      Run in benchmark mode
"""

import sys
import os
import json
import argparse
import time
from datetime import datetime

# Import BIVAR modules
from function_matcher import get_objdump_functions, match_functions
from diff_engine import extract_function_asm, parse_instructions, diff_functions
from security_semantic import analyze_function_security
from security_invariant import analyze_invariants_from_diff
from patch_completeness import analyze_patch_completeness
from variant_hunter import hunt_variants


def print_banner():
    print("=" * 70)
    print("  BIVAR v1.0 - Binary Patch-Guided Vulnerability Variant Analyzer")
    print("=" * 70)
    print()


def step1_function_matching(old_bin, new_bin, verbose=False):
    """Step 1: Match functions between two binaries."""
    print("[Step 1/6] Function Matching")
    print("-" * 40)
    
    t0 = time.time()
    old_funcs = get_objdump_functions(old_bin)
    new_funcs = get_objdump_functions(new_bin)
    matches = match_functions(old_funcs, new_funcs)
    
    unchanged = [m for m in matches if m[2] == 'unchanged']
    modified = [m for m in matches if m[2] == 'modified']
    added = [m for m in matches if m[2] == 'added']
    removed = [m for m in matches if m[2] == 'removed']
    
    print(f"  Old binary functions: {len(old_funcs)}")
    print(f"  New binary functions: {len(new_funcs)}")
    print(f"  Unchanged:  {len(unchanged)}")
    print(f"  Modified:   {len(modified)}")
    print(f"  Added:      {len(added)}")
    print(f"  Removed:    {len(removed)}")
    print(f"  Time: {time.time()-t0:.2f}s")
    print()
    
    return {
        'old_total': len(old_funcs),
        'new_total': len(new_funcs),
        'unchanged': len(unchanged),
        'modified': len(modified),
        'added': len(added),
        'removed': len(removed),
        'modified_funcs': modified,
        'all_matches': matches
    }


def step2_instruction_diff(old_bin, new_bin, modified_funcs, verbose=False):
    """Step 2: Instruction-level diff of modified functions."""
    print("[Step 2/6] Instruction-Level Diff")
    print("-" * 40)
    
    results = []
    
    for old_name, new_name, status in modified_funcs:
        old_asm = extract_function_asm(old_bin, old_name)
        new_asm = extract_function_asm(new_bin, new_name)
        
        old_insts = parse_instructions(old_asm)
        new_insts = parse_instructions(new_asm)
        
        differences = diff_functions(old_asm, new_asm)
        added = len([d for d in differences if d['type'] == 'added'])
        removed = len([d for d in differences if d['type'] == 'removed'])
        
        if verbose:
            print(f"  {old_name}:")
            print(f"    Old: {len(old_insts)} insns, New: {len(new_insts)} insns")
            print(f"    Added: {added}, Removed: {removed}")
        
        results.append({
            'function': old_name,
            'old_insn_count': len(old_insts),
            'new_insn_count': len(new_insts),
            'added_insns': added,
            'removed_insns': removed,
            'differences': differences,
            'old_insts': old_insts,
            'new_insts': new_insts
        })
    
    print(f"  Analyzed {len(results)} modified functions")
    print()
    return results


def step3_security_semantic(diff_results, verbose=False):
    """Step 3: Security semantic classification."""
    print("[Step 3/6] Security Semantic Classification")
    print("-" * 40)
    
    findings = []
    
    for r in diff_results:
        result = analyze_function_security(r['old_insts'], r['new_insts'])
        
        if result['security_findings']:
            for finding in result['security_findings']:
                f = {
                    'function': r['function'],
                    'category': finding['category'],
                    'score': finding['score'],
                    'reasons': finding['reasons']
                }
                findings.append(f)
                if verbose:
                    print(f"  {r['function']}: {finding['category']} (score={finding['score']})")
    
    print(f"  Security findings: {len(findings)}")
    
    # Count by category
    categories = {}
    for f in findings:
        cat = f['category']
        categories[cat] = categories.get(cat, 0) + 1
    
    for cat, count in categories.items():
        print(f"    {cat}: {count}")
    
    print()
    return findings


def step4_security_invariants(diff_results, verbose=False):
    """Step 4: Extract security invariants from patches."""
    print("[Step 4/6] Security Invariant Extraction")
    print("-" * 40)
    
    invariants = []
    
    for r in diff_results:
        invs = analyze_invariants_from_diff(
            r['old_insts'], r['new_insts'], r['differences']
        )
        for inv in invs:
            invariants.append({
                'function': r['function'],
                **inv.to_dict()
            })
    
    print(f"  Security invariants extracted: {len(invariants)}")
    for inv in invariants:
        print(f"    {inv['function']}: {inv['type']} - {inv['condition']}")
    
    print()
    return invariants


def step5_patch_completeness(old_bin, new_bin, modified_funcs, all_matches, verbose=False):
    """Step 5: Analyze patch completeness."""
    print("[Step 5/6] Patch Completeness Analysis")
    print("-" * 40)
    
    # Use the first modified function as the patched function
    if not modified_funcs:
        print("  No modified functions to analyze")
        return {}
    
    patched_func = modified_funcs[0][0]  # old function name
    
    result = analyze_patch_completeness(
        new_bin, patched_func
    )
    
    print(f"  Patched function: {patched_func}")
    print(f"  Callers found: {len(result.get('callers', []))}")
    
    print()
    return result


def step6_variant_hunting(new_bin, invariants, verbose=False):
    """Step 6: Hunt for variants."""
    print("[Step 6/6] Variant Hunting")
    print("-" * 40)
    
    # For now, use invariants to guide variant search
    variants = []
    
    for inv in invariants:
        # Search for similar patterns in the new binary
        result = hunt_variants(new_bin, inv)
        if result:
            variants.extend(result)
    
    print(f"  Potential variants found: {len(variants)}")
    for v in variants[:10]:
        print(f"    {v}")
    
    print()
    return variants


def generate_report(old_bin, new_bin, stats, diff_results, findings, invariants, completeness, variants, output_file):
    """Generate JSON report."""
    
    report = {
        'tool': 'BIVAR v1.0',
        'timestamp': datetime.now().isoformat(),
        'old_binary': old_bin,
        'new_binary': new_bin,
        'function_stats': stats,
        'modified_functions': [
            {
                'function': r['function'],
                'old_insns': r['old_insn_count'],
                'new_insns': r['new_insn_count'],
                'added': r['added_insns'],
                'removed': r['removed_insns']
            }
            for r in diff_results
        ],
        'security_findings': findings,
        'security_invariants': invariants,
        'patch_completeness': completeness,
        'variants': variants
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description='BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer'
    )
    parser.add_argument('old_binary', help='Path to old (vulnerable) binary')
    parser.add_argument('new_binary', help='Path to new (patched) binary')
    parser.add_argument('--output', '-o', default='bivar_report.json',
                        help='Output JSON report file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--no-invariants', action='store_true',
                        help='Skip invariant extraction')
    parser.add_argument('--no-completeness', action='store_true',
                        help='Skip patch completeness analysis')
    parser.add_argument('--no-variants', action='store_true',
                        help='Skip variant hunting')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Step 1: Function matching
    stats = step1_function_matching(args.old_binary, args.new_binary, args.verbose)
    
    # Step 2: Instruction diff
    diff_results = step2_instruction_diff(
        args.old_binary, args.new_binary, stats['modified_funcs'], args.verbose
    )
    
    # Step 3: Security semantic
    findings = step3_security_semantic(diff_results, args.verbose)
    
    # Step 4: Security invariants
    invariants = []
    if not args.no_invariants:
        invariants = step4_security_invariants(diff_results, args.verbose)
    
    # Step 5: Patch completeness
    completeness = {}
    if not args.no_completeness:
        completeness = step5_patch_completeness(
            args.old_binary, args.new_binary, 
            stats['modified_funcs'], stats['all_matches'], args.verbose
        )
    
    # Step 6: Variant hunting
    variants = []
    if not args.no_variants and invariants:
        variants = step6_variant_hunting(args.new_binary, invariants, args.verbose)
    
    # Generate report
    print("=" * 70)
    print("  Final Report Summary")
    print("=" * 70)
    
    report = generate_report(
        args.old_binary, args.new_binary,
        stats, diff_results, findings, invariants,
        completeness, variants, args.output
    )
    
    print(f"\n  Modified functions: {len(diff_results)}")
    print(f"  Security findings: {len(findings)}")
    print(f"  Security invariants: {len(invariants)}")
    print(f"  Patch completeness: {len(completeness.get('unpatched', []))} unpatched consumers")
    print(f"  Potential variants: {len(variants)}")
    
    print(f"\n  Full report saved to: {args.output}")
    print("=" * 70)


if __name__ == '__main__':
    main()
