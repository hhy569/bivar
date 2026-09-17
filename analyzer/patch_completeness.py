#!/usr/bin/env python3
"""
BIVAR: Patch Completeness Analyzer.

Checks whether a security patch fully covers all variants of the same bug.
"""

import subprocess
import re
from collections import defaultdict


def get_function_calls(binary_path, function_name):
    """
    Find all calls to a specific function from other functions.
    """
    result = subprocess.run(
        ['objdump', '-d', '-C', binary_path],
        capture_output=True,
        text=True
    )
    
    callers = []
    current_function = None
    
    for line in result.stdout.split('\n'):
        # Track current function
        func_match = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if func_match:
            current_function = func_match.group(2)
            continue
        
        # Check for call instruction
        call_match = re.match(r'^\s+[0-9a-f]+:\s*.*\scall\s+<([^>]+)>', line)
        if call_match and current_function:
            called_func = call_match.group(1)
            if function_name in called_func:
                callers.append(current_function)
    
    return list(set(callers))


def analyze_patch_completeness(binary_path, patched_function, consumer_pattern=None):
    """
    Analyze patch completeness.
    
    patched_function: The function that was patched (e.g. getNtpHeader)
    consumer_pattern: Pattern to match consumer functions (e.g. getStratum, getRootDelay)
    
    Returns: dict with completeness analysis.
    """
    print(f"Analyzing patch completeness for: {patched_function}")
    
    # Find all functions that call the patched function
    callers = get_function_calls(binary_path, patched_function)
    print(f"  Found {len(callers)} callers:")
    for c in callers[:10]:
        print(f"    - {c}")
    
    # Now check which of these callers are "direct consumers" that might need their own guards
    # (Functions that directly access the returned pointer without null check)
    
    # For now, we'll just classify them
    consumers = []
    internal = []
    
    for caller in callers:
        if 'getNtpHeader' in caller:
            internal.append(caller)
        else:
            consumers.append(caller)
    
    result = {
        'patched_function': patched_function,
        'total_callers': len(callers),
        'internal_callers': len(internal),
        'external_consumers': len(consumers),
        'consumers': consumers,
        'analysis': []
    }
    
    # For each consumer, check if it has its own null/error handling
    # (This is a simplified version - full analysis would need CFG)
    for consumer in consumers:
        # Simple heuristic: check if the function has any conditional branches
        # that might be null checks
        
        # Extract the function's instructions
        result['analysis'].append({
            'function': consumer,
            'has_own_guard': 'unknown',  # TODO: implement this
            'risk': 'high'  # Assume high risk for now
        })
    
    return result


def analyze_getter_guards(binary_path, getter_names):
    """
    Analyze each getter function to see if it has its own length guard.
    """
    result = subprocess.run(
        ['objdump', '-d', '-C', binary_path],
        capture_output=True,
        text=True
    )
    
    lines = result.stdout.split('\n')
    functions = {}
    current_func = None
    current_instructions = []
    
    for line in lines:
        func_match = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if func_match:
            if current_func:
                functions[current_func] = current_instructions
            current_func = func_match.group(2)
            current_instructions = []
            continue
        
        inst_match = re.match(r'^\s+[0-9a-f]+:\s*.*\s+(\w+)\s', line)
        if inst_match and current_func:
            current_instructions.append(inst_match.group(1).lower())
    
    if current_func:
        functions[current_func] = current_instructions
    
    # Analyze each getter
    results = []
    for getter in getter_names:
        # Find matching function
        matching = [f for f in functions.keys() if getter in f]
        
        if not matching:
            results.append({
                'getter': getter,
                'found': False,
                'has_length_check': None
            })
            continue
        
        func_name = matching[0]
        insts = functions[func_name]
        
        # Check if there's a CMP followed by conditional jump (length check)
        has_cmp = any(inst == 'cmp' for inst in insts)
        has_cond_jcc = any(inst.startswith('j') and inst != 'jmp' for inst in insts)
        
        has_length_check = has_cmp and has_cond_jcc
        
        results.append({
            'getter': getter,
            'found': True,
            'function': func_name,
            'instruction_count': len(insts),
            'has_cmp': has_cmp,
            'has_conditional_jump': has_cond_jcc,
            'has_length_check': has_length_check,
            'risk_level': 'high' if not has_length_check else 'low'
        })
    
    return results


if __name__ == '__main__':
    import sys
    import json
    
    if len(sys.argv) != 2:
        print("Usage: patch_completeness.py <binary>")
        sys.exit(1)
    
    binary = sys.argv[1]
    
    # NTP getters to check
    ntp_getters = [
        'getStratum',
        'getRootDelay',
        'getReferenceIdentifier',
        'getReferenceTimestamp',
        'getOriginTimestamp',
        'getTransmitTimestamp',
    ]
    
    print("Analyzing NTP getter patch completeness...")
    results = analyze_getter_guards(binary, ntp_getters)
    
    print("\n=== Patch Completeness Analysis ===")
    print(f"{'Getter':<30} {'Found':<6} {'Has Length Check':<18} {'Risk Level':<12}")
    print("-" * 70)
    
    high_risk_count = 0
    for r in results:
        if not r['found']:
            print(f"{r['getter']:<30} {'No':<6} {'N/A':<18} {'N/A':<12}")
        else:
            status = 'Yes' if r['has_length_check'] else 'No'
            print(f"{r['getter']:<30} {'Yes':<6} {status:<18} {r['risk_level']:<12}")
            if r['risk_level'] == 'high':
                high_risk_count += 1
    
    print(f"\nHigh risk getters (no own length check): {high_risk_count}/{len(ntp_getters)}")
    
    if high_risk_count > 0:
        print("\n⚠️  Patch may be incomplete!")
        print("   The patch only guards getNtpHeader(), but individual getters")
        print("   may still crash if they access fields directly without null check.")
    
    # Save
    with open('patch_completeness.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to patch_completeness.json")
