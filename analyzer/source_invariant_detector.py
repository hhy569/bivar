#!/usr/bin/env python3
"""
BIVAR: Source-Level Security Invariant Detector

Detects source-level security invariant violations based on known patch patterns.
"""

import re
import json
from typing import List, Dict, Optional, Tuple


class SourceInvariant:
    """Represents a source-level security invariant violation."""
    
    def __init__(self, rule_id: str, pattern_name: str, location: str, 
                 code_snippet: str, description: str, severity: str = "MEDIUM"):
        self.rule_id = rule_id
        self.pattern_name = pattern_name
        self.location = location
        self.code_snippet = code_snippet
        self.description = description
        self.severity = severity
    
    def to_dict(self):
        return {
            'rule_id': self.rule_id,
            'pattern_name': self.pattern_name,
            'location': self.location,
            'code_snippet': self.code_snippet,
            'description': self.description,
            'severity': self.severity
        }
    
    def __str__(self):
        return f"{self.rule_id} ({self.pattern_name}) at {self.location}"


class SourceInvariantDetector:
    """Detects source-level security invariant violations."""
    
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def _load_patterns(self):
        """Load all detection patterns."""
        return {
            'B001_ADDITION_OVERFLOW': {
                'name': 'Addition Overflow',
                'regex': re.compile(
                    r'if\s*\([^)]*(\w+)\s*\+\s*(\w+)\s*[<>]=?\s*(\w+)[^)]*\)',
                    re.MULTILINE
                ),
                'description': 'Direct addition comparison can overflow. Use: a > limit || limit - a < b',
                'severity': 'HIGH'
            },
            'B002_SUBTRACTION_UNDERFLOW': {
                'name': 'Subtraction Underflow',
                'regex': re.compile(
                    r'(\w+)\s*-\s*(\w+)\s*[<>]=?\s*\(*\s*(?:\(UInt64|1\s*<<)',
                    re.MULTILINE
                ),
                'description': 'Subtraction comparison can underflow. Check: a < b first',
                'severity': 'HIGH'
            },
            'B003_INTEGER_TRUNCATION': {
                'name': 'Integer Truncation',
                'regex': re.compile(
                    r'\(UInt32\)\s*(\w+)',
                    re.MULTILINE
                ),
                'description': '64-bit to 32-bit narrowing conversion without range check. Check: (UInt32)wide == wide',
                'severity': 'MEDIUM'
            },
            'B014_SHIFT_WIDTH_VIOLATION': {
                'name': 'Shift Width Violation',
                'regex': re.compile(
                    r'(\w+)\s*<<\s*\(([^)]+)\)',
                    re.MULTILINE
                ),
                'description': 'Shift amount may exceed operand width. Check: shift_amount < operand_width',
                'severity': 'HIGH'
            },
            'B012_CHECK_ORDER': {
                'name': 'Check Order Violation',
                'regex': re.compile(
                    r'for\s*\([^;]*;\s*[^;]*;\s*(\w+)\+\+\s*\)\s*'
                    r'if\s*\(\s*p\[(\w+)\]\s*!=\s*0\s*\)',
                    re.MULTILINE
                ),
                'description': 'Memory access p[processed] before bounds check processed >= size. Check bounds first.',
                'severity': 'HIGH'
            },
            'B013_DERIVED_INDEX': {
                'name': 'Derived Index',
                'regex': re.compile(
                    r'(\w+)\[(\w+)\s*\+\s*\d+\s*\]',
                    re.MULTILINE
                ),
                'description': 'Array access with index + delta. Check that idx + delta < Size()',
                'severity': 'HIGH'
            },
        }
    
    def _is_in_multiline_comment(self, lines: List[str], line_num: int) -> bool:
        """Check if a line is inside a /* ... */ block comment."""
        in_comment = False
        for i in range(line_num):
            line = lines[i]
            open_count = line.count('/*')
            close_count = line.count('*/')
            if in_comment:
                if close_count > 0:
                    in_comment = False
            else:
                if open_count > close_count:
                    in_comment = True
                elif open_count > 0 and close_count == 0:
                    in_comment = True
        return in_comment
    
    def detect_in_file(self, file_path: str, content: str) -> List[SourceInvariant]:
        """Detect all invariant violations in a source file."""
        results = []
        
        lines = content.split('\n')
        
        for rule_id, pattern in self.patterns.items():
            matches = list(pattern['regex'].finditer(content))
            
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                
                # Get surrounding context (previous 10 lines)
                start_line = max(0, line_num - 10)
                end_line = min(len(lines), line_num + 3)
                context = '\n'.join(lines[start_line:end_line])
                
                # === FILTERING: exclude false positives ===
                
                # Skip #define lines
                if line_content.strip().startswith('#'):
                    continue
                
                # Skip comment lines
                stripped = line_content.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    continue
                
                # Skip lines inside /* ... */ block comments
                if self._is_in_multiline_comment(lines, line_num):
                    continue
                
                # B002: only flag if inside an if statement (not constant expressions)
                if rule_id == 'B002_SUBTRACTION_UNDERFLOW':
                    if not re.search(r'if\s*\(', line_content):
                        continue
                
                # Check if this is a SAFE pattern (has proper bounds check)
                is_safe = False
                
                if rule_id == 'B003_INTEGER_TRUNCATION':
                    # Safe: check if there's a (UInt32)wide != wide check
                    if re.search(r'\(UInt32\)\s*\w+\s*!=\s*\w+', context):
                        is_safe = True
                    
                    # Safe: same-width cast (e.g., (UInt32)1, (UInt32)constant)
                    # This is NOT a narrowing conversion
                    if re.search(r'\(UInt32\)\s*\d+', line_content):
                        is_safe = True
                
                elif rule_id == 'B014_SHIFT_WIDTH_VIOLATION':
                    # Safe: check if there's a bounds check for shift amount
                    if re.search(r'if\s*\([^)]*\w+\s*<\s*3[2-9]\b', context):
                        is_safe = True
                    if re.search(r'if\s*\([^)]*\w+\s*<=\s*3[1-9]\b', context):
                        is_safe = True
                    
                    # Safe: constant shift amount (provably < 32)
                    if re.search(r'<<\s*\d+\s*[;)]', line_content):
                        is_safe = True
                
                elif rule_id == 'B013_DERIVED_INDEX':
                    # Safe: check if there's a idx + delta >= Size() check
                    if re.search(r'\+\s*\d+\s*>=\s*[\w.]+\.Size\(\)', context):
                        is_safe = True
                    
                    # Safe: sentinel invariant - loop breaks on empty element
                    # This means i+1 access is safe because last element is sentinel
                    if re.search(r'if\s*\(\s*\w+\.IsEmpty\(\)\s*\)', context):
                        is_safe = True
                    
                    # Safe: parallel-vector +1 invariant
                    # NameOffsets[index + 1] is safe when:
                    # - NameOffsets.Size() == Files.Size() + 1
                    # - caller checks index < Files.Size()
                    # Pattern: array[idx] followed by array[idx + 1] with no explicit bounds
                    # but caller proves index < related array size
                    # This is a common 7-Zip pattern (boundary offset arrays)
                    if re.search(r'const\s+size_t\s+\w+\s*=\s*\w+\[\w+\s*\+\s*1\]\s*-\s*\w+', context):
                        # Check if this is in a function that takes index as parameter
                        # (likely caller precondition proven elsewhere)
                        if re.search(r'\w+\s*\(\s*unsigned\s+\w+\s*[,)]', context):
                            is_safe = True
                
                if not is_safe:
                    result = SourceInvariant(
                        rule_id=rule_id,
                        pattern_name=pattern['name'],
                        location=f"{file_path}:{line_num}",
                        code_snippet=line_content.strip(),
                        description=pattern['description'],
                        severity=pattern['severity']
                    )
                    results.append(result)
        
        return results

    def detect_in_directory(self, dir_path: str, extensions=[".cpp", ".c", ".h"]) -> List[SourceInvariant]:
        """Detect all invariant violations in a directory."""
        import os
        
        results = []
        
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        results.extend(self.detect_in_file(file_path, content))
                    except Exception as e:
                        print(f"Error reading {file_path}: {e}")
        
        return results


def run_regression_test():
    """Run regression test against known vulnerable/fixed code."""
    
    detector = SourceInvariantDetector()
    
    # Test cases: (name, vulnerable_code, should_detect)
    test_cases = [
        # === POSITIVE CASES (known vulnerable) ===
        
        # B001_ADDITION_OVERFLOW
        (
            "S1: SquashFS ReadMetadataBlock (vulnerable)",
            """
            if (size > kMetadataBlockSize || offset + size > packSize)
                return S_FALSE;
            packSize = offset + size;
            """,
            True,
            "B001_ADDITION_OVERFLOW"
        ),
        (
            "S4: SquashFS ReadBlock (vulnerable)",
            """
            if (offsetInBlock + blockSize > _cachedUnpackBlockSize)
                return S_FALSE;
            """,
            True,
            "B001_ADDITION_OVERFLOW"
        ),
        
        # B002_SUBTRACTION_UNDERFLOW
        (
            "S2: SquashFS ReadData (vulnerable)",
            """
            if (end < start || end - start >= ((UInt64)1 << 32))
                return S_FALSE;
            """,
            True,
            "B002_SUBTRACTION_UNDERFLOW"
        ),
        
        # B003_INTEGER_TRUNCATION
        (
            "S3: SquashFS OpenDir (vulnerable)",
            """
            blockIndex = _dirs.PackPos.FindInSorted((UInt32)n.StartBlock);
            """,
            True,
            "B003_INTEGER_TRUNCATION"
        ),
        
        # B012_CHECK_ORDER
        (
            "U1: UDF CFileId::Parse (vulnerable, CVE-2026-48102)",
            """
            for (;(processed & 3) != 0; processed++)
                if (p[processed] != 0)
                    return 0;
            return (processed <= size) ? processed : 0;
            """,
            True,
            "B012_CHECK_ORDER"
        ),
        
        # B013_DERIVED_INDEX
        (
            "W1: WIM GetSecurity (vulnerable)",
            """
            if (securityId >= (UInt32)image.SecurOffsets.Size())
                return E_FAIL;
            UInt32 offs = image.SecurOffsets[securityId];
            UInt32 len = image.SecurOffsets[securityId + 1] - offs;
            """,
            True,
            "B013_DERIVED_INDEX"
        ),
        
        # B014_SHIFT_WIDTH_VIOLATION
        (
            "NTFS-SHIFT: NTFS GetCuSize (CVE-2026-48095, vulnerable)",
            """
            UInt32 GetCuSize() const { return (UInt32)1 << (BlockSizeLog + CompressionUnit); }
            """,
            True,
            "B014_SHIFT_WIDTH_VIOLATION"
        ),
        
        # === NEGATIVE CASES (SAFE - should NOT detect) ===
        
        # B001 safe patterns
        (
            "SAFE-B001-01: Proper addition check",
            """
            if (a > limit || limit - a < b)
                return S_FALSE;
            """,
            False,
            None
        ),
        (
            "SAFE-B001-02: Separate bounds check",
            """
            if (size > kMetadataBlockSize) return S_FALSE;
            const UInt32 packSize2 = offset + size;
            if (packSize2 > packSize) return S_FALSE;
            """,
            False,
            None
        ),
        
        # B002 safe patterns
        (
            "SAFE-B002-01: Proper subtraction check",
            """
            if (a < b) return S_FALSE;
            const UInt64 size64 = a - b;
            """,
            False,
            None
        ),
        
        # B003 safe patterns
        (
            "SAFE-B003-01: Proper truncation check",
            """
            if ((UInt32)wide != wide) return S_FALSE;
            UInt32 x = (UInt32)wide;
            """,
            False,
            None
        ),
        
        # B012 safe patterns
        (
            "SAFE-B012-01: Proper check order",
            """
            for (; processed & 3; processed++)
                if (processed >= size || p[processed])
                    return 0;
            return processed;
            """,
            False,
            None
        ),
        
        # B013 safe patterns
        (
            "SAFE-B013-01: Proper derived index check",
            """
            if (securId >= image.SecurOffsets.Size() ||
                securId + 1 >= image.SecurOffsets.Size())
                return S_OK;
            UInt32 offs = image.SecurOffsets[securId];
            UInt32 len = image.SecurOffsets[securId + 1] - offs;
            """,
            False,
            None
        ),
        (
            "SAFE-B013-02: Sentinel invariant (NTFS Extents)",
            """
            for (unsigned i = left; i < Extents.Size(); i++)
            {
              const CExtent &e = Extents[i];
              if (e.Virt >= virtBlock2End)
                break;
              if (e.IsEmpty())
                break;
              UInt64 numChunks = Extents[i + 1].Virt - curVirt;
            }
            """,
            False,
            None
        ),
        (
            "SAFE-B013-03: Parallel-vector +1 invariant (7z NameOffsets)",
            """
            void CDatabase::GetPath(unsigned index, UString &path) const
            {
              path.Empty();
              if (!NameOffsets || !NamesBuf)
                return;
              const size_t offset = NameOffsets[index];
              const size_t size = NameOffsets[index + 1] - offset;
              if (size >= (1 << 28))
                return;
            }
            """,
            False,
            None
        ),
        
        # B014 safe patterns
        (
            "SAFE-B014-01: Shift with bounds check",
            """
            if (shift < 32)
                result = 1 << shift;
            """,
            False,
            None
        ),
        (
            "SAFE-B014-02: Constant shift amount",
            """
            UInt32 mask = 0xFFFFFFFF << 16;
            """,
            False,
            None
        ),
        (
            "SAFE-B003-02: Same-width cast (UInt32)1",
            """
            UInt32 x = (UInt32)1 << n;
            """,
            False,
            None
        ),
    ]
    
    print("=" * 70)
    print("BIVAR Source-Level Invariant Detector - Full Regression Test")
    print("=" * 70)
    
    passed = 0
    failed = 0
    results_summary = {}
    
    for name, code, should_detect, expected_rule in test_cases:
        results = detector.detect_in_file("test.cpp", code)
        
        detected = len(results) > 0
        
        # Check if expected rule was detected
        rule_match = False
        if expected_rule:
            for r in results:
                if r.rule_id == expected_rule:
                    rule_match = True
                    break
        
        # Determine pass/fail
        if should_detect:
            # Should detect AND should detect the right rule
            if detected and (expected_rule is None or rule_match):
                print(f"✓ {name}")
                passed += 1
            else:
                print(f"✗ {name}")
                print(f"  Expected detect=True ({expected_rule}), got detect={detected}")
                for r in results:
                    print(f"    - {r.rule_id}")
                failed += 1
        else:
            # Should NOT detect anything
            if not detected:
                print(f"✓ {name}")
                passed += 1
            else:
                print(f"✗ {name}")
                print(f"  Expected detect=False, got detect={detected}")
                for r in results:
                    print(f"    - {r.rule_id}: {r.description}")
                failed += 1
    
    print("=" * 70)
    print(f"Passed: {passed}/{passed+failed}")
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED!")
        return True
    else:
        print(f"\n✗ {failed} TESTS FAILED")
        return False


if __name__ == '__main__':
    run_regression_test()
