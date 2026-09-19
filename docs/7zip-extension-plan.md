# BIVAR Extension: Source-Level Security Invariants

## Current State
BIVAR currently detects 3 invariants based on disassembly:
- LENGTH_CHECK
- NULL_CHECK
- INTEGER_OVERFLOW_CHECK

## New Rules to Implement (from 7-Zip 26.00→26.01 patches)

### B001_ADDITION_OVERFLOW
**Pattern**: `if (a + b > limit)` where a,b attacker-controlled
**Safe**: `if (a > limit || limit - a < b)`
**Example**: SquashFS ReadMetadataBlock, ReadBlock

### B002_SUBTRACTION_UNDERFLOW
**Pattern**: `if (a - b > limit)` without checking `a < b`
**Safe**: `if (a < b || ...)`
**Example**: SquashFS ReadData

### B003_INTEGER_TRUNCATION
**Pattern**: `UInt32 x = (UInt32)wide;` without checking truncation
**Safe**: `if ((UInt32)wide != wide) error;`
**Example**: SquashFS OpenDir

### B012_CHECK_ORDER
**Pattern**: Memory access before dominating bounds check
**Safe**: Bounds check dominates memory access
**Example**: UDF CFileId::Parse (CVE-2026-48102)

### B013_DERIVED_INDEX
**Pattern**: Validated `idx < count`, but access `array[idx + delta]`
**Safe**: `idx + delta < count` must be checked
**Example**: WIM GetSecurity

## Implementation Plan
1. Extend SecurityInvariant class with new types
2. Add source-level pattern matching (AST-based or regex-based)
3. Add 7-Zip benchmarks as regression tests
4. Test against known vulnerable and fixed code

## Benchmark Suite
| Benchmark | Pattern | Vulnerable | Fixed |
|-----------|---------|-----------|-------|
| S1 ReadMetadataBlock | ADDITION_OVERFLOW | ✓ | ✓ |
| S2 ReadData | SUBTRACTION_UNDERFLOW | ✓ | ✓ |
| S3 OpenDir | INTEGER_TRUNCATION | ✓ | ✓ |
| S4 ReadBlock | ADDITION_OVERFLOW | ✓ | ✓ |
| U1 CFileId::Parse | CHECK_ORDER | ✓ | ✓ |
| W1 GetSecurity | DERIVED_INDEX | ✓ | ✓ |

## Status
- [ ] Implement B001_ADDITION_OVERFLOW
- [ ] Implement B002_SUBTRACTION_UNDERFLOW
- [ ] Implement B003_INTEGER_TRUNCATION
- [ ] Implement B012_CHECK_ORDER
- [ ] Implement B013_DERIVED_INDEX
- [ ] Add 7-Zip regression benchmarks
- [ ] Test regression suite
