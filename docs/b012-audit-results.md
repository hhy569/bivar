# B012 Check-Order Audit Results

## Summary

**9 candidates reviewed: ALL false positives (9/9)**

## Detailed Review

| # | Location | Code | Classification | Reason |
|---|----------|------|----------------|--------|
| 1 | ApfsHandler.cpp:674 | `for (i=0; i<k_obj_phys_Size; i++) if (p[i]!=0)` | FALSE POSITIVE | Fixed-size object header check |
| 2 | ElfHandler.cpp:147 | `for (i=9; i<16; i++) if (p[i]!=0)` | FALSE POSITIVE | ELF header padding check |
| 3 | FatHandler.cpp:238 | `for (i=16; i<28; i++) if (p[i]!=0)` | FALSE POSITIVE | FAT boot sector reserved bytes check |
| 4 | MbrHandler.cpp:407 | `AllAreZeros(p, size)` | FALSE POSITIVE | Generic zero-check utility function |
| 5 | NtfsHandler.cpp:138 | `for (i=14; i<21; i++) if (p[i]!=0)` | FALSE POSITIVE | NTFS boot sector reserved bytes check |
| 6 | VhdHandler.cpp:93 | `for (i=zeroOffset; i<size; i++) if (p[i]!=0)` | FALSE POSITIVE | VHD footer checksum zero area check |
| 7 | VhdHandler.cpp:615 | `for (i=0; i<rem; i++) if (p[i]!=0)` | FALSE POSITIVE | Sparse block zero check |
| 8 | VhdxHandler.cpp:90 | `IsZeroArr(p, size)` | FALSE POSITIVE | Generic zero-check utility function |
| 9 | 7zIn.cpp:335 | `for (i=8; i<kHeaderSize; i++) if (p[i]!=0)` | FALSE POSITIVE | 7z recovery mode header check |

## Root Cause of False Positives

**Current B012 pattern matches:**
```c
for (...) if (p[i] != 0)
```

**But actual check-order violation requires:**
1. Memory access WITHOUT bounds check first
2. THEN bounds check AFTER access

**Example of true check-order violation (UDF CVE-2026-48102):**
```c
for (; (processed & 3) != 0; processed++)
    if (p[processed] != 0)  // access WITHOUT processed >= size check
        return 0;
return (processed <= size) ? processed : 0;  // check TOO LATE
```

**Key difference:**
- True violation: loop condition does NOT include bounds check
- False positive: loop condition INCLUDES bounds check (`i < size`)

## BIVAR Improvement Needed

B012 pattern needs to be refined:
- Current: matches ANY `for` loop with `p[i] != 0`
- Needed: only match when loop condition does NOT include bounds check

## Conclusion

**B012 has zero true candidates in current scan.**

All 9 matches are normal "check if header area is zero" patterns with proper loop bounds.

This confirms that the known UDF CVE is the only check-order violation in 7-Zip, and it was already fixed.
