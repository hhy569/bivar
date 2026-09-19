# BIVAR v0.3: Night Work Summary

## Date: 2026-09-18

## Completed Tonight

### 1. 7-Zip Patch Analysis
Analyzed 7-Zip 26.00 → 26.01 security patches:
- **S1: SquashFS ReadMetadataBlock** - Addition overflow (offset+size > packSize)
- **S2: SquashFS ReadData** - Subtraction underflow (end-start)
- **S3: SquashFS OpenDir** - Integer truncation (64→32 bit StartBlock)
- **S4: SquashFS ReadBlock** - Addition overflow (offset+blockSize > cachedSize)
- **U1: UDF CFileId::Parse** - Check-order violation (CVE-2026-48102)
- **W1: WIM GetSecurity** - Derived-index OOB (securityId+1)

### 2. BIVAR Source-Level Invariant Detector
Implemented 5 new security invariant rules:
- **B001_ADDITION_OVERFLOW**: Direct a+b > limit comparison
- **B002_SUBTRACTION_UNDERFLOW**: a-b > limit without a<b check
- **B003_INTEGER_TRUNCATION**: (UInt32)wide without range check
- **B012_CHECK_ORDER**: Memory access before bounds check
- **B013_DERIVED_INDEX**: array[idx + delta] without idx+delta < Size() check

### 3. Regression Suite
**12/12 tests passed:**
- 6 positive (known vulnerable) cases
- 6 negative (SAFE) cases

### 4. Full Archive/** Scan
**1785 total candidates found:**
- B002_SUBTRACTION_UNDERFLOW: 935 (high FP rate)
- B003_INTEGER_TRUNCATION: 714
- B013_DERIVED_INDEX: 66
- B001_ADDITION_OVERFLOW: 61
- B012_CHECK_ORDER: 9

**Top handlers by candidate count:**
1. NsisIn.cpp: 78
2. ExtHandler.cpp: 71
3. ApfsHandler.cpp: 66
4. VhdxHandler.cpp: 60
5. ZipIn.cpp: 59
6. PeHandler.cpp: 56
7. NtfsHandler.cpp: 52
8. HfsHandler.cpp: 51
9. Rar5Handler.cpp: 48
10. SquashfsHandler.cpp: 46
11. UdfIn.cpp: 40

## Key Achievements
1. **Real-world patch extraction**: 6 actual 7-Zip security patches from 26.00→26.01
2. **Pattern generalization**: 5 new security invariant rules
3. **Validation**: 12/12 regression tests pass (precision + recall)
4. **Full scan**: 1785 candidates across entire Archive/**
5. **Methodology**: Patch-guided variant analysis (known patch → invariant → variant hunt)

## Next Steps (per ChatGPT)
1. B002 refinement (exclude #define bitmasks)
2. NTFS manual audit (B001/B003/B013)
3. B012 full review (9 candidates)
4. Top B001/B013 candidates manual validation
5. ASan/dynamic validation
6. Variant discovery (new candidates not matching known patches)

## Status
- ✅ BIVAR v0.3 regression suite complete
- ✅ Full Archive/** scan complete
- ⏳ Manual triage pending
