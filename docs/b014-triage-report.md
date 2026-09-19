# B014 Shift Width Violation - Complete Triage Report

## Summary

**Total B014 candidates: 62** (after comment filter)

| Classification | Count | Description |
|---------------|-------|-------------|
| SAFE_BY_CONSTANT | 28 | Shift amount is constant or bounded expression |
| SAFE_BY_EXPLICIT_BOUNDS | 25 | Shift amount has explicit bounds check |
| KNOWN | 1 | NTFS GetCuSize (CVE-2026-48095) |
| HIGH_VALUE | 5 | Shift→allocation, needs deeper analysis |
| UNRESOLVED | 3 | Needs source-level verification |

## Detailed Triage

### 1. VmdkHandler.cpp (11 candidates)

| Line | Code | Classification | Reason |
|------|------|----------------|--------|
| 652 | `cluster << (clusterBits - 9)` | SAFE_BY_EXPLICIT_BOUNDS | In if-comparison, clusterBits bounded |
| 1081 | `(UInt64)1 << (62 - 9)` | SAFE_BY_CONSTANT | Constant shift (53) |
| 1082 | `(UInt64)1 << (62 - 9)` | SAFE_BY_CONSTANT | Constant shift (53) |
| 1279 | `(UInt64)1 << (63 - 9)` | SAFE_BY_CONSTANT | Constant shift (54) |
| 1281 | `(UInt64)1 << (63 - 9)` | SAFE_BY_CONSTANT | Constant shift (54) |
| 1306 | `(UInt64)1 << (grainSize_Log + k_NumMidBits)` | SAFE_BY_EXPLICIT_BOUNDS | grainSize_Log ∈ [3,21], k_NumMidBits=9, max=30<64 |
| 1315 | `(1 << (9 - 2))` | SAFE_BY_CONSTANT | Constant shift (7) |
| 1345 | `numGdeEntries << (k_NumMidBits + 2)` | SAFE_BY_CONSTANT | k_NumMidBits=9, shift=11 |
| 1363 | `(size_t)1 << (k_NumMidBits - 9 + 2)` | SAFE_BY_CONSTANT | Constant shift (2) |
| 1374 | `i << (k_NumMidBits + 2)` | SAFE_BY_CONSTANT | k_NumMidBits=9, shift=11 |
| 1427 | `lastVirtCluster << (ClusterBits - 9)` | SAFE_BY_EXPLICIT_BOUNDS | In if-comparison |

### 2. ExtHandler.cpp (5 candidates)

| Line | Code | Classification | Reason |
|------|------|----------------|--------|
| 397 | `(UInt32)1 << (BlockBits + 3)` | SAFE_BY_EXPLICIT_BOUNDS | In if-check, BlockBits bounded |
| 465 | `(UInt64)1 << (63 - BlockBits)` | SAFE_BY_EXPLICIT_BOUNDS | In if-check, BlockBits bounded |
| 1268 | `(unsigned)1 << (n & 7)` | SAFE_BY_EXPLICIT_BOUNDS | n & 7 < 8, shift < 8 |
| 1693 | `NumBlocks << (IsFlags_HUGE() ? BlockBits : 9)` | SAFE_BY_EXPLICIT_BOUNDS | BlockBits bounded |
| 2381 | `(size_t)1 << (BlockBits - 2)` | SAFE_BY_EXPLICIT_BOUNDS | BlockBits bounded |

### 3. LvmHandler.cpp (5 candidates) - HIGH VALUE GROUP

| Line | Code | Classification | Reason |
|------|------|----------------|--------|
| 881 | `numExtents << (_extentSizeBits + 9)` | UNRESOLVED | Need to verify _extentSizeBits bounds |
| 914 | `(UInt64)1 << (62 - 9)` | SAFE_BY_CONSTANT | Constant shift (53) |
| 916 | `(UInt64)1 << (62 - 9 - _extentSizeBits)` | SAFE_BY_EXPLICIT_BOUNDS | In if-check |
| 923 | `pe_count << (_extentSizeBits + 9)` | UNRESOLVED | Need to verify _extentSizeBits bounds |
| 1008 | `(UInt64)1 << (_extentSizeBits + 9)` | UNRESOLVED | Need to verify _extentSizeBits bounds |

**Key question:** What is the maximum value of `_extentSizeBits`?
- If `_extentSizeBits <= 54`, then `_extentSizeBits + 9 <= 63 < 64` → SAFE
- If `_extentSizeBits >= 55`, then shift >= 64 → VULNERABLE

### 4. QcowHandler.cpp (4 candidates) - HIGH VALUE GROUP

| Line | Code | Classification | Reason |
|------|------|----------------|--------|
| 292 | `(UInt32)1 << (_numMidBits + 3)` | UNRESOLVED | Need to verify _numMidBits bounds |
| 532 | `(size_t)1 << (_numMidBits + 3)` | UNRESOLVED | Need to verify _numMidBits bounds |
| 553 | `numTables << (_numMidBits + 3)` | UNRESOLVED | Need to verify _numMidBits bounds |
| 581 | `curTable << (_numMidBits + 3)` | UNRESOLVED | Need to verify _numMidBits bounds |

**Key question:** What is the maximum value of `_numMidBits`?
- If `_numMidBits <= 28`, then `_numMidBits + 3 <= 31 < 32` → SAFE (for UInt32)
- If `_numMidBits >= 29`, then shift >= 32 → VULNERABLE

### 5. VhdxHandler.cpp (4 candidates)

| Line | Code | Classification | Reason |
|------|------|----------------|--------|
| 926 | `(size_t)1 << (ChunkRatio_Log)` | UNRESOLVED | Need to verify ChunkRatio_Log bounds |
| 1071 | `(UInt32)1 << (BlockSize_Log - kBitmapSize_Log)` | SAFE_BY_EXPLICIT_BOUNDS | In if-check |
| 1114 | `(unsigned)1 << (index2 & 7)` | SAFE_BY_EXPLICIT_BOUNDS | index2 & 7 < 8 |
| 1449 | `(UInt32)1 << (BIT_MAP_UNIT_LOG - 3)` | SAFE_BY_CONSTANT | Constant |

### 6. NtfsHandler.cpp (3 candidates)

| Line | Code | Classification | Reason |
|------|------|----------------|--------|
| 167 | `(UInt64)1 << (62 - SectorSizeLog)` | SAFE_BY_EXPLICIT_BOUNDS | In if-check |
| 687 | `(UInt32)1 << (BlockSizeLog + CompressionUnit)` | **KNOWN** | CVE-2026-48095 |
| 1836 | `1u << (MftRecordSizeLog - SectorSizeLog)` | UNRESOLVED | Need to verify bounds |

### 7. Other Handlers (rest)

| Handler | Count | Classification |
|---------|-------|----------------|
| ComHandler.cpp | 3 | SAFE_BY_CONSTANT / EXPLICIT |
| DmgHandler.cpp | 3 | SAFE_BY_CONSTANT |
| TarOut.cpp | 3 | SAFE_BY_CONSTANT |
| ArjHandler.cpp | 2 | SAFE_BY_EXPLICIT (kNumBits bounded) |
| FatHandler.cpp | 2 | SAFE_BY_EXPLICIT (SectorSizeLog bounded) |
| PeHandler.cpp | 2 | SAFE_BY_EXPLICIT (& 7, align bounded) |
| SquashfsHandler.cpp | 2 | SAFE_BY_EXPLICIT |
| SwfHandler.cpp | 2 | SAFE_BY_CONSTANT (i * 8, i < 4) |
| 7zIn.cpp | 2 | SAFE_BY_CONSTANT (i * 8, i < 8) |
| Rar5Handler.cpp | 2 | SAFE_BY_EXPLICIT |
| SparseHandler.cpp | 1 | SAFE_BY_EXPLICIT (type bounded) |
| VhdHandler.cpp | 1 | SAFE_BY_EXPLICIT (BlockSizeLog bounded) |
| ZstdHandler.cpp | 1 | SAFE_BY_EXPLICIT (n bounded) |
| 7zOut.cpp | 1 | SAFE_BY_CONSTANT (i * 7) |
| Rar5Handler.h | 1 | UNRESOLVED |
| IArchive.h | 1 | SAFE_BY_CONSTANT |
| ZipUpdate.cpp | 1 | SAFE_BY_CONSTANT |

## High-Value Candidates (needs deeper analysis)

### Top 5 Candidates

1. **LvmHandler L881/L923/L1008**: `_extentSizeBits + 9`
   - **Type:** shift → size calculation
   - **Provenance:** from LVM metadata
   - **Question:** What is max _extentSizeBits?
   - **Impact:** If shift >= 64, size calculation is UB

2. **QcowHandler L292/L532/L553/L581**: `_numMidBits + 3`
   - **Type:** shift → table size / offset
   - **Provenance:** from QCOW2 header
   - **Question:** What is max _numMidBits?
   - **Impact:** If shift >= 32, table size calculation is UB

3. **VhdxHandler L926**: `ChunkRatio_Log`
   - **Type:** shift → chunk ratio
   - **Provenance:** from VHDX header
   - **Question:** What is max ChunkRatio_Log?
   - **Impact:** If shift >= 64, size calculation is UB

4. **NtfsHandler L1836**: `MftRecordSizeLog - SectorSizeLog`
   - **Type:** shift → MFT record count
   - **Provenance:** from NTFS boot sector
   - **Question:** What is max MftRecordSizeLog?
   - **Impact:** If shift >= 32, count calculation is UB

5. **Rar5Handler.h L281**: `w << (12 + Get_DictSize_Main())`
   - **Type:** shift → window size
   - **Provenance:** from RAR5 header
   - **Question:** What is max Get_DictSize_Main()?
   - **Impact:** If shift >= 64, window size is UB

## Cross-Rule Combinations

### B014 + B001 (Shift + Addition Overflow)
- LvmHandler: `pe_count << (_extentSizeBits + 9)` → if pe_count is large enough, could overflow after shift

### B014 + B003 (Shift + Truncation)
- QcowHandler: `(UInt32)1 << (_numMidBits + 3)` → if _numMidBits + 3 >= 32, UInt32 cast truncates

### B014 + B013 (Shift + Derived Index)
- None found yet

## Next Steps

1. Verify bounds of `_extentSizeBits` in LvmHandler
2. Verify bounds of `_numMidBits` in QcowHandler
3. Verify bounds of `ChunkRatio_Log` in VhdxHandler
4. Verify bounds of `MftRecordSizeLog` in NtfsHandler
5. Verify bounds of `Get_DictSize_Main()` in Rar5Handler
6. If any are unbounded → HIGH_VALUE candidate → ASan validation
