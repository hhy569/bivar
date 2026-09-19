# NTFS Handler: B013 Derived-Index Candidate Analysis

## Candidate: NTFS-B013-001

**Location**: `NtfsHandler.cpp:939`
**Rule**: B013_DERIVED_INDEX
**Severity**: HIGH

### Code
```c
const UInt64 virtBlock2End = virtBlock2 + comprUnitSize;
if (CompressionUnit != 0)
  for (unsigned i = left; i < Extents.Size(); i++)
  {
    const CExtent &e = Extents[i];
    if (e.Virt >= virtBlock2End)
      break;
    if (e.IsEmpty())
    {
      isCompressed = true;
      break;
    }
    // ...
    UInt64 numChunks = Extents[i + 1].Virt - curVirt;  // <-- OOB if i == Size()-1!
    if (curVirt + numChunks > virtBlock2End)
      numChunks = virtBlock2End - curVirt;
    const size_t compressed = (size_t)numChunks << BlockSizeLog;
    RINOK(ReadStream_FALSE(Stream, _inBuf + offs, compressed))
    curVirt += numChunks;
    _physPos += compressed;
    offs += compressed;
  }
```

### Root Cause Analysis

**Vulnerable pattern:**
- Loop condition: `i < Extents.Size()`
- Memory access: `Extents[i + 1].Virt`
- Guard: only checks `Extents[i].Virt >= virtBlock2End` and `e.IsEmpty()`

**OOB scenario:**
1. `i == Extents.Size() - 1` (last element)
2. `Extents[i].Virt < virtBlock2End` (doesn't break)
3. `Extents[i].IsEmpty() == false` (doesn't break)
4. Access `Extents[i + 1]` = `Extents[Extents.Size()]` → **OOB read!**

### Comparison with WIM CVE (CVE-2026-xxxx)

**WIM GetSecurity (known patch):**
- Guard: `securityId >= Size()` → reject
- Access: `SecurOffsets[securityId + 1]`
- OOB when `securityId == Size() - 1`

**NTFS candidate (this analysis):**
- Guard: `Extents[i].Virt >= virtBlock2End` → break
- Access: `Extents[i + 1].Virt`
- OOB when `i == Size() - 1` and no break condition hits

**Same pattern:** validated index, derived index access

### Additional Issues Found

**B001_ADDITION_OVERFLOW at line 940:**
```c
if (curVirt + numChunks > virtBlock2End)
  numChunks = virtBlock2End - curVirt;
```
- `curVirt` and `numChunks` are UInt64
- Addition overflow unlikely (UInt64 max ~1.8e19)
- But follows same pattern as SquashFS patches

**B003_INTEGER_TRUNCATION at line 942:**
```c
const size_t compressed = (size_t)numChunks << BlockSizeLog;
```
- `numChunks` is UInt64
- Cast to `size_t` (32-bit on 32-bit systems)
- Then shift left by `BlockSizeLog`
- Potential truncation on 32-bit builds

### Reachability Assessment

**Attacker-controlled inputs:**
- `virtBlock2` (from compressed block metadata)
- `comprUnitSize` (from NTFS header)
- `Extents` (from attribute parsing)

**Reachable via:**
- NTFS compressed file parsing
- Malformed NTFS image with crafted extent table

### Classification

**Status: POTENTIAL VARIANT CANDIDATE**
- Same invariant as WIM CVE (derived-index OOB)
- Different handler (NTFS vs WIM)
- Different root cause mechanism
- Needs dynamic validation (ASan)

### Next Steps

1. Build vulnerable NTFS parser with ASan
2. Craft malformed NTFS image with:
   - Compressed attribute
   - Extents array where last element has Virt < virtBlock2End
3. Verify OOB read with ASan
4. If confirmed → new vulnerability disclosure
