# 7z B013 Derived-Index Candidate Analysis

## Candidate: 7Z-B013-001

**Location**: `7z/7zIn.cpp:535` (CDatabase::GetPath)
**Rule**: B013_DERIVED_INDEX
**Severity**: HIGH

### Code
```c
void CDatabase::GetPath(unsigned index, UString &path) const
{
  path.Empty();
  if (!NameOffsets || !NamesBuf)
    return;

  const size_t offset = NameOffsets[index];
  const size_t size = NameOffsets[index + 1] - offset;  // <-- OOB if index == Size()-1!

  if (size >= (1 << 28))
    return;

  wchar_t *s = path.GetBuf((unsigned)size - 1);
  // ... copy path data ...
}
```

**Caller** (`7zHandlerOut.cpp:473`):
```c
_db.GetPath((unsigned)ui.IndexInArchive, name);
```

### Root Cause Analysis

**Vulnerable pattern:**
- Input: `index` (from `ui.IndexInArchive`)
- Access: `NameOffsets[index]`
- Derived access: `NameOffsets[index + 1]`
- Guard: only checks `!NameOffsets || !NamesBuf`
- **MISSING**: `index < NameOffsets.Size() - 1`

**OOB scenario:**
1. `index == NameOffsets.Size() - 1` (last element)
2. `NameOffsets[index]` is valid
3. `NameOffsets[index + 1]` = `NameOffsets[Size()]` → **OOB read!**

### Comparison with WIM CVE (known patch)

**WIM GetSecurity (CVE-2026-xxxx):**
- Guard: `securityId >= Size()` → reject
- Access: `SecurOffsets[securityId + 1]`
- OOB when `securityId == Size() - 1`

**7z GetPath (this candidate):**
- Guard: only `!NameOffsets || !NamesBuf`
- Access: `NameOffsets[index + 1]`
- OOB when `index == Size() - 1`

**Same exact pattern:** validated index, derived index access, missing `+1` bounds check

### Other Candidates in Same File

**Line 569 (GetPath_Prop):**
```c
const size_t offset = NameOffsets[index];
const size_t size = NameOffsets[index + 1] - offset;
```
Same pattern, different function

**Line 619/637/638:**
```c
size_t len = NameOffsets[cur + 1] - NameOffsets[cur];
unsigned len = (unsigned)(NameOffsets[cur + 1] - NameOffsets[cur] - 1);
const Byte *p = (const Byte *)NamesBuf + (NameOffsets[cur + 1] * 2) - 2;
```
Derived index on `cur`

**Line 1470:**
```c
ReadBytes(db.SecureBuf + offset, db.SecureOffsets[i + 1] - offset);
```
Same WIM-like pattern on SecureOffsets

**Line 77/87:**
```c
return (unsigned)(FoToCoderUnpackSizes[folderIndex + 1] - FoToCoderUnpackSizes[folderIndex]);
return PackPositions[index + 1] - PackPositions[index];
```
Derived index on folderIndex/index

### Reachability Assessment

**Attacker-controlled inputs:**
- 7z archive file structure
- Number of files (NumFiles)
- NameOffsets array contents

**Reachable via:**
- Malformed 7z archive with crafted NameOffsets table
- File listing operation (GetPath called for each file)

### Classification

**Status: HIGH-VALUE POTENTIAL VARIANT CANDIDATE**
- Same invariant as WIM CVE (derived-index OOB)
- Different archive format (7z vs WIM)
- Multiple instances in same file
- Needs dynamic validation (ASan)

### Next Steps

1. Build 7z parser with ASan
2. Craft malformed 7z archive with:
   - NameOffsets array of size N
   - Request file with index = N-1 (last)
   - Trigger GetPath()
3. Verify OOB read with ASan
4. If confirmed → new vulnerability disclosure
