# Anatomy of an Integer-Overflow Heap OOB Write: A Case Study in Assimp's SIB Importer

*A crash is a question, not an answer. This article walks from a single
AddressSanitizer report to a fully characterized heap write primitive.*

## Setting up

While auditing Assimp 6.0.5's less-traveled importers, I fuzzed the
Sibelius geometry (`.sib`) importer with a structure-aware seed. ASan
reported:

```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000004fc
WRITE of size 4 at 0x5020000004fc thread T0
    #0 ReadFaces  code/AssetLib/SIB/SIBImporter.cpp:249
```

A `WRITE of size 4` is much more interesting than a read. But "heap-buffer-
overflow" alone says nothing about exploitability. The real work is
answering: **what can I control, and how far does it reach?**

## The vulnerable code

```c
static void ReadFaces(SIBMesh *mesh, StreamReaderLE *stream) {
    uint32_t ptIdx = 0;
    while (stream->GetRemainingSizeToLimit() > 0) {
        uint32_t numPoints = stream->GetU4();          // attacker-controlled

        size_t pos = mesh->idx.size() + 1;
        mesh->idx.resize(pos + numPoints * N);        // N = 3  ← BUG
        mesh->idx[pos - 1] = numPoints;
        uint32_t *idx = &mesh->idx[pos];

        for (uint32_t n = 0; n < numPoints; n++, idx += N, ptIdx++) {
            uint32_t p = stream->GetU4();
            if (p >= mesh->pos.size())
                throw DeadlyImportError("Vertex index is out of range.");
            idx[POS] = p;      // attacker-influenced
            idx[NRM] = ptIdx;
            idx[UV]  = ptIdx;
        }
    }
}
```

## Step 1: The arithmetic

`numPoints * N` is evaluated in **32-bit** arithmetic. Choosing
`numPoints = 0x55555556`:

```
0x55555556 * 3 = 0x1_0000_0002
                 └─ truncated to 32 bits ─┘ → 0x00000002
```

So `resize(pos + 2)` allocates a handful of bytes, while the loop is still
bound to the **original** `numPoints` (1.4 billion iterations).

| Quantity | Value |
|----------|-------|
| numPoints | 0x55555556 |
| product (mathematical) | 0x100000002 |
| product (uint32) | 2 |
| actual allocation | 3 × uint32 = **12 bytes** |
| intended allocation | ~16 GB |

## Step 2: Bypassing the in-loop check

There *is* a bounds check: `if (p >= mesh->pos.size()) throw`. It looks
protective, but it guards the *vertex index*, not the *write destination*.
Once the oversized loop runs past the end of the file, `GetU4()` returns 0,
so `p = 0`, which passes `0 < pos.size()`. The check is satisfied while the
OOB writes continue. A guard on the wrong variable is worse than no guard —
it creates false confidence.

## Step 3: Characterizing the primitive

Each iteration writes three consecutive uint32 values with a 12-byte stride:

```
write_address = base + 12 + n*12
  +0  POS = attacker-controlled (or 0 at EOF)
  +4  NRM = n (sequential counter)
  +8  UV  = n (sequential counter)
```

| Aspect | Controllability |
|--------|-----------------|
| Written value (POS) | **Yes** — from the input stream |
| Written value (NRM/UV) | No — loop counter |
| Write count | **Yes** — via numPoints |
| Stride | Fixed at 12 bytes |
| First OOB offset | Deterministic (byte 12) |

This is a **sequential heap OOB write with a partially controlled value at a
fixed stride** — the classic ingredient for corrupting an adjacent heap
object.

## Step 4: The second-stage primitive

After ReadFaces, `ReadUVs` consumes the index buffer:

```c
uint32_t id = idx[UV];
mesh->uv[id].x = stream->GetF4();   // corrupted index → array access
mesh->uv[id].y = stream->GetF4();
```

The counter values written out of bounds are later *dereferenced as array
indices*. Corrupting an `idx[UV]` slot therefore yields a second-stage
out-of-bounds access into the `uv`/`nrm` arrays — a way to extend reach even
if the first write cannot directly touch a high-value object.

## Step 5: Toward exploitation (and where to stop honestly)

The textbook path from here is heap feng shui → tcache poisoning → arbitrary
chunk → control-flow hijack:

1. Groom same-size freed tcache chunks adjacent to the 12-byte buffer.
2. Use the POS channel to overwrite a freed chunk's `fd`.
3. On glibc ≥ 2.32, honor safe-linking:
   `forged_fd = target ^ (fd_field_addr >> 12)`.
4. Two same-size allocations later, `malloc` returns the target address.
5. Overwrite a C++ vtable pointer / callback (GOT is read-only under Full
   RELRO; `__malloc_hook` is gone since glibc 2.34).

I built a standalone lab that demonstrates each of these steps against a toy
program with the identical bug class, including the safe-linking arithmetic.
But I am **not** claiming RCE in Assimp: the fixed 12-byte stride and the
need to place a specific object adjacent make a reliable chain an open
research problem, and a responsible write-up states that boundary.

## Lessons

1. **The width of the arithmetic matters as much as the check.** A 32-bit
   multiply feeding a 64-bit allocation is the whole bug.
2. **A bounds check on the wrong variable is not a defense.**
3. **Classify the primitive before discussing severity.** Value control,
   offset control, count control, and post-corruption use are four separate
   questions.
4. **A crash is not a vulnerability, and an OOB write is not RCE.** Each link
   in the chain needs evidence.
5. **One bug is a pattern.** The invariant
   (`allocation ≥ count × elements`, overflow-safe) generalizes — which is
   what the next article covers.

## Disclosure status

This case matches the public Assimp issue #6733 and was treated as a
**known-issue reproduction and primitive analysis**, not claimed as a new
CVE. Reproducing a public bug to build a reusable analysis method is
legitimate and valuable; relabeling it as a novel find is not.

---

*All analysis was performed locally against open source code under
AddressSanitizer. No third-party systems were tested.*
