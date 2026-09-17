# BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer

*How one patched CVE can be turned into a systematic search for its siblings.*

## The problem

When a security patch lands, the public usually treats it as "one bug fixed."
In practice, a single root cause — say, an integer overflow in a
`count * element_size` allocation — is often copy-pasted across dozens of
parsers, importers, and decoders in the same codebase. The patch fixes one
call site; the **variant** call sites remain.

Manual variant hunting is slow and error-prone. Pure pattern matching
(grep for `malloc`) produces thousands of false positives. BIVAR
(**BI**nary **V**ariant **A**nalyze**R**) is a tool I built to make the
process systematic and reproducible.

## Core idea: patches encode the missing invariant

A security patch is not just a diff. It reveals a **security invariant** that
the vulnerable code violated. For example, a patch that changes

```c
buf = malloc(count * sizeof(item));
```

to

```c
if (count > SIZE_MAX / sizeof(item)) return ERROR;
buf = malloc(count * sizeof(item));
```

encodes the invariant:

> `count * sizeof(item)` must not overflow, and the allocation must be large
> enough for every subsequent indexed access.

BIVAR extracts that invariant from the patch, lifts it into a small
intermediate representation, and then searches the binary/source for other
sites that violate the *same* invariant — not just sites that look similar
textually.

## The six-step pipeline

```
 1. Patch ingestion      collect vulnerable + fixed revisions
 2. Differential analysis locate the changed guards / arithmetic
 3. Invariant extraction  lift the fix into a typed IR
 4. Pattern compilation   turn the invariant into a matcher
 5. Variant scanning      walk the target, rank candidate sites
 6. Evidence packaging    emit a reproducible report per candidate
```

### Step 1–2: Patch ingestion and differential analysis

BIVAR ingests a vulnerable and a fixed revision (source or binary). The
differential pass isolates security-relevant changes: added bounds checks,
widened integer types, checked-arithmetic calls, and allocation/loop-bound
mismatches. Cosmetic changes are ignored.

### Step 3: Invariant IR

Each finding is expressed as a typed invariant rather than a regex. Examples:

- `ALLOC_SIZE(count, E) >= count * E` with overflow-safe width
- `index < bound` must dominate every `array[index]`
- `offset + length <= buffer_size` computed without wrapping
- allocation width must be ≥ the width of the loop counter that fills it

### Step 4–5: Compile and scan

The invariant compiles to a matcher that combines structural patterns
(allocation dominated by a multiply, followed by a count-bounded write loop)
with data-flow checks (does the multiply use the same variable as the loop
bound? is it 32-bit where the count is attacker-controlled?).

Candidates are scored by how many invariant clauses they violate.

### Step 6: Evidence packaging

Every candidate ships with:
- exact file/function/line
- the data-flow trace from attacker field to memory operation
- the specific clause violated
- a suggested dynamic validation (which input field to mutate)

## Validation on real CVEs

BIVAR was benchmarked against three known memory-safety CVEs to prove the
invariant extraction generalizes across bug classes:

| Benchmark | Bug class | Invariant recovered | Sibling sites surfaced |
|-----------|-----------|--------------------|------------------------|
| Assimp SIB #6733 | integer overflow → heap OOB write | alloc ≥ count×E, overflow-safe | 6 MDL/Unreal candidates |
| Assimp IQM #6708 | stride overflow → OOB read | offset+stride within buffer | related accessor paths |
| LIEF CVE-2025-15504 | bounds check missing | index < bound dominates access | neighboring accessors |

The point of these benchmarks is not to "re-find" public bugs — it is to show
the extracted invariant is precise enough to re-identify the known site and
specific enough to rank true siblings above noise.

## What BIVAR is not

- It is not a fuzzer. It does not generate inputs; it tells you *where* to aim.
- It is not a proof of exploitability. A flagged site is a **candidate** that
  still requires dynamic validation.
- It does not claim a variant is a vulnerability until ASan/UBSan confirms it.

## Why this matters for research workflow

BIVAR sits between static review and fuzzing:

```
 patch  →  BIVAR (invariant + candidates)  →  targeted mutation  →  ASan
   ↑                                                        ↓
   └──────────── confirmed variant refines the IR ←──────────┘
```

It converts a single CVE into a **repeatable hunting strategy**, which is
exactly the leverage a small security team needs when auditing a large
native codebase.

## Repository

The tool, benchmarks, and documentation are open source:
**https://github.com/hhy569/bivar**

---

*This is research tooling. All testing was performed locally against open
source software. Candidates are never reported as vulnerabilities without
dynamic confirmation.*
