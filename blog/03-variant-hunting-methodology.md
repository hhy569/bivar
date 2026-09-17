# From One CVE to a Hunting Strategy: Security-Invariant Variant Analysis

*Why auditors who only grep for `malloc` drown in false positives, and how to
do better.*

## The variant problem

Security teams are repeatedly caught by the same root cause in a different
function. A vendor patches an integer overflow in importer A; importers B, C,
and D contain the same `count * size` pattern and are fixed months or years
later, sometimes under separate CVEs.

The reason is straightforward: patches are organized by *location*, but bugs
recur by *invariant*. If your review process is also organized by location
("audit file X"), you will rediscover the same class forever.

This article describes the method I encoded into a tool (BIVAR) and applied
manually to Assimp. The method matters more than the tool — you can execute
it with a debugger, a notebook, and discipline.

## What a security invariant looks like

An invariant is a property that must hold at a memory operation. Examples:

```
ALLOC:   allocated_elements >= loop_iterations * elements_per_item
INDEX:   index < bound   dominates every array[index]
RANGE:   offset + length <= buffer_size      (without integer wrap)
WIDTH:   arithmetic width >= maximum attacker-controlled value
LIFETIME: object is not used after free, and not used before initialization
```

A patch is valuable because it shows, concretely, which invariant the
developer believed was missing. Read the patch *as an invariant*, not as a
line change.

### Worked example

Vulnerable:

```c
mesh->idx.resize(pos + numPoints * 3);
for (i = 0; i < numPoints; i++) idx[i*3+k] = v;
```

Patch (conceptual):

```c
if (numPoints > SIZE_MAX / 3) return ERROR;   // width + overflow guard
mesh->idx.resize(pos + (size_t)numPoints * 3);
```

Extracted invariant:

> The allocation expression must be evaluated in a width wide enough that
> `numPoints * 3` cannot wrap, and the resulting allocation must dominate a
> write loop bounded by the same `numPoints`.

That sentence — not the specific function — is what you hunt for next.

## The five-stage method

### Stage 1 — Anchor on a confirmed root cause

Start from a bug you have **fully reproduced**, not from a CVE title. You
must understand the data flow: attacker field → parsed variable → arithmetic
→ allocation → memory operation. Without the full chain you cannot tell a
true sibling from a look-alike.

### Stage 2 — Generalize to an invariant + an anti-pattern

Write two things:

- the invariant that must hold;
- the structural anti-pattern that violates it
  (e.g. `[narrow multiply feeding allocation] dominated-by [count-bounded write]`).

Keep the anti-pattern structural but attach data-flow conditions. A bare
regex (`\* 3`) is too noisy; a regex plus "multiply operand == loop bound"
plus "multiply is 32-bit" plus "attacker reaches the count" is precise.

### Stage 3 — Enumerate candidates broadly, triage narrowly

Cast a wide structural net, then reject candidates by proving a *defense*
exists. A site is safe if any one of these is true:

1. the loop bound equals the (correctly computed) allocation;
2. the input cannot reach a wrapping value (narrow domain, e.g. int16);
3. an explicit bounds check dominates the access;
4. the allocation growth cannot reach overflow (geometric, capped);
5. allocation size equals the subsequent copy length.

Document **why** each reject is safe. Negative results with reasoning are
evidence of rigor; a table of "no bug" with no analysis is worthless.

### Stage 4 — Dynamic validation of survivors

For every candidate that survives static triage, do not file it. Validate:

```
minimal valid seed
   → mutate the single controlling field to a wrap/edge value
   → run under ASan + UBSan
   → observe whether the predicted invariant violation fires
```

UBSan is especially useful for integer-overflow candidates because it
catches the wrap even where the downstream OOB does not immediately fire.

### Stage 5 — Refine and re-run

A confirmed variant either strengthens or corrects the invariant. Feed that
back: if the new bug violates a clause you did not model, add the clause. The
hunter improves as it finds things.

## A real triage table (Assimp)

Starting from one confirmed integer-overflow OOB write, the method produced
13 structural candidates. Most were provably safe:

| Pattern found | Why it is safe |
|---------------|----------------|
| `faces.size()*3` then loop over `size()*3` | loop bound matches allocation |
| `width*height` with int16 dimensions | domain cannot wrap |
| `memcpy(dst, src, n)` after `new T[n]` | alloc == copy length |
| geometric `alloc*2` growth | capped, cannot reach wrap |
| index write after `if (i >= size) continue` | check dominates access |

Six survivors (MDL/Unreal importers) shared the exact anti-pattern but use
binary containers; they enter a dynamic-validation queue with a prescribed
seed-and-mutate experiment. **None were called vulnerabilities before ASan
confirmed them.**

## Why this beats both pure fuzzing and pure review

- **Fuzzing** tells you a reachable bug exists; it cannot tell you where the
  *unreached* siblings are, and it spends most of its CPU re-exploring shallow
  paths. Invariant analysis points the fuzzer at the fields that matter.
- **Manual review** finds subtle logic but does not scale across hundreds of
  parsers and cannot be re-run mechanically after every release.
- **Invariant variant analysis** uses one confirmed bug to aim both: it
  produces a ranked target list for review and a field-level mutation guide
  for fuzzing.

The two are complementary. My own workflow is:

```
reproduce root cause → extract invariant → enumerate variants
   → static triage → targeted mutation under ASan/UBSan
   → confirmed variants refine the invariant → repeat
```

## Reporting discipline

The method is only credible if you resist inflating results:

- A multiply is not a bug. A flagged site is a **candidate**.
- A crash is not a vulnerability until triaged and root-caused.
- An OOB write is not RCE until a control-flow hijack is demonstrated.
- A public bug reproduced independently is a *reproduction*, never a new CVE.
- Negative results, with the reasoning, are part of the deliverable.

## Takeaway

Individual bugs get fixed. **Bug classes** recur. The durable skill — and the
thing worth demonstrating in a security portfolio — is the ability to lift
one patched bug into an invariant, mechanically find its siblings, and
honestly separate confirmed vulnerabilities from candidates and noise.

That is the research loop: evidence → invariant → search → validation →
refinement. It transfers from one codebase to another, which is the whole
point.

---

*All experiments described were run locally against open source software
with AddressSanitizer and UndefinedBehaviorSanitizer.*
