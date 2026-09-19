# Interview Q&A - Binary Security Research

## General Questions

### Q1: Tell me about yourself and your background in binary security.

**A:** I'm a binary security researcher with hands-on experience in vulnerability discovery, fuzzing, reverse engineering, and security tool development. My work includes:
- Developing BIVAR, a patch-guided variant hunting framework that systematically searches for vulnerability variants across large codebases
- Finding and reporting real vulnerabilities (brpc HPACK stack overflow confirmed by Apache PMC, VirtualBox CVE-2026-60160)
- Deep research on production-grade codebases like 7-Zip, liblnk, and Linux kernel drivers
- Building complete research pipelines from static analysis to dynamic validation

My approach is quality over quantity - I focus on understanding root causes and building reproducible research, not just counting crashes.

---

### Q2: Why are you interested in this position?

**A:** I'm looking to work in binary security because I enjoy the challenge of finding subtle bugs in complex codebases. What excites me most is the combination of:
- Deep technical understanding needed to find real vulnerabilities
- The satisfaction of contributing to real-world software security
- The opportunity to work on complex, high-impact codebases

I'm particularly interested in [WithSecure / game anti-cheat / commercial security] because of the technical depth required and the impact of the work.

---

## Fuzzing Questions

### Q3: Why did you choose this fuzz target?

**A:** I chose 7-Zip archive handlers for several reasons:
1. **Real-world impact:** 7-Zip is widely used, so vulnerabilities have real impact
2. **Complex input formats:** Archive parsing involves complex state machines and nested structures
3. **Known security history:** 7-Zip has had real security vulnerabilities, which provides canaries for our tool
4. **Good infrastructure:** It's open source, easy to build, and has good ASan support
5. **Large attack surface:** 30+ archive format handlers provide plenty of code to analyze

---

### Q4: How do you design a fuzz harness?

**A:** I start by asking: "What's the optimal parsing boundary to fuzz?"

For 7-Zip, I considered multiple entry points:
- Full program (7za CLI)
- Archive open function
- Individual handler open function
- Internal parser function

I chose to build at the handler level because:
1. Lower startup cost = higher exec/sec
2. More focused on the parsing logic we care about
3. Easier to control the initial state
4. Better signal-to-noise ratio

The key principle is: don't fuzz the entire program if you can fuzz a smaller, more focused boundary.

---

### Q5: How do you handle fuzzing plateau?

**A:** When coverage stops growing, I don't just keep running - I stop and diagnose.

My process:
1. **Measure:** Is it really plateau? Check coverage delta over observation window
2. **Diagnose:** Why isn't coverage growing?
   - Harness problem?
   - Seed problem?
   - Mutation problem?
   - Precondition gate?
3. **Hypothesize:** What's blocking deeper path reach?
4. **Experiment:** Test the hypothesis with targeted changes
5. **Decide:** Continue, adjust, or abandon

For example, in FFmpeg HTJ2K fuzzing, we hit a plateau at 422 edges. We diagnosed that random bytes couldn't reach the deep HT decoder because the input structure was too constrained. The solution wasn't more fuzzing time - it was building structure-aware mutation with valid seeds.

---

### Q6: How do you build your seed corpus?

**A:** Quality over quantity. I build seeds in layers:

1. **Minimal seeds:** Smallest possible valid input
2. **Normal seeds:** Typical valid inputs
3. **Complex seeds:** Nested structures, edge cases
4. **Boundary seeds:** Values at critical boundaries
5. **Malformed-but-parseable seeds:** Inputs that pass early checks but trigger later bugs

Then I do:
- Deduplication: Remove redundant seeds
- Minimization: Shrink seeds while preserving coverage
- Coverage-based selection: Keep only seeds that add new coverage

The goal is a small, high-coverage corpus, not a large random collection.

---

## Reverse Engineering Questions

### Q7: How do you approach reverse engineering a new file format?

**A:** My approach:

1. **Start with documentation:** If there's a spec, read it first
2. **Find entry points:** Where does parsing start? What's the magic number?
3. **Map the state machine:** How does the parser transition between states?
4. **Identify key structures:** What are the important data structures?
5. **Trace data flow:** How does input data flow into memory operations?
6. **Find dangerous patterns:** Where are the risky memory operations?

For example, with LNK files:
- Magic: 4C 00 00 00
- Header: fixed structure
- Then variable-length sections (link info, data, etc.)
- Each section has its own parsing logic
- Security-sensitive: offsets, sizes, counts, lengths

---

### Q8: How do you identify security-sensitive code paths?

**A:** I look for specific patterns:

1. **Length/size fields:** Anywhere a length from input controls memory allocation
2. **Offset fields:** Anywhere an offset from input controls data access
3. **Count fields:** Anywhere a count from input controls loop iterations
4. **Index fields:** Anywhere an index from input controls array access
5. **Type conversion:** Narrowing conversions (UInt64 → UInt32)
6. **Arithmetic:** Addition, subtraction, multiplication on input-derived values

The key is: attacker-controlled input → arithmetic → memory operation. If the chain is incomplete (missing validation), that's a potential vulnerability.

---

## Vulnerability Research Questions

### Q9: What's the difference between a crash and a vulnerability?

**A:** This is a critical distinction:

- **Crash:** Program terminates unexpectedly (segfault, assert, abort)
- **Memory safety bug:** Memory operation violates safety invariants (OOB read/write, UAF, double free)
- **Vulnerability:** Security-relevant bug that can be exploited for impact (info disclosure, code execution, privilege escalation)

Not every crash is a vulnerability:
- Some crashes are just null pointer derefs with no exploitability
- Some crashes are in non-security-critical paths
- Some crashes are caused by intentional validation checks

My process:
1. Reproduce the crash
2. Triage: What kind of bug is it?
3. Root cause: Why does it happen?
4. Impact assessment: Is it security-relevant?
5. Exploitability analysis: Can it be weaponized?

---

### Q10: Can you walk me through your vulnerability research methodology?

**A:** My methodology has 12 steps:

1. **Target selection:** Choose a target with good properties (open source, complex parser, known security history)
2. **Binary recon:** Analyze the target's architecture, mitigations, input surface
3. **Input surface discovery:** Map all entry points and parsing paths
4. **Harness design:** Build an optimal fuzz harness
5. **Seed corpus construction:** Build a high-quality seed corpus
6. **Baseline fuzzing:** Establish baseline coverage metrics
7. **Coverage analysis:** Identify bottlenecks and unreached paths
8. **Targeted fuzzing:** Structure-aware mutation, directed fuzzing
9. **Crash triage:** Reproduce, deduplicate, minimize, classify
10. **Root cause analysis:** Understand why the bug happens
11. **Patch/regression:** Verify the fix, build regression tests
12. **Final report:** Document everything with full evidence chain

---

### Q11: What is BIVAR and why did you build it?

**A:** BIVAR is a patch-guided variant hunting framework I built.

**Motivation:** When you find a vulnerability and see the patch, you often think: "Are there other places in the codebase with the same bug?" But manually checking all similar patterns is tedious and error-prone.

**How it works:**
1. Take a known vulnerability patch as input
2. Extract the underlying security invariant (e.g., "addition overflow in bounds check")
3. Systematically scan the entire codebase for similar patterns
4. Classify candidates using structural safety proofs
5. Output a ranked list of high-value targets

**What it does:**
- 6 detection rules (addition overflow, subtraction underflow, integer truncation, check ordering, derived index, shift width)
- 6 structural safety proof classes (sentinel, container relation, explicit bounds, range proof, explicit check, constant)
- 18/18 regression test coverage
- Scanned 571 candidates across 7-Zip's archive handlers

**Why it matters:** It turns "I found one bug" into "I systematically searched for all similar bugs" - which is much more valuable for a security researcher.

---

## Engineering Questions

### Q12: How do you ensure your research is reproducible?

**A:** Reproducibility is a core principle of my work:

1. **Version pinning:** I pin exact commit hashes for all targets
2. **Build scripts:** I document exact build commands and flags
3. **Experiment logs:** Every experiment is logged with:
   - Hypothesis
   - Configuration
   - Observation
   - Result
   - Decision
4. **Evidence chains:** Every finding has full evidence:
   - Source code location
   - Input that triggers it
   - Runtime behavior
   - Root cause analysis
5. **Negative results:** I document what didn't work too

The goal is that anyone can take my research and reproduce it exactly.

---

### Q13: How do you prioritize your work?

**A:** I use a clear priority framework:

**P0: Confirmed, high-impact vulnerabilities**
- Real bugs with clear root cause
- Security-relevant impact
- Easy to reproduce

**P1: High-value candidates**
- Strong static evidence
- Clear data flow from input to memory operation
- No obvious safety proof

**P2: Medium-value candidates**
- Interesting pattern but unclear exploitability
- Needs more analysis

**P3: Low-value candidates**
- Likely false positive
- No clear security impact

I also have strict stop conditions:
- If coverage hasn't grown in N observation windows, stop and diagnose
- If no new paths in M runs, switch strategy
- Don't waste CPU on low-value targets

---

### Q14: How do you handle false positives?

**A:** False positive management is critical for static analysis.

My approach:
1. **Structural safety proofs:** I have 6 classes of proofs that explain why a pattern is safe:
   - SAFE_BY_SENTINEL: Loop breaks on sentinel
   - SAFE_BY_CONTAINER_RELATION: Parallel-vector invariant
   - SAFE_BY_EXPLICIT_BOUNDS: Explicit check before use
   - SAFE_BY_RANGE_PROOF: Mathematical range proof
   - SAFE_BY_EXPLICIT_CHECK: Cast inside comparison
   - SAFE_BY_CONSTANT: Constant operand

2. **Context-aware filtering:** I look at surrounding code (10 lines before and after) to understand the context

3. **Type awareness:** I track variable types - if one operand is 64-bit, addition can't overflow 32-bit

4. **Range tracking:** I track the maximum possible value of variables based on how they're derived

The goal is to reduce 571 raw candidates down to a small set of truly high-value targets that need manual review.

---

## Deep Technical Questions

### Q15: Can you explain integer overflow and how it leads to vulnerabilities?

**A:** Integer overflow happens when an arithmetic operation produces a value too large to fit in the integer type.

**Example:**
```c
UInt32 a = 0xFFFFFFF0;
UInt32 b = 0x20;
UInt32 c = a + b;  // Overflow! c = 0x10, not 0x100000010
```

**How it leads to vulnerabilities:**

1. **Allocation size truncation:**
   ```c
   UInt32 size = count * element_size;
   void *buf = malloc(size);  // size is too small due to overflow
   ```

2. **Bounds check bypass:**
   ```c
   if (offset + size > buffer_size) {  // offset + size overflows to small value
       return ERROR;  // Check passes incorrectly
   }
   // Now we write beyond buffer
   memcpy(buf + offset, data, size);
   ```

3. **Loop count truncation:**
   ```c
   UInt32 num = count * 2;  // Overflow
   for (UInt32 i = 0; i < num; i++) {
       // Access beyond array
   }
   ```

**Key insight:** The compiler doesn't warn about signed integer overflow (it's undefined behavior), and unsigned integer overflow wraps silently. So it's easy to miss.

---

### Q16: What's the difference between stack-based and heap-based memory corruption?

**A:**

**Stack-based:**
- Affects stack memory (local variables, return addresses)
- Usually easier to exploit (return address overwrite → ROP)
- Stack canaries mitigate simple overwrites
- ASLR makes addresses random

**Heap-based:**
- Affects heap memory (malloc'd buffers)
- More complex exploitation (need heap feng shui)
- Different allocators have different mitigations
- Heap metadata corruption can lead to code execution

**Why heap bugs are harder:**
- You need to control heap layout
- You need to find useful objects to corrupt
- Mitigations like heap canaries, safe unlinking, etc.
- More research needed to understand exploitability

---

### Q17: How does AddressSanitizer work?

**A:** AddressSanitizer (ASan) is a memory error detector.

**How it works:**
1. **Shadow memory:** Every 8 bytes of application memory has 1 byte of shadow memory
2. **Redzones:** When you allocate memory, ASan adds "redzone" bytes around it
3. **Instrumentation:** At compile time, ASan inserts checks before every memory access
4. **On access:** Before reading/writing, it checks the shadow memory
5. **On error:** If the shadow says the memory is poisoned, it reports an error

**What it detects:**
- Heap buffer overflow
- Stack buffer overflow
- Use-after-free
- Double-free
- Memory leaks

**Trade-offs:**
- ~2x slowdown
- ~2-3x memory overhead
- Catches many bugs that would otherwise be silent

---

### Q18: What's the difference between white-box and black-box fuzzing?

**A:**

**Black-box fuzzing:**
- No access to source code
- Only sees input/output
- Uses coverage feedback (like AFL)
- Good for closed-source targets

**White-box fuzzing:**
- Has access to source code
- Can use static analysis to guide fuzzing
- Can build custom harnesses
- Can instrument with ASan, coverage, etc.
- Good for open-source targets

**Gray-box fuzzing:**
- Mix of both
- Uses coverage feedback but also static analysis hints
- libFuzzer is gray-box (uses coverage feedback, but you write the harness)

My work is mostly white-box because I focus on open-source targets and can deeply understand the code.

---

## Closing Questions

### Q19: What are your weaknesses?

**A:** I'm honest about my limitations:
- I haven't done much kernel-level exploitation yet (mostly user-space parsers)
- I'm still building my exploit development skills (mostly bug finding, not weaponization)
- I'm relatively new to the industry (coming from self-study + personal projects)

But I'm actively working on these:
- Building exploit development skills (ROP chains, heap feng shui)
- Expanding into kernel research
- Learning from experienced researchers

---

### Q20: Where do you see yourself in 5 years?

**A:** In 5 years, I see myself as:
- A senior binary security researcher with deep expertise in a specific area (e.g., browser exploitation, kernel exploitation, or virtualization)
- Contributing to open-source security tools and research
- Mentoring junior researchers
- Having published high-quality research at top conferences or workshops

I'm particularly interested in [game anti-cheat / EDR bypass / virtualization security] and want to build deep expertise in that area.

---

## Final Tips

1. **Be specific:** Don't just say "I found a bug" - explain the root cause, the data flow, the impact
2. **Show your process:** Explain how you approach problems, not just results
3. **Be honest:** Don't overstate your achievements - it's better to under-promise and over-deliver
4. **Show curiosity:** Ask questions, show you're interested in learning
5. **Be confident:** You've done real work, stand by it
