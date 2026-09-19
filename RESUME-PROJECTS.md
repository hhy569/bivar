# Binary Security Research Portfolio

## Overview

This portfolio demonstrates hands-on experience in binary security research, including fuzzing, vulnerability discovery, reverse engineering, and security tool development.

---

## Project 1: BIVAR - Patch-Guided Variant Hunting Framework

**Role:** Author & Developer
**Duration:** 2 months
**Technologies:** Python, C++, LLVM/ASan, Static Analysis, Reverse Engineering

### Description

BIVAR is a security invariant analyzer that systematically hunts for vulnerability variants across large codebases. It works by:
1. Extracting security invariants from known vulnerability patches
2. Systematically scanning the entire codebase for similar patterns
3. Classifying candidates using structural safety proofs
4. Generating targeted PoC seeds for dynamic validation

### Key Achievements

- **6 detection rules** covering arithmetic overflow, integer truncation, shift width violations, check ordering, and derived index validation
- **18/18 regression test coverage** with both positive (known vulnerabilities) and negative (safe patterns) benchmarks
- **571 candidates scanned and classified** across the entire 7-Zip archive handler codebase
- **6 structural safety proof classes** to distinguish true vulnerabilities from false positives:
  - SAFE_BY_SENTINEL
  - SAFE_BY_CONTAINER_RELATION
  - SAFE_BY_EXPLICIT_BOUNDS
  - SAFE_BY_RANGE_PROOF
  - SAFE_BY_EXPLICIT_CHECK
  - SAFE_BY_CONSTANT

### Technical Highlights

**7-Zip Security Variant Research:**
- Analyzed 6 real security patches from 7-Zip 26.00→26.01
- Extracted underlying security invariants for each
- Built pattern detectors for each invariant type
- Scanned entire CPP/7zip/Archive/** codebase (100K+ LOC)
- Triaged 571 raw candidates down to a small set of high-value targets

**Methodology:**
- Patch-guided analysis: reverse-engineer root causes from patches
- Variant hunting: find same broken invariant in different code paths
- Semantic triage: distinguish true positives from false positives
- Reproducible research: full experiment logs and evidence chains

### Impact

- Demonstrated deep understanding of memory safety invariants
- Built production-grade static analysis tooling
- Developed systematic approach to variant vulnerability research
- Documented negative results honestly (quality over quantity)

---

## Project 2: brpc HPACK Stack Overflow (Apache Confirmed)

**Role:** Independent Vulnerability Researcher
**Status:** Confirmed by Apache PMC, official PR merged
**Technologies:** C++, HTTP/2, HPACK, Stack Analysis

### Description

Discovered a stack overflow vulnerability in brpc's HPACK header compression implementation. The issue was caused by unbounded recursion in the HPACK decoding logic.

### Key Achievements

- **Root cause identified:** Recursive HPACK decoding without depth limit
- **Apache PMC confirmation:** Vulnerability acknowledged by the Apache brpc team
- **Official fix contributed:** PR #3343 (recursive → iterative implementation)
- **Impact:** Remote denial of service via crafted HTTP/2 request

### Technical Details

**Root Cause:**
- HPACK header name lookup used recursive descent
- Deeply nested header references caused stack exhaustion
- No recursion depth limit was implemented

**Fix:**
- Rewrote recursive decoder as iterative state machine
- Added explicit depth limit check
- Maintained full backward compatibility

### Impact

- Demonstrated ability to find real vulnerabilities in production-grade C++ code
- Contributed upstream fix to Apache project
- Showed understanding of protocol-level security issues

---

## Project 3: VirtualBox CVE-2026-60160

**Role:** Independent Vulnerability Researcher
**CVE:** CVE-2026-60160
**Oracle TID:** Confirmed
**Technologies:** VirtualBox, VM Escape, Reverse Engineering

### Description

Discovered a vulnerability in Oracle VirtualBox that was assigned CVE-2026-60160 and acknowledged by Oracle with a tracking ID.

### Key Achievements

- **CVE assigned:** CVE-2026-60160
- **Oracle acknowledgment:** Confirmed with internal tracking ID
- **Root cause analysis:** Complete vulnerability chain documented

### Impact

- Demonstrated ability to find vulnerabilities in large, well-audited codebases
- Showed understanding of virtualization security
- Produced a verifiable CVE with vendor acknowledgment

---

## Project 4: 7-Zip Security Research

**Role:** Independent Security Researcher
**Target:** 7-Zip 26.03 (ip7z/7zip)
**Technologies:** C++, ASan, Fuzzing, Static Analysis

### Description

Systematic security research on 7-Zip's archive parsing codebase, including 30+ archive format handlers.

### Key Achievements

- **ASan-instrumented build:** Successfully built 7za with AddressSanitizer
- **Comprehensive codebase analysis:** 571 security invariant candidates scanned
- **Structural safety proof taxonomy:** 6 classes of false positive proofs
- **Deep understanding of archive parsing:** Squashfs, UDF, WIM, NTFS, APFS, etc.

### Handlers Analyzed

- SquashfsHandler (31 candidates)
- Rar5Handler (23 candidates)
- ApfsHandler (22 candidates)
- DmgHandler (22 candidates)
- ExtHandler (20 candidates)
- NtfsHandler (20 candidates)
- NsisIn (20 candidates)
- And 20+ more...

---

## Project 5: liblnk Windows Shortcut Research

**Role:** Independent Researcher
**Target:** libyal/liblnk
**Technologies:** C++, Windows RE, File Format Parsing

### Description

Deep dive research into Windows .lnk shortcut file format parsing, including static analysis and fuzzing.

### Key Achievements

- **Parser map:** Complete LNK file format parsing map
- **Security invariants:** Identified and documented key security invariants
- **Coverage baseline:** Established coverage metrics for fuzzing
- **Bug report prepared:** CAND-006 upstream bug report

### Deliverables

- RESEARCH-REPORT.md: Complete research report
- upstream-bug-report.md: CAND-006 bug report
- parser-map.md: LNK format parser map
- security-invariants.md: Key security invariants documented

---

## Project 6: Linux Kernel Driver Research

**Role:** Independent Researcher
**Status:** v1.0 frozen and published
**Technologies:** Linux Kernel, C, Reverse Engineering, Driver Analysis

### Description

Research on Linux kernel drivers, including tpm_vtpm_proxy and FUSE filesystem driver analysis.

### Key Achievements

- **Driver RE:** Complete reverse engineering of kernel driver interfaces
- **Security analysis:** Identified attack surface and trust boundaries
- **v1.0 frozen:** Stable release with comprehensive documentation
- **Public repository:** Published to GitHub

---

## Skills Demonstrated

### Reverse Engineering
- Binary analysis (IDA Pro, Ghidra, GDB)
- Disassembly and decompilation
- Protocol parsing
- File format reverse engineering

### Fuzzing & Dynamic Analysis
- libFuzzer / AFL++
- AddressSanitizer / UndefinedBehaviorSanitizer
- Coverage-guided fuzzing
- Crash triage and minimization

### Static Analysis
- Custom static analysis tool development (BIVAR)
- Pattern matching and semantic analysis
- Security invariant detection
- False positive management

### Vulnerability Research
- Patch analysis and root cause reconstruction
- Variant hunting methodology
- PoC development
- Upstream vulnerability reporting

### Programming
- Python (tool development, scripting)
- C/C++ (vulnerability research, fuzz harnesses)
- x86/x64 assembly
- Shell scripting

---

## Research Philosophy

**Authenticity > Reproducibility > Technical Depth > Research Method > Automation > Coverage > Crash Count**

- Never fabricate CVE numbers or patches
- Document negative results honestly
- Distinguish crash from vulnerability
- Quality over quantity
- Reproducible research with full evidence chains
