# BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer

## Overview

BIVAR is a binary security analysis tool that automatically:
1. Compares two versions of a binary
2. Identifies modified functions
3. Performs instruction-level diffing
4. Detects added security checks
5. Analyzes patch security semantics

This is the binary-level counterpart to [SVTA (Source Variant Analysis)](https://github.com/hhy569/pcapplusplus-ntp-vuln), providing complementary binary patch analysis capability.

---

## Current Capabilities (v0.3)

### ✅ Implemented
- **Function Extraction**: Disassembles ELF binaries and extracts all functions
- **Function Matching**: Identifies unchanged vs modified functions between two versions
- **Instruction Diff**: Performs instruction-level comparison of modified functions
- **Guard Pattern Detection**: Identifies CMP + conditional branch pairs
- **Security Semantic Classification**: Classifies security check types (length check / bounds check / null check)
- **Patch Completeness Analysis**: Automatically checks whether a security patch fully covers all consumer functions

### 🔄 In Progress
- Basic-block-level diffing
- More accurate security check classification
- Variant hunting across similar functions

### 📋 Roadmap
- v0.5: Patch completeness analysis
- v0.6: Variant Hunter (find similar unpatched bugs)
- v0.7: 3+ real CVE benchmarks
- v1.0: GDB dynamic validation

---

## Quick Start

### Requirements
- Linux (or WSL)
- objdump (binutils)
- Python 3.6+

### Usage
```bash
python3 bivar.py <old_binary> <new_binary>
```

### Example
```bash
python3 bivar.py benchmarks/old-vulnerable.o benchmarks/new-patched.o
```

---

## Example Output: NTP Patch Analysis

### Input
- Old binary: `NtpLayer.cpp.o` (v26.07, vulnerable)
- New binary: `NtpLayer.cpp.o` (with length check patch)

### Results
```
Old binary: 99 functions
New binary: 99 functions
Unchanged: 98
Modified: 1

Modified function:
  pcpp::NtpLayer::getNtpHeader() const
    Old instructions: 19
    New instructions: 35
    Added instructions: 17
    Removed instructions: 1
```

**Interpretation**: BIVAR correctly identified that only `getNtpHeader()` was modified, which is exactly where we applied the security patch (adding minimum-length validation before accessing the header).

---

## Project Structure

```
bivar/
├── analyzer/
│   ├── function_matcher.py    # Function extraction & matching
│   ├── diff_engine.py         # Instruction-level diffing
│   ├── security_semantic.py   # Security check classification
│   ├── patch_completeness.py  # Patch completeness analysis
│   └── bivar.py               # Main entry point
├── benchmarks/
│   └── ntp-patch-test/
│       ├── old-vulnerable.o   # PcapPlusPlus v26.07 NTP layer
│       └── new-patched.o      # Patched version with length check
└── README.md
```

---

## Why This Matters

This tool demonstrates real binary security analysis capability:
- **Binary Reverse Engineering**: Understanding compiled code without source
- **Patch Diffing**: Analyzing what changed between versions
- **Security Semantics**: Distinguishing security fixes from normal code changes
- **Variant Analysis**: Finding similar bugs that may not have been fixed

These are core skills for Vulnerability Research / Reverse Engineering positions at companies like Two Six Technologies, Qualys, Mandiant, and Google Project Zero.

---

## Related Projects

- [pcapplusplus-ntp-vuln](https://github.com/hhy569/pcapplusplus-ntp-vuln) - Source-level NTP vulnerability analysis (SVTA)

Together, these two projects demonstrate both source-level and binary-level vulnerability analysis capability.
