#!/usr/bin/env python3
"""Fix detect_in_directory function definition"""

with open('source_invariant_detector.py', 'r', encoding='utf-8') as f:
    content = f.read()

old = '        return results\n        """Detect all invariant violations'
new = '        return results\n\n    def detect_in_directory(self, dir_path: str, extensions=[".cpp", ".c", ".h"]) -> List[SourceInvariant]:\n        """Detect all invariant violations'

if old in content:
    content = content.replace(old, new)
    with open('source_invariant_detector.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print('Fixed!')
else:
    print('Pattern not found - maybe already fixed?')
