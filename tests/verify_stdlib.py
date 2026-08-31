#!/usr/bin/env python3
"""
verify_stdlib.py — proves a Python script imports nothing but the
standard library

Usage:
    python3 verify_stdlib.py linux_audit.py

How it works:
    Parses the target file's AST (Abstract syntax tree)
    Exits 0 with a PASS message if nothing but stdlib was found
    otherwise exits with a FAIL message (error code 1) 

This is just a script made for checking are there genuinely standard libraries and there is no dependency installed with pip
For that level of trust I am using AST which is the python's brain to check if the imports are from standard library or not and
there are no hidden imports
"""

import ast 
import sys


def collect_imports(source_path):
    with open(source_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=source_path)

    modules = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                modules.add(node.module.split(".")[0])

    return modules


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <script.py>")
        return 2
    
    # "$1"
    target = sys.argv[1]

    try:
        stdlib_names = sys.stdlib_module_names
    except AttributeError:
        print(
            "Error: sys.stdlib_module_names requires Python 3.10+ version "
            f"You are running {sys.version.split()[0]}."
        )
        return 2

    imports = collect_imports(target)
    third_party = sorted(imports - set(stdlib_names))

    print(f"Target file:        {target}")
    print(f"Python version:     {sys.version.split()[0]}")
    print(f"Imports found:      {sorted(imports)}")
    print(f"Third-party (non-stdlib) imports: {third_party if third_party else 'NONE'}")
    print()

    if third_party:
        print(f"Fail: {len(third_party)} non-stdlib import(s) detected: {third_party}")
        return 1

    print("Pass: every import resolves to the Python standard library.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
