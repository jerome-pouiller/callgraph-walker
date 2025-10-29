#!/usr/bin/env python3
# Copyright (c) 2025 Silicon Laboratories Inc.
#
# The licensor of this software is Silicon Laboratories Inc. Your use of this
# software is governed by the terms of the Silicon Labs Master Software License
# Agreement (MSLA) available at [1].  This software is distributed to you in
# Object Code format and/or Source Code format and is governed by the sections
# of the MSLA applicable to Object Code, Source Code and Modified Open Source
# Code. By using this software, you agree to the terms of the MSLA.
#
# [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
import re
import sys
import subprocess
from typing import Dict, Set

# Change these values accordingly to you environment
cmd_objdump = "objdump"
pattern_fn = re.compile(r'^([0-9a-f]+) <(.+)>:')
pattern_call = re.compile(r'^\s+[0-9a-f]+:\s+.+\s+bl[x]?\s+[0-9a-f]+\s+<(.+)>')

class Symbol:
    def __init__(self, name: str, offset: int = 0):
        self.name = name
        self.offset = offset
        self.callees: Set[str] = set()
        self.callers: Set[str] = set()


def parse_objdump(elf_file):
    try:
        output = subprocess.check_output([cmd_objdump, '-d', elf_file],
                                         universal_newlines=True)
    except subprocess.CalledProcessError:
        sys.exit(f"Error running {cmd_objdump}")

    symbols = {}
    cur_fn = ""
    for line in output.split('\n'):
        m = pattern_fn.match(line)
        if m:
            cur_fn = m.group(2)
            symbols[cur_fn] = Symbol(cur_fn, int(m.group(1), 16))
        m = pattern_call.match(line)
        if m:
            if not cur_fn:
                raise Exception("Parser error")
            symbols[cur_fn].callees.add(m.group(1))
    return symbols

def build_reverse_callgraph(symbols):
    for caller in symbols:
        for callee in symbols[caller].callees:
            symbols[callee].callers.add(caller)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ELF_FILE")
        sys.exit(1)

    symbols = parse_objdump(sys.argv[1])
    build_reverse_callgraph(symbols)

    print("Call Graph:")
    for fn in sorted(symbols.keys()):
        print(f"  {fn} -> {', '.join(sorted(symbols[fn].callees))}")

if __name__ == "__main__":
    main()
