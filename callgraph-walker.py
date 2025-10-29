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
import sys
from collector import parse_objdump, add_symbols_info, build_reverse_callgraph, detect_recursion

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ELF_FILE")
        sys.exit(1)

    symbols = parse_objdump(sys.argv[1])
    add_symbols_info(symbols, sys.argv[1])
    build_reverse_callgraph(symbols)
    cycles = detect_recursion(symbols)
    print("Cycles:")
    for k, v in enumerate(cycles):
        print(f"  {k} -> {', '.join(v)}")

    print("Call Graph:")
    for fn in sorted(symbols.keys()):
        print(f"  {fn} -> {', '.join(sorted(symbols[fn].all_callees))}")

if __name__ == "__main__":
    main()
