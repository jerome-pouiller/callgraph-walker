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
import argparse
from collector import parse_objdump, add_symbols_info, build_reverse_callgraph, detect_recursion

def action_list_cycles(cycles):
    for k, v in enumerate(cycles):
        print(f"{k} -> {', '.join(v)}")


def main():
    parser = argparse.ArgumentParser(
        description='Extract the call graph and other useful from an ELF binary',
        usage='%(prog)s -e ELF_FILE ACTION [ARGS...]'
    )
    parser.add_argument('-e', '--elf', required=True, help='ELF binary file')
    parser.add_argument('action', help='Action to perform')
    parser.add_argument('args', nargs='*', help='Action arguments')
    args = parser.parse_args()
    elf_file = args.elf
    action = args.action

    symbols = parse_objdump(elf_file)
    add_symbols_info(symbols, elf_file)
    build_reverse_callgraph(symbols)
    cycles = detect_recursion(symbols)
    if action == 'list_cycles':
        action_list_cycles(cycles)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
