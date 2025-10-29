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
import collector

def action_list_cycles(cycles):
    for k, v in enumerate(cycles):
        print(f"{k} -> {', '.join(v)}")

def action_health(symbols):
    """List symbols with errors or missing information."""
    syms = []
    for name in sorted(symbols):
        if symbols[name].sym_not_found:
            syms.append(name)
    if syms:
        print(f"Symbol not found:")
        print(f"  {', '.join(syms)}")
        print()

    syms = []
    for name in sorted(symbols):
        if symbols[name].sym_name_mismatch:
            syms.append(name)
    if syms:
        print(f"Symbol name mismatch:")
        print(f"  {', '.join(syms)}")
        print()

    syms = []
    for name in sorted(symbols):
        if symbols[name].size < 0:
            syms.append(name)
    if syms:
        print(f"Size unknown:")
        print(f"  {', '.join(syms)}")
        print()

    syms = []
    for name in sorted(symbols):
        if not symbols[name].src_file:
            syms.append(name)
    if syms:
        print(f"Source not found:")
        print(f"  {', '.join(syms)}")
        print()

    syms = []
    for name in sorted(symbols):
        if symbols[name].sym_type not in ['t', 'T', 'w', 'W']:
            syms.append(f"{name} ({symbols[name].sym_type})")
    if syms:
        print(f"Type incorrect:")
        print(f"  {', '.join(syms)}")
        print()

    syms = []
    for name in sorted(symbols):
        if symbols[name].indirect_call:
            syms.append(name)
    if syms:
        print(f"Has indriect calls:")
        print(f"  {', '.join(syms)}")
        print()

    syms = []
    for name in sorted(symbols):
        if symbols[name].cycles:
            syms.append(name)
    if syms:
        print(f"Part of a cycle:")
        print(f"  {', '.join(syms)}")
        print()

def show(sym):
        print(f"Symbol: {sym.name}")
        print(f"  offset: 0x{sym.offset:x}")
        print(f"  size: {sym.size}")
        print(f"  type: {sym.sym_type}")
        print(f"  source: {sym.src_file}:{sym.src_line}" if sym.src_file else "  source: (none)")
        print(f"  cycles: {sym.cycles if sym.cycles else '(none)'}")
        print(f"  callers ({len(sym.callers)}): {', '.join(sorted(sym.callers)) if sym.callers else '(none)'}")
        print(f"  callees ({len(sym.callees)}): {', '.join(sorted(sym.callees)) if sym.callees else '(none)'}")
        print(f"  all callees ({len(sym.all_callees)}): {', '.join(sorted(sym.all_callees)) if sym.all_callees else '(none)'}")
        print(f"  indirect call: {sym.indirect_call}")
        print(f"  flags: ", end="")
        flags = []
        if sym.sym_name_mismatch:
            flags.append("name_mismatch")
        if sym.sym_type not in ['t', 'T', 'w', 'W']:
            flags.append("type_mismatch")
        if sym.sym_not_found:
            flags.append("not_found")
        if not sym.src_file:
            flags.append("no_src")
        print(", ".join(flags) if flags else "(none)")
        print()

def action_show(symbols, symbol_names):
    for sym in symbol_names:
        if sym not in symbols:
            print(f"Symbol not found: {sym}")
            continue
        show(symbols[sym])


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

    symbols = collector.parse_objdump(elf_file)
    collector.build_reverse_callgraph(symbols)
    cycles = collector.detect_recursion(symbols)
    collector.add_nm_info(symbols, elf_file)

    if action == 'list_cycles':
        action_list_cycles(cycles)
    elif action == 'health':
        action_health(symbols)
    elif action == 'show':
        if not args.args:
            print("Error: 'show' action requires at least one symbol name")
            sys.exit(1)
        action_show(symbols, args.args)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
