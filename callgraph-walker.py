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
import os
import re
import sys
import argparse
import collector

prefix_strip = ""

def action_list_cycles(cycles):
    for k, v in enumerate(cycles):
        print(f"{k} -> {', '.join(v)}")

def action_health(symbols, has_su):

    def print_issue(title, predicate, formatter=lambda s: f"{s.name}"):
        syms =  [formatter(symbols[key]) for key in sorted(symbols) if predicate(symbols[key])]
        if syms:
            print(f"{title}:")
            print(f"  {', '.join(syms)}")
            print()

    print_issue("Symbol not found", lambda s: s.sym_not_found)
    print_issue("Size unknown", lambda s: s.size < 0)

    if not has_su:
        print(f"No stack usage data found.")
        print()
    else:
        print_issue("Stack usage not found", lambda s: s.su_not_found)

    print_issue("Source not found", lambda s: not s.src_file)
    print_issue("Type incorrect",
                lambda s: s.sym_type not in ['t', 'T', 'w', 'W'],
                lambda s: f"{s.name} ({s.sym_type})")
    print_issue("Has indirect calls", lambda s: s.indirect_call)
    print_issue("Part of a cycle", lambda s: s.cycles)

def action_show(symbols, symbol_names):

    def show(sym):
        print(f"Symbol: {sym.name}")
        print(f"  offset: 0x{sym.offset:x}")
        print(f"  size: {sym.size}")
        print(f"  frame size: {sym.frame_size}")
        print(f"  frame qualifiers: {sym.frame_qualifiers}")
        print(f"  symbol type: {sym.sym_type}")
        if sym.src_file:
            print(f"  source: {re.sub(prefix_strip, '', sym.src_file)}:{sym.src_line}")
        else:
            print(f"  source: (none)")
        print(f"  cycles: {sym.cycles if sym.cycles else '(none)'}")

        vals = { }
        for key in sym.callers:
            src_file = symbols[key].src_file
            if not src_file in vals:
                vals[src_file] = []
            if symbols[key].indirect_call:
                vals[src_file].append(f"{key[0]}[I]")
            else:
                vals[src_file].append(f"{key[0]}")
        if not vals:
            print(f"  callers (0): (none)")
        else:
            print(f"  callers ({len(sym.callers)}):")
            for key in sorted(vals):
                print(f"    {re.sub(prefix_strip, '', key) if key else '<unknown>'}: {', '.join(sorted(vals[key]))}")


        vals = { }
        for key in sym.callees:
            src_file = symbols[key].src_file
            if not src_file in vals:
                vals[src_file] = []
            if symbols[key].indirect_call:
                vals[src_file].append(f"{key[0]}[I]")
            else:
                vals[src_file].append(f"{key[0]}")
        if not vals:
            print(f"  callees (0): (none)")
        else:
            print(f"  callees ({len(sym.callees)}):")
            for key in sorted(vals):
                print(f"    {re.sub(prefix_strip, '', key) if key else '<unknown>'}: {', '.join(sorted(vals[key]))}")

        vals = { }
        for key in sym.all_callees:
            src_file = symbols[key].src_file
            if not src_file in vals:
                vals[src_file] = []
            if symbols[key].indirect_call:
                vals[src_file].append(f"{key[0]}[I]")
            else:
                vals[src_file].append(f"{key[0]}")
        if not vals:
            print(f"  all callees (0): (none)")
        else:
            print(f"  all callees ({len(sym.all_callees)}):")
            for key in sorted(vals):
                print(f"    {re.sub(prefix_strip, '', key) if key else '<unknown>'}: {', '.join(sorted(vals[key]))}")

        if sym.indirect_call:
            print(f"  indirect calls ({len(sym.indirect_call)}):")
            for offset, src_file, src_line in sym.indirect_call:
                if src_file:
                    print(f"    0x{offset:x} -> {re.sub(prefix_strip, '', src_file)}:{src_line}")
                else:
                    print(f"    0x{offset:x}")
        else:
            print(f"  indirect calls: (none)")
        print(f"  flags: ", end="")
        flags = []
        if sym.sym_type not in ['t', 'T', 'w', 'W']:
            flags.append("type_mismatch")
        if sym.sym_not_found:
            flags.append("not_found")
        if not sym.src_file:
            flags.append("no_src")
        print(", ".join(flags) if flags else "(none)")
        print()

    for sym_name in symbol_names:
        # Find symbol by name
        found = False
        for key, sym in symbols.items():
            if sym.name == sym_name:
                show(sym)
                found = True
        if not found:
            print(f"Symbol not found: {sym_name}")
            print()


def main():
    global prefix_strip

    parser = argparse.ArgumentParser(
        description='Extract the call graph and other useful from an ELF binary',
        usage='%(prog)s -e ELF_FILE ACTION [ARGS...]'
    )
    parser.add_argument('-e', '--elf', required=True, help='ELF binary file')
    parser.add_argument('-p', '--prefix', help='Prefix to strip when display file paths')
    parser.add_argument('action', help='Action to perform')
    parser.add_argument('args', nargs='*', help='Action arguments')
    args = parser.parse_args()
    elf_file = args.elf
    action = args.action
    prefix_strip = f'^{args.prefix}'
    searchpath_su = os.path.dirname(os.path.dirname(os.path.abspath(elf_file)))

    symbols = collector.parse_objdump(elf_file)
    collector.build_reverse_callgraph(symbols)
    cycles = collector.detect_recursion(symbols)
    collector.add_nm_info(symbols, elf_file)
    has_su = collector.add_su_info(symbols, searchpath_su)
    collector.add_addr2line_info(symbols, elf_file)

    if action == 'list_cycles':
        action_list_cycles(cycles)
    elif action == 'health':
        action_health(symbols, has_su)
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
