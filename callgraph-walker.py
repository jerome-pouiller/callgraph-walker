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
import fnmatch
import argparse
import collector

def action_list_cycles(cycles):
    for k, v in enumerate(cycles):
        print(f"{k} -> {', '.join(v)}")

def action_list(symbols, glob):
    for key in sorted(symbols):
        if not glob:
            print(symbols[key].name)
        elif fnmatch.fnmatchcase(symbols[key].name, glob):
            print(symbols[key].name)

def action_health(symbols, has_su):

    def print_issue(title, predicate, formatter=lambda s: f"{s.name}"):
        syms = [formatter(symbols[key]) for key in sorted(symbols) if predicate(symbols[key])]
        if syms:
            print(f"{title}:")
            print(f"  {', '.join(syms)}")
            print()

    print_issue("Symbol not found", lambda s: s.sym_not_found)
    print_issue("Size unknown", lambda s: s.size < 0 and not s.sym_not_found)

    if not has_su:
        print(f"No stack usage data found.")
        print()
    else:
        print_issue("Stack usage not found", lambda s: s.su_not_found and not s.sym_not_found)

    print_issue("Source not found", lambda s: not s.src.file and not s.sym_not_found)
    print_issue("Type incorrect",
                lambda s: s.sym_type not in ['t', 'T', 'w', 'W'] and not s.sym_not_found,
                lambda s: f"{s.name} ({s.sym_type})")
    print_issue("Has indirect calls", lambda s: s.indirect_call)
    print_issue("Part of a cycle", lambda s: s.cycles)

    # Memory section checks (only if ranges are defined)
    if collector.Symbol.ram_range and collector.Symbol.flash_range:
        def ram_calls_flash(sym):
            if not sym.is_in_ram():
                return False
            for callee_key in sym.callees:
                if callee_key in symbols and symbols[callee_key].is_in_flash():
                    return True
            return False

        print_issue("Symbols located in unknown section", lambda s: s.is_unknown_section())
        print_issue("Symbols located in RAM", lambda s: s.is_in_ram())
        print_issue("Symbols in RAM calls symbols in Flash", ram_calls_flash)


def action_show(symbols, symbol_names):

    def print_grouped(title, sym_ids):
        if not sym_ids:
            print(f"    {title} (0): (none)")
            return
        print(f"    {title} ({len(sym_ids)}):")
        sources = {}
        for key in sym_ids:
            src_file = symbols[key].src.file
            if src_file not in sources:
                sources[src_file] = []
            sources[src_file].append(str(symbols[key]))
        for key in sorted(sources):
            file = collector.Src(file=key)
            print(f"        - {file}: {', '.join(sorted(sources[key]))}")

    def show(sym):
        # Determine section
        section = ""
        if collector.Symbol.ram_range and collector.Symbol.flash_range:
            if sym.is_in_ram():
                section = " (RAM)"
            elif sym.is_in_flash():
                section = " (Flash)"
            else:
                section = " (Unknown Section)"

        print(f"Symbol: {sym.name}")
        print(f"    address: 0x{sym.src.addr:x}{section}")
        print(f"    size: {sym.size}")
        print(f"    frame size: {sym.frame_size}")
        print(f"    frame qualifiers: {sym.frame_qualifiers}")
        print(f"    symbol type: {sym.sym_type}")
        print(f"    source: {sym.src}")
        print(f"    cycles: {sym.cycles if sym.cycles else '(none)'}")

        print_grouped("callers", sym.callers)
        print_grouped("callees", sym.callees)
        print_grouped("all callees", sym.all_callees)

        if sym.indirect_call:
            print(f"    indirect calls ({len(sym.indirect_call)}):")
            for src in sym.indirect_call:
                print(f"        - 0x{src.addr:x} -> {src}")
        else:
            print(f"    indirect calls: (none)")
        print(f"    flags: ", end="")
        flags = []
        if sym.sym_type not in ['t', 'T', 'w', 'W']:
            flags.append("type_mismatch")
        if sym.sym_not_found:
            flags.append("not_found")
        if not sym.src.file:
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


def action_check_stack_depth(symbols):
    # Find entry point symbols (no callers) with worst stack depth
    worst_stack = []
    for key, sym in symbols.items():
        if not sym.callers and sym.worst_stack_depth > 0 and len(sym.cycles) == 0:
            worst_stack.append((sym.worst_stack_depth, key, sym))
    worst_stack.sort(reverse=True, key=lambda x: x[0])

    for depth, key, sym in worst_stack[:10]:
        # Build the call chain
        chain = []
        current_key = key
        while current_key:
            current_sym = symbols[current_key]
            chain.append((current_sym.name, current_sym.frame_size))
            current_key = current_sym.callee_worst_stack
        # Display
        print(f"{sym.name}: {depth} bytes")
        for i, (name, frame) in enumerate(chain):
            indent = "  " * i
            print(f"  {indent}{name} ({frame} bytes)")


def main():
    parser = argparse.ArgumentParser(
        description='Extract the call graph and other useful from an ELF binary',
        usage='%(prog)s -e ELF_FILE ACTION [ARGS...]',
        epilog='''
Available actions:
  list [GLOB]           List all symbols, optionally filtered by glob pattern
  show SYMBOL [...]     Show detailed information for one or more symbols
  health                Check for symbols with issues (missing info, etc.)
  list_cycles           List all detected recursion cycles
  check_stack_depth     Show functions with worst stack depth
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-e', '--elf', required=True,
                        help='ELF binary file')
    parser.add_argument('-p', '--prefix', default="",
                        help='Prefix to strip when display file paths')
    parser.add_argument('-c', '--cross', default="",
                        help='Cross-compilation prefix (e.g., arm-none-eabi-)')
    parser.add_argument('action', help='Action to perform')
    parser.add_argument('args', nargs='*', help='Action arguments')
    args = parser.parse_args()
    elf_file = args.elf
    action = args.action
    cmd_objdump = f"{args.cross}objdump"
    cmd_nm = f"{args.cross}nm"
    cmd_addr2line = f"{args.cross}addr2line"
    collector.Src.prefix_strip = f'^{args.prefix}'

    searchpath_su = os.path.dirname(os.path.dirname(os.path.abspath(elf_file)))

    arch_config = collector.detect_arch(elf_file)
    symbols = collector.parse_objdump(elf_file, arch_config, cmd_objdump)
    collector.build_reverse_callgraph(symbols)
    collector.add_nm_info(symbols, elf_file, cmd_nm)
    has_su = collector.add_su_info(symbols, searchpath_su)
    collector.add_addr2line_info(symbols, elf_file, cmd_addr2line)
    cycles = collector.detect_recursion(symbols)

    if action == 'list_cycles':
        action_list_cycles(cycles)
    elif action == 'health':
        action_health(symbols, has_su)
    elif action == 'list':
        action_list(symbols, args.args[0] if args.args else "")
    elif action == 'show':
        if not args.args:
            print("Error: 'show' action requires at least one symbol name")
            sys.exit(1)
        action_show(symbols, args.args)
    elif action == 'check_stack_depth':
        action_check_stack_depth(symbols)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
