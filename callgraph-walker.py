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

def action_sanity(symbols, has_su):

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
                lambda s: s.sym_type.lower() not in ['t', 'w', 'v'] and not s.sym_not_found,
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


def action_show(symbols, patterns):

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
        if sym.callee_worst_stack:
            print(f"    worse stack: {sym.worst_stack_depth} bytes ({symbols[sym.callee_worst_stack]})")
        else:
            print(f"    worse stack: (unknown)")
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
        if sym.sym_type.lower() not in ['t', 'w', 'v']:
            flags.append("type_mismatch")
        if sym.sym_not_found:
            flags.append("not_found")
        if not sym.src.file:
            flags.append("no_src")
        print(", ".join(flags) if flags else "(none)")
        print()

    # Match symbols using glob patterns
    matched_keys = set()
    for pattern in patterns:
        for key, sym in symbols.items():
            if fnmatch.fnmatchcase(sym.name, pattern):
                matched_keys.add(key)

    # Show matched symbols
    if matched_keys:
        for key in sorted(matched_keys):
            show(symbols[key])
    else:
        print(f"No symbols matched the patterns: {', '.join(patterns)}")
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


def parse_cmake_cache(build_dir):
    """
    Parse CMakeCache.txt and other build files to extract PATH variables that can be used for path substitution.
    Returns a dict mapping variable names to their values.
    """
    cmake_vars = {}

    # Parse CMakeCache.txt
    cache_file = os.path.join(build_dir, 'CMakeCache.txt')
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # CMakeCache.txt format: VARIABLE_NAME:TYPE=VALUE
                    if ':' in line and '=' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            var_name = parts[0]
                            value_part = parts[1].split('=', 1)
                            if len(value_part) == 2:
                                var_type = value_part[0]
                                var_value = value_part[1]
                                # Only consider PATH variables (and some common ones)
                                if var_type in ['PATH', 'FILEPATH'] or \
                                   var_name.endswith('_DIR') or \
                                   var_name.endswith('_BASE') or \
                                   '_MODULE_DIR' in var_name:
                                    cmake_vars[var_name] = var_value
        except (IOError, ValueError):
            pass

    # Parse Kconfig module dirs file (contains ZEPHYR_*_MODULE_DIR variables)
    kconfig_env_file = os.path.join(build_dir, 'Kconfig', 'kconfig_module_dirs.env')
    if os.path.exists(kconfig_env_file):
        try:
            with open(kconfig_env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Format: VARIABLE_NAME=VALUE
                    if '=' in line and not line.startswith('#'):
                        parts = line.split('=', 1)
                        if len(parts) == 2:
                            var_name = parts[0]
                            var_value = parts[1]
                            if '_MODULE_DIR' in var_name or var_name.endswith('_BASE'):
                                cmake_vars[var_name] = var_value
        except (IOError, ValueError):
            pass

    return cmake_vars


def map_path_to_cmake_var(file_path, cmake_vars):
    """
    Try to map a file path to a CMake variable.
    Returns the path with CMake variable substitution if a match is found.
    """
    # Sort by length (longest first) to match most specific paths first
    sorted_vars = sorted(cmake_vars.items(), key=lambda x: len(x[1]), reverse=True)

    for var_name, var_value in sorted_vars:
        if var_value and file_path.startswith(var_value):
            # Replace the variable value with ${VAR_NAME}
            remaining_path = file_path[len(var_value):].lstrip('/')
            if remaining_path:
                return f"${{{var_name}}}/{remaining_path}"
            else:
                return f"${{{var_name}}}"

    return file_path


def action_relocate(symbols, patterns, build_dir=None):
    """
    Generate CMake fragments with zephyr_code_relocate() calls to relocate
    the specified symbols and all their callees to RAM.

    Args:
        symbols: Dictionary of symbols
        patterns: List of patterns to match symbols
        build_dir: Optional build directory to parse CMakeCache.txt for path mapping
    """
    # Parse CMake cache if build directory is provided
    cmake_vars = {}
    if build_dir:
        cmake_vars = parse_cmake_cache(build_dir)

    # Find all symbols matching the patterns
    matched_keys = set()
    for pattern in patterns:
        for key, sym in symbols.items():
            if fnmatch.fnmatchcase(sym.name, pattern):
                matched_keys.add(key)

    if not matched_keys:
        print(f"No symbols matched the patterns: {', '.join(patterns)}")
        return

    # Collect all symbols to relocate: matched symbols + all their callees
    symbols_to_relocate = set()
    for key in matched_keys:
        symbols_to_relocate.add(key)
        # Add all callees (transitive closure)
        for callee_key in symbols[key].all_callees:
            if callee_key in symbols:
                symbols_to_relocate.add(callee_key)

    # Check for indirect calls and warn the user
    indirect_call_warnings = []
    for key in symbols_to_relocate:
        sym = symbols[key]
        if sym.indirect_call:
            for src in sym.indirect_call:
                indirect_call_warnings.append((sym.name, src))

    if indirect_call_warnings:
        print("WARNING: Found indirect calls in functions to relocate:", file=sys.stderr)
        for func_name, src in indirect_call_warnings:
            print(f"  {func_name}(): {src}", file=sys.stderr)
        print("", file=sys.stderr)

    # Group symbols by source file
    file_to_symbols = {}
    for key in symbols_to_relocate:
        sym = symbols[key]
        if not sym.src.file:
            # Skip symbols without source file info
            continue
        # Skip header files (.h, .hpp, etc.) as they don't generate object files
        # and functions in headers are typically inline
        if sym.src.file.lower().endswith(('.h', '.hpp', '.hxx', '.hh')):
            continue
        if sym.src.file not in file_to_symbols:
            file_to_symbols[sym.src.file] = []
        file_to_symbols[sym.src.file].append(sym.name)

    if not file_to_symbols:
        print("No symbols with source file information found.")
        return

    # Generate CMake code for each file
    for src_file, func_names in sorted(file_to_symbols.items()):
        # Escape function names and create FILTER pattern
        # Pattern format: "func1|func2|func3" with escaped special chars
        escaped_names = [re.escape(name) for name in sorted(func_names)]
        filter_pattern = "|".join(escaped_names)

        # Map to CMake variable if build_dir was provided
        if cmake_vars:
            file_stripped = map_path_to_cmake_var(src_file, cmake_vars)
            # If mapping succeeded, use it; otherwise fall back to prefix stripping
            if file_stripped == src_file:
                # No CMake variable match, apply prefix stripping
                for prefix in collector.Src.prefix_strip:
                    file_stripped = re.sub(f'^{prefix}', '', file_stripped)
        else:
            # No build_dir provided, use prefix stripping
            file_stripped = src_file
            for prefix in collector.Src.prefix_strip:
                file_stripped = re.sub(f'^{prefix}', '', file_stripped)

        # Generate CMake command
        print(f"zephyr_code_relocate(FILES {file_stripped}")
        print(f"                     FILTER \"{filter_pattern}\"")
        print(f"                     LOCATION RAM)")


def main():
    parser = argparse.ArgumentParser(
        description='Extract the call graph and other useful from an ELF binary',
        usage='%(prog)s -e ELF_FILE ACTION [ARGS...]',
        epilog='''
Available actions:
  list [GLOB...]        List all symbols, optionally filtered by glob patterns
  show PATTERN [...]    Show detailed information for symbols matching patterns
  sanity                Check for symbols with issues (missing info, etc.)
  list_cycles           List all detected recursion cycles
  check_stack_depth     Show functions with worst stack depth
  relocate PATTERN [...] Generate CMake fragments with zephyr_code_relocate() calls (experimental)
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-e', '--elf', required=True,
                        help='ELF binary file')
    parser.add_argument('-p', '--prefix', action='append', default=[],
                        help='Prefix to strip when display file paths (can be specified multiple times)')
    parser.add_argument('-c', '--cross', default="",
                        help='Cross-compilation prefix (e.g., arm-none-eabi-)')
    parser.add_argument('-b', '--build-dir', default="",
                        help='Build directory path. Used to search stack usage'
                             ' (.su) files and for "relocate" to detect paths'
                             ' mapping. If not specified some heristocs are'
                             ' used to detect it')
    parser.add_argument('action', help='Action to perform')
    parser.add_argument('args', nargs='*', help='Action arguments')
    args = parser.parse_args()
    m = re.match('(.*)/zephyr/zephyr.elf', args.elf)
    if not args.build_dir and m:
        args.build_dir = m.group(1)

    cmd_objdump = f"{args.cross}objdump"
    cmd_nm = f"{args.cross}nm"
    cmd_addr2line = f"{args.cross}addr2line"
    collector.Src.prefix_strip = args.prefix

    arch_config = collector.detect_arch(args.elf)
    symbols = collector.parse_objdump(args.elf, arch_config, cmd_objdump)
    collector.build_reverse_callgraph(symbols)
    collector.add_nm_info(symbols, args.elf, cmd_nm)
    if args.build_dir:
        collector.add_su_info(symbols, args.build_dir)
    collector.add_addr2line_info(symbols, args.elf, cmd_addr2line)
    cycles = collector.detect_recursion(symbols)

    if args.action == 'list_cycles':
        action_list_cycles(cycles)
    elif args.action == 'sanity':
        action_sanity(symbols, bool(args.stack_usage))
    elif args.action == 'list':
        action_list(symbols, args.args)
    elif args.action == 'show':
        if not args.args:
            print("Error: 'show' requires at least one pattern")
            sys.exit(1)
        action_show(symbols, args.args)
    elif args.action == 'check_stack_depth':
        action_check_stack_depth(symbols)
    elif args.action == 'relocate':
        if not args.args:
            print("Error: 'relocate' requires at least one pattern")
            sys.exit(1)
        action_relocate(symbols, args.args, args.build_dir)
    else:
        print(f"Unknown action: {args.action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
