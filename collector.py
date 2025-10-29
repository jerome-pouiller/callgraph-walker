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
import subprocess
from typing import Dict, Set

# Change these values accordingly to you environment
cmd_objdump = "objdump"
cmd_nm = "nm"
pattern_fn = re.compile(r'^([0-9a-f]+) <(.+)>:')
pattern_call = re.compile(r'^\s+[0-9a-f]+:\s+.+\s+bl[x]?\s+[0-9a-f]+\s+<(.+)>')
pattern_fn_ptr = re.compile(r'^\s+([0-9a-f]+):\s+.+\s+bl[x]?\s+(r\d+)')

class Symbol:
    def __init__(self, name: str, offset: int = 0):
        self.name = name
        self.offset = offset
        self.size = -1
        self.frame_size = -1
        self.frame_qualifiers = ""
        self.sym_type = ""
        self.src_file = ""
        self.src_line = -1
        self.callers: Set[str] = set()
        self.callees: Set[str] = set()
        self.all_callees: Set[str] = set()
        self.cycles: Set[int] = set()
        self.sym_name_mismatch = False
        self.sym_not_found = True
        self.su_not_found = True
        self.indirect_call: list = []


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
        m = pattern_fn_ptr.match(line)
        if m:
            if not cur_fn:
                raise Exception("Parser error")
            symbols[cur_fn].indirect_call.append(int(m.group(1), 16))
    return symbols


def parse_nm(elf_file):
    try:
        output = subprocess.check_output([cmd_nm, '-Sl', elf_file],
                                         universal_newlines=True)
    except subprocess.CalledProcessError:
        sys.exit(f"Error running {cmd_nm}")

    nm_data = {}
    for line in output.split('\n'):
        parts = line.split()
        if len(parts) < 3:
            continue

        # Format: OFFSET [SIZE] TYPE NAME [SOURCE:LINE]
        offset = int(parts[0], 16)
        if len(parts) >= 4 and parts[1][0] in '0123456789abcdef':
            # Has size
            size = int(parts[1], 16)
            sym_type = parts[2]
            name = parts[3]
            src_partnum = 4
        else:
            # No size
            size = -1
            sym_type = parts[1]
            name = parts[2]
            src_partnum = 3

        if len(parts) > src_partnum:
            src_info = parts[src_partnum]
            if not ':' in src_info:
                raise Exception("Parser error")
            parts = src_info.rsplit(':', 1)
            src_file = parts[0]
            src_line = int(parts[1])
        else:
            src_file = ""
            src_line = -1
        # FIXME: multiple symbols can be decared on same offset
        # FIXME: detect case where binary has not been built with -g and no
        #        source files are available
        nm_data[offset] = (name, size, sym_type, src_file, src_line)

    return nm_data


def add_nm_info(symbols, elf_file):
    nm_data = parse_nm(elf_file)
    for name, sym in symbols.items():
        if not sym.offset in nm_data:
            continue
        sym.size = nm_data[sym.offset][1]
        sym.sym_type = nm_data[sym.offset][2]
        sym.src_file = nm_data[sym.offset][3]
        sym.src_line = nm_data[sym.offset][4]
        sym.sym_not_found = False
        if nm_data[sym.offset][0] != name:
            sym.sym_name_mismatch = True

def parse_su(search_dir):
    su_data = {}

    for root, dirs, files in os.walk(search_dir):
        for filename in files:
            if not filename.endswith('.su'):
                continue
            try:
                with open(os.path.join(root, filename), 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # Format: file:line:col:function\tframe_size\tqualifiers
                        parts = line.split('\t')
                        if len(parts) < 3:
                            continue
                        # Parse location: file:line:col:function
                        loc_parts = parts[0].rsplit(':', 3)
                        if len(loc_parts) < 4:
                            continue

                        frame_size = int(parts[1])
                        qualifiers = parts[2]
                        src_file = loc_parts[0]
                        src_line = int(loc_parts[1])
                        function = loc_parts[3]
                        key = (function, src_file, src_line)
                        su_data[key] = (frame_size, qualifiers)
            except (IOError, ValueError):
                continue

    return su_data


def add_su_info(symbols, search_dir):
    su_data = parse_su(search_dir)
    if not su_data:
        return False
    for sym in symbols.values():
        su_key = (sym.name, sym.src_file, sym.src_line)
        if su_key in su_data:
            sym.frame_size, sym.frame_qualifiers = su_data[su_key]
            sym.su_not_found = False
    return True

def build_reverse_callgraph(symbols):
    for caller in symbols:
        for callee in symbols[caller].callees:
            symbols[callee].callers.add(caller)


def detect_recursion(symbols):
    visited = set()
    cycles = [ ]

    def dfs(name, callstack):
        if name in callstack:
            # Found a cycle - mark all functions in the cycle with unique ID
            cycle_start = callstack.index(name)
            for func in callstack[cycle_start:]:
                symbols[func].cycles.add(len(cycles))
            cycles.append(callstack[cycle_start:].copy())
            return set()
        if name in visited:
            return symbols[name].all_callees
        visited.add(name)
        callstack.append(name)
        symbols[name].all_callees = set()
        for callee in symbols[name].callees:
            symbols[name].all_callees.add(callee)
            symbols[name].all_callees.update(dfs(callee, callstack.copy()))
        return symbols[name].all_callees

    for name in symbols:
        if name not in visited:
            dfs(name, [])
    return cycles
