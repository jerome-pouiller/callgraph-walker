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

class ArchConfig:
    def __init__(self, pattern_fn: str, pattern_call: str, pattern_fn_ptr: str):
        self.pattern_fn = re.compile(pattern_fn)
        self.pattern_call = re.compile(pattern_call)
        self.pattern_fn_ptr = re.compile(pattern_fn_ptr)

arch_configs = {
    'arm': ArchConfig(
        pattern_fn=r'^([0-9a-f]+) <(.+)>:',
        pattern_call=r'^\s+[0-9a-f]+:\s+.+\s+bl[x]?\s+([0-9a-f]+)\s+<(.+)>',
        pattern_fn_ptr=r'^\s+([0-9a-f]+):\s+.+\s+bl[x]?\s+(r\d+)'
    ),
    'x86': ArchConfig(
        pattern_fn=r'^([0-9a-f]+) <(.+)>:',
        pattern_call=r'^\s+[0-9a-f]+:\s+.+\s+call\s+([0-9a-f]+)\s+<(.+)>',
        pattern_fn_ptr=r'^\s+([0-9a-f]+):\s+.+\s+call\s+\*%(\w+)'
    ),
    'x86-64': ArchConfig(
        pattern_fn=r'^([0-9a-f]+) <(.+)>:',
        pattern_call=r'^\s+[0-9a-f]+:\s+.+\s+call\s+([0-9a-f]+)\s+<(.+)>',
        pattern_fn_ptr=r'^\s+([0-9a-f]+):\s+.+\s+call\s+\*%(\w+)'
    ),
}

class Src:
    prefix_strip = ""

    def __init__(self, addr: int = 0, file: str = "", line: int = -1):
        if isinstance(addr, str):
            addr = int(addr, 16)
        if isinstance(line, str):
            line = int(line, 10)
        if not isinstance(addr, int) or not isinstance(line, int):
            raise Exception("Invalid type")
        self.addr = addr
        self.file = file
        self.line = line

    def __str__(self):
        if not self.file:
            return "<unknown>"
        file_stripped = re.sub(self.prefix_strip, '', self.file)
        if self.line < 0:
            return f"{file_stripped}"
        return f"{file_stripped}:{self.line}"

class SymId:
    def __init__(self, name: str, addr):
        if isinstance(addr, str):
            addr = int(addr, 16)
        if not isinstance(addr, int):
            raise Exception("Invalid type")
        self.name = name
        self.addr = addr

    def __lt__(self, other):
        return (self.name, self.addr) < (other.name, other.addr)

    def __eq__(self, other):
        return (self.name, self.addr) == (other.name, other.addr)

    def __hash__(self):
        return hash((self.name, self.addr))

class Symbol:
    ram_range = None  # Tuple (start, end) or None
    flash_range = None  # Tuple (start, end) or None

    def __init__(self, name: str, addr):
        self.name = name
        self.src = Src(addr=addr)
        self.size = -1
        self.frame_size = -1
        self.frame_qualifiers = ""
        self.sym_type = ""
        self.callers: Set[SymId] = set()
        self.callees: Set[SymId] = set()
        self.all_callees: Set[SymId] = set()
        self.cycles: Set[int] = set()
        self.sym_not_found = True
        self.su_not_found = True
        self.indirect_call: list = []
        self.callee_worst_stack = None  # SymId of worst callee
        self.worst_stack_depth = -1

    def is_in_ram(self):
        return Symbol.ram_range and Symbol.ram_range[0] <= self.src.addr <= Symbol.ram_range[1]

    def is_in_flash(self):
        return Symbol.flash_range and Symbol.flash_range[0] <= self.src.addr <= Symbol.flash_range[1]

    def is_unknown_section(self):
        return Symbol.ram_range and Symbol.flash_range and not self.is_in_ram() and not self.is_in_flash()

    def __str__(self):
        suffix = ""
        if self.indirect_call:
            suffix += "[I]"
        if self.is_in_ram():
            suffix += "[R]"
        elif self.is_unknown_section():
            suffix += "[U]"
        return f"{self.name}{suffix}"


def detect_arch(elf_file):
    """Detect architecture from ELF file using 'file' command"""
    try:
        output = subprocess.check_output(['file', elf_file],
                                         universal_newlines=True)
    except subprocess.CalledProcessError:
        sys.exit(f"Error running file command on {elf_file}")

    if 'ARM' in output:
        return arch_configs['arm']
    elif 'x86-64' in output:
        return arch_configs['x86-64']
    elif 'i386' in output:
        return arch_configs['i386']
    else:
        sys.exit(f"Unsupported architecture in {elf_file}: {output}")


def parse_objdump(elf_file, arch_config, cmd_objdump):
    try:
        output = subprocess.check_output([cmd_objdump, '-d', elf_file],
                                         universal_newlines=True)
    except subprocess.CalledProcessError:
        sys.exit(f"Error running {cmd_objdump}")

    symbols = {}
    cur_fn = None
    for line in output.split('\n'):
        m = arch_config.pattern_fn.match(line)
        if m:
            cur_fn = SymId(m.group(2), m.group(1))
            symbols[cur_fn] = Symbol(m.group(2), m.group(1))
        m = arch_config.pattern_call.match(line)
        if m:
            if not cur_fn:
                raise Exception("Parser error")
            symbols[cur_fn].callees.add(SymId(m.group(2), m.group(1)))
        m = arch_config.pattern_fn_ptr.match(line)
        if m:
            if not cur_fn:
                raise Exception("Parser error")
            symbols[cur_fn].indirect_call.append(Src(addr=m.group(1)))
    return symbols


def parse_nm(elf_file, cmd_nm):
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
        addr = parts[0]
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
            if ':' in src_info:
                parts = src_info.rsplit(':', 1)
                src_file = parts[0]
                src_line = int(parts[1])
            else:
                src_file = ""
                src_line = -1
        else:
            src_file = ""
            src_line = -1
        # FIXME: detect case where binary has not been built with -g and no
        #        source files are available
        nm_data[SymId(name, addr)] = (size, sym_type, src_file, src_line)

    return nm_data


def add_nm_info(symbols, elf_file, cmd_nm):
    nm_data = parse_nm(elf_file, cmd_nm)

    # Search for memory range symbols
    for key, data in nm_data.items():
        if key.name == '_image_ram_start':
            ram_start = key.addr
        elif key.name == '_image_ram_end':
            ram_end = key.addr
        elif key.name == '__rom_region_start':
            flash_start = key.addr
        elif key.name == '__rom_region_end':
            flash_end = key.addr

    # Set memory ranges as class variables if found
    if 'ram_start' in locals() and 'ram_end' in locals() and \
       'flash_start' in locals() and 'flash_end' in locals():
        Symbol.ram_range = (ram_start, ram_end)
        Symbol.flash_range = (flash_start, flash_end)

    for key, sym in symbols.items():
        if key not in nm_data:
            continue
        sym.size = nm_data[key][0]
        sym.sym_type = nm_data[key][1]
        sym.src.file = nm_data[key][2]
        sym.src.line = nm_data[key][3]
        sym.sym_not_found = False

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
        su_key = (sym.name, sym.src.file, sym.src.line)
        if su_key in su_data:
            sym.frame_size, sym.frame_qualifiers = su_data[su_key]
            sym.su_not_found = False
    return True


def parse_addr2line(elf_file, addresses, cmd_addr2line):
    if not addresses:
        return {}

    try:
        # Pass addresses as hex strings to addr2line
        addr_input = '\n'.join([f'{addr:x}' for addr in addresses])
        output = subprocess.check_output([cmd_addr2line, '-e', elf_file],
                                         input=addr_input,
                                         universal_newlines=True)
    except subprocess.CalledProcessError:
        return {}

    addr2line_data = {}

    # Format:
    #  file:line (discriminator X)
    #  file:line
    #  ??:?
    for i, line in enumerate(output.strip().split('\n')):
        parts = line.rsplit(':', 1)
        src_file = parts[0] if parts[0] != '??' else ""
        src_line = parts[1].split()[0]  if parts[1] != '?' else "-1"
        addr2line_data[addresses[i]] = (src_file, int(src_line))

    return addr2line_data


def add_addr2line_info(symbols, elf_file, cmd_addr2line):
    all_addrs = []
    for sym in symbols.values():
        for src in sym.indirect_call:
            all_addrs.append(src.addr)

    if not all_addrs:
        return
    addr2line_data = parse_addr2line(elf_file, all_addrs, cmd_addr2line)
    for sym in symbols.values():
        for src in sym.indirect_call:
            if src.addr in addr2line_data:
                src.file, src.line = addr2line_data[src.addr]


def simplify_veneer_funcs(symbols):
    # Replace veneer function references with their actual targets
    veneer_mapping = {}
    for key, sym in symbols.items():
        base_name = re.sub(r'__(.*)_veneer', r'\1', key.name)
        if base_name == key.name:
            continue
        matches = [k for k in symbols if k.name == base_name]
        if len(matches) != 1:
            raise Exception(f"Cannot fix veneer symbol {key.name}: {len(matches)} symbols found")
        veneer_mapping[key] = matches[0]

    for sym in symbols.values():
        new_callees = set()
        for key in sym.callees:
            if key in veneer_mapping:
                new_callees.add(veneer_mapping[key])
            else:
                new_callees.add(key)
        sym.callees = new_callees


def build_reverse_callgraph(symbols):
    for caller_key in symbols:
        for callee_key in symbols[caller_key].callees:
            if callee_key in symbols:
                symbols[callee_key].callers.add(caller_key)


def detect_recursion(symbols):
    visited = set()
    cycles = []

    def dfs(key, callstack):
        if key in callstack:
            # Found a cycle - mark all functions in the cycle with unique ID
            cycle_start = callstack.index(key)
            for func_key in callstack[cycle_start:]:
                symbols[func_key].cycles.add(len(cycles))
            cycles.append([symbols[k].name for k in callstack[cycle_start:]])
            return set()
        if key in visited:
            return symbols[key].all_callees
        visited.add(key)
        callstack.append(key)
        symbols[key].all_callees = set()
        # Calculate worst stack depth
        worst_depth = 0
        worst_callee = None
        for callee_key in symbols[key].callees:
            symbols[key].all_callees.add(callee_key)
            if callee_key in symbols:
                symbols[key].all_callees.update(dfs(callee_key, callstack.copy()))
                callee_sym = symbols[callee_key]
                if callee_sym.worst_stack_depth >= 0:
                    depth = callee_sym.worst_stack_depth
                    if depth > worst_depth:
                        worst_depth = depth
                        worst_callee = callee_key
        symbols[key].callee_worst_stack = worst_callee
        if symbols[key].frame_size >= 0:
            symbols[key].worst_stack_depth = worst_depth + symbols[key].frame_size
        return symbols[key].all_callees

    for key in symbols:
        if key not in visited:
            dfs(key, [])
    return cycles
