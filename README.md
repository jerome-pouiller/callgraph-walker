Callgraph Walker
================

This is an experimental tool that extract the call graph and other useful from
an ELF binary. Then it provide various report about specific aspects of the
binary.

This initially targeted Zephyr firmware but it can be used for general embedded
development (or even for general application). This aims to help on two
problems:
  - How to properly size the stack of the threads
  - Improve latencies of some part of the code by placing it in RAM


For now, the features are rather limited. At the end we expect to be able to:
  - Detect loops in the callgraph
  - Detect pointers to functions in the callgraph
  - Recursively list the function called by a function
  - Compute the size of the deepest stack used by a function
  - Identify if a function in RAM depends on functions in Flash
  - Identify the potential entry points in the binary (entry functions for
    threads, ISR, etc...)


Previous work
-------------

[Puncover][1] is a reference for binary analysis. However, it focus on
interactive use while the current tools aims to run from CI or other automated
environment.

Thanassis Tsiodras wrote a similar tool called [checkStackUsage][2]. I wanted to
go further on this way.

Clang and LLVM are able to generate callgraphs since version 20. Many Language
Server are also able to provide it. They require a perfect knowledge of the
build environment. Callgraph walker tries to be more versatile and easier to
setup.


[1]: https://github.com/HBehrens/puncover
[2]: https://github.com/ttsiodras/checkStackUsage

Installation
------------

You need a version of objdump able to parse foreign assembly. On Debian, you can
use `binutils-multiarch`.

    apt-get install python3 binutils-multiarch


Usage
-----

You can first list all the known symbols:

    ./callgraph-walker.py -e zephyr/build/zephyr/zephyr.elf list

Since this list is huge, you may want to filter it:

    ./callgraph-walker.py -e zephyr/build/zephyr/zephyr.elf list z_*

Then, you can get detailed information about a specific symbol:

    ./callgraph-walker.py -e zephyr/build/zephyr/zephyr.elf show main

By default, full paths are displayed. You may want to strip common prefix with
`-p`:

    ./callgraph-walker.py -e zephyr/build/zephyr/zephyr.elf -p /home/user/zephyr show main
