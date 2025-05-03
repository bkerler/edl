#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from edlclient.Library.api import *
import os

LOADER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "path/to/programmer.mbn")
PEEK_OUTPUT = "peek_output.bin"

def dump():
    return os.system(f"cat {PEEK_OUTPUT} | xxd")

def main():
    e = edl_api()
    e.set_arg("--loader", LOADER)
    e.set_arg("--debugmode", True)

    if (e.init() == 1):
        return 1

    e.peek(0x100000, 80, PEEK_OUTPUT)
    dump()

    e.reset_arg("--debugmode")
    if (e.reinit() == 1):
        return 1

    e.printgpt()

    e.pbl("pbl.bin")

    e.reset()
    return e.deinit()

if (__name__ == "__main__"):
    main()
