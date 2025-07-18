#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
# Beagle to EDL Loader

import sys
from struct import unpack


def main():
    if len(sys.argv) < 2:
        print("Usage: ./beagle_to_loader.py [beagle_log.bin] [loader.elf]")
        sys.exit(0)
    with open(sys.argv[1], "rb") as rf:
        data = rf.read()
        outdata = bytearray()
        i = 0
        seq = b"\x03\x00\x00\x00\x14\x00\x00\x00\x0D\x00\x00\x00"
        with open(sys.argv[2], "wb") as wf:
            while True:
                idx = data.find(seq)
                if idx == -1:
                    if i == 0:
                        seq = b"\x12\x00\x00\x00\x20\x00\x00\x00\x0D\x00\x00\x00\x00\x00\x00\x00"
                        i += 1
                        continue
                    else:
                        break
                else:
                    cmd = unpack("<I", data[idx:idx + 4])[0]
                    if cmd == 0x03:
                        cmd, tlen, slen, offset, length = unpack("<IIIII", data[idx:idx + 0x14])
                    elif cmd == 0x12:
                        cmd, tlen, slen, offset, length = unpack("<IIQQQ", data[idx:idx + 0x20])
                    data = data[idx + 0x14:]
                    print("Offset : %08X Length: %08X" % (offset, length))
                    while len(outdata) < offset + length:
                        outdata.append(0xFF)
                    outdata[offset:offset + length] = data[:length]
                    i += 1
            wf.write(outdata)

        print("Done.")


if __name__ == "__main__":
    main()
