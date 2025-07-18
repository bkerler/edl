#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import argparse

import pt
import pt64


def pt64_walk(data, ttbr, tnsz, levels=3):
    print("Dumping page tables (levels=%d)" % levels)
    print("First level (ptbase = %016x)" % ttbr)
    print("---------------------------------------------")
    fl = data[ttbr - ttbr:ttbr - ttbr + 0x1000]

    if levels <= 1:
        return

    for (va, fle) in pt64.parse_pt(fl, 0, tnsz, 1):
        if "TABLE" in str(fle):
            print("Second level (ptbase = %016x)" % fle.output)
            print("---------------------------------------------")

            sl = data[fle.output - ttbr:fle.output - ttbr + 0x4000]
            sl = pt64.parse_pt(sl, va, tnsz, 2)

            if levels <= 2:
                continue

            for (mva, sle) in sl:
                if "TABLE" in str(sle):
                    print("Third level (ptbase = %016x)" % sle.output)
                    print("---------------------------------------------")
                    tl = data[sle.output - ttbr:sle.output - ttbr + 0x1000]
                    pt64.parse_pt(tl, mva, tnsz, 3)


def pt32_walk(data, ttbr, skip):
    print("First level (va = %08x)" % ttbr)
    print("---------------------------------------------")
    fl = data[ttbr - ttbr:ttbr - ttbr + 0x4000]

    i = 0
    for (va, fl) in pt.parse_pt(fl):
        i += 1
        if i <= skip:
            continue
        if isinstance(fl, pt.pt_desc):
            print("")
            print("Second level (va = %08x)" % va)
            print("---------------------------------------------")
            sldata = data[fl.coarse_base - ttbr:fl.coarse_base - ttbr + 0x400]
            pt.parse_spt(sldata, va)


def main():
    parser = argparse.ArgumentParser(
        prog="memparse",
        usage="python memparse.py -arch <32,64> -in <filename> -mem <offset>",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-in', '--in', dest='infile', help='memory dump', default="")
    parser.add_argument('-arch', '--arch', dest='arch', help='architecture=32,64', default="32")
    parser.add_argument('-mem', '--mem', dest='mem', help='memoryoffset', default="0x200000")
    args = parser.parse_args()
    if args.infile == "":
        print("You need to add an -in [memorydump filename]")
        return

    with open(args.infile, "rb") as rf:
        data = rf.read()
        if args.arch == "32":
            pt32_walk(data, int(args.mem, 16), False)
        else:
            pt64_walk(data, int(args.mem, 16), 0, 3)


main()
