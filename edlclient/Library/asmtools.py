#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
from capstone import *
from keystone import *
from binascii import unhexlify
import argparse


def asm(code, cpu, mode, bigendian):
    if bigendian:
        little = KS_MODE_BIG_ENDIAN  # big-endian mode
    else:
        little = KS_MODE_LITTLE_ENDIAN  # little-endian mode (default mode)
    print("CPU: %s, MODE: %s" % (cpu, mode))
    ks = None
    if cpu == "arm":
        # ARM architecture (including Thumb, Thumb-2)
        if mode == "arm":
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM + little)  # ARM mode
        elif mode == "thumb":
            ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB + little)  # THUMB mode (including Thumb-2)
        elif mode == "mclass":
            ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB + little)
        elif mode == "v8":
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_V8 + little)
    elif cpu == "arm64":
        # ARM-64, also called AArch64
        ks = Ks(KS_ARCH_ARM64, little)  # ARM mode
    elif cpu == "mips":
        # Mips architecture
        if mode == "micro":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MICRO + little)  # MicroMips mode
        elif mode == "3":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS3 + little)  # Mips III ISA
        elif mode == "32R6":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32R6 + little)  # Mips32r6 ISA
        elif mode == "32":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + little)  # Mips32 ISA
        elif mode == "64":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + little)  # Mips64 ISA
    elif cpu == "x86":
        # X86 architecture (including x86 & x86-64)
        if mode == "16":
            ks = Ks(KS_ARCH_X86, KS_MODE_16 + little)  # 16-bit mode
        elif mode == "32":
            ks = Ks(KS_ARCH_X86, KS_MODE_32 + little)  # 32-bit mode
        elif mode == "64":
            ks = Ks(KS_ARCH_X86, KS_MODE_64 + little)  # 64-bit mode
    elif cpu == "ppc":
        # PowerPC architecture (currently unsupported)
        if mode == "32":
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + little)  # 32-bit mode
        elif mode == "64":
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64 + little)  # 64-bit mode
        elif mode == "qpx":
            ks = Ks(KS_ARCH_PPC, KS_MODE_QPX + little)  # Quad Processing eXtensions mode
    elif cpu == "sparc":
        # Sparc architecture
        if mode == "32":
            ks = Ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + little)  # 32-bit mode
        elif mode == "64":
            ks = Ks(KS_ARCH_SPARC, KS_MODE_SPARC64 + little)  # 64-bit mode
        elif mode == "v9":
            ks = Ks(KS_ARCH_SPARC, KS_MODE_V9 + little)  # SparcV9 mode
    elif cpu == "systemz":
        ks = Ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN)  # SystemZ architecture (S390X)
    elif cpu == "hexagon":
        ks = Ks(KS_ARCH_HEXAGON, KS_MODE_LITTLE_ENDIAN)  # QDSP6 Hexagon Qualcomm

    if ks is None:
        print("CPU and/or Mode not supported!")
        exit(0)

    encoding, count = ks.asm(code)
    return encoding


def disasm(code, cpu, mode, bigendian, size):
    cs = None
    if bigendian:
        little = CS_MODE_BIG_ENDIAN  # big-endian mode
    else:
        little = CS_MODE_LITTLE_ENDIAN  # little-endian mode (default mode)

    if cpu == "arm":
        if mode == "arm":
            cs = Cs(CS_ARCH_ARM, CS_MODE_ARM + little)  # ARM mode
        elif mode == "thumb":
            cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + little)  # THUMB mode (including Thumb-2)
        elif mode == "mclass":
            cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS + little)  # ARM Cortex-M
        elif mode == "v8":
            cs = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_V8 + little)  # ARMv8 A32 encodings for ARM
    elif cpu == "arm64":
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + little)
    elif cpu == "mips":
        if mode == "micro":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MICRO + little)  # MicroMips mode
        elif mode == "32":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + little)  # Mips III ISA
        elif mode == "64":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + little)  # Mips III ISA
        elif mode == "32R6-Micro":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32R6 + CS_MODE_MICRO + little)  # Mips32r6 ISA
        elif mode == "32R6":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32R6 + little)  # General Purpose Registers are 64bit wide
    elif cpu == "x86":
        # X86 architecture (including x86 & x86-64)
        if mode == "16":
            cs = Cs(CS_ARCH_X86, CS_MODE_16 + little)  # 16-bit mode
        elif mode == "32":
            cs = Cs(CS_ARCH_X86, CS_MODE_32 + little)  # 32-bit mode
        elif mode == "64":
            cs = Cs(CS_ARCH_X86, CS_MODE_64 + little)  # 64-bit mode
    elif cpu == "ppc":
        # PowerPC architecture (currently unsupported)
        if mode == "64":
            cs = Cs(CS_ARCH_PPC, little)  # 64-bit mode
    elif cpu == "sparc":
        # Sparc architecture
        if mode == "None":
            cs = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN)  # 32-bit mode
        elif mode == "v9":
            cs = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN + CS_MODE_V9)  # SparcV9 mode
    elif cpu == "systemz":
        cs = Cs(CS_ARCH_SYSZ, 0)  # SystemZ architecture (S390X)
    elif cpu == "xcore":
        cs = Cs(CS_ARCH_XCORE, 0)  # XCore architecture

    if cs is not None:
        print("CPU and/or mode not supported!")
        exit(0)

    instr = []
    for i in cs.disasm(code, size):
        # print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        instr.append("%s\t%s" % (i.mnemonic, i.op_str))
    return instr


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Disasm/Asm Tool (c) B. Kerler 2018')

    parser.add_argument(
        '--infile', '-in',
        help='Input File',
        default='')
    parser.add_argument(
        '--outfile', '-out',
        help='Output File',
        default='')

    parser.add_argument(
        '--cstyle', '-cstyle',
        help='Print in c style',
        action="store_true")

    parser.add_argument(
        '--bigendian', '-bigendian',
        help='Big endian',
        action="store_true")

    parser.add_argument(
        '--disasm', '-disasm',
        help='Disasm: arm[arm,thumb,mclass,v8],arm64[arm],mips[micro,3,32R6,GP64],x86[16,32,64],ppc[64],sparc[32,64,'
             'v9],systemz,xcore',
        default='')

    parser.add_argument(
        '--asm', '-asm',
        help='Asm: arm[arm,thumb,mclass,v8],arm64[arm],mips[micro,32,64,32R6,32R6-Micro],x86[16,32,64],ppc[32,64,'
             'qpx],sparc[None,v9],systemz,hexagon',
        default='')

    parser.add_argument(
        '--inp', '-input',
        help='Disasm: hexstring, Asm: instruction string input ',
        default='')

    args = parser.parse_args()

    if args.asm == '' and args.disasm == '':
        print("[asmtools] Usage: -asm cpu,mode or -disasm cpu,mode")
        exit(0)

    if args.infile == '' and args.inp == '':
        print("[asmtools] I must have an infile to work on (-in)")
        exit(0)

    if args.asm != "":
        cpu, mode = args.asm.split(",")
    else:
        cpu, mode = args.disasm.split(",")

    if args.inp != "":
        args.inp = args.inp.replace("\\n", "\n")
        if args.asm != "":
            aa = asm(args.inp, cpu, mode, args.bigendian)
        else:
            aa = disasm(unhexlify(args.inp), cpu, mode, args.bigendian, len(args.inp))
    else:
        with open(args.infile, "rb") as rf:
            code = rf.read()
            if args.asm != "":
                aa = asm(code, cpu, mode, args.bigendian)
            else:
                aa = disasm(code, cpu, mode, args.bigendian, len(code))

    if args.outfile != "":
        with open(args.outfile, "wb") as wf:
            if args.asm != "":
                ba = bytearray()
                for i in aa:
                    ba.append(i)
                wf.write(ba)
            else:
                wf.write(aa)
    else:
        if args.asm != "":
            sc = ""
            count = 0
            out = ""
            for i in aa:
                if args.cstyle:
                    out += ("\\x%02x" % i)
                else:
                    out += ("%02x" % i)
                sc += "%02x" % i
                count += 1
            print(out)
        else:
            print(aa)
        '''
        segment=bytearray(code[0x01C97C:0x01C990])
        segment[7]=0xE1
        segment[11]=0xE1
        segment[15]=0xE5
        segment[19]=0xEA
        print(hex(segment[7]))
        print(disasm(bytes(segment),len(segment)))
        '''


main()
