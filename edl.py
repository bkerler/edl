#!/usr/bin/env python3
# Qualcomm Sahara / Firehose Client (c) B.Kerler 2018-2020.
# Licensed under MIT License
"""
Usage:
    edl.py -h | --help
    edl.py [--vid=vid] [--pid=pid]
    edl.py [--loader=filename] [--memory=memtype]
    edl.py [--debugmode]
    edl.py [--gpt-num-part-entries=number] [--gpt-part-entry-size=number] [--gpt-part-entry-start-lba=number]
    edl.py [--memory=memtype] [--skipstorageinit] [--maxpayload=bytes] [--sectorsize==bytes]
    edl.py server [--tcpport=portnumber] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py memorydump [--debugmode] [--vid=vid] [--pid=pid]
    edl.py printgpt [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--debugmode]  [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py gpt <directory> [--memory=memtype] [--lun=lun] [--genxml] [--loader=filename]  [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py r <partitionname> <filename> [--memory=memtype] [--sectorsize==bytes] [--lun=lun] [--loader=filename]  [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py rl <directory> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skip=partnames] [--genxml]  [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py rf <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--debugmode]  [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py rs <start_sector> <sectors> <filename> [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py w <partitionname> <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skipwrite] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py wl <directory> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skip=partnames] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py wf <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py ws <start_sector> <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skipwrite] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py e <partitionname> [--memory=memtype] [--skipwrite] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py es <start_sector> <sectors> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skipwrite] [--loader=filename] [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py footer <filename> [--memory=memtype] [--lun=lun] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py peek <offset> <length> <filename> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py peekhex <offset> <length> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py peekdword <offset> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py peekqword <offset> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py memtbl <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py poke <offset> <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py pokehex <offset> <data> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py pokedword <offset> <data> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py pokeqword <offset> <data> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py memcpy <offset> <size> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py secureboot [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py pbl <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py qfp <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py getstorageinfo [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py setbootablestoragedrive <lun> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py send <command> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py xml <xmlfile> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py rawxml <xmlstring> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py reset [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py nop [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py modules <command> <options> [--memory=memtype] [--lun=lun] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]

Description:
    server [--tcpport=portnumber]                                                # Run tcp/ip server
    printgpt [--memory=memtype] [--lun=lun]                                      # Print GPT Table information
    gpt <directory> [--memory=memtype] [--lun=lun]                               # Save gpt table to given directory
    r <partitionname> <filename> [--memory=memtype] [--lun=lun]                  # Read flash to filename
    rl <directory> [--memory=memtype] [--lun=lun] [--skip=partname]              # Read all partitions from flash to a directory
    rf <filename> [--memory=memtype] [--lun=lun]                                 # Read whole flash to file
    rs <start_sector> <sectors> <filename> [--lun=lun]                           # Read sectors starting at start_sector to filename
    w <partitionname> <filename> [--memory=memtype] [--lun=lun] [--skipwrite]    # Write filename to partition to flash
    wl <directory> [--memory=memtype] [--lun=lun]                                # Write all files from directory to flash
    wf <filename> [--memory=memtype] [--lun=lun]                                 # Write whole filename to flash
    ws <start_sector> <filename> [--memory=memtype] [--lun=lun] [--skipwrite]    # Write filename to flash at start_sector
    e <partitionname> [--memory=memtype] [--skipwrite] [--lun=lun]               # Erase partition from flash
    es <start_sector> <sectors> [--memory=memtype] [--lun=lun] [--skipwrite]     # Erase sectors at start_sector from flash
    footer <filename> [--memory=memtype] [--lun=lun]                             # Read crypto footer from flash
    peek <offset> <length> <filename>                                            # Dump memory at offset with given length to filename
    peekhex <offset> <length>                                                    # Dump memory at offset and given length as hex string
    peekdword <offset>                                                           # Dump DWORD at memory offset
    peekqword <offset>                                                           # Dump QWORD at memory offset
    memtbl <filename>                                                            # Dump memory table to file
    poke <offset> <filename>                                                     # Write filename to memory at offset to memory
    pokehex <offset> <data>                                                      # Write hex string data at offset to memory
    pokedword <offset> <data>                                                    # Write DWORD to memory at offset
    pokeqword <offset> <data>                                                    # Write QWORD to memory at offset
    memcpy <offset> <size>                                                       # Copy memory from srcoffset with given size to dstoffset
    secureboot                                                                   # Print secureboot fields from qfprom fuses
    pbl <filename>                                                               # Dump primary bootloader to filename
    qfp <filename>                                                               # Dump QFPROM fuses to filename
    getstorageinfo                                                               # Print storage info in firehose mode
    setbootablestoragedrive <lun>                                                # Change bootable storage drive to lun number
    send <command>                                                               # Send firehose command
    xml <xmlfile>                                                                # Send firehose xml file
    rawxml <xmlstring>                                                           # Send firehose xml raw string
    reset                                                                        # Send firehose reset command
    nop                                                                          # Send firehose nop command
    modules <command> <options>                                                  # Enable submodules, for example: "oemunlock enable"

Options:
    --loader=filename                  Use specific EDL loader, disable autodetection [default: None]
    --vid=vid                          Set usb vendor id used for EDL [default: 0x05c6]
    --pid=pid                          Set usb product id used for EDL [default: 0x9008]
    --lun=lun                          Set lun to read/write from (UFS memory only) [default: None]
    --maxpayload=bytes                 Set the maximum payload for EDL [default: 0x100000]
    --sectorsize=bytes                 Set default sector size [default: 0x200]
    --memory=memtype                   Set memory type (EMMC or UFS) [default: eMMC]
    --skipwrite                        Do not allow any writes to flash (simulate only)
    --skipresponse                     Do not expect a response from phone on read/write (some Qualcomms)
    --skipstorageinit                  Skip storage initialisation
    --debugmode                        Enable verbose mode
    --gpt-num-part-entries=number      Set GPT entry count [default: 0]
    --gpt-part-entry-size=number       Set GPT entry size [default: 0]
    --gpt-part-entry-start-lba=number  Set GPT entry start lba sector [default: 0]
    --tcpport=portnumber               Set port for tcp server [default: 1340]
    --skip=partnames                   Skip reading partition with names "partname1,partname2,etc."
    --genxml                           Generate rawprogram[lun].xml
    --devicemodel=value                Set device model [default: ""]
"""
import sys
import time
import logging
from docopt import docopt

args = docopt(__doc__, version='3')

from Library.utils import log_class
from Library.usblib import usb_class
from Library.sahara import qualcomm_sahara
from Library.streaming_client import streaming_client
from Library.firehose_client import firehose_client
from Library.streaming import QualcommStreaming

print("Qualcomm Sahara / Firehose Client V3 (c) B.Kerler 2018-2020.")

LOGGER = None


def doconnect(cdc, loop, mode, resp, sahara):
    global LOGGER
    while not cdc.connected:
        cdc.connected = cdc.connect()
        if not cdc.connected:
            sys.stdout.write('.')
            if loop >= 20:
                sys.stdout.write('\n')
                loop = 0
            loop += 1
            time.sleep(1)
            sys.stdout.flush()
        else:
            LOGGER.info("Device detected :)")
            try:
                mode, resp = sahara.connect()
                if mode == "" or resp == -1:
                    mode, resp = sahara.connect()
            except Exception as e:
                if mode == "" or resp == -1:
                    mode, resp = sahara.connect()
            if mode == "":
                LOGGER.info("Unknown mode. Aborting.")
                cdc.close()
                sys.exit()
            LOGGER.info(f"Mode detected: {mode}")
            break

    return mode, resp

def exit(cdc):
    cdc.close()
    sys.exit()

def parse_option(args):
    options={}
    for arg in args:
        if "--" in arg or "<" in arg:
            options[arg]=args[arg]
    return options

def parse_cmd(args):
    cmd=""
    if args["server"]:
        cmd = "server"
    elif args["printgpt"]:
        cmd = "printgpt"
    elif args["gpt"]:
        cmd = "gpt"
    elif args["r"]:
        cmd = "r"
    elif args["rl"]:
        cmd = "rl"
    elif args["rf"]:
        cmd = "rf"
    elif args["rs"]:
        cmd = "rs"
    elif args["w"]:
        cmd = "w"
    elif args["wl"]:
        cmd = "wl"
    elif args["wf"]:
        cmd = "wf"
    elif args["ws"]:
        cmd = "ws"
    elif args["e"]:
        cmd = "e"
    elif args["es"]:
        cmd = "es"
    elif args["footer"]:
        cmd = "footer"
    elif args["peek"]:
        cmd = "peek"
    elif args["peekhex"]:
        cmd = "peekhex"
    elif args["peekdword"]:
        cmd = "peekdword"
    elif args["peekqword"]:
        cmd = "peekqword"
    elif args["memtbl"]:
        cmd = "memtbl"
    elif args["poke"]:
        cmd = "poke"
    elif args["pokehex"]:
        cmd = "pokehex"
    elif args["pokedword"]:
        cmd = "pokedword"
    elif args["pokeqword"]:
        cmd = "pokeqword"
    elif args["memcpy"]:
        cmd = "memcpy"
    elif args["secureboot"]:
        cmd = "secureboot"
    elif args["pbl"]:
        cmd = "pbl"
    elif args["qfp"]:
        cmd = "qfp"
    elif args["getstorageinfo"]:
        cmd = "getstorageinfo"
    elif args["setbootablestoragedrive"]:
        cmd = "setbootablestoragedrive"
    elif args["send"]:
        cmd = "send"
    elif args["xml"]:
        cmd = "xml"
    elif args["rawxml"]:
        cmd = "rawxml"
    elif args["reset"]:
        cmd = "reset"
    elif args["nop"]:
        cmd = "nop"
    return cmd

def main():
    global LOGGER
    mode = ""
    loop = 0
    vid = int(args["--vid"], 16)
    pid = int(args["--pid"], 16)
    usbids = [[vid, pid], [0x05c6, 0x9025], [0x1199, 0x9062], [0x1199, 0x9070], [0x1199, 0x9090], [0x0846, 0x68e0]]
    filename = "log.txt"
    if args["--debugmode"]:
        LOGGER = log_class(logging.DEBUG, filename)
        # ch = logging.StreamHandler()
        # ch.setLevel(logging.ERROR)
    else:
        LOGGER = log_class(logging.INFO, filename)

    cdc = usb_class(usbids, log=LOGGER, interface=-1)
    sahara = qualcomm_sahara(cdc)

    if args["--loader"] == 'None':
        LOGGER.info("Trying with no loader given ...")
        sahara.programmer = ""
    else:
        loader = args["--loader"]
        LOGGER.info(f"Using loader {loader} ...")
        sahara.programmer = loader

    LOGGER.info("Waiting for the device")
    resp = None
    cdc.timeout = 100
    LOGGER.debug("Ohuh")
    mode, resp = doconnect(cdc, loop, mode, resp, sahara)
    if resp == -1:
        mode, resp = doconnect(cdc, loop, mode, resp, sahara)
        if resp == -1:
            LOGGER.error("USB desync, please rerun command !")
            sys.exit()
    # print((mode, resp))
    if mode == "sahara":
        if "mode" in resp:
            mode = resp["mode"]
            if mode == sahara.sahara_mode.SAHARA_MODE_MEMORY_DEBUG:
                if args["memorydump"]:
                    time.sleep(0.5)
                    print("Device is in memory dump mode, dumping memory")
                    sahara.debug_mode()
                    exit(cdc)
                else:
                    print("Device is in streaming mode, uploading loader")
                    cdc.timeout = None
                    sahara_info = sahara.streaminginfo()
                    if sahara_info:
                        mode, resp = sahara.connect()
                        if mode == "sahara":
                            mode = sahara.upload_loader()
                            if "enprg" in sahara.programmer.lower():
                                mode = "load_enandprg"
                            elif "nprg" in sahara.programmer.lower():
                                mode = "load_nandprg"
                            else:
                                mode = "load_" + mode
                            if mode != "load_":
                                time.sleep(0.3)
                            else:
                                print("Error, couldn't find suitable enprg/nprg loader :(")
                                exit(cdc)
            else:
                print("Device is in EDL mode .. continuing.")
                cdc.timeout = None
                sahara_info = sahara.info()
                if sahara_info:
                    mode, resp = sahara.connect()
                    if mode == "sahara":
                        mode = sahara.upload_loader()
                        if mode == "firehose":
                            if "enprg" in sahara.programmer.lower():
                                mode = "enandprg"
                            elif "nprg" in sahara.programmer.lower():
                                mode = "nandprg"
                        if mode != "":
                            if mode != "firehose":
                                streaming = QualcommStreaming(cdc, sahara)
                                if streaming.connect(1):
                                    print("Successfully uploaded programmer :)")
                                    mode = "nandprg"
                                else:
                                    print("Device is in an unknown state")
                                    exit(cdc)
                            else:
                                print("Successfully uploaded programmer :)")
                        else:
                            print("No suitable loader found :(")
                            exit(cdc)
                else:
                    print("Device is in an unknown sahara state")
                    print("resp={0}".format(resp))
                    exit(cdc)
        else:
            print("Device is in an unknown state")
            exit(cdc)
    else:
        sahara.bit64 = True

    if mode == "firehose":
        cdc.timeout = None
        fh = firehose_client(args, cdc, sahara, LOGGER,print)
        cmd=parse_cmd(args)
        options=parse_option(args)
        if cmd!="":
            fh.handle_firehose(cmd,options)
    elif mode == "nandprg" or mode == "enandprg" or mode == "load_nandprg" or mode == "load_enandprg":
        sc = streaming_client(args, cdc, sahara, LOGGER,print)
        cmd = parse_cmd(args)
        options = parse_option(args)
        if "load_" in mode:
            options["<mode>"] = 1
        else:
            options["<mode>"] = 0
        sc.handle_streaming(cmd, options)
    else:
        LOGGER.error("Sorry, couldn't talk to Sahara, please reboot the device !")

    exit(cdc)


if __name__ == '__main__':
    main()
