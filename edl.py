#!/usr/bin/env python3
# Qualcomm Sahara / Firehose Client (c) B.Kerler 2018-2019.
# Licensed under MIT License
"""
Usage:
    edl.py -h | --help
    edl.py [--vid=vid] [--pid=pid]
    edl.py [--loader=filename]
    edl.py [--debugmode]
    edl.py [--gpt-num-part-entries=number] [--gpt-part-entry-size=number] [--gpt-part-entry-start-lba=number]
    edl.py [--memory=memtype] [--skipstorageinit] [--maxpayload=bytes] [--sectorsize==bytes]
    edl.py server [--tcpport=portnumber]
    edl.py printgpt [--memory=memtype] [--lun=lun]
    edl.py gpt <filename> [--memory=memtype] [--lun=lun]
    edl.py r <partitionname> <filename> [--memory=memtype] [--lun=lun]
    edl.py rl <directory> [--memory=memtype] [--lun=lun] [--skip=partnames] [--autolun]
    edl.py rf <filename> [--memory=memtype] [--lun=lun]
    edl.py rs <start_sector> <sectors> <filename> [--lun=lun]
    edl.py w <partitionname> <filename> [--memory=memtype] [--lun=lun] [--skipwrite]
    edl.py wl <directory> [--memory=memtype] [--lun=lun] [--skip=partnames] [--autolun]
    edl.py wf <filename> [--memory=memtype] [--lun=lun]
    edl.py ws <start_sector> <filename> [--memory=memtype] [--lun=lun] [--skipwrite]
    edl.py e <partitionname> [--memory=memtype] [--skipwrite] [--lun=lun]
    edl.py es <start_sector> <sectors> [--memory=memtype] [--lun=lun] [--skipwrite]
    edl.py footer <filename> [--memory=memtype] [--lun=lun]
    edl.py peek <offset> <length> <filename>
    edl.py peekhex <offset> <length>
    edl.py peekdword <offset>
    edl.py peekqword <offset>
    edl.py memtbl <filename>
    edl.py poke <offset> <filename>
    edl.py pokehex <offset> <data>
    edl.py pokedword <offset> <data>
    edl.py pokeqword <offset> <data>
    edl.py memcpy <srcoffset> <dstoffset> <size>
    edl.py secureboot
    edl.py pbl <filename>
    edl.py qfp <filename>
    edl.py getstorageinfo
    edl.py setbootablestoragedrive <lun>
    edl.py send <command>
    edl.py xml <xmlfile>
    edl.py reset
    edl.py nop

Description:
    server [--tcpport=portnumber]                                                # Run tcp/ip server
    printgpt [--memory=memtype] [--lun=lun]                                      # Print GPT Table information
    gpt <filename> [--memory=memtype] [--lun=lun]                                # Save gpt table to file
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
    memcpy <srcoffset> <dstoffset> <size>                                        # Copy memory from srcoffset with given size to dstoffset
    secureboot                                                                   # Print secureboot fields from qfprom fuses
    pbl <filename>                                                               # Dump primary bootloader to filename
    qfp <filename>                                                               # Dump QFPROM fuses to filename
    getstorageinfo                                                               # Print storage info in firehose mode
    setbootablestoragedrive <lun>                                                # Change bootable storage drive to lun number
    send <command>                                                               # Send firehose command
    xml <xmlfile>                                                                # Send firehose xml file
    reset                                                                        # Send firehose reset command
    nop                                                                          # Send firehose nop command

Options:
    --loader=filename                  Use specific EDL loader, disable autodetection [default: None]
    --vid=vid                          Set usb vendor id used for EDL [default: 0x05c6]
    --pid=pid                          Set usb product id used for EDL [default: 0x9008]
    --lun=lun                          Set lun to read from (UFS memory only) [default: 0]
    --maxpayload=bytes                 Set the maximum payload for EDL [default: 0x100000]
    --sectorsize=bytes                 Set default sector size [default: 0x200]
    --memory=memtype                   Set memory type (EMMC or UFS) [default: eMMC]
    --skipwrite                        Do not allow any writes to flash (simulate only)
    --skipstorageinit                  Skip storage initialisation
    --debugmode                        Enable verbose mode
    --gpt-num-part-entries=number      Set GPT entry count [default: 0]
    --gpt-part-entry-size=number       Set GPT entry size [default: 0]
    --gpt-part-entry-start-lba=number  Set GPT entry start lba sector [default: 0]
    --tcpport=portnumber               Set port for tcp server [default:1340]
    --skip=partnames                   Skip reading partition with names "partname1,partname2,etc."
"""
print("Qualcomm Sahara / Firehose Client (c) B.Kerler 2018-2019.")

from docopt import docopt
args = docopt(__doc__, version='EDL 2.0')

import time
from Library.utils import *
from Library.usblib import usb_class
from Library.sahara import qualcomm_sahara
from Library.firehose import qualcomm_firehose
from Library.streaming import qualcomm_streaming
from struct import unpack, pack
from Library.xmlparser import xmlparser

logger = logging.getLogger(__name__)

msmids={
	0x009440E1: "2432",		#7be49b72f9e4337223ccb84d6eccca4e61ce16e3602ac2008cb18b75babe6d09
    0x006220E1: "MSM7227A",
	0x009680E1: "APQ8009",
	0x007060E1: "APQ8016",
    0x008040E1: "APQ8026",
    0x000550E1: "APQ8017",
    0x0090C0E1: "APQ8036",
    0x0004F0E1: "APQ8037",
    0x0090D0E1: "APQ8039",
    0x009770E1: "APQ8052",
    0x000660E1: "APQ8053",
    0x009F00E1: "APQ8056",
    0x007190E1: "APQ8064",
    0x009D00E1: "APQ8076",
    0x009000E1: "APQ8084",
    0x009300E1: "APQ8092",
    0x000620E1: "APQ8098",
    0x008110E1: "MSM8210",
    0x008140E1: "MSM8212",
    0x008120E1: "MSM8610",
    0x008150E1: "MSM8612",
    0x008010E1: "MSM8626",
    0x000940E1: "MSM8905",
    0x009600E1: "MSM8909",
    0x007050E1: "MSM8916",
    0x000560E1: "MSM8917",
    0x000860E1: "MSM8920",
    0x008050E1: "MSM8926",
    0x009180E1: "MSM8928",
    0x0091B0E1: "MSM8929",
    0x007210E1: "MSM8930",
    0x0072C0E1: "MSM8930",
    #0x000000E1: "MSM8936",
    0x0004F0E1: "MSM8937",
    0x0090B0E1: "MSM8939",	#7be49b72f9e4337223ccb84d6eccca4e61ce16e3602ac2008cb18b75babe6d09
    0x0006B0E1: "MSM8940",
    0x009720E1: "MSM8952",	#0x9B00E1
    0x000460E1: "MSM8953",
    0x009B00E1: "MSM8956",
    0x009100E1: "MSM8962",
    0x007B00E1: "MSM8974",
    0x007B40E1: "MSM8974AB",
    0x007B80E1: "MSM8974Pro",
    0x007BC0E1: "MSM8974ABv3",
    0x006B10E1: "MSM8974AC",
    0x009900E1: "MSM8976",
    0x009690E1: "MSM8992",
    0x009400E1: "MSM8994",
    0x009470E1: "MSM8996",
    0x0006F0E1: "MSM8996AU",
    0x1006F0E1: "MSM8996AU",
    0x4006F0E1: "MSM8996AU",
    0x0005F0E1: "MSM8996Pro",
    0x0005E0E1: "MSM8998",
    0x0094B0E1: "MSM9055",
    0x009730E1: "MDM9206",
    0x000480E1: "MDM9207",
    0x0004A0E1: "MDM9607",
    0x007F50E1: "MDM9x25",
    0x009500E1: "MDM9x40",
    0x009540E1: "MDM9x45",
    0x009210E1: "MDM9x35",
    0x000320E1: "MDM9250",
    0x000340E1: "MDM9255",      
    0x000390E1: "MDM9350",
    0x0003A0E1: "MDM9650",
    0x0003B0E1: "MDM9655",
    0x0003A0E1: "MDM9x50",
    0x0007D0E1: "MDM9x60",
    0x0007F0E1: "MDM9x65",
    0x008090E1: "MDM9916",
    0x0080B0E1: "MDM9955",
    0x000BE0E1: "SDM429",
    0x000BF0E1: "SDM439",
    0x0009A0E1: "SDM450",
    0x000AC0E1: "SDM630",	#0x30070x00 #afca69d4235117e5bfc21467068b20df85e0115d7413d5821883a6d244961581
    0x000BA0E1: "SDM632",
    0x000BB0E1: "SDA632",
    0x000CC0E1: "SDM636",
    0x0008C0E1: "SDM660",	#0x30060000
    0x000910E1: "SDM670",	#0x60040100
    0x000930E1: "SDA670",   #0x60040100
    #0x000930E1: "SDA835",   #0x30020000 => HW_ID1 3002000000290022
    0x0008B0E1: "SDM845",	#0x60000100 => HW_ID1 6000000000010000
    0x000A50E1: "SDM855"
}

infotbl={
	"2432":[[],[0x01900000, 0x100000],[]],
	"APQ8009": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "APQ8016": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "APQ8017": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "APQ8036": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "APQ8037": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "APQ8039": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "APQ8053": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "APQ8056": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "APQ8076": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "APQ8084": [[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "APQ8092": [[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "APQ8098": [[0x300000,0x3c000], [0x780000, 0x10000], []],
    "MSM7227A":[[], [], []],
    "MSM8210": [[], [], []],
    "MSM8212": [[], [], []],
    "MSM8905": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "MSM8909": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "MSM8916": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "MSM8917": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8920": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8926": [[], [], []],
    "MSM8928": [[], [], []],
    "MSM8929": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "MSM8930": [[0x100000, 0x18000], [0x700000, 0x1000], []],
    "MSM8936": [[0x100000, 0x18000], [0x700000, 0x1000], []],
    "MSM8937": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8939": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "MSM8940": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8952": [[0x100000, 0x18000], [0x00058000, 0x1000], [0x200000, 0x24000]],
    "MSM8953": [[0x100000, 0x18000], [0xA0000, 0x1000], [0x200000, 0x24000]],
    "MSM8956": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8974": [[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8974Pro":[[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8974AB":[[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8974ABv3":[[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8974AC":[[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8976": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8992": [[0xFC010000, 0x18000], [0xFC4B8000, 0x6FFF], [0xFE800000, 0x24000]],
    "MSM8994": [[0xFC010000, 0x18000], [0xFC4B8000, 0x6FFF], [0xFE800000, 0x24000]],
    "MSM8996": [[0x100000, 0x18000],[0x70000, 0x6158], [0x200000, 0x24000]],
    "MSM8996AU": [[0x100000, 0x18000],[0x70000, 0x6158], [0x200000, 0x24000]],
    "MSM8996Pro": [[0x100000, 0x18000],[0x70000, 0x6158], [0x200000, 0x24000]],
	"MSM8998": [[0x300000,0x3c000], [0x780000, 0x10000], []],
	"MSM9206": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
	"MSM9207": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
	"MDM9250": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
	"MDM9350": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
	"MSM9607": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
	"MDM9650": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
	"MDM9x50": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "SDM429": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "SDM439": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "SDM450": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "SDM632": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "SDA632": [[0x100000, 0x18000], [0x000A0000, 0x6FFF], [0x200000, 0x24000]],
    "SDM630": [[0x300000,0x3c000], [0x780000, 0x10000], []],
    "SDM636": [[0x300000,0x3c000], [0x780000, 0x10000], [0x14009003,0x24000]],
    "SDM660": [[0x300000,0x3c000], [0x780000, 0x10000], []],
  	"SDM670": [[0x300000,0x3c000], [0x780000, 0x10000], []],
  	"SDA670": [[0x300000,0x3c000], [0x780000, 0x10000], []],
    "SDM845": [[0x300000,0x3c000], [0x780000, 0x10000], []],
}

secureboottbl={
	"2432": 0x019018c8,
    #"MSM7227A":[[], [], []],
    #"MSM8210": [[], [], []],
    #"MSM8212":
    "APQ8009": 0x00058098,
    "APQ8036": 0x00058098,
    "APQ8039": 0x00058098,
    "APQ8037": 0x000a01d0,
    "APQ8053": 0x000a01d0,
    "APQ8052": 0x00058098,
    "APQ8056": 0x000a01d0,
    "APQ8076": 0x000a01d0,
    "APQ8084": 0xFC4B83E8,
    "APQ8092": 0xFC4B83E8,
    "APQ8098": 0x00780350,
    "MSM8909": 0x00058098,
    "MSM8916": 0x00058098,
    "MSM8917": 0x000A01D0,
    "MSM8920": 0x000A01D0,
    #"MSM8926": [[], [], []],
    #"MSM8928": [[], [], []],
    "MSM8929": 0x00058098,
    "MSM8610": 0xFC4B83E8,
    "MSM8226": 0xFC4B83E8,
    "MSM8930": 0x700310,
    "MSM8936": 0x700310,
    "MSM8937": 0x000A01D0,
    "MSM8929": 0x00058098,
    "MSM8939": 0x00058098,
    "MSM8940": 0x000A01D0,
    "MSM8952": 0x00058098,
    "MSM8953": 0x000a01d0,
    "MSM8956": 0x000a01d0,
    "MSM8974": 0xFC4B83F8,
    "MSM8974AB": 0xFC4B83F8,
    "MSM8974ABv3": 0xFC4B83F8,
    "MSM8974AC": 0xFC4B83F8,
    "MSM8976": 0x000a01d0,
    "MSM8992": 0xFC4B83F8,
    "MSM8994": 0xFC4B83F8,
    "MSM8996": 0x00070378,
    "MSM8996AU": 0x00070378,
    "MSM8996Pro": 0x00070378,
    "MSM8998": 0x00780350,
    "MDM9206": 0x000a01d0,
    "MDM9207": 0x000a01d0,
    "MDM9250": 0x000a01d0,
    "MDM9350": 0x000a01d0,
    "MDM9607": 0x000a01d0,
    "MDM9650": 0x000a01d0,
    "MDM9x50": 0x000a01d0,
	"SDM429": 0x000a01d0,
    "SDM439": 0x000a01d0,
    "SDM450": 0x000a01d0,
    #"SDM636": 0x70378,
    "SDM630": 0x00780350,
    "SDM632": 0x000a01d0,
    "SDA632": 0x000a01d0,
    "SDM636": 0x00780350,
    "SDM660": 0x00780350,
    "SDM670": 0x00780350,
    "SDA670": 0x00780350,
    "SDM845": 0x00780350
}

def check_cmd(supported_funcs,func):
    if supported_funcs==[]:
        return True
    for sfunc in supported_funcs:
        if func.lower()==sfunc.lower():
            return True
    return False

def main():
    mode=""
    loop=0
    vid=int(args["--vid"],16)
    pid=int(args["--pid"],16)
    cdc = usb_class(vid=vid, pid=pid)
    sahara = qualcomm_sahara(cdc)

    if args["--loader"]=='None':
        logger.info("Trying with no loader given ...")
        sahara.programmer = None
    else:
        loader=args["--loader"]
        logger.info(f"Using loader {loader} ...")
        with open(loader, "rb") as rf:
            sahara.programmer = rf.read()

    logger.info("Waiting for the device")

    resp=None
    cdc.timeout = 50
    mode, resp = doconnect(cdc, loop, mode, resp, sahara)
    if resp==-1:
        mode, resp = doconnect(cdc, loop, mode, resp, sahara)
        if resp == -1:
            logger.error("USB desync, please rerun command !")
            exit(0)
        
    if mode=="sahara":
        if "mode" in resp:
            mode = resp["mode"]
            if mode == sahara.sahara_mode.SAHARA_MODE_MEMORY_DEBUG:
                print("Device is in memory dump mode, dumping memory")
                sahara.debug_mode()
                exit(0)
            else:
                print("Device is in EDL mode .. continuing.")
                cdc.timeout = None
                m = sahara.info()
                mode, resp = sahara.connect()
                mode = sahara.upload_loader()
                if mode != "":
                    time.sleep(0.3)
                    print("Successfully uploaded programmer :)")
        else:
            print("Device is in an unknown state")
            exit(0)
    else:
        sahara.bit64=True

    if mode=="firehose":
        handle_firehose(args,cdc,sahara)
    elif mode=="nandprg" or mode=="enandprg":
        handle_streaming(args,cdc,sahara)
    else:
        logger.error("Sorry, couldn't talk to Sahara, please reboot the device !")
        exit(0)


    exit(0)


def doconnect(cdc, loop, mode, resp, sahara):
    while (cdc.connected == False):
        cdc.connected = cdc.connect()
        if cdc.connected == False:
            sys.stdout.write('.')
            if (loop >= 20):
                sys.stdout.write('\n')
                loop = 0
            loop += 1
            time.sleep(1)
            sys.stdout.flush()
        else:
            logger.info("Device detected :)")
            mode, resp = sahara.connect()
            if mode == "" or resp==-1:
                mode, resp = sahara.connect()
                if mode == "":
                    logger.info("Unknown mode. Aborting.")
                    cdc.close()
                    exit(0)
            logger.info(f"Mode detected: {mode}")
            break

    return mode, resp


def handle_streaming(args, cdc, sahara):
    fh = qualcomm_streaming(cdc,sahara)

def do_firehose_server(mainargs,cdc,sahara):
    cfg = qualcomm_firehose.cfg()
    cfg.MemoryName = mainargs["--memory"]
    cfg.ZLPAwareHost = 1
    cfg.SkipStorageInit = mainargs["--skipstorageinit"]
    cfg.SkipWrite = mainargs["--skipwrite"]
    cfg.MaxPayloadSizeToTargetInBytes = int(mainargs["--maxpayload"],16)
    cfg.SECTOR_SIZE_IN_BYTES = int(mainargs["--sectorsize"],16)
    cfg.bit64 = sahara.bit64
    fh = qualcomm_firehose(cdc, xmlparser(), cfg)
    supported_functions = fh.connect(0)
    if "hwid" in dir(sahara):
        hwid = sahara.hwid
        if hwid >> 8 in msmids:
            TargetName = msmids[hwid >> 8]
    else:
        TargetName = fh.cfg.TargetName

    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost',int(mainargs["--tcpport"]))
    print ('starting up on %s port %s' % server_address)
    sock.bind(server_address)
    sock.listen(1)
    while True:
        print('waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)
            while True:
                data = connection.recv(4096).decode('utf-8')
                print ('received %s' % data)
                if data:
                    print('handling request')
                    lines=data.split("\n")
                    for line in lines:
                        if ":" in line:
                            cmd=line.split(":")[0]
                            args=line.split(":")[1]
                            if "," in args:
                                args=args.split(",")
                            else:
                                args=[args]
                            if cmd=="gpt":
                                if len(args) != 1:
                                    response="<NAK>\n"+"Usage: gpt:<lun>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    fh.cmd_read(lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES*4, args[1])
                                    response=f"<ACK>\n"+f"Dumped GPT to {args[1]}"
                                    connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="printgpt":
                                if len(args) != 1:
                                    response="<NAK>\n"+"Usage: printgpt:<lun>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]), int(mainargs["--gpt-part-entry-size"]),
                                                          int(mainargs["--gpt-part-entry-start-lba"]))
                                    if guid_gpt != None:
                                        response="<ACK>\n"+guid_gpt.tostring()
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        response="Error on reading GPT, maybe wrong memoryname given ?"
                                        response = "<NAK>\n" + response
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="r":
                                if len(args) != 3:
                                    response="<NAK>\n"+"Usage: r:<lun>,<partitionname>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    partitionname = args[1]
                                    filename = args[2]
                                    guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]), int(mainargs["--gpt-part-entry-size"]),
                                                          int(mainargs["--gpt-part-entry-start-lba"]))
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        found=False
                                        for partition in guid_gpt.partentries:
                                            if partition.name == partitionname:
                                                fh.cmd_read(lun, partition.sector, partition.sectors, filename)
                                                response="<ACK>\n"+f"Dumped sector {str(partition.sector)} with sector count {str(partition.sectors)} as {filename}."
                                                connection.sendall(bytes(response,'utf-8'))
                                                found=True
                                                break
                                        if found==False:
                                            response="<NAK>\n"+f"Error: Couldn't detect partition: {partitionname}"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="rl":
                                if len(args) != 3:
                                    response="<NAK>\n"+"Usage: rl:<lun>,<directory><skip_partname>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    directory = args[1]
                                    skip = args[2]
                                    if not os.path.exists(directory):
                                        os.mkdir(directory)
                                    guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]), int(mainargs["--gpt-part-entry-size"]),
                                                          int(mainargs["--gpt-part-entry-start-lba"]))
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        response = "<ACK>\n"
                                        for partition in guid_gpt.partentries:
                                            partitionname=partition.name
                                            if partition.name==skip:
                                                continue
                                            filename=os.path.join(directory,partitionname+".bin")
                                            fh.cmd_read(lun, partition.sector, partition.sectors, filename)
                                            response += f"Dumped partition {str(partition.name)} with sector count {str(partition.sectors)} as {filename}."
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="rf":
                                if len(args)!=2:
                                    response = "<NAK>\n" + "Usage: rf:<lun>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    filename = args[1]
                                    guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]), int(mainargs["--gpt-part-entry-size"]),
                                                          int(mainargs["--gpt-part-entry-start-lba"]))
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error: Couldn't reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        fh.cmd_read(lun, 0, guid_gpt.totalsectors, filename)
                                        response="<ACK>\n"+f"Dumped sector 0 with sector count {str(guid_gpt.totalsectors)} as {filename}."
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="pbl":
                                if len(args)!=1:
                                    response = "<NAK>\n" + "Usage: pbl:<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        filename = args[0]
                                        if TargetName in infotbl:
                                            v = infotbl[TargetName]
                                            if len(v[0]) > 0:
                                                if fh.cmd_peek(v[0][0], v[0][1], filename, True):
                                                    response="<ACK>\n"+f"Dumped pbl at offset {hex(v[0][0])} as {filename}."
                                                    connection.sendall(bytes(response,'utf-8'))
                                                else:
                                                    response="<NAK>\n"+"No known pbl offset for this chipset"
                                                    connection.sendall(bytes(response,'utf-8'))
                                            else:
                                                response="<NAK>\n"+"Unknown target chipset"
                                                connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="qfp":
                                if len(args)!=1:
                                    response = "<NAK>\n" + "Usage: qfp:<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        filename = args
                                        if TargetName in infotbl:
                                            v = infotbl[TargetName]
                                            if len(v[1]) > 0:
                                               if fh.cmd_peek(v[1][0], v[1][1], filename):
                                                   response="<ACK>\n"+"Dumped qfprom at offset {hex(v[1][0])} as {filename}."
                                                   connection.sendall(bytes(response,'utf-8'))
                                            else:
                                                response = "<NAK>\n" + "No known qfprom offset for this chipset"
                                                connection.sendall(bytes(response,'utf-8'))
                                        else:
                                            response = "<NAK>\n" + "Unknown target chipset"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="secureboot":
                                if not check_cmd(supported_functions, "peek"):
                                    response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                    connection.sendall(bytes(response, 'utf-8'))
                                else:
                                    response="<ACK>\n"
                                    if TargetName in secureboottbl:
                                        v = secureboottbl[TargetName]
                                        value = int(hexlify(fh.cmd_peek(v, 4)), 16)
                                        is_secure = False
                                        for area in range(0, 4):
                                            sec_boot = (value >> (area * 8)) & 0xF
                                            pk_hashindex = sec_boot & 3
                                            oem_pkhash = True if ((sec_boot >> 4) & 1) == 1 else False
                                            auth_enabled = True if ((sec_boot >> 5) & 1) == 1 else False
                                            use_serial = True if ((sec_boot >> 6) & 1) == 1 else False
                                            if auth_enabled:
                                                is_secure = True
                                            response+=f"Sec_Boot{str(area)} PKHash-Index:{str(pk_hashindex)} OEM_PKHash: {str(oem_pkhash)} Auth_Enabled: {str(auth_enabled)} Use_Serial: {str(use_serial)}\n"
                                        if is_secure:
                                            response+=f"Secure boot enabled."
                                        else:
                                            response+="Secure boot disabled."
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        response="<NAK>\n"+"Unknown target chipset"
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="memtbl":
                                if len(args)!=1:
                                    response = "<NAK>\n" + "Usage: memtbl:<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        filename = args[0]
                                        if TargetName in infotbl:
                                            v = infotbl[TargetName]
                                            if len(v[2]) > 0:
                                                if fh.cmd_peek(v[2][0], v[2][1], filename):
                                                    response = "<ACK>\n" + f"Dumped qfprom at offset {hex(v[2][0])} as {filename}."
                                                    connection.sendall(bytes(response,'utf-8'))
                                            else:
                                                response = "<NAK>\n" + "No known memory table offset for this chipset"
                                                connection.sendall(bytes(response,'utf-8'))
                                        else:
                                            response = "<NAK>\n" + "Unknown target chipset"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="footer":
                                if len(args)!=2:
                                    response = "<NAK>\n" + "Usage: footer:<lun>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    filename = args[1]
                                    guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]), int(mainargs["--gpt-part-entry-size"]),
                                                          int(mainargs["--gpt-part-entry-start-lba"]))
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error: Couldn't reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        pnames = ["userdata2", "metadata", "userdata", "reserved1", "reserved2", "reserved3"]
                                        found=False
                                        for partition in guid_gpt.partentries:
                                            if partition.name in pnames:
                                                response="<ACK>\n"+f"Detected partition: {partition.name}\n"
                                                data = fh.cmd_read_buffer(lun,partition.sector + (partition.sectors - (0x4000 // cfg.SECTOR_SIZE_IN_BYTES)),(0x4000 // cfg.SECTOR_SIZE_IN_BYTES), filename)
                                                val = struct.unpack("<I", data[:4])[0]
                                                if ((val & 0xFFFFFFF0) == 0xD0B5B1C0):
                                                   with open(filename, "wb") as wf:
                                                       wf.write(data)
                                                       response+=f"Dumped footer from {partition.name} as {filename}."
                                                       connection.sendall(bytes(response,'utf-8'))
                                                       break
                                                else:
                                                    response = "<NAK>\n"+f"Unknown footer structure or no footer found."
                                                    connection.sendall(bytes(response,'utf-8'))
                                                found=True
                                        if found==False:
                                            response="<NAK>\n"+f"Error: Couldn't find footer"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="rs":
                                if len(args) != 4:
                                    response="<NAK>\n"+f"Usage: -rs <lun>,<start_sector> <sectors> <filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    start = int(args[1])
                                    sectors = int(args[2])
                                    filename = args[3]
                                    fh.cmd_read(lun, start, sectors, filename)
                                    response="<ACK>\n"+f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}."
                                    connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="peek":
                                if len(args) != 3:
                                    response="<NAK>\n"+"Usage: peek:<offset>,<length>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        length = int(args[1], 16)
                                        filename = args[2]
                                        fh.cmd_peek(offset, length, filename, False)
                                        response = "<ACK>\n" + f"Dumped data from {str(offset)} with length {str(length)} to {filename}."
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="peekhex":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: peekhex:<offset>,<length>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        length = int(args[1], 16)
                                        resp = fh.cmd_peek(offset, length, "", False)
                                        response="<ACK>\n"+hexlify(resp)
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="peekqword":
                                if len(args) != 1:
                                    response="<NAK>\n"+"Usage: peekqword:<offset>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        resp = fh.cmd_peek(offset, 8, "",  False)
                                        response="<ACK>\n"+hex(unpack("<Q", resp[:8])[0])
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="peekdword":
                                if len(args) != 1:
                                    response="<NAK>\n"+"Usage: peekdword:<offset>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "peek"):
                                        response = "<NAK>\n" + "Peek command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        resp = fh.cmd_peek(offset, 4, "",  False)
                                        response = "<ACK>\n"+hex(unpack("<I", resp[:4])[0])
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="poke":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: poke:<offset>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "poke"):
                                        response = "<NAK>\n" + "Poke command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        filename = unhexlify(args[1])
                                        fh.cmd_poke(offset, "", filename,  False)
                                        response="<ACK>\n"+f"Successfully wrote data to {hex(offset)} from {filename}."
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="pokehex":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: pokehex:<offset>,<data>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "poke"):
                                        response = "<NAK>\n" + "Poke command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        data = unhexlify(args[1])
                                        fh.cmd_poke(offset, data, "",  False)
                                        resp = fh.cmd_peek(offset, len(data), "",  False)
                                        if resp == data:
                                            response="<ACK>\n"+f"Data correctly written to {hex(offset)}."
                                        else:
                                            response = "<NAK>\n" + f"Writing data to {hex(offset)} failed."
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="pokeqword":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: pokeqword:<offset>,<qword>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "poke"):
                                        response = "<NAK>\n" + "Poke command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        data = pack("<Q", int(args[1], 16))
                                        fh.cmd_poke(offset, data, "",  False)
                                        resp = fh.cmd_peek(offset, 8, "",  False)
                                        if resp==data:
                                            response="<ACK>\n"+f"QWORD {args[1]} correctly written to {hex(offset)}."
                                        else:
                                            response = "<NAK>\n" + f"Error writing data to {hex(offset)}."
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="pokedword":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: pokedword:<offset>,<dword>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "poke"):
                                        response = "<NAK>\n" + "Poke command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        offset = int(args[0], 16)
                                        data = pack("<I", int(args[1], 16))
                                        fh.cmd_poke(offset, data, "",  False)
                                        resp = fh.cmd_peek(offset, 4, "",  False)
                                        response="<ACK>\n"+hex(unpack("<I", resp[:4])[0])
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="memcpy":
                                if len(args) != 3:
                                    response="<NAK>\n"+"Usage: memcpy:<dstoffset>,<srcoffset>,<size>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "poke"):
                                        response = "<NAK>\n" + "Poke command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        dstoffset = int(args[0], 16)
                                        srcoffset = int(args[1], 16)
                                        size = int(args[2], 16)
                                        resp=fh.cmd_memcpy(dstoffset,srcoffset,size)
                                        response="<ACK>\n"+hex(unpack("<I", resp[:4])[0])
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="reset":
                                fh.cmd_reset()
                                response="<ACK>\nSent reset cmd."
                                connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="nop":
                                if not check_cmd(supported_functions, "Nop"):
                                    response = "<NAK>\n" + "Nop command isn't supported by edl loader"
                                    connection.sendall(bytes(response, 'utf-8'))
                                else:
                                    info=fh.cmd_nop()
                                    if info!=False:
                                        response="<ACK>\n"+info
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        response = "<NAK>\n" + "Error sending nop cmd"
                                        connection.sendall(bytes(response, 'utf-8'))
                            elif cmd=="setbootablestoragedrive":
                                if len(args) != 1:
                                    response = "<NAK>\n" + "Usage: setbootablestoragedrive:<lun>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    if not check_cmd(supported_functions, "setbootablestoragedrive"):
                                        response = "<NAK>\n" + "setbootablestoragedrive command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        lun=int(args[0])
                                        fh.cmd_setbootablestoragedrive(lun)
                                        response="<ACK>\n"+f"Bootable Storage Drive set to {args[0]}"
                                        connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="getstorageinfo":
                                    if not check_cmd(supported_functions, "GetStorageInfo"):
                                        response = "<NAK>\n" + "GetStorageInfo command isn't supported by edl loader"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        data=fh.cmd_getstorageinfo_string()
                                        if data=="":
                                            response = "<NAK>\nGetStorageInfo command isn't supported."
                                            connection.sendall(bytes(response,'utf-8'))
                                        else:
                                            response="<ACK>\n"+data
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="send":
                                if len(args) != 2:
                                    response = "<NAK>\n" + "Usage: send:<response:True/False>,<command>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    scmd = args[1]
                                    if args[0]=="True":
                                        resp=fh.cmd_send(scmd)
                                        if resp==False:
                                            response = f"<NAK>\nCommand {scmd} failed."
                                        else:
                                            response = "<ACK>\n" + resp.decode('utf-8').replace("\n","")
                                    else:
                                        fh.cmd_send(scmd,False)
                                        response="<ACK>\n"+f"Executed {args[1]}"
                                    connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="w":
                                if len(args) != 3:
                                    response="<NAK>\n"+"Usage: w:<lun>,<partitionname>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    partitionname = args[1]
                                    filename = args[2]

                                    if not os.path.exists(filename):
                                        response="<NAK>\n"+f"Error: Couldn't find file: {filename}"
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]),
                                                              int(mainargs["--gpt-part-entry-size"]),
                                                              int(mainargs["--gpt-part-entry-start-lba"]))
                                        if guid_gpt == None:
                                            response = "<NAK>\n" + f"Error: Couldn't reading GPT Table"
                                            connection.sendall(bytes(response, 'utf-8'))
                                        else:
                                            found=False
                                            for partition in guid_gpt.partentries:
                                                if partition.name == partitionname:
                                                    found=True
                                                    sectors = os.stat(filename).st_size // fh.cfg.SECTOR_SIZE_IN_BYTES
                                                    if (os.stat(filename).st_size % fh.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                                                        sectors += 1
                                                    if sectors > partition.sectors:
                                                        response="<NAK>\n"+f"Error: {filename} has {sectors} sectors but partition only has {partition.sectors}."
                                                    else:
                                                        fh.cmd_write(lun, partition.sector, filename)
                                                        response="<ACK>\n"+f"Wrote {filename} to sector {str(partition.sector)}."
                                            if found==False:
                                                response="<NAK>\n"+f"Error: Couldn't detect partition: {partitionname}"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="ws":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: ws:<lun>,<start_sector>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    start = int(args[1])
                                    filename = args[2]
                                    if not os.path.exists(filename):
                                        response="<NAK>\n"+f"Error: Couldn't find file: {filename}"
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        if fh.cmd_write(lun, start, filename) == True:
                                            response="<ACK>\n"+f"Wrote {filename} to sector {str(start)}."
                                            connection.sendall(bytes(response,'utf-8'))
                                        else:
                                            response="<NAK>\n"+f"Error on writing {filename} to sector {str(start)}"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="wf":
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: wf:<lun>,<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    start = 0
                                    filename = args[1]
                                    if not os.path.exists(filename):
                                        response="<NAK>\n"+f"Error: Couldn't find file: {filename}"
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        if fh.cmd_write(lun, start, filename) == True:
                                            response="<ACK>\n"+f"Wrote {filename} to sector {str(start)}."
                                            connection.sendall(bytes(response,'utf-8'))
                                        else:
                                            response="<NAK>\n"+f"Error on writing {filename} to sector {str(start)}"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="e":
                                if len(args) != 2:
                                    response = "<NAK>\n" + "Usage: e:<lun>,<partname>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    partitionname = args[1]
                                    guid_gpt = fh.get_gpt(lun, int(mainargs["--gpt-num-part-entries"]), int(mainargs["--gpt-part-entry-size"]),
                                                          int(mainargs["--gpt-part-entry-start-lba"]))
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error: Couldn't reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        found=False
                                        for partition in guid_gpt.partentries:
                                            if partition.name == partitionname:
                                                fh.cmd_erase(lun, partition.sector, partition.sectors)
                                                response="<ACK>\n"+f"Erased {partitionname} starting at sector {str(partition.sector)} with sector count " + f"{str(partition.sectors)}."
                                                connection.sendall(bytes(response,'utf-8'))
                                                found = True
                                        if found==False:
                                            response="<NAK>\n"+f"Error: Couldn't detect partition: {partitionname}"
                                            connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="es":
                                if len(args) != 3:
                                    response="<NAK>\n"+"Usage: es:<lun>,<start_sector>,<sectors>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    start = int(args[1])
                                    sectors = int(args[2])
                                    fh.cmd_erase(lun, start, sectors)
                                    print(f"Erased sector {str(start)} with sector count {str(sectors)}.")
                                    connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="xml":
                                if len(args) != 1:
                                    response = "<NAK>\n" + "Usage: xml:<filename>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    filename=args[0]
                                    if fh.cmd_xml(filename):
                                        response = "<ACK>\n" + f"Sent xml content of {filename}"
                                        connection.sendall(bytes(response,'utf-8'))
                                    else:
                                        response = "<NAK>\n" + f"Error running xml:{filename}"
                                        connection.sendall(bytes(response,'utf-8'))
                            else:
                                response="<NAK>\n"+"Unknown/Missing command, a command is required."
                                connection.sendall(bytes(response,'utf-8'))

                else:
                    print('no more data from', client_address)
                    break
        finally:
            connection.close()

def handle_firehose(args, cdc, sahara):
    cfg = qualcomm_firehose.cfg()
    cfg.MemoryName = args["--memory"]
    cfg.ZLPAwareHost = 1
    cfg.SkipStorageInit = args["--skipstorageinit"]
    cfg.SkipWrite = args["--skipwrite"]
    cfg.MaxPayloadSizeToTargetInBytes = int(args["--maxpayload"],16)
    cfg.SECTOR_SIZE_IN_BYTES = int(args["--sectorsize"],16)
    cfg.bit64 = sahara.bit64
    fh = qualcomm_firehose(cdc, xmlparser(), cfg)
    supported_functions = fh.connect(0)
    TargetName=fh.cfg.TargetName
    if "hwid" in dir(sahara):
        hwid=sahara.hwid>>32
        if hwid in msmids:
            TargetName = msmids[hwid]

    if args["gpt"]:
        lun=int(args["--lun"])
        filename = args["<filename>"]
        fh.cmd_read(lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES, filename)
        print(f"Dumped GPT to {filename}")
        exit(0)
    elif args["printgpt"]:
        lun=int(args["--lun"])
        guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                              int(args["--gpt-part-entry-start-lba"]))
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            guid_gpt.print()
        exit(0)
    elif args["r"]:
        lun = int(args["--lun"])
        partitionname = args["<partitionname>"]
        filename = args["<filename>"]

        guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                              int(args["--gpt-part-entry-start-lba"]))
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            for partition in guid_gpt.partentries:
                if partition.name == partitionname:
                    fh.cmd_read(lun, partition.sector, partition.sectors, filename)
                    print(
                        f"Dumped sector {str(partition.sector)} with sector count {str(partition.sectors)} as {filename}.")
                    exit(0)
            logger.error(f"Error: Couldn't detect partition: {partitionname}\nAvailable partitions:")
            for partition in guid_gpt.partentries:
                print(partition.name)
        exit(0)
    elif args["rl"]:
        lun = int(args["--lun"])
        directory = args["<directory>"]
        skip = args["--skip"].split(",")
        autolun = args["--autolun"]
        luns=[]
        if autolun and not args["--memory"].lower()=="emmc":
            for i in range(0,99):
                luns.append(i)
        else:
            luns=[lun]

        if not os.path.exists(directory):
            os.mkdir(directory)

        for slun in luns:
            guid_gpt = fh.get_gpt(slun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                                  int(args["--gpt-part-entry-start-lba"]))
            if guid_gpt == None:
                break
            else:
                if len(luns)>1:
                    storedir=os.path.join(directory,"lun"+str(slun))
                else:
                    storedir=directory
                if not os.path.exists(storedir):
                    os.mkdir(storedir)
                for partition in guid_gpt.partentries:
                    partitionname=partition.name
                    if partition.name in skip:
                        continue
                    filename=os.path.join(storedir,partitionname+".bin")
                    logging.info(f"Dumping partition {str(partition.name)} with sector count {str(partition.sectors)} as {filename}.")
                    fh.cmd_read(slun, partition.sector, partition.sectors, filename)
        exit(0)
    elif args["rf"]:
        lun = int(args["--lun"])
        filename = args["<filename>"]
        guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                              int(args["--gpt-part-entry-start-lba"]))
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            fh.cmd_read(lun, 0, guid_gpt.totalsectors, filename)
            print(f"Dumped sector 0 with sector count {str(guid_gpt.totalsectors)} as {filename}.")
        exit(0)
    elif args["pbl"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            filename = args["<filename>"]
            if TargetName in infotbl:
                v = infotbl[TargetName]
                if len(v[0]) > 0:
                        if fh.cmd_peek(v[0][0], v[0][1], filename,True):
                            print(f"Dumped pbl at offset {hex(v[0][0])} as {filename}.")
                            exit(0)
                else:
                    logger.error("No known pbl offset for this chipset")
            else:
                logger.error("Unknown target chipset")
            logger.error("Error on dumping pbl")
        exit(0)
    elif args["qfp"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            filename = args["<filename>"]
            if TargetName in infotbl:
                v = infotbl[TargetName]
                if len(v[1]) > 0:
                    if fh.cmd_peek(v[1][0], v[1][1], filename):
                        print(f"Dumped qfprom at offset {hex(v[1][0])} as {filename}.")
                        exit(0)
                else:
                    logger.error("No known qfprom offset for this chipset")
            else:
                logger.error("Unknown target chipset")
            logger.error("Error on dumping qfprom")
        exit(0)
    elif args["secureboot"] == True:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            if TargetName in secureboottbl:
                v = secureboottbl[TargetName]
                value=int(hexlify(fh.cmd_peek(v, 4)),16)
                is_secure=False
                for area in range(0,4):
                    sec_boot=(value>>(area*8))&0xF
                    pk_hashindex=sec_boot&3
                    oem_pkhash=True if ((sec_boot>>4)&1)==1 else False
                    auth_enabled=True if ((sec_boot>>5)&1)==1 else False
                    use_serial=True if ((sec_boot>>6)&1)==1 else False
                    if auth_enabled:
                        is_secure=True
                    print(f"Sec_Boot{str(area)} PKHash-Index:{str(pk_hashindex)} OEM_PKHash: {str(oem_pkhash)} Auth_Enabled: {str(auth_enabled)} Use_Serial: {str(use_serial)}")
                if is_secure:
                    print(f"Secure boot enabled.")
                else:
                    print("Secure boot disabled.")
            else:
                logger.error("Unknown target chipset")
        exit(0)
    elif args["memtbl"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            filename = args["<filename>"]
            if TargetName in infotbl:
                v = infotbl[TargetName]
                if len(v[2]) > 0:
                    if fh.cmd_peek(v[2][0], v[2][1], filename):
                        print(f"Dumped memtbl at offset {hex(v[2][0])} as {filename}.")
                        exit(0)
                else:
                    logger.error("No known memtbl offset for this chipset")
            else:
                logger.error("Unknown target chipset")
            logger.error("Error on dumping memtbl")
        exit(0)
    elif args["footer"]:
        lun = int(args["--lun"])
        filename = args["<filename>"]
        guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                              int(args["--gpt-part-entry-start-lba"]))
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            pnames = ["userdata2", "metadata", "userdata", "reserved1", "reserved2", "reserved3"]
            for partition in guid_gpt.partentries:
                if partition.name in pnames:
                    print(f"Detected partition: {partition.name}")
                    data = fh.cmd_read_buffer(lun,
                                              partition.sector + (partition.sectors - (0x4000 // cfg.SECTOR_SIZE_IN_BYTES)),
                                              (0x4000 // cfg.SECTOR_SIZE_IN_BYTES), filename)
                    val = struct.unpack("<I", data[:4])[0]
                    if ((val & 0xFFFFFFF0) == 0xD0B5B1C0):
                        with open(filename, "wb") as wf:
                            wf.write(data)
                            print(f"Dumped footer from {partition.name} as {filename}.")
                            exit(0)
                else:
                    logger.error(f"Error: Couldn't detect partition: {partition.name}")
        exit(0)
    elif args["rs"]:
        lun = int(args["--lun"])
        start = int(args["<start_sector>"])
        sectors = int(args["<sectors>"])
        filename = args["<filename"]
        data = fh.cmd_read(lun, start, sectors, filename)
        print(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
        exit(0)
    elif args["peek"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            length = int(args["<length>"], 16)
            filename = args["<filename"]
            fh.cmd_peek(offset, length, filename, True)
        exit(0)
    elif args["peekhex"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            length = int(args["<length>"], 16)
            resp=fh.cmd_peek(offset, length, "",True)
            print("\n")
            print(hexlify(resp))
        exit(0)
    elif args["peekqword"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            resp=fh.cmd_peek(offset, 8, "",True)
            print("\n")
            print(hex(unpack("<Q",resp[:8])[0]))
        exit(0)
    elif args["peekdword"]:
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            resp=fh.cmd_peek(offset, 4, "",True)
            print("\n")
            print(hex(unpack("<I",resp[:4])[0]))
        exit(0)
    elif args["send"]:
        command = args["<command>"]
        resp=fh.cmd_send(command,True)
        print("\n")
        print(resp)
        exit(0)
    elif args["poke"]:
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            filename = unhexlify(args["<filename>"])
            fh.cmd_poke(offset, "", filename, True)
        exit(0)
    elif args["pokehex"]:
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            data = unhexlify(args["<data>"])
            fh.cmd_poke(offset, data, "", True)
            resp = fh.cmd_peek(offset, len(data), "", True)
            if resp==data:
                print("Data correctly written")
            else:
                print("Sending data failed")
        exit(0)
    elif args["pokeqword"]:
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            data = pack("<Q",int(args["<data>"],16))
            fh.cmd_poke(offset, data, "", True)
            resp = fh.cmd_peek(offset, 8, "", True)
            print(hex(unpack("<Q", resp[:8])[0]))
        exit(0)
    elif args["pokedword"]:
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args["<offset>"], 16)
            data = pack("<I", int(args["<data>"], 16))
            fh.cmd_poke(offset, data, "", True)
            resp = fh.cmd_peek(offset, 4, "", True)
            print(hex(unpack("<I", resp[:4])[0]))
        exit(0)
    elif args["reset"]:
        fh.cmd_reset()
        exit(0)
    elif args["nop"]:
        if not check_cmd(supported_functions,"nop"):
            logger.error("Nop command isn't supported by edl loader")
            exit(0)
        else:
            print(fh.cmd_nop())
        exit(0)
    elif args["setbootablestoragedrive"]:
        if not check_cmd(supported_functions,"setbootablestoragedrive"):
            logger.error("setbootablestoragedrive command isn't supported by edl loader")
            exit(0)
        else:
            fh.cmd_setbootablestoragedrive(int(args["<lun>"]))
        exit(0)
    elif args["getstorageinfo"]:
        if not check_cmd(supported_functions,"getstorageinfo"):
            logger.error("getstorageinfo command isn't supported by edl loader")
            exit(0)
        else:
            fh.cmd_getstorageinfo()
        exit(0)
    elif args["w"]:
        lun = int(args["--lun"])
        partitionname = args["<partitionname>"]
        filename = args["<filename>"]
        if not os.path.exists(filename):
            logger.error(f"Error: Couldn't find file: {filename}")
            exit(0)
        guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                              int(args["--gpt-part-entry-start-lba"]))
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            if "partentries" in dir(guid_gpt):
                for partition in guid_gpt.partentries:
                    if partition.name == partitionname:
                        sectors = os.stat(filename).st_size // fh.cfg.SECTOR_SIZE_IN_BYTES
                        if (os.stat(filename).st_size % fh.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                            sectors += 1
                        if sectors > partition.sectors:
                            logger.error(f"Error: {filename} has {sectors} sectors but partition only has {partition.sectors}.")
                            exit(0)
                        fh.cmd_write(lun, partition.sector, filename)
                        print(f"Wrote {filename} to sector {str(partition.sector)}.")
                        exit(0)
                logger.error(f"Error: Couldn't detect partition: {partitionname}")
            else:
                print("Couldn't write partition. Either wrong memorytype given or no gpt partition.")
        exit(0)
    elif args["wl"]:
        directory=args["<directory>"]
        skip = args["--skip"].split(",")
        luns = []
        autolun=args["--autolun"]
        if autolun:
            for i in range(0,99):
                luns.append(i)
        else:
            luns=[int(args["--lun"])]

        if not os.path.exists(directory):
            logger.error(f"Error: Couldn't find directory: {directory}")
            exit(0)
        filenames = []
        for dirName, subdirList, fileList in os.walk(directory):
            for fname in fileList:
                filenames.append(os.path.join(dirName, fname))
        for lun in luns:
            guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                                  int(args["--gpt-part-entry-start-lba"]))
            if guid_gpt == None:
                break
            else:
                if "partentries" in dir(guid_gpt):
                    for filename in filenames:
                        for partition in guid_gpt.partentries:
                            partname=filename[filename.rfind("/")+1:]
                            if ".bin" in partname[-4:]:
                                partname=partname[:-4]
                            if partition.name == partname:
                                if partition.name in skip:
                                    continue
                                sectors = os.stat(filename).st_size // fh.cfg.SECTOR_SIZE_IN_BYTES
                                if (os.stat(filename).st_size % fh.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                                    sectors += 1
                                if sectors > partition.sectors:
                                    logger.error(f"Error: {filename} has {sectors} sectors but partition only has {partition.sectors}.")
                                    exit(0)
                                print(f"Writing {filename} to partition {str(partition.name)}.")
                                fh.cmd_write(lun, partition.sector, filename)
                else:
                    print("Couldn't write partition. Either wrong memorytype given or no gpt partition.")
        exit(0)
    elif args["ws"]:
        lun = int(args["--lun"])
        start = int(args["<start_sector>"])
        filename = args["<filename>"]
        if not os.path.exists(filename):
            logger.error(f"Error: Couldn't find file: {filename}")
            exit(0)
        if fh.cmd_write(lun, start, filename) == True:
            print(f"Wrote {filename} to sector {str(start)}.")
        else:
            logger.error(f"Error on writing {filename} to sector {str(start)}")
        exit(0)
    elif args["wf"]:
        lun = int(args["--lun"])
        start = 0
        filename = args["<filename>"]
        if not os.path.exists(filename):
            logger.error(f"Error: Couldn't find file: {filename}")
            exit(0)
        if fh.cmd_write(lun, start, filename) == True:
            print(f"Wrote {filename} to sector {str(start)}.")
        else:
            logger.error(f"Error on writing {filename} to sector {str(start)}")
        exit(0)
    elif args["e"]:
        lun = int(args["--lun"])
        partitionname = args["<partitionname>"]
        guid_gpt = fh.get_gpt(lun, int(args["--gpt-num-part-entries"]), int(args["--gpt-part-entry-size"]),
                              int(args["--gpt-part-entry-start-lba"]))
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            if "partentries" in dir(guid_gpt):
                for partition in guid_gpt.partentries:
                    if partition.name == partitionname:
                        fh.cmd_erase(lun, partition.sector, partition.sectors)
                        print(f"Erased {partitionname} starting at sector {str(partition.sector)} with sector count "+
                              f"{str(partition.sectors)}.")
                        exit(0)
            else:
                    print("Couldn't erase partition. Either wrong memorytype given or no gpt partition.")
                    exit(0)
            logger.error(f"Error: Couldn't detect partition: {partitionname}")
        exit(0)
    elif args["es"]:
        lun = int(args["--lun"])
        start = int(args["<start_sector>"])
        sectors = int(args["<sectors"])
        fh.cmd_erase(lun, start, sectors)
        print(f"Erased sector {str(start)} with sector count {str(sectors)}.")
        exit(0)
    elif args["xml"]:
        fh.cmd_xml(args["<xmlfile>"])
        exit(0)
    elif args["server"]:
        do_firehose_server(args,cdc,sahara)
        exit(0)
    else:
        logger.error("Unknown/Missing command, a command is required.")
        exit(0)


if __name__ == '__main__':
    main()
