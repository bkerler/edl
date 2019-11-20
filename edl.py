#!/usr/bin/env python3
'''
Licensed under MIT License, (c) B. Kerler 2018-2019
'''

import argparse
import time
import os
from Library.utils import *
from Library.usblib import usb_class
from Library.gpt import gpt
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
    info='Qualcomm Sahara / Firehose Client (c) B.Kerler 2018-2019.'
    parser = argparse.ArgumentParser(description=info)
    print("\n"+info+"\n\n")
    parser.add_argument('-loader',metavar="none,<filename>",help='[Option] Flash programmer to load e.g. prog_emmc_firehose.elf', default='')
    parser.add_argument('-vid',metavar="<vid>",help='[Option] Specify vid, default=0x05c6)', default="0x05C6")
    parser.add_argument('-pid',metavar="<pid>", help='[Option] Specify pid, default=0x9008)', default="0x9008")
    parser.add_argument('-maxpayload',metavar="<bytes>",help='[Option] The max bytes to transfer in firehose mode (default=1048576)', type=int, default=1048576)
    parser.add_argument('-skipwrite', help='[Option] Do not write actual data to disk (use this for UFS provisioning)', action="store_true")
    parser.add_argument('-skipstorageinit', help='[Option] Do not initialize storage device (use this for UFS provisioning)',action="store_true")
    parser.add_argument('-memory', metavar="<UFS/eMMC>",help='[Option] Memory type (default=UFS)',default='UFS')
    parser.add_argument('-sectorsize', metavar="<bytes>",help='[Option] Define Disk Sector Size (default=512)',type=int,default=512)
    #parser.add_argument('-lun', metavar="<num>",help='[Option] Define LUN',type=int,default=0)
    #parser.add_argument('-debug', help='[Option] Enable debug output', action="store_true")
    parser.add_argument('-debugmode', help='[CMD:Sahara] Switch to Memory Dump mode (Debug only)',action="store_true")
    parser.add_argument('-debugread', help='[CMD:Sahara] Read Debug Logs',action="store_true")
    parser.add_argument('-dmss', help='[CMD:Sahara] Switch to DMSS Download mode',action="store_true")
    parser.add_argument('-streaming', help='[CMD:Sahara] Switch to Streaming Download mode', action="store_true")

    parser.add_argument('-r', metavar=("<lun>","<PartName>","<filename>"), help='[CMD:Firehose] Dump partition based on partition name', nargs=3,default=[])
    parser.add_argument('-rl', metavar=("<lun>", "<directory>"), help='[CMD:Firehose] Dump whole lun/flash partitions to a directory', nargs=2,default=[])
    parser.add_argument('-rf', metavar=("<lun>","<filename>"),help='[CMD:Firehose] Dump whole lun/flash', nargs=2, default=[])
    parser.add_argument('-rs', metavar=("<lun>","<start_sector>","<sectors>","<filename>"), help='[CMD:Firehose] Dump from start sector to end sector to file', nargs=4,default=[])
    parser.add_argument('-w', metavar=("<lun>","<partitionname>","<filename>"), help='[CMD:Firehose] Write filename to GPT partition', nargs=3, default=[])
    parser.add_argument('-ws', metavar=("<lun>","<start_sector>","<filename>"), help='[CMD:Firehose] Write filename at sector <start_sector>', nargs=3, default=[])
    parser.add_argument('-e', metavar=("<lun>","<partitionname>"), help='[CMD:Firehose] Erase the entire partition specified',nargs=2, default=[])
    parser.add_argument('-es', metavar=("<lun>","<start_sector>","<num_sectors>"), help='[CMD:Firehose] Erase disk from start sector for number of sectors',nargs=3,default=[])
    parser.add_argument('-gpt', metavar="<lun>,<filename>", help='[CMD:Firehose] Dump gpt to file', nargs=2, default=[])
    parser.add_argument('-printgpt', help='[CMD:Firehose] Print gpt', default="")
    parser.add_argument('-footer', metavar=("<lun>","<filename>"), help='[CMD:Firehose] Dump crypto footer', nargs=2, default=[])

    parser.add_argument('-pbl', metavar=("<filename>"),help='[CMD:Firehose] Dump boot rom (pbl)', default="")
    parser.add_argument('-qfp', metavar=("<filename>"), help='[CMD:Firehose] Dump qfprom', default="")
    parser.add_argument('-secureboot', help='[CMD:Firehose] Get secure boot info', action="store_true")
    parser.add_argument('-memtbl', metavar=("<filename>"), help='[CMD:Firehose] Dump memory table', default="")

    parser.add_argument('-peek', metavar=("<offset>","<length>","<filename>"),help='[CMD:Firehose] Read memory from offset,length to file', nargs=3, default=[])
    parser.add_argument('-peekhex', metavar=("<offset>","<length>"),help='[CMD:Firehose] Read memory from offset, length and display', nargs=2, default=[])
    parser.add_argument('-peekdword', metavar=("<offset>"),help='[CMD:Firehose] Read dword (hex) from offset, length and display', nargs=1, default=[])
    parser.add_argument('-peekqword', metavar=("<offset>"),help='[CMD:Firehose] Read qword (hex) from offset, length and display', nargs=1, default=[])
    parser.add_argument('-poke', metavar=("<offset>", "<filename>"),help='[CMD:Firehose] write data at offset from file', nargs=2, default=[])
    parser.add_argument('-pokehex', metavar=("<offset>", "<data>"),help='[CMD:Firehose] write data at offset as hexstring to memory', nargs=2, default=[])
    parser.add_argument('-pokedword', metavar=("<offset>", "<data>"),help='[CMD:Firehose] write dword (hex) at offset to memory', nargs=2, default=[])
    parser.add_argument('-pokeqword', metavar=("<offset>", "<data>"), help='[CMD:Firehose] write qword (hex) at offset to memory', nargs=2, default=[])
    parser.add_argument('-memcpy', metavar=("<srcoffset>", "<dstoffset>", "<size>"), help='[CMD:Firehose] copy memory offset from src to dst', nargs=3, default=[])
    parser.add_argument('-reset', help='[CMD:Firehose] Reset device', action="store_true")
    parser.add_argument('-nop', help='[CMD:Firehose] NOP', action="store_true")
    parser.add_argument('-getstorageinfo', help='[CMD:Firehose] Get Storage/Flash Info', action="store_true")
    parser.add_argument('-setbootablestoragedrive', metavar="<number>",
                        help='[CMD:Firehose] Set the physical partition number active for booting',default='')
    parser.add_argument('-send', metavar="<command>", help='[CMD:Firehose] Send xml command', default='')
    parser.add_argument('-xml', metavar="<xmlfile>", help='[CMD:Firehose] XML to run in firehose mode', default='')
    parser.add_argument('-gpt-num-part-entries', metavar="<number>", type=int, help='[CMD:Firehose] Number of partitions', default=None)
    parser.add_argument('-gpt-part-entry-size', metavar="<number>", type=int, help='[CMD:Firehose] Size of partition entry', default=None)
    parser.add_argument('-gpt-part-entry-start-lba', metavar="<number>", type=int, help='[CMD:Firehose] Beginning of partition entries', default=None)
    parser.add_argument('-server', help='Run as a TCP/IP Server, listing on port 1336', action="store_true")


    args = parser.parse_args()

    mode=""
    loop=0
    if args.vid!="":
        vid=int(args.vid,16)
    if args.pid!="":
        pid=int(args.pid,16)
    cdc = usb_class(vid=vid, pid=pid)
    sahara = qualcomm_sahara(cdc)

    if args.loader=='none':
        logger.info("Trying with no loader given ...")
        sahara.programmer = None
    elif (args.loader==""):
        logger.info("Trying with loaders in Loader directory ...")
        sahara.programmer = None
    elif (args.loader!=''):
        logger.info(f"Using loader {args.loader} ...")
        with open(args.loader, "rb") as rf:
            sahara.programmer = rf.read()
    else:
        print("Sorry, you need a firehose loader (-loader) or try without loader \"-loader none\" !")
        print("Use with -h for displaying help.")
        exit(0)

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

def do_firehose_server(args,cdc,sahara):
    cfg = qualcomm_firehose.cfg()
    cfg.MemoryName = args.memory
    cfg.ZLPAwareHost = 1
    cfg.SkipStorageInit = args.skipstorageinit
    cfg.SkipWrite = args.skipwrite
    cfg.MaxPayloadSizeToTargetInBytes = args.maxpayload
    cfg.SECTOR_SIZE_IN_BYTES = args.sectorsize
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
    server_address = ('localhost',1340)
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
                                    response="<NAK>\n"+"Usage: gpt:<lun>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    fh.cmd_read(lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES*4, args.gpt)
                                    response=f"<ACK>\n"+f"Dumped GPT to {args.gpt}"
                                    connection.sendall(bytes(response,'utf-8'))
                            elif cmd=="printgpt":
                                if len(args) != 1:
                                    response="<NAK>\n"+"Usage: printgpt:<lun>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                          args.gpt_part_entry_start_lba)
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
                                    guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                          args.gpt_part_entry_start_lba)
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
                                if len(args) != 2:
                                    response="<NAK>\n"+"Usage: rl:<lun>,<directory>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun = int(args[0])
                                    directory = args[1]
                                    if not os.path.exists(directory):
                                        os.mkdir(directory)
                                    guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                          args.gpt_part_entry_start_lba)
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        response = "<ACK>\n"
                                        for partition in guid_gpt.partentries:
                                            partitionname=partition.name
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
                                    guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                          args.gpt_part_entry_start_lba)
                                    if guid_gpt == None:
                                        response = "<NAK>\n" + f"Error: Couldn't reading GPT Table"
                                        connection.sendall(bytes(response, 'utf-8'))
                                    else:
                                        fh.cmd_read(args.lun, 0, guid_gpt.totalsectors, filename)
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
                                        filename = args.pbl
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
                                    guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                          args.gpt_part_entry_start_lba)
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
                                        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                              args.gpt_part_entry_start_lba)
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
                            elif cmd=="e":
                                if len(args) != 2:
                                    response = "<NAK>\n" + "Usage: e:<lun>,<partname>"
                                    connection.sendall(bytes(response,'utf-8'))
                                else:
                                    lun=int(args[0])
                                    partitionname = args[1]
                                    guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                                                          args.gpt_part_entry_start_lba)
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
                                    response="<NAK>\n"+"Usage: ws:<lun>,<start_sector>,<sectors>"
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
    cfg.MemoryName = args.memory
    cfg.ZLPAwareHost = 1
    cfg.SkipStorageInit = args.skipstorageinit
    cfg.SkipWrite = args.skipwrite
    cfg.MaxPayloadSizeToTargetInBytes = args.maxpayload
    cfg.SECTOR_SIZE_IN_BYTES = args.sectorsize
    cfg.bit64 = sahara.bit64
    fh = qualcomm_firehose(cdc, xmlparser(), cfg)
    supported_functions = fh.connect(0)
    TargetName=fh.cfg.TargetName
    if "hwid" in dir(sahara):
        hwid=sahara.hwid>>32
        if hwid in msmids:
            TargetName = msmids[hwid]

    if len(args.gpt) != 0:
        if len(args.gpt) != 2:
            print("Usage: -gpt <lun> <filename>")
            exit(0)
        lun=args.gpt[0]
        filename = args.gpt[1]
        fh.cmd_read(lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES, filename)
        print(f"Dumped GPT to {filename}")
        exit(0)
    elif args.printgpt!="":
        lun=int(args.printgpt)
        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            guid_gpt.print()
        exit(0)
    elif len(args.r) != 0:
        if len(args.r) != 3:
            print("Usage: -r <lun> <partitionname> <filename>")
            exit(0)
        lun = int(args.r[0])
        partitionname = args.r[1]
        filename = args.r[2]

        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
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
    elif len(args.rl) != "":
        if len(args.rl) != 2:
            print("Usage: -rl <lun> <directory_to_save_files>")
            exit(0)
        lun = int(args.rl[0])
        directory = args.rl[1]
        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            if not os.path.exists(directory):
                os.mkdir(directory)
            for partition in guid_gpt.partentries:
                partitionname=partition.name
                filename=os.path.join(directory,partitionname+".bin")
                logging.info(f"Dumping partition {str(partition.name)} with sector count {str(partition.sectors)} as {filename}.")
                fh.cmd_read(lun, partition.sector, partition.sectors, filename)
            exit(0)
        exit(0)
    elif len(args.rf) != 0:
        if len(args.r) != 2:
            print("Usage: -r <lun> <filename>")
            exit(0)
        lun = int(args.rf[0])
        filename = args.rf[1]
        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
        if guid_gpt == None:
            logger.error("Error on reading GPT, maybe wrong memoryname given ?")
        else:
            fh.cmd_read(lun, 0, guid_gpt.totalsectors, filename)
            print(f"Dumped sector 0 with sector count {str(guid_gpt.totalsectors)} as {filename}.")
        exit(0)
    elif args.pbl != '':
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            filename = args.pbl
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
    elif args.qfp != '':
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            filename = args.qfp
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
    elif args.secureboot == True:
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
    elif args.memtbl != '':
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            filename = args.memtbl
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
    elif len(args.footer) != 0:
        if len(args.footer) != 2:
            print("Usage: -footer <lun> <filename>")
            exit(0)
        lun = int(args.footer[0])
        filename = args.footer[1]
        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
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
    elif len(args.rs) != 0:
        if len(args.rs) != 4:
            print("Usage: -rs <lun> <start_sector> <sectors> <filename>")
            exit(0)
        lun = int(args.rs[0])
        start = int(args.rs[1])
        sectors = int(args.rs[2])
        filename = args.rs[3]
        data = fh.cmd_read(lun, start, sectors, filename)
        print(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
        exit(0)
    elif len(args.peek) != 0:
        if len(args.peek) != 3:
            print("Usage: -peek <offset> <length> <filename>")
            exit(0)
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.peek[0], 16)
            length = int(args.peek[1], 16)
            filename = args.peek[2]
            fh.cmd_peek(offset, length, filename, True)
        exit(0)
    elif len(args.peekhex) != 0:
        if len(args.peekhex) != 2:
            print("Usage: -peekhex <offset> <length>")
            exit(0)
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.peekhex[0], 16)
            length = int(args.peekhex[1], 16)
            resp=fh.cmd_peek(offset, length, "",True)
            print("\n")
            print(hexlify(resp))
        exit(0)
    elif len(args.peekqword) != 0:
        if len(args.peekqword) != 1:
            print("Usage: -peekqword <offset>")
            exit(0)
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.peekqword[0], 16)
            resp=fh.cmd_peek(offset, 8, "",True)
            print("\n")
            print(hex(unpack("<Q",resp[:8])[0]))
        exit(0)
    elif len(args.peekdword) != 0:
        if len(args.peekdword) != 1:
            print("Usage: -peekdword <offset>")
            exit(0)
        if not check_cmd(supported_functions,"peek"):
            logger.error("Peek command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.peekdword[0], 16)
            resp=fh.cmd_peek(offset, 4, "",True)
            print("\n")
            print(hex(unpack("<I",resp[:4])[0]))
        exit(0)
    elif args.send != "":
        command = args.send
        resp=fh.cmd_send(command,True)
        print("\n")
        print(resp)
        exit(0)
    elif len(args.poke) != 0:
        if len(args.poke) != 2:
            print("Usage: -poke <offset> <filename>")
            exit(0)
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.poke[0], 16)
            filename = unhexlify(args.poke[1])
            fh.cmd_poke(offset, "", filename, True)
        exit(0)
    elif len(args.pokehex) != 0:
        if len(args.pokehex) != 2:
            print("Usage: -pokehex <offset> <data>")
            exit(0)
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.pokehex[0], 16)
            data = unhexlify(args.pokehex[1])
            fh.cmd_poke(offset, data, "", True)
            resp = fh.cmd_peek(offset, len(data), "", True)
            if resp==data:
                print("Data correctly written")
            else:
                print("Sending data failed")
        exit(0)
    elif len(args.pokeqword) != 0:
        if len(args.pokeqword) != 2:
            print("Usage: -pokeqword <offset> <qword>")
            exit(0)
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.pokeqword[0], 16)
            data = pack("<Q",int(args.pokeqword[1],16))
            fh.cmd_poke(offset, data, "", True)
            resp = fh.cmd_peek(offset, 8, "", True)
            print(hex(unpack("<Q", resp[:8])[0]))
        exit(0)
    elif len(args.pokedword) != 0:
        if len(args.pokedword) != 2:
            print("Usage: -pokedword <offset> <dword>")
            exit(0)
        if not check_cmd(supported_functions,"poke"):
            logger.error("Poke command isn't supported by edl loader")
            exit(0)
        else:
            offset = int(args.pokedword[0], 16)
            data = pack("<I",int(args.pokedword[1],16))
            fh.cmd_poke(offset, data, "", True)
            resp = fh.cmd_peek(offset, 4, "", True)
            print(hex(unpack("<I", resp[:4])[0]))
        exit(0)
    elif args.reset:
        fh.cmd_reset()
        exit(0)
    elif args.nop:
        if not check_cmd(supported_functions,"nop"):
            logger.error("Nop command isn't supported by edl loader")
            exit(0)
        else:
            print(fh.cmd_nop())
        exit(0)
    elif args.setbootablestoragedrive != '':
        if not check_cmd(supported_functions,"setbootablestoragedrive"):
            logger.error("setbootablestoragedrive command isn't supported by edl loader")
            exit(0)
        else:
            fh.cmd_setbootablestoragedrive(int(args.setbootablestoragedrive))
        exit(0)
    elif args.getstorageinfo:
        if not check_cmd(supported_functions,"getstorageinfo"):
            logger.error("getstorageinfo command isn't supported by edl loader")
            exit(0)
        else:
            fh.cmd_getstorageinfo()
        exit(0)
    elif len(args.w) != 0:
        if len(args.w) != 3:
            print("Usage: -w <lun> <partitionname> <filename>")
            exit(0)
        lun = int(args.w[0])
        partitionname = args.w[1]
        filename = args.w[2]
        if not os.path.exists(filename):
            logger.error(f"Error: Couldn't find file: {filename}")
            exit(0)
        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
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
    elif len(args.ws) != 0:
        if len(args.ws) != 3:
            print("Usage: -ws <lun> <start_sector> <filename>")
            exit(0)
        lun = int(args.ws[0])
        start = int(args.ws[1])
        filename = args.ws[2]
        if not os.path.exists(filename):
            logger.error(f"Error: Couldn't find file: {filename}")
            exit(0)
        if fh.cmd_write(lun, start, filename) == True:
            print(f"Wrote {filename} to sector {str(start)}.")
        else:
            logger.error(f"Error on writing {filename} to sector {str(start)}")
        exit(0)
    elif len(args.e) != 0:
        if len(args.e) != 2:
            print("Usage: -e <lun> <partname>")
            exit(0)
        lun = args.e[0]
        partitionname = args.e[1]
        guid_gpt = fh.get_gpt(lun, args.gpt_num_part_entries, args.gpt_part_entry_size,
                              args.gpt_part_entry_start_lba)
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
    elif len(args.es) != 0:
        if len(args.es) != 3:
            print("Usage: -ws <lun> <start_sector> <sectors>")
            exit(0)
        lun = int(args.es[0])
        start = int(args.es[1])
        sectors = int(args.es[2])
        fh.cmd_erase(lun, start, sectors)
        print(f"Erased sector {str(start)} with sector count {str(sectors)}.")
        exit(0)
    elif args.xml != '':
        fh.cmd_xml(args.xml)
        exit(0)
    elif args.server != '':
        do_firehose_server(args,cdc,sahara)
        exit(0)
    else:
        logger.error("Unknown/Missing command, a command is required.")
        exit(0)


if __name__ == '__main__':
    main()
