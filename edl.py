#!/usr/bin/env python3
'''
Licensed under MIT License, (c) B. Kerler 2018-2019
'''

import argparse
import time
import os
from Library.utils import *
from Library.usb import usb_class
from Library.gpt import gpt
from Library.sahara import qualcomm_sahara
from Library.firehose import qualcomm_firehose, xmlparser

msmids={
    0x006220E1: "MSM7227A",
    0x008110E1: "MSM8210",
    0x008140E1: "MSM8212",
    0x009600E1: "MSM8909",
    0x007050E1: "MSM8916",
    0x000560E1: "MSM8917",
    0x008050E1: "MSM8926",
    0x009180E1: "MSM8928",
    0x0091B0E1: "MSM8929",
    0x0072C0E1: "MSM8930",
    #0x000000E1: "MSM8936",
    0x0004F0E1: "MSM8937",
    0x0090B0E1: "MSM8939",
    0x0006B0E1: "MSM8940",
    0x009B00E1: "MSM8952",
    0x000460E1: "MSM8953",
    #0x000000E1: "MSM8956",
    0x007B40E1: "MSM8974",
    0x007B80E1: "MSM8974AB",
    0x009900E1: "MSM8976",
    0x109400E1: "MSM8994",
    0x009470E1: "MSM8996",
    0x0005F0E1: "MSM8996Pro",
    0x0005E0E1: "MSM8998",
    0x000CC0E1: "SDM636",
    0x0008C0E1: "SDM660"
}

infotbl={
    "MSM7227A":[[], [], []],
    "MSM8210": [[], [], []],
    "MSM8212": [[], [], []],
    "MSM8909": [[0x100000, 0x18000], [0x5C000, 0x1000], [0x200000, 0x24000]],
    "MSM8916": [[0x100000, 0x18000], [0x5C000, 0x1000], [0x200000, 0x24000]],
    "MSM8917": [[0x100000, 0x18000], [0xA0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8926": [[], [], []],
    "MSM8928": [[], [], []],
    "MSM8929": [[0x100000, 0x18000], [], []],
    "MSM8930": [[0x100000, 0x18000], [0x700000, 0x1000], []],
    "MSM8936": [[0x100000, 0x18000], [0x700000, 0x1000], []],
    "MSM8937": [[0x100000, 0x18000], [0xA0000, 0x6FFF], [0x200000, 0x24000]],
    "MSM8939": [[], [], []],
    "MSM8940": [[], [], []],
    "MSM8952": [[0x100000, 0x18000], [0xA0000, 0x1000], [0x200000, 0x24000]],
    "MSM8953": [[0x100000, 0x18000], [0xA0000, 0x1000], [0x200000, 0x24000]],
    "MSM8956": [[], [], []],
    "MSM8974": [[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8974AB": [[0xFC010000, 0x18000], [0xFC4B8000, 0x60F0], [0x200000, 0x24000]],
    "MSM8976": [[0x100000, 0x18000], [0xA0000, 0x1000], [0x200000, 0x24000]],
    "MSM8994": [[0xFC010000, 0x18000], [0xFC4B8000, 0x6FFF], [0xFE800000, 0x24000]],
    "MSM8996": [[],[0x70000, 0x6158], [0x200000, 0x24000]],
    "MSM8996Pro": [[],[0x70000, 0x6158], [0x200000, 0x24000]],
    "MSM8998": [[], [0x780000, 0x621c], []],
    "SDM636": [[], [], []],
    "SDM660": [[], [0x780000, 0x6220], []]
}

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
    parser.add_argument('-lun', metavar="<num>",help='[Option] Define LUN',type=int,default=0)
    #parser.add_argument('-debug', help='[Option] Enable debug output', action="store_true")
    parser.add_argument('-debugmode', help='[CMD:Sahara] Switch to Memory Dump mode (Debug only)',action="store_true")
    parser.add_argument('-debugread', help='[CMD:Sahara] Read Debug Logs',action="store_true")
    parser.add_argument('-dmss', help='[CMD:Sahara] Switch to DMSS Download mode',action="store_true")
    parser.add_argument('-streaming', help='[CMD:Sahara] Switch to Streaming Download mode', action="store_true")
    parser.add_argument('-r', metavar=("<PartName>","<filename>"), help='[CMD:Firehose] Dump entire partition based on partition name', nargs=2,default=[])
    parser.add_argument('-rf', metavar=("<filename>"),help='[CMD:Firehose] Dump whole lun', default="")
    parser.add_argument('-rs', metavar=("<start_sector>","<sectors>","<filename>"), help='[CMD:Firehose] Dump from start sector to end sector to file', nargs=3,default=[])
    parser.add_argument('-pbl', metavar=("<filename>"),help='[CMD:Firehose] Dump boot rom (pbl)', default="")
    parser.add_argument('-qfp', metavar=("<filename>"), help='[CMD:Firehose] Dump qfprom', default="")
    parser.add_argument('-memtbl', metavar=("<filename>"), help='[CMD:Firehose] Dump memory table', default="")
    parser.add_argument('-footer', metavar=("<filename>"), help='[CMD:Firehose] Dump crypto footer', default="")
    parser.add_argument('-gpt', metavar="<filename>", help='[CMD:Firehose] Dump gpt to file', default="")
    parser.add_argument('-printgpt', help='[CMD:Firehose] Print gpt', action="store_true")
    parser.add_argument('-peek', metavar=("<offset>","<length>","<filename>"),help='[CMD:Firehose] Read memory from offset,length to file', nargs=3, default=[])
    parser.add_argument('-w', metavar=("<partitionname>","<filename>"), help='[CMD:Firehose] Write filename to GPT partition', nargs=2, default=[])
    parser.add_argument('-ws', metavar=("<start_sector>","<filename>"), help='[CMD:Firehose] Write filename at sector <start_sector>', nargs=2, default=[])
    parser.add_argument('-e', metavar="<partitionname>", help='[CMD:Firehose] Erase the entire partition specified',default='')
    parser.add_argument('-es', metavar=("<start_sector>","<num_sectors>"), help='[CMD:Firehose] Erase disk from start sector for number of sectors',nargs=2,default=[])
    parser.add_argument('-reset', help='[CMD:Firehose] Reset device', action="store_true")
    parser.add_argument('-getstorageinfo', help='[CMD:Firehose] Get Storage/Flash Info', action="store_true")
    parser.add_argument('-setbootablestoragedrive', metavar="<number>",
                        help='[CMD:Firehose] Set the physical partition number active for booting',default='')
    parser.add_argument('-x', metavar="<xmldata>", help='[CMD:Firehose] XML to run in firehose mode', default='')
    parser.add_argument('-gpt-num-part-entries', metavar="<number>", type=int, help='[CMD:Firehose] Number of partitions', default=None)
    parser.add_argument('-gpt-part-entry-size', metavar="<number>", type=int, help='[CMD:Firehose] Size of partition entry', default=None)
    parser.add_argument('-gpt-part-entry-start-lba', metavar="<number>", type=int, help='[CMD:Firehose] Beginning of partition entries', default=None)


    args = parser.parse_args()
    xml = xmlparser()

    mode=""
    loop=0
    if args.vid!="":
        vid=int(args.vid,16)
    if args.pid!="":
        pid=int(args.pid,16)
    cdc = usb_class(vid=vid, pid=pid)
    sahara = qualcomm_sahara(cdc)

    if args.loader=='none':
        print("Trying with no loader given ...")
        sahara.programmer = None
    elif (args.loader==""):
        print("Trying with loaders in Loader directory ...")
        sahara.programmer = None
    elif (args.loader!=''):
        print(f"Using loader {args.loader} ...")
        with open(args.loader, "rb") as rf:
            sahara.programmer = rf.read()
    else:
        print("Sorry, you need a firehose loader (-loader) or try without loader \"-loader none\" !")
        print("Use with -h for displaying help.")
        exit(0)

    print("Waiting for the device")

    while (cdc.connected==False):
        cdc.connected=cdc.connect()
        if cdc.connected==False:
            sys.stdout.write('.')
            if (loop>=20):
                sys.stdout.write('\n')
                loop=0
            loop+=1
            time.sleep(1)
            sys.stdout.flush()
        else:
            print("Device detected :)")
            mode=sahara.connect()
            print(f"Mode detected: {mode}")
            break

    if mode=="Sahara":
        m = sahara.info()
        if args.debugmode:
            sahara.debug_mode()
            exit(0)
        elif args.debugread:
            sahara.cmdexec_read_debug_data()
        elif args.dmss:
            sahara.cmdexec_switch_to_dmss_dload()
            exit(0)
        elif args.streaming:
            sahara.cmdexec_switch_to_stream_dload()
            exit(0)
        else:
            if sahara.upload_firehoseloader()==True:
               time.sleep(0.3)
               mode="Firehose"
               print("Successfully uploaded programmer :)")
    else:
        sahara.bit64=True

    if mode=="Firehose":
        cfg=qualcomm_firehose.cfg()
        cfg.MemoryName = args.memory
        cfg.ZLPAwareHost = 1
        cfg.SkipStorageInit = args.skipstorageinit
        cfg.SkipWrite = args.skipwrite
        cfg.MaxPayloadSizeToTargetInBytes = args.maxpayload
        cfg.SECTOR_SIZE_IN_BYTES=args.sectorsize
        cfg.bit64=sahara.bit64
        fh = qualcomm_firehose(cdc,xml,cfg)
        info=fh.connect(0)
        if args.gpt!='':
            fh.cmd_read(args.lun, 0, 0x4000//cfg.SECTOR_SIZE_IN_BYTES, args.gpt)
            print(f"Dumped GPT to {args.gpt}")
            exit(0)
        elif args.printgpt==True:
            data = fh.cmd_read_buffer(args.lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES)
            if data!='':
                guid_gpt = gpt(
                    num_part_entries=args.gpt_num_part_entries,
                    part_entry_size=args.gpt_part_entry_size,
                    part_entry_start_lba=args.gpt_part_entry_start_lba,
                )
                guid_gpt.parse(data,cfg.SECTOR_SIZE_IN_BYTES)
                guid_gpt.print()
            else:
                print("Error on reading GPT, maybe wrong memoryname given ?")
            exit(0)
        elif len(args.r)!=0:
            if len(args.r)!=2:
                print("Usage: -r <partitionname> <filename>")
                exit(0)
            partitionname=args.r[0]
            filename=args.r[1]
            data = fh.cmd_read_buffer(args.lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES,False)
            guid_gpt = gpt(
                num_part_entries=args.gpt_num_part_entries,
                part_entry_size=args.gpt_part_entry_size,
                part_entry_start_lba=args.gpt_part_entry_start_lba,
            )
            guid_gpt.parse(data, cfg.SECTOR_SIZE_IN_BYTES)

            for partition in guid_gpt.partentries:
                if partition.name==partitionname:
                    data = fh.cmd_read(args.lun, partition.sector, partition.sectors, filename)
                    print(f"Dumped sector {str(partition.sector)} with sector count {str(partition.sectors)} as {filename}.")
                    exit(0)
            print(f"Error: Couldn't detect partition: {partitionname}")
            exit(0)
        elif args.rf!='':
            filename=args.rf
            data = fh.cmd_read_buffer(args.lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES,False)
            guid_gpt = gpt(
                num_part_entries=args.gpt_num_part_entries,
                part_entry_size=args.gpt_part_entry_size,
                part_entry_start_lba=args.gpt_part_entry_start_lba,
            )
            guid_gpt.parse(data, cfg.SECTOR_SIZE_IN_BYTES)
            data = fh.cmd_read(args.lun, 0, guid_gpt.totalsectors, filename)
            print(f"Dumped sector 0 with sector count {str(guid_gpt.totalsectors)} as {filename}.")
            exit(0)
        elif args.pbl!='':
            filename=args.pbl
            if fh.cfg.TargetName in infotbl:
                v=infotbl[fh.cfg.TargetName]
                if len(v[0])>0:
                    if fh.cmd_peek(v[0][0],v[0][1],filename):
                        print(f"Dumped pbl at offset {hex(v[0][0])} as {filename}.")
                        exit(0)
                else:
                    print("No known pbl offset for this chipset")
            else:
                print("Unknown target chipset")
            print("Error on dumping pbl")
            exit(0)
        elif args.qfp!='':
            filename=args.qfp
            if fh.cfg.TargetName in infotbl:
                v=infotbl[fh.cfg.TargetName]
                if len(v[1])>0:
                    if fh.cmd_peek(v[1][0],v[1][1],filename):
                        print(f"Dumped qfprom at offset {hex(v[1][0])} as {filename}.")
                        exit(0)
                else:
                    print("No known qfprom offset for this chipset")
            else:
                print("Unknown target chipset")
            print("Error on dumping pbl")
            exit(0)
        elif args.memtbl!='':
            filename=args.memtbl
            if fh.cfg.TargetName in infotbl:
                v=infotbl[fh.cfg.TargetName]
                if len(v[2])>0:
                    if fh.cmd_peek(v[2][0],v[2][1],filename):
                        print(f"Dumped qfprom at offset {hex(v[2][0])} as {filename}.")
                        exit(0)
                else:
                    print("No known qfprom offset for this chipset")
            else:
                print("Unknown target chipset")
            print("Error on dumping pbl")
            exit(0)
        elif args.footer!='':
            filename=args.footer
            data = fh.cmd_read_buffer(args.lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES,False)
            guid_gpt = gpt(
                num_part_entries=args.gpt_num_part_entries,
                part_entry_size=args.gpt_part_entry_size,
                part_entry_start_lba=args.gpt_part_entry_start_lba,
            )
            guid_gpt.parse(data, cfg.SECTOR_SIZE_IN_BYTES)
            pnames=["userdata2","metadata","userdata","reserved1","reserved2","reserved3"]
            for partition in guid_gpt.partentries:
                if partition.name in pnames:
                    print(f"Detected partition: {partition.name}")
                    data = fh.cmd_read_buffer(args.lun, partition.sector+(partition.sectors-(0x4000 // cfg.SECTOR_SIZE_IN_BYTES)), (0x4000 // cfg.SECTOR_SIZE_IN_BYTES), filename)
                    val=struct.unpack("<I",data[:4])[0]
                    if ((val&0xFFFFFFF0)==0xD0B5B1C0):
                        with open(filename,"wb") as wf:
                            wf.write(data)
                            print(f"Dumped footer from {partition.name} as {filename}.")
                            exit(0)
            print(f"Error: Couldn't detect partition: {partitionname}")
            exit(0)
        elif len(args.rs)!=0:
            if len(args.rs)!=3:
                print("Usage: -rs <start_sector> <sectors> <filename>")
                exit(0)
            start=int(args.rs[0])
            sectors=int(args.rs[1])
            filename=args.rs[2]
            data = fh.cmd_read(args.lun, start, sectors, filename)
            print(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
            exit(0)
        elif len(args.peek)!=0:
            if len(args.peek)!=3:
                print("Usage: -peek <offset> <length> <filename>")
                exit(0)
            offset=int(args.peek[0],16)
            length=int(args.peek[1],16)
            filename=args.peek[2]
            fh.cmd_peek(offset,length,filename)
            exit(0)
        elif args.reset:
            fh.cmd_reset()
            exit(0)
        elif args.setbootablestoragedrive!='':
            fh.cmd_setbootablestoragedrive(int(args.setbootablestoragedrive))
            exit(0)
        elif args.getstorageinfo:
            fh.cmd_getstorageinfo()
            exit(0)
        elif len(args.w) != 0:
            if len(args.w) != 2:
                print("Usage: -w <partitionname> <filename>")
                exit(0)
            partitionname=args.w[0]
            filename=args.w[1]
            if not os.path.exists(filename):
                print(f"Error: Couldn't find file: {filename}")
                exit(0)
            data = fh.cmd_read_buffer(args.lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES,False)
            guid_gpt = gpt(
                num_part_entries=args.gpt_num_part_entries,
                part_entry_size=args.gpt_part_entry_size,
                part_entry_start_lba=args.gpt_part_entry_start_lba,
            )
            guid_gpt.parse(data, cfg.SECTOR_SIZE_IN_BYTES)

            for partition in guid_gpt.partentries:
                if partition.name==partitionname:
                    sectors=os.stat(filename).st_size//fh.cfg.SECTOR_SIZE_IN_BYTES
                    if (os.stat(filename).st_size%fh.cfg.SECTOR_SIZE_IN_BYTES)>0:
                        sectors+=1
                    if sectors>partition.sectors:
                        print(f"Error: {filename} has {sectors} sectors but partition only has {partition.sectors}.")
                        exit(0)
                    data = fh.cmd_write(args.lun, partition.sector, filename)
                    print(f"Wrote {filename} to sector {str(partition.sector)}.")
                    exit(0)
            print(f"Error: Couldn't detect partition: {partitionname}")
            exit(0)
        elif len(args.ws)!=0:
            if len(args.ws)!=2:
                print("Usage: -ws <start_sector> <filename>")
                exit(0)
            start=int(args.ws[0])
            filename=args.ws[1]
            if not os.path.exists(filename):
                print(f"Error: Couldn't find file: {filename}")
                exit(0)
            if fh.cmd_write(args.lun, start, filename)==True:
                print(f"Wrote {filename} to sector {str(start)}.")
            else:
                print(f"Error on writing {filename} to sector {str(start)}")
            exit(0)
        elif args.e != '':
            partitionname=args.e
            data = fh.cmd_read_buffer(args.lun, 0, 0x4000 // cfg.SECTOR_SIZE_IN_BYTES,False)
            guid_gpt=gpt(
                    num_part_entries=args.gpt_num_part_entries,
                    part_entry_size=args.gpt_part_entry_size,
                    part_entry_start_lba=args.gpt_part_entry_start_lba,
                )
            guid_gpt.parse(data, cfg.SECTOR_SIZE_IN_BYTES)

            for partition in guid_gpt.partentries:
                if partition.name==partitionname:
                    fh.cmd_erase(args.lun, partition.sector, partition.sectors)
                    print(f"Erased {partitionname} starting at sector {str(partition.sector)} with sector count {str(partition.sectors)}.")
                    exit(0)
            print(f"Error: Couldn't detect partition: {partitionname}")
            exit(0)
        elif len(args.es)!=0:
            if len(args.es)!=2:
                print("Usage: -ws <start_sector> <sectors>")
                exit(0)
            start=int(args.es[0])
            sectors=int(args.es[1])
            data = fh.cmd_erase(args.lun, start, sectors)
            print(f"Erased sector {str(start)} with sector count {str(sectors)}.")
            exit(0)
        elif args.x != '':
            data=fh.cmd_xml(args.x)
            exit(0)
        else:
            print("Unknown/Missing command, a command is required.")
            exit(0)
    else:
        print("Sorry, couldn't talk to Sahara, please reboot the device !")
        exit(0)


    exit(0)


if __name__ == '__main__':
    main()
