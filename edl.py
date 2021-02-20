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
    edl.py rs <start_sector> <sectors> <filename> [--lun=lun] [--sectorsize==bytes] [--memory=memtype] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py w <partitionname> <filename> [--partitionfilename=filename] [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skipwrite] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py wl <directory> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skip=partnames] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py wf <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py ws <start_sector> <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skipwrite] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py e <partitionname> [--memory=memtype] [--skipwrite] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py es <start_sector> <sectors> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--skipwrite] [--loader=filename] [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py ep <partitionname> <sectors> [--memory=memtype] [--skipwrite] [--lun=lun] [--sectorsize==bytes] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
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
    edl.py getstorageinfo [--loader=filename] [--memory=memtype] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py setbootablestoragedrive <lun> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py send <command> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]
    edl.py xml <xmlfile> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py rawxml <xmlstring> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py reset [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py nop [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid]
    edl.py modules <command> <options> [--memory=memtype] [--lun=lun] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value]
    edl.py qfil <rawprogram> <patch> <imagedir> [--loader=filename] [--memory=memtype] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid]

Description:
    server [--tcpport=portnumber]                                                # Run tcp/ip server
    printgpt [--memory=memtype] [--lun=lun]                                      # Print GPT Table information
    gpt <directory> [--memory=memtype] [--lun=lun]                               # Save gpt table to given directory
    r <partitionname> <filename> [--memory=memtype] [--lun=lun]                  # Read flash to filename
    rl <directory> [--memory=memtype] [--lun=lun] [--skip=partname]              # Read all partitions from flash to a directory
    rf <filename> [--memory=memtype] [--lun=lun]                                 # Read whole flash to file
    rs <start_sector> <sectors> <filename> [--lun=lun]                           # Read sectors starting at start_sector to filename
    w <partitionname> <filename> [--partitionfilename=filename] [--memory=memtype] [--lun=lun] [--skipwrite]    # Write filename to partition to flash
    wl <directory> [--memory=memtype] [--lun=lun]                                # Write all files from directory to flash
    wf <filename> [--memory=memtype] [--lun=lun]                                 # Write whole filename to flash
    ws <start_sector> <filename> [--memory=memtype] [--lun=lun] [--skipwrite]    # Write filename to flash at start_sector
    e <partitionname> [--memory=memtype] [--skipwrite] [--lun=lun]               # Erase partition from flash
    es <start_sector> <sectors> [--memory=memtype] [--lun=lun] [--skipwrite]     # Erase sectors at start_sector from flash
    ep <partitionname> <sectors> [--memory=memtype] [--skipwrite] [--lun=lun]    # Erase sector count from flash partition
    footer <filename> [--memory=memtype] [--lun=lun]                             # Read crypto footer from flash
    peek <offset> <length> <filename>                                            # Dump memory at offset with given length to filename
    peekhex <offset> <length>                                                    # Dump memory at offset and given length
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
    qfil <rawprogram> <patch> <imagedir>                                         # Write rawprogram xml files
                                                                                 # <rawprogram> : program config xml, such as rawprogram_unsparse.xml or rawprogram*.xml
                                                                                 # <patch> : patch config xml, such as patch0.xml or patch*.xml
                                                                                 # <imagedir> : directory name of image files

Options:
    --loader=filename                  Use specific EDL loader, disable autodetection [default: None]
    --vid=vid                          Set usb vendor id used for EDL [default: -1]
    --pid=pid                          Set usb product id used for EDL [default: -1]
    --lun=lun                          Set lun to read/write from (UFS memory only)
    --maxpayload=bytes                 Set the maximum payload for EDL [default: 0x100000]
    --sectorsize=bytes                 Set default sector size
    --memory=memtype                   Set memory type ("NAND", "eMMC", "UFS", "spinor")
    --partitionfilename=filename       Set partition table as filename for streaming mode
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

import os
import sys
import time
import logging
import subprocess
import re
from docopt import docopt
from Library.utils import LogBase
from Library.usblib import usb_class
from Library.sahara import sahara
from Library.streaming_client import streaming_client
from Library.firehose_client import firehose_client
from Library.streaming import Streaming

args = docopt(__doc__, version='3')

default_ids = [
    [0x05c6, 0x9008, -1],
    [0x05c6, 0x900e, -1],
    [0x05c6, 0x9025, -1],
    [0x1199, 0x9062, -1],
    [0x1199, 0x9070, -1],
    [0x1199, 0x9090, -1],
    [0x0846, 0x68e0, -1],
    [0x19d2, 0x0076, -1]
]


print("Qualcomm Sahara / Firehose Client V3.2 (c) B.Kerler 2018-2021.")


class main(metaclass=LogBase):
    def __init__(self):
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning

    def doconnect(self, loop, mode, resp):
        while not self.cdc.connected:
            self.cdc.connected = self.cdc.connect()
            if not self.cdc.connected:
                sys.stdout.write('.')
                if loop == 5:
                    sys.stdout.write('\n')
                    self.info("Hint:   Press and hold vol up+dwn, connect usb. For some, only use vol up.")
                    self.info("Xiaomi: Press and hold Vol up + pwr, in fastboot mode connect usb.\n" +
                              "        Run \"./fastboot oem edl\".")
                    self.info("Other:  Run \"adb reboot edl\".")
                    sys.stdout.write('\n')

                if loop >= 20:
                    sys.stdout.write('\n')
                    loop = 6
                loop += 1
                time.sleep(1)
                sys.stdout.flush()
            else:
                self.info("Device detected :)")
                try:
                    mode, resp = self.sahara.connect()
                except Exception as e:
                    if mode == "" or resp == -1:
                        mode, resp = self.sahara.connect()
                if mode == -1:
                    mode, resp = self.sahara.connect()
                if mode == "":
                    self.info("Unknown mode. Aborting.")
                    self.exit()
                self.info(f"Mode detected: {mode}")
                break

        return mode, resp

    def exit(self):
        self.cdc.close()
        sys.exit()

    def parse_option(self, args):
        options = {}
        for arg in args:
            if "--" in arg or "<" in arg:
                options[arg] = args[arg]
        return options

    def parse_cmd(self, args):
        cmds = ["server", "printgpt", "gpt", "r", "rl", "rf", "rs", "w", "wl", "wf", "ws", "e", "es", "ep", "footer",
                "peek", "peekhex",
                "peekdword", "peekqword", "memtbl", "poke", "pokehex", "pokedword", "pokeqword", "memcpy", "secureboot",
                "pbl",
                "qfp", "getstorageinfo", "setbootablestoragedrive", "send", "xml", "rawxml", "reset", "nop", "modules",
                "memorydump", "qfil"]
        for cmd in cmds:
            if args[cmd]:
                return cmd
        return ""

    def console_cmd(self, cmd):
        read = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, \
                                stderr=subprocess.STDOUT, close_fds=True)
        output = read.stdout.read().decode()
        return output

    def run(self):
        if sys.platform == 'win32' or sys.platform == 'win64' or sys.platform == 'winnt':
            proper_driver = self.console_cmd(r'reg query HKLM\HARDWARE\DEVICEMAP\SERIALCOMM')
            if re.findall(r'QCUSB', str(proper_driver)):
                self.warning(f'Please first install libusb_win32 driver from Zadig')

        mode = ""
        loop = 0
        vid = int(args["--vid"], 16)
        pid = int(args["--pid"], 16)
        interface = -1
        if vid != -1 and pid != -1:
            portconfig = [[vid, pid, interface]]
        else:
            portconfig = default_ids
        if args["--debugmode"]:
            logfilename = "log.txt"
            if os.path.exists(logfilename):
                os.remove(logfilename)
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

        self.cdc = usb_class(portconfig=portconfig, loglevel=self.__logger.level)
        self.sahara = sahara(self.cdc, loglevel=self.__logger.level)

        if args["--loader"] == 'None':
            self.info("Trying with no loader given ...")
            self.sahara.programmer = ""
        else:
            loader = args["--loader"]
            self.info(f"Using loader {loader} ...")
            self.sahara.programmer = loader

        self.info("Waiting for the device")
        resp = None
        self.cdc.timeout = 100
        mode, resp = self.doconnect(loop, mode, resp)
        if resp == -1:
            mode, resp = self.doconnect(loop, mode, resp)
            if resp == -1:
                self.error("USB desync, please rerun command !")
                self.exit()
        # print((mode, resp))
        if mode == "sahara":
            if resp is None:
                if mode == "sahara":
                    print("Sahara in error state, resetting ...")
                    self.sahara.cmd_reset()
                    data = self.cdc.read(5)
                    self.exit()
            elif "mode" in resp:
                mode = resp["mode"]
                if mode == self.sahara.sahara_mode.SAHARA_MODE_MEMORY_DEBUG:
                    if args["memorydump"]:
                        time.sleep(0.5)
                        print("Device is in memory dump mode, dumping memory")
                        self.sahara.debug_mode()
                        self.exit()
                    else:
                        print("Device is in streaming mode, uploading loader")
                        self.cdc.timeout = None
                        sahara_info = self.sahara.streaminginfo()
                        if sahara_info:
                            mode, resp = self.sahara.connect()
                            if mode == "sahara":
                                mode = self.sahara.upload_loader()
                                if "enprg" in self.sahara.programmer.lower():
                                    mode = "load_enandprg"
                                elif "nprg" in self.sahara.programmer.lower():
                                    mode = "load_nandprg"
                                elif mode != "":
                                    mode = "load_" + mode
                                if "load_" in mode:
                                    time.sleep(0.3)
                                else:
                                    print("Error, couldn't find suitable enprg/nprg loader :(")
                                    self.exit()
                else:
                    print("Device is in EDL mode .. continuing.")
                    self.cdc.timeout = None
                    sahara_info = self.sahara.check_info()
                    if sahara_info:
                        mode, resp = self.sahara.connect()
                        if mode == "sahara":
                            mode = self.sahara.upload_loader()
                            if mode == "firehose":
                                if "enprg" in self.sahara.programmer.lower():
                                    mode = "enandprg"
                                elif "nprg" in self.sahara.programmer.lower():
                                    mode = "nandprg"
                            if mode != "":
                                if mode != "firehose":
                                    streaming = Streaming(self.cdc, self.sahara, self.__logger.level)
                                    if streaming.connect(1):
                                        print("Successfully uploaded programmer :)")
                                        mode = "nandprg"
                                    else:
                                        print("Device is in an unknown state")
                                        self.exit()
                                else:
                                    print("Successfully uploaded programmer :)")
                            else:
                                print("No suitable loader found :(")
                                self.exit()
                    else:
                        print("Device is in an unknown sahara state, resetting")
                        print("resp={0}".format(resp))
                        self.sahara.cmd_reset()
                        self.exit()
            else:
                print("Device is in an unknown state")
                self.exit()
        else:
            self.sahara.bit64 = True

        if mode == "firehose":
            self.cdc.timeout = None
            fh = firehose_client(args, self.cdc, self.sahara, self.__logger.level, print)
            cmd = self.parse_cmd(args)
            options = self.parse_option(args)
            if cmd != "":
                fh.handle_firehose(cmd, options)
        elif mode == "nandprg" or mode == "enandprg" or mode == "load_nandprg" or mode == "load_enandprg":
            sc = streaming_client(args, self.cdc, self.sahara, self.__logger.level, print)
            cmd = self.parse_cmd(args)
            options = self.parse_option(args)
            if "load_" in mode:
                options["<mode>"] = 1
            else:
                options["<mode>"] = 0
            sc.handle_streaming(cmd, options)
        else:
            self.error("Sorry, couldn't talk to Sahara, please reboot the device !")

        self.exit()


if __name__ == '__main__':
    base = main()
    base.run()
