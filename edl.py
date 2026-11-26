#!/usr/bin/env python3
# (c) B.Kerler 2018-2025 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

"""
Usage:
    edl.py -h | --help
    edl.py [--vid=vid] [--pid=pid] [--portname=portname] [--serial]
    edl.py [--loader=filename] [--memory=memtype] [--portname=portname] [--serial]
    edl.py [--debugmode] [--portname=portname] [--serial]
    edl.py [--gpt-num-part-entries=number] [--gpt-part-entry-size=number] [--gpt-part-entry-start-lba=number] [--portname=portname] [--serial]
    edl.py [--memory=memtype] [--skipstorageinit] [--maxpayload=bytes] [--sectorsize==bytes] [--pagesperblock=number] [--portname=portname] [--serial]
    edl.py server [--tcpport=portnumber] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py memorydump [--partitions=partnames] [--debugmode] [--vid=vid] [--pid=pid] [--portname=portname] [--serial] [--serial_number=serial_number]
    edl.py printgpt [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--loader=filename] [--debugmode]  [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py gpt <directory> [--memory=memtype] [--lun=lun] [--genxml] [--loader=filename]  [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--pagesperblock=number] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py r <partitionname> <filename> [--memory=memtype] [--sectorsize==bytes] [--pagesperblock=number] [--lun=lun] [--loader=filename]  [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py rl <directory> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--skip=partnames] [--genxml]  [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py rf <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--loader=filename] [--debugmode]  [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py rs <start_sector> <sectors> <filename> [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--memory=memtype] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py w <partitionname> <filename> [--partitionfilename=filename] [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--skipwrite] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py wl <directory> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--skip=partnames] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py wf <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--loader=filename] [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py ws <start_sector> <filename> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--skipwrite] [--skipresponse] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py e <partitionname> [--memory=memtype] [--skipwrite] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py es <start_sector> <sectors> [--memory=memtype] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--skipwrite] [--loader=filename] [--skipresponse] [--debugmode] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py ep <partitionname> <sectors> [--memory=memtype] [--skipwrite] [--lun=lun] [--sectorsize==bytes] [--pagesperblock=number] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py footer <filename> [--memory=memtype] [--lun=lun] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py peek <offset> <length> <filename> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]
    edl.py peekhex <offset> <length> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]
    edl.py peekdword <offset> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py peekqword <offset> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py memtbl <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py poke <offset> <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py pokehex <offset> <data> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py pokedword <offset> <data> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py pokeqword <offset> <data> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py memcpy <offset> <size> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]
    edl.py secureboot [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py pbl <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py qfp <filename> [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]
    edl.py getstorageinfo [--loader=filename] [--memory=memtype] [--pagesperblock=number] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py setbootablestoragedrive <lun> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py getactiveslot [--memory=memtype] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py setactiveslot <slot> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py send <command> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py xml <xmlfile> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py rawxml <xmlstring> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py reset [--resetmode=mode] [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py nop [--loader=filename] [--debugmode] [--vid=vid] [--pid=pid] [--skipstorageinit] [--portname=portname] [--serial] [--devicemodel=value]
    edl.py modules <command> <options> [--memory=memtype] [--lun=lun] [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--devicemodel=value] [--portname=portname] [--serial]
    edl.py provision <xmlfile> [--loader=filename] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]  [--devicemodel=value]
    edl.py qfil <rawprogram> <patch> <imagedir> [--loader=filename] [--memory=memtype] [--pagesperblock=number] [--debugmode] [--skipresponse] [--vid=vid] [--pid=pid] [--portname=portname] [--serial]  [--devicemodel=value]

Description:
    server                      # Run tcp/ip server
    printgpt                    # Print GPT Table information
    gpt                         # Save gpt table to given directory
    r                           # Read flash to filename
    rl                          # Read all partitions from flash to a directory
    rf                          # Read whole flash to file
    rs                          # Read sectors starting at start_sector to filename
    w                           # Write filename to partition to flash
    wl                          # Write all files from directory to flash
    wf                          # Write whole filename to flash
    ws                          # Write filename to flash at start_sector
    e                           # Erase partition from flash
    es                          # Erase sectors at start_sector from flash
    ep                          # Erase sector count from flash partition
    footer                      # Read crypto footer from flash
    peek                        # Dump memory at offset with given length to filename
    peekhex                     # Dump memory at offset and given length
    peekdword                   # Dump DWORD at memory offset
    peekqword                   # Dump QWORD at memory offset
    memtbl                      # Dump memory table to file
    poke                        # Write filename to memory at offset to memory
    pokehex                     # Write hex string data at offset to memory
    pokedword                   # Write DWORD to memory at offset
    pokeqword                   # Write QWORD to memory at offset
    memcpy                      # Copy memory from srcoffset with given size to dstoffset
    secureboot                  # Print secureboot fields from qfprom fuses
    pbl                         # Dump primary bootloader to filename
    qfp                         # Dump QFPROM fuses to filename
    getstorageinfo              # Print storage info in firehose mode
    setbootablestoragedrive     # Change bootable storage drive to lun number
    send                        # Send firehose command
    xml                         # Send firehose xml file
    rawxml                      # Send firehose xml raw string
    reset                       # Send firehose reset command, reset modes: reset, off, edl
    nop                         # Send firehose nop command
    modules                     # Enable submodules, for example: "oemunlock enable"
    setactiveslot               # Set partition as active (Slot A/B)
    provision                   # UFS provision
    qfil                        # Write rawprogram xml files
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
    --pagesperblock=number             Set NAND pages per block (firehose configure attribute)
    --memory=memtype                   Set memory type ("NAND", "eMMC", "UFS", "spinor")
    --partitionfilename=filename       Set partition table as filename for streaming mode
    --vip-table-path=path              Directory with the signed VIP digest tables
                                       (DigestsToSign.bin.mbn, ChainedTableOfDigests<n>.bin)
    --create-digests=path              Write VIP digest tables for this session into path
    --partitions=partnames             Skip reading partition with names != "partname1,partname2,etc."
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
    --devicemodel=value                Set device model
    --portname=portname                Set serial port name (/dev/ttyUSB0 for Linux/MAC; \\\\.\\COM1 for Windows)
    --serial                           Use serial port (port autodetection)
    --slot                             Set active slot for setactiveslot [a or b]
    --resetmode=mode                   Resetmode for reset (poweroff, reset, edl, etc.)
"""

import logging
import os
import re
import subprocess
import sys
import time

from docopt import docopt

from edlclient.Config.usb_ids import default_ids
from edlclient.Library.Connection.devicehandler import DeviceClass
from edlclient.Library.Connection.seriallib import serial_class
from edlclient.Library.Connection.usblib import usb_class
from edlclient.Library.firehose_client import firehose_client
from edlclient.Library.sahara import sahara
from edlclient.Library.sahara_defs import cmd_t, sahara_mode_t
from edlclient.Library.streaming import Streaming
from edlclient.Library.streaming_client import streaming_client
from edlclient.Library.utils import LogBase, is_windows


def _extract_vip_options(argv):
    """Pull the global VIP options out of argv before docopt sees them.

    They apply to every flashing command, so listing them in all ~30 usage
    patterns would only add noise.
    """
    opts = {"--vip-table-path": None, "--create-digests": None}
    rest = list(argv[:1])
    i = 1
    while i < len(argv):
        arg = argv[i]
        for key in list(opts):
            if arg == key and i + 1 < len(argv):
                opts[key] = argv[i + 1]
                i += 2
                break
            if arg.startswith(key + "="):
                opts[key] = arg.split("=", 1)[1]
                i += 1
                break
        else:
            rest.append(arg)
            i += 1
    return opts, rest


_vip_options, _argv = _extract_vip_options(sys.argv)
args = docopt(__doc__, argv=_argv[1:], version='3')
args.update(_vip_options)

print("Qualcomm Sahara / Firehose Client V3.62 (c) B.Kerler 2018-2025.")


class main(metaclass=LogBase):
    __logger: logging.Logger
    def __init__(self, args, imported: str = ''):
        self.serial = None
        self.portname = None
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.__logger.setLevel(self.__logger.level)
        self.__logger.setLevel(self.__logger.level)
        self.cdc: DeviceClass | None = None
        self.sahara: sahara | None = None
        self.vid = None
        self.pid = None
        self.serial_number = None
        self.args = args
        self.fh = None
        self.log_handler = None

        if imported == '':
            self.imported = True
        else:
            self.imported = False

    def parse_cmd(self, rargs):
        if self.imported:
            return ""

        cmds = ["server", "printgpt", "gpt", "r", "rl", "rf", "rs", "w", "wl", "wf", "ws", "e", "es", "ep", "footer",
                "peek", "peekhex", "peekdword", "peekqword", "memtbl", "poke", "pokehex", "pokedword", "pokeqword",
                "memcpy", "secureboot", "pbl", "qfp", "getstorageinfo", "setbootablestoragedrive", "getactiveslot",
                "setactiveslot",
                "send", "xml", "rawxml", "reset", "nop", "modules", "memorydump", "provision", "qfil"]
        for cmd in cmds:
            if rargs[cmd]:
                return cmd
        return ""


    def console_cmd(self, cmd):
        """Run a local command without a shell and return its output."""
        read = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, close_fds=True)
        if read.stdout is None:
            return ""
        data = read.stdout.read()
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode("ISO-8859-1")


    def parse_option(self, rargs):
        options = {}
        for arg in rargs:
            if "--" in arg or "<" in arg:
                options[arg] = rargs[arg]
        return options

    def doconnect(self, loop) -> dict:
        if self.cdc is None or self.sahara is None:
            self.error("No connection backend initialized")
            return {"mode": "error"}
        while not self.cdc.connected:
            self.cdc.connected = self.cdc.connect(portname=self.portname or "")
            if not self.cdc.connected:
                sys.stdout.write('.')
                if loop == 5:
                    sys.stdout.write('\n')
                    self.info("Hint:   Press and hold vol up+dwn, connect usb. For some, only use vol up.")
                    self.info("Xiaomi: Press and hold vol dwn + pwr, in fastboot mode connect usb.\n" +
                              "        Run \"./fastpwn oem edl\".")
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
                    resp = self.sahara.connect()
                    self.vid = self.cdc.vid
                    self.pid = self.cdc.pid
                except Exception as err:  # pylint: disable=broad-except
                    self.debug(str(err))
                    continue
                if "mode" in resp:
                    mode = resp["mode"]
                    self.info(f"Mode detected: {mode}")
                    return resp
        return {"mode": "error"}

    def exit(self, status: int = 0, cdc_close: bool = True):
        if cdc_close and self.cdc is not None:
            self.cdc.close()

        if self.imported:
            return status
        else:
            sys.exit(status)

    def run(self):
        if is_windows():
            proper_driver = self.console_cmd(['reg', 'query', r'HKLM\HARDWARE\DEVICEMAP\SERIALCOMM'])
            if re.findall(r'QCUSB', str(proper_driver)):
                self.warning('Please first install libusb_win32 driver from Zadig')

        loop = 0
        vid = int(self.args["--vid"], 16)
        pid = int(self.args["--pid"], 16)
        interface = -1
        if vid != -1 and pid != -1:
            portconfig = [[vid, pid, interface]]
        else:
            portconfig = default_ids
        if self.args["--debugmode"]:
            logfilename = "log.txt"
            try:
                if os.path.exists(logfilename):
                    os.remove(logfilename)
            except OSError as err:
                self.debug(f"Couldn't remove old {logfilename}: {err}")
            # Keep the log handler separate from self.fh, which holds the firehose client
            self.log_handler = logging.FileHandler(logfilename)
            self.__logger.addHandler(self.log_handler)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

        if self.args["--serial"]:
            self.serial = True
        else:
            self.serial = False
        if self.args["--portname"]:
            self.portname = self.args["--portname"]
            self.serial = True
        else:
            self.portname = ""
        if self.serial:
            self.cdc = serial_class(loglevel=self.__logger.level, portconfig=portconfig)
        else:
            if self.args["--serial_number"]:
                self.serial_number = self.args["--serial_number"]
            self.cdc = usb_class(portconfig=portconfig, loglevel=self.__logger.level, serial_number=self.serial_number)

        self.sahara = sahara(self.cdc, loglevel=self.__logger.level)

        if self.args["--loader"] == 'None':
            self.info("Trying with no loader given ...")
            self.sahara.programmer = ""
        else:
            loader = self.args["--loader"]
            self.info(f"Using loader {loader} ...")
            self.sahara.programmer = loader

        self.info("Waiting for the device")
        if self.cdc is None or self.sahara is None:
            self.error("Failed to initialize the connection backend")
            return self.exit(1)
        self.cdc.timeout = 1500
        conninfo = self.doconnect(loop)
        mode = conninfo["mode"]
        conninfo_data = conninfo.get("data")
        if conninfo_data is not None and hasattr(conninfo_data, "version"):
            version = conninfo_data.version
        else:
            version = 2
        if mode == "sahara":
            cmd = conninfo["cmd"]
            if cmd == cmd_t.SAHARA_HELLO_REQ:
                if "data" in conninfo:
                    data = conninfo["data"]
                    if data.mode == sahara_mode_t.SAHARA_MODE_MEMORY_DEBUG:
                        if self.args["memorydump"] or self.cdc.pid == 0x900E:
                            time.sleep(0.5)
                            print("Device is in memory dump mode, dumping memory")
                            if self.args["--partitions"]:
                                self.sahara.debug_mode(self.args["--partitions"].split(","), version=version)
                            else:
                                self.sahara.debug_mode(version=version)
                            return self.exit()
                        else:
                            print("Device is in streaming mode, uploading loader")
                            self.cdc.timeout = None
                            sahara_info = self.sahara.streaminginfo()
                            if sahara_info:
                                sahara_connect = self.sahara.connect()
                                if isinstance(sahara_connect, dict):
                                    mode = sahara_connect["mode"]
                                else:
                                    mode = sahara_connect[0]
                                if mode == "sahara":
                                    mode = self.sahara.upload_loader(version=version)
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
                                        return self.exit()
                    else:
                        sahara_info = self.sahara.cmd_info(version=version)
                        if sahara_info is not None:
                            resp = self.sahara.connect()
                            mode = resp["mode"]
                            if "data" in resp:
                                data = resp["data"]
                            if mode == "sahara":
                                mode = self.sahara.upload_loader(version=version)
                        else:
                            print("Error on sahara handshake, resetting.")
                            self.sahara.cmd_reset()
                            return self.exit(1)
        else:
            if self.__logger.level != logging.DEBUG:
                self.__logger.setLevel(logging.ERROR)
        if mode == "error":
            print("Connection detected, quiting.")
            return self.exit(1)
        elif mode == "firehose":
            if "enprg" in self.sahara.programmer.lower():
                mode = "enandprg"
            elif "nprg" in self.sahara.programmer.lower():
                mode = "nandprg"
            if mode != "firehose":
                streaming = Streaming(self.cdc, self.sahara, self.__logger.level)
                if streaming.connect(1):
                    print("Successfully uploaded programmer :)")
                    mode = "nandprg"
                else:
                    print("No suitable loader found :(")
                    return self.exit()
        if mode != "firehose":
            sc = streaming_client(self.args, self.cdc, self.sahara, self.__logger.level, print)
            cmd = self.parse_cmd(self.args)
            options = self.parse_option(self.args)
            if "load_" in mode:
                options["<mode>"] = 1
            else:
                options["<mode>"] = 0
            sc.handle_streaming(cmd, options)
        else:
            self.cdc.timeout = None
            cmd = self.parse_cmd(self.args)
            if cmd == 'provision':
                self.args["--memory"] = 'ufs'
                self.args["--skipstorageinit"] = 1
            self.fh = firehose_client(self.args, self.cdc, self.sahara, self.__logger.level, print)
            options = self.parse_option(self.args)
            if cmd != "" or self.imported:
                self.info("Trying to connect to firehose loader ...")
                if self.fh.connect(sahara):
                    try:
                        if self.imported:
                            return self.exit(cdc_close=False)
                        elif not self.fh.handle_firehose(cmd, options):
                            return self.exit(1)
                    finally:
                        # Writes the VIP digest tables when --create-digests was used
                        self.fh.finalize()
                else:
                    return self.exit(1)


def run():
    """Script entry point."""
    base = main(args, __name__)
    try:
        base.run()
    except KeyboardInterrupt:
        print("\n[!] Exiting cleanly…")
        sys.exit(0)


if __name__ == '__main__':
    run()
