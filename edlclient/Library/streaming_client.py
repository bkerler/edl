#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import sys
import os
import logging
from binascii import hexlify, unhexlify
from struct import unpack, pack
from edlclient.Library.streaming import Streaming
from edlclient.Library.utils import do_tcp_server, LogBase, getint


class streaming_client(metaclass=LogBase):
    def __init__(self, arguments, cdc, sahara, loglevel, printer):
        self.cdc = cdc
        self.__logger = self.__logger
        self.sahara = sahara
        self.arguments = arguments
        self.streaming = Streaming(cdc, sahara, loglevel)
        self.printer = printer
        self.__logger.setLevel(loglevel)
        self.error = self.__logger.error
        self.info = self.__logger.info
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def disconnect(self):
        self.cdc.close()
        sys.exit(0)

    def check_param(self, parameters):
        error = False
        params = ""
        for parameter in parameters:
            params += parameter + " "
            if parameter not in parameters:
                error = True
        if error:
            if len(parameters) == 1:
                self.printer("Argument " + params + "required.")
            else:
                self.printer("Arguments " + params + "required.")
            return False
        return True

    def print_partitions(self, partitions):
        self.printer("Name            Offset\t\tLength\t\tAttr\t\t\tFlash")
        self.printer("-------------------------------------------------------------")
        for name in partitions:
            partition = partitions[name]
            if not isinstance(partition, dict):
                continue
            for i in range(0x10 - len(name)):
                name += " "
            offset = partition["offset"] * self.streaming.settings.num_pages_per_blk * self.streaming.settings.PAGESIZE
            length = partition["length"] * self.streaming.settings.num_pages_per_blk * self.streaming.settings.PAGESIZE
            attr1 = partition["attr1"]
            attr2 = partition["attr2"]
            attr3 = partition["attr3"]
            which_flash = partition["which_flash"]
            self.printer(
                f"{name}\t%08X\t%08X\t{hex(attr1)}/{hex(attr2)}/{hex(attr3)}\t{which_flash}" % (offset, length))

    def handle_streaming(self, cmd, options):
        mode = 0
        """
        offset = getint(options["<offset>"])
        length = getint(options["<length>"])
        filename = options["<filename>"]
        self.streaming.streaming_mode=self.streaming.Qualcomm
        self.streaming.memread=self.streaming.qc_memread
        self.streaming.memtofile(offset, length, filename)
        """

        if "<mode>" in options:
            mode = options["<mode>"]
        if self.streaming.connect(mode):
            xflag = 0
            self.streaming.hdlc.receive_reply(5)
            if self.streaming.streaming_mode == self.streaming.Patched:
                self.streaming.nand_init(xflag)
            if cmd == "gpt":
                directory = options["<directory>"]
                if directory is None:
                    directory = ""
                data = self.streaming.read_partition_table()
                sfilename = os.path.join(directory, f"partition.bin")
                if data != b"":
                    with open(sfilename, "wb") as write_handle:
                        write_handle.write(data)
                    self.printer(f"Dumped Partition Table to {sfilename}")
                else:
                    self.error(f"Error on dumping partition table to {sfilename}")
            elif cmd == "printgpt":
                partitions = self.streaming.get_partitions()
                self.print_partitions(partitions)
                self.streaming.nand_post()
            elif cmd == "r":
                partitionname = options["<partitionname>"]
                filename = options["<filename>"]
                filenames = filename.split(",")
                partitions = partitionname.split(",")
                if len(partitions) != len(filenames):
                    self.error("You need to gives as many filenames as given partitions.")
                    return
                i = 0
                rpartitions = self.streaming.get_partitions()
                for partition in partitions:
                    if partition in rpartitions:
                        spartition = rpartitions[partition]
                        offset = spartition["offset"]
                        length = spartition["length"]
                        # attr1 = spartition["attr1"]
                        # attr2 = spartition["attr2"]
                        # attr3 = spartition["attr3"]
                        partfilename = filenames[i]
                        self.printer(f"Dumping Partition {partition}...")
                        self.streaming.read_raw(offset, length, self.streaming.settings.UD_SIZE_BYTES, partfilename)
                        self.printer(f"Dumped sector {str(offset)} with sector count {str(length)} as {partfilename}.")
                    else:
                        self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                        self.print_partitions(rpartitions)
            elif cmd == "rs":
                sector = getint(options["<start_sector>"])  # Page
                sectors = getint(options["<sectors>"])
                filename = options["<filename>"]
                self.printer(f"Dumping at Sector {hex(sector)} with Sectorcount {hex(sectors)}...")
                if self.streaming.read_sectors(sector, sectors, filename, True):
                    self.printer(f"Dumped sector {str(sector)} with sector count {str(sectors)} as {filename}.")
            elif cmd == "rf":
                sector = 0
                sectors = self.streaming.settings.MAXBLOCK * self.streaming.settings.num_pages_per_blk * \
                          self.streaming.settings.sectors_per_page
                filename = options["<filename>"]
                self.printer(f"Dumping Flash from sector 0 to sector {hex(sectors)}...")
                if self.streaming.read_sectors(sector, sectors, filename, True):
                    self.printer(f"Dumped sector {str(sector)} with sector count {str(sectors)} as {filename}.")
            elif cmd == "rl":
                directory = options["<directory>"]
                if options["--skip"]:
                    skip = options["--skip"].split(",")
                else:
                    skip = []
                if not os.path.exists(directory):
                    os.mkdir(directory)
                storedir = directory
                if not os.path.exists(storedir):
                    os.mkdir(storedir)
                sfilename = os.path.join(storedir, f"partition.bin")
                partdata = self.streaming.read_partition_table()
                if partdata != -1:
                    with open(sfilename, "wb") as write_handle:
                        write_handle.write(partdata)
                else:
                    self.error(f"Couldn't detect partition header.")
                    return
                partitions = self.streaming.get_partitions()
                for partition in partitions:
                    if partition in skip:
                        continue
                    filename = os.path.join(storedir, partition + ".bin")
                    spartition = partitions[partition]
                    offset = spartition["offset"]
                    length = spartition["length"]
                    # attr1 = spartition["attr1"]
                    # attr2 = spartition["attr2"]
                    # attr3 = spartition["attr3"]
                    partfilename = filename
                    self.info(f"Dumping partition {str(partition)} with block count {str(length)} as " +
                              f"{filename}.")
                    self.streaming.read_raw(offset, length, self.streaming.settings.UD_SIZE_BYTES, partfilename)
            elif cmd == "peek":
                offset = getint(options["<offset>"])
                length = getint(options["<length>"])
                filename = options["<filename>"]
                if self.streaming.memtofile(offset, length, filename):
                    self.info(
                        f"Peek data from offset {hex(offset)} and length {hex(length)} was written to {filename}")
            elif cmd == "peekhex":
                offset = getint(options["<offset>"])
                length = getint(options["<length>"])
                resp = self.streaming.memread(offset, length)
                self.printer("\n")
                self.printer(hexlify(resp))
            elif cmd == "peekqword":
                offset = getint(options["<offset>"])
                resp = self.streaming.memread(offset, 8)
                self.printer("\n")
                self.printer(hex(unpack("<Q", resp[:8])[0]))
            elif cmd == "peekdword":
                offset = getint(options["<offset>"])
                resp = self.streaming.mempeek(offset)
                self.printer("\n")
                self.printer(hex(resp))
            elif cmd == "poke":
                offset = getint(options["<offset>"])
                filename = unhexlify(options["<filename>"])
                try:
                    with open(filename, "rb") as rf:
                        data = rf.read()
                        if self.streaming.memwrite(offset, data):
                            self.info("Poke succeeded.")
                        else:
                            self.error("Poke failed.")
                except Exception as e:
                    self.error(str(e))
            elif cmd == "pokehex":
                offset = getint(options["<offset>"])
                data = unhexlify(options["<data>"])
                if self.streaming.memwrite(offset, data):
                    self.info("Poke succeeded.")
                else:
                    self.error("Poke failed.")
            elif cmd == "pokeqword":
                offset = getint(options["<offset>"])
                data = pack("<Q", getint(options["<data>"]))
                if self.streaming.memwrite(offset, data):
                    self.info("Poke succeeded.")
                else:
                    self.error("Poke failed.")
            elif cmd == "pokedword":
                offset = getint(options["<offset>"])
                data = pack("<I", getint(options["<data>"]))
                if self.streaming.mempoke(offset, data):
                    self.info("Poke succeeded.")
                else:
                    self.error("Poke failed.")
            elif cmd == "reset":
                if self.streaming.reset():
                    self.info("Reset succeeded.")
            elif cmd == "memtbl":
                filename = options["<filename>"]
                memtbl = self.streaming.settings.memtbl
                data = self.streaming.memread(memtbl[0], memtbl[1])
                if data != b"":
                    with open(filename, "wb") as wf:
                        wf.write(data)
                        self.printer(f"Dumped memtbl at offset {hex(memtbl[0])} as {filename}.")
                else:
                    self.error("Error on dumping memtbl")
            elif cmd == "secureboot":
                value = self.streaming.mempeek(self.streaming.settings.secureboot)
                if value != -1:
                    is_secure = False
                    for area in range(0, 4):
                        sec_boot = (value >> (area * 8)) & 0xFF
                        pk_hashindex = sec_boot & 3
                        oem_pkhash = True if ((sec_boot >> 4) & 1) == 1 else False
                        auth_enabled = True if ((sec_boot >> 5) & 1) == 1 else False
                        use_serial = True if ((sec_boot >> 6) & 1) == 1 else False
                        if auth_enabled:
                            is_secure = True
                        self.printer(f"Sec_Boot{str(area)} PKHash-Index:{str(pk_hashindex)} " +
                                     f"OEM_PKHash: {str(oem_pkhash)} " +
                                     f"Auth_Enabled: {str(auth_enabled)} " +
                                     f"Use_Serial: {str(use_serial)}")
                    if is_secure:
                        self.printer("Secure boot enabled.")
                    else:
                        self.printer("Secure boot disabled.")
                else:
                    self.error("Unknown target chipset")
            elif cmd == "pbl":
                filename = options["<filename>"]
                pbl = self.streaming.settings.pbl
                self.printer("Dumping pbl....")
                data = self.streaming.memread(pbl[0], pbl[1])
                if data != b"":
                    with open(filename, "wb") as wf:
                        wf.write(data)
                        self.printer(f"Dumped pbl at offset {hex(pbl[0])} as {filename}.")
                else:
                    self.error("Error on dumping pbl")
            elif cmd == "qfp":
                filename = options["<filename>"]
                qfp = self.streaming.settings.qfprom
                self.printer("Dumping qfprom....")
                data = self.streaming.memread(qfp[0], qfp[1])
                if data != b"":
                    with open(filename, "wb") as wf:
                        wf.write(data)
                        self.printer(f"Dumped qfprom at offset {hex(qfp[0])} as {filename}.")
                else:
                    self.error("Error on dumping qfprom")
            elif cmd == "memcpy":
                if not self.check_param(["<offset>", "<size>"]):
                    return False
                srcoffset = getint(options["<offset>"])
                size = getint(options["<size>"])
                dstoffset = srcoffset + size
                if self.streaming.cmd_memcpy(dstoffset, srcoffset, size):
                    self.printer(f"Memcpy from {hex(srcoffset)} to {hex(dstoffset)} succeeded")
                    return True
                else:
                    return False
            ###############################
            elif cmd == "nop":
                # resp=self.streaming.send(b"\x7E\x09")
                self.error("Nop command isn't supported by streaming loader")
                return True
            elif cmd == "setbootablestoragedrive":
                self.error("setbootablestoragedrive command isn't supported by streaming loader")
                return True
            elif cmd == "getstorageinfo":
                self.error("getstorageinfo command isn't supported by streaming loader")
                return True
            elif cmd == "w":
                if not self.check_param(["<partitionname>", "<filename>"]):
                    return False
                partitionname = options["<partitionname>"]
                filename = options["<filename>"]
                partitionfilename = ""
                if "--partitionfilename" in options:
                    partitionfilename = options["--partitionfilename"]
                    if partitionfilename is not None:
                        if not os.path.exists(partitionfilename):
                            self.error(f"Error: Couldn't find partition file: {partitionfilename}")
                            return False
                        else:
                            ptable = open(partitionfilename, "rb").read()
                else:
                    self.error("Partition file is needed for writing (--partitionfilename)")
                    sys.exit(1)
                if not os.path.exists(filename):
                    self.error(f"Error: Couldn't find file: {filename}")
                    return False
                """
                if partitionfilename is None:
                    ptable = None
                    rpartitions = self.streaming.get_partitions()
                    if partitionname in rpartitions:
                        spartition = rpartitions[partitionname]
                        offset = spartition["offset"]
                        length = spartition["length"]
                        attr1 = spartition["attr1"]
                        attr2 = spartition["attr2"]
                        attr3 = spartition["attr3"]
                        which_flash = spartition["which_flash"]
                        numparts = 1
                        pname = bytes("0:"+partitionname,'utf-8')
                        pname += (16-len(pname))*b"\x00"
                        ptable = pack("<IIII",0xAA7D1B9A,0x1F7D48BC,rpartitions["version"],numparts)
                        ptable += pname
                        ptable += pack("<IIBBBB",offset,length,attr1,attr2,attr3,which_flash)
                        while len(ptable)%4!=0:
                            ptable += b"\xFF"
                    else:
                        self.error(f"Partition {partitionname} not found. Aborting.")
                        return False
                else:
                """
                rpartitions = self.streaming.get_partitions(partitionfilename)
                if self.streaming.enter_flash_mode(ptable=ptable):
                    if partitionname in rpartitions:
                        spartition = rpartitions[partitionname]
                        offset = spartition["offset"]
                        length = spartition["length"]
                        # attr1 = spartition["attr1"]
                        # attr2 = spartition["attr2"]
                        # attr3 = spartition["attr3"]
                        sectors = int(os.stat(
                            filename).st_size / self.streaming.settings.num_pages_per_blk /
                                      self.streaming.settings.PAGESIZE)
                        if sectors > length:
                            self.error(
                                f"Error: {filename} has {sectors} sectors but partition only has {length}.")
                            return False
                        if self.streaming.modules is not None:
                            self.streaming.modules.writeprepare()
                        if self.streaming.write_flash(lba=0, partname=partitionname, filename=filename):
                            self.printer(f"Wrote {filename} to sector {str(offset)}.")
                            return True
                        else:
                            self.printer(f"Error writing {filename} to sector {str(offset)}.")
                            return False
                    else:
                        self.error(f"Error: Couldn't detect partition: {partitionname}\nAvailable partitions:")
                        self.print_partitions(rpartitions)
                return False
            elif cmd == "wl":
                if not self.check_param(["<directory>"]):
                    return False
                directory = options["<directory>"]
                if options["--skip"]:
                    skip = options["--skip"].split(",")
                else:
                    skip = []
                if not os.path.exists(directory):
                    self.error(f"Error: Couldn't find directory: {directory}")
                    return False
                filenames = []
                if self.streaming.enter_flash_mode():
                    if self.streaming.modules is not None:
                        self.streaming.modules.writeprepare()
                    rpartitions = self.streaming.get_partitions()
                    for dirName, subdirList, fileList in os.walk(directory):
                        for fname in fileList:
                            filenames.append(os.path.join(dirName, fname))
                            for filename in filenames:
                                for partition in rpartitions:
                                    partname = filename[filename.rfind("/") + 1:]
                                    if ".bin" in partname[-4:]:
                                        partname = partname[:-4]
                                    if partition == partname:
                                        if partition in skip:
                                            continue
                                        spartition = rpartitions[partition]
                                        offset = spartition["offset"]
                                        length = spartition["length"]
                                        # attr1 = spartition["attr1"]
                                        # attr2 = spartition["attr2"]
                                        # attr3 = spartition["attr3"]
                                        sectors = int(os.stat(filename).st_size /
                                                      self.streaming.settings.num_pages_per_blk /
                                                      self.streaming.settings.PAGESIZE)
                                        if sectors > length:
                                            self.error(
                                                f"Error: {filename} has {sectors} sectors but partition only has {length}.")
                                            return False
                                        self.printer(f"Writing {filename} to partition {str(partition)}.")
                                        self.streaming.write_flash(partition, filename)
                        else:
                            self.printer("Couldn't write partition. Either wrong memorytype given or no gpt partition.")
                            return False
                return True
            elif cmd == "ws":
                self.error("ws command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "wf":
                self.error("wf command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "e":
                self.error("e command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "es":
                self.error("es command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "xml":
                self.error("xml command isn't supported by streaming loader")
                return False
            elif cmd == "rawxml":
                self.error("rawxml command isn't supported by streaming loader")
                return False
            elif cmd == "send":
                self.error("send command isn't supported by streaming loader")
                return False
            ###############################
            elif cmd == "server":
                return do_tcp_server(self, options, self.handle_streaming)
            elif cmd == "modules":
                if not self.check_param(["<command>", "<options>"]):
                    return False
                command = options["<command>"]
                options = options["<options>"]
                if self.streaming.modules is None:
                    self.error("Feature is not supported")
                    return False
                else:
                    return self.streaming.modules.run(mainargs=options, command=command)
            else:
                self.error("Unknown/Missing command, a command is required.")
                return False
