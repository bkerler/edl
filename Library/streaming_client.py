import sys
import os
import logging
from Library.streaming import Streaming
from binascii import hexlify, unhexlify
from struct import unpack, pack
from Library.utils import do_tcp_server


class streaming_client:
    def __init__(self, arguments, cdc, sahara, loglevel, printer):
        self.cdc = cdc
        self.sahara = sahara
        self.arguments = arguments
        self.streaming = Streaming(cdc, sahara, loglevel)
        self.printer = printer
        self.__logger.setLevel(loglevel)
        if loglevel==logging.DEBUG:
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
            for i in range(0x10 - len(name)):
                name += " "
            offset = partition[
                         "offset"] * self.streaming.settings.num_pages_per_blk * self.streaming.settings.PAGESIZE
            length = partition[
                         "length"] * self.streaming.settings.num_pages_per_blk * self.streaming.settings.PAGESIZE
            attr1 = partition["attr1"]
            attr2 = partition["attr2"]
            attr3 = partition["attr3"]
            which_flash = partition["which_flash"]
            self.printer(
                f"{name}\t%08X\t%08X\t{hex(attr1)}/{hex(attr2)}/{hex(attr3)}\t{which_flash}" % (offset, length))

    def handle_streaming(self, cmd, options):
        mode = 0
        if "<mode>" in options:
            mode = options["<mode>"]
        if self.streaming.connect(mode):
            xflag = 0
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
                    self.__logger.error(f"Error on dumping partition table to {sfilename}")
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
                    self.__logger.error("You need to gives as many filenames as given partitions.")
                    return
                i = 0
                rpartitions = self.streaming.get_partitions()
                for partition in partitions:
                    if partition.lower() in rpartitions:
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
                        self.__logger.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                        self.print_partitions(rpartitions)
            elif cmd == "rs":
                start = int(options["<start_sector>"])
                sectors = int(options["<sectors>"])
                filename = options["<filename>"]
                self.printer(f"Dumping Sector {hex(start)} with Sectorcount {hex(sectors)}...")
                block = 131
                page = 0x20
                data, extra = self.streaming.flash_read(block, page, sectors, self.streaming.settings.UD_SIZE_BYTES)
                try:
                    with open(filename, "wb") as write_handle:
                        write_handle.write(data)
                        self.printer(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
                        return
                except Exception as error:
                    self.__logger.error(f"Couldn't open {filename} for writing: %s" % str(error))
                self.streaming.nand_post()
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
                    self.__logger.error(f"Couldn't detect partition header.")
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
                    self.__logger.info(f"Dumping partition {str(partition)} with block count {str(length)} as " +
                                     f"{filename}.")
                    self.streaming.read_raw(offset, length, self.streaming.settings.UD_SIZE_BYTES, partfilename)
            elif cmd == "peek":
                offset = int(options["<offset>"], 16)
                length = int(options["<length>"], 16)
                filename = options["<filename>"]
                with open(filename, "wb") as wf:
                    while length > 0:
                        size = 0x20000
                        if length < size:
                            size = length
                            data = self.streaming.memread(offset, size)
                            if data != b"":
                                wf.write(data)
                            else:
                                break
                        length -= size
                self.__logger.info(
                    f"Peek data from offset {hex(offset)} and length {hex(length)} was written to {filename}")
            elif cmd == "peekhex":
                offset = int(options["<offset>"], 16)
                length = int(options["<length>"], 16)
                resp = self.streaming.memread(offset, length)
                self.printer("\n")
                self.printer(hexlify(resp))
            elif cmd == "peekqword":
                offset = int(options["<offset>"], 16)
                resp = self.streaming.memread(offset, 8)
                self.printer("\n")
                self.printer(hex(unpack("<Q", resp[:8])[0]))
            elif cmd == "peekdword":
                offset = int(options["<offset>"], 16)
                resp = self.streaming.mempeek(offset)
                self.printer("\n")
                self.printer(hex(resp))
            elif cmd == "poke":
                offset = int(options["<offset>"], 16)
                filename = unhexlify(options["<filename>"])
                try:
                    with open(filename, "rb") as rf:
                        data = rf.read()
                        if self.streaming.memwrite(offset, data):
                            self.__logger.info("Poke succeeded.")
                        else:
                            self.__logger.error("Poke failed.")
                except Exception as e:
                    self.__logger.error(str(e))
            elif cmd == "pokehex":
                offset = int(options["<offset>"], 16)
                data = unhexlify(options["<data>"])
                if self.streaming.memwrite(offset, data):
                    self.__logger.info("Poke succeeded.")
                else:
                    self.__logger.error("Poke failed.")
            elif cmd == "pokeqword":
                offset = int(options["<offset>"], 16)
                data = pack("<Q", int(options["<data>"], 16))
                if self.streaming.memwrite(offset, data):
                    self.__logger.info("Poke succeeded.")
                else:
                    self.__logger.error("Poke failed.")
            elif cmd == "pokedword":
                offset = int(options["<offset>"], 16)
                data = pack("<I", int(options["<data>"], 16))
                if self.streaming.mempoke(offset, data):
                    self.__logger.info("Poke succeeded.")
                else:
                    self.__logger.error("Poke failed.")
            elif cmd == "reset":
                if self.streaming.reset():
                    self.__logger.info("Reset succeeded.")
            elif cmd == "memtbl":
                filename = options["<filename>"]
                memtbl = self.streaming.settings.memtbl
                data = self.streaming.memread(memtbl[0], memtbl[1])
                if data != b"":
                    with open(filename, "wb") as wf:
                        wf.write(data)
                        self.printer(f"Dumped memtbl at offset {hex(memtbl[0])} as {filename}.")
                else:
                    self.__logger.error("Error on dumping memtbl")
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
                    self.__logger.error("Unknown target chipset")
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
                    self.__logger.error("Error on dumping pbl")
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
                    self.__logger.error("Error on dumping qfprom")
            elif cmd == "memcpy":
                if not self.check_param(["<offset>", "<size>"]):
                    return False
                srcoffset = int(options["<offset>"], 16)
                size = int(options["<size>"], 16)
                dstoffset = srcoffset + size
                if self.streaming.cmd_memcpy(dstoffset, srcoffset, size):
                    self.printer(f"Memcpy from {hex(srcoffset)} to {hex(dstoffset)} succeeded")
                    return True
                else:
                    return False
            ###############################
            elif cmd == "nop":
                self.__logger.error("Nop command isn't supported by streaming loader")
                return True
            elif cmd == "setbootablestoragedrive":
                self.__logger.error("setbootablestoragedrive command isn't supported by streaming loader")
                return True
            elif cmd == "getstorageinfo":
                self.__logger.error("getstorageinfo command isn't supported by streaming loader")
                return True
            elif cmd == "w":
                if not self.check_param(["<partitionname>", "<filename>"]):
                    return False
                partitionname = options["<partitionname>"]
                filename = options["<filename>"]
                if not os.path.exists(filename):
                    self.__logger.error(f"Error: Couldn't find file: {filename}")
                    return False
                rpartitions = self.streaming.get_partitions()
                if self.streaming.enter_flash_mode():
                    if partitionname in rpartitions:
                        spartition = rpartitions[partitionname]
                        offset = spartition["offset"]
                        length = spartition["length"]
                        # attr1 = spartition["attr1"]
                        # attr2 = spartition["attr2"]
                        # attr3 = spartition["attr3"]
                        sectors = int(os.stat(
                            filename).st_size / self.streaming.settings.num_pages_per_blk / self.streaming.settings.PAGESIZE)
                        if sectors > length:
                            self.__logger.error(
                                f"Error: {filename} has {sectors} sectors but partition only has {length}.")
                            return False
                        if self.streaming.modules is not None:
                            self.streaming.modules.writeprepare()
                        if self.streaming.write_flash(partitionname, filename):
                            self.printer(f"Wrote {filename} to sector {str(offset)}.")
                            return True
                        else:
                            self.printer(f"Error writing {filename} to sector {str(offset)}.")
                            return False
                    else:
                        self.__logger.error(f"Error: Couldn't detect partition: {partitionname}\nAvailable partitions:")
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
                    self.__logger.error(f"Error: Couldn't find directory: {directory}")
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
                                            self.__logger.error(
                                                f"Error: {filename} has {sectors} sectors but partition only has {length}.")
                                            return False
                                        self.printer(f"Writing {filename} to partition {str(partition)}.")
                                        self.streaming.write_flash(partition, filename)
                        else:
                            self.printer("Couldn't write partition. Either wrong memorytype given or no gpt partition.")
                            return False
                return True
            elif cmd == "ws":
                self.__logger.error("ws command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "wf":
                self.__logger.error("wf command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "e":
                self.__logger.error("e command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "es":
                self.__logger.error("es command isn't supported by streaming loader")  # todo
                return False
            elif cmd == "xml":
                self.__logger.error("xml command isn't supported by streaming loader")
                return False
            elif cmd == "rawxml":
                self.__logger.error("rawxml command isn't supported by streaming loader")
                return False
            elif cmd == "send":
                self.__logger.error("send command isn't supported by streaming loader")
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
                    self.__logger.error("Feature is not supported")
                    return False
                else:
                    return self.streaming.modules.run(mainargs=options, command=command)
            else:
                self.__logger.error("Unknown/Missing command, a command is required.")
                return False
