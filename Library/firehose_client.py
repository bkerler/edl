import os
import sys
from binascii import hexlify, unhexlify
from struct import unpack, pack
from Library.firehose import qualcomm_firehose
from Config.qualcomm_config import infotbl, msmids, secureboottbl, sochw
from Library.xmlparser import xmlparser
from Library.utils import do_tcp_server

class firehose_client:
    def __init__(self, arguments, cdc, sahara, LOGGER, printer):
        self.LOGGER = LOGGER
        self.cdc = cdc
        self.sahara = sahara
        self.arguments = arguments
        self.printer = printer

        self.cfg = qualcomm_firehose.cfg()
        self.cfg.MemoryName = arguments["--memory"]
        self.cfg.ZLPAwareHost = 1
        self.cfg.SkipStorageInit = arguments["--skipstorageinit"]
        self.cfg.SkipWrite = arguments["--skipwrite"]
        self.cfg.MaxPayloadSizeToTargetInBytes = int(arguments["--maxpayload"], 16)
        self.cfg.SECTOR_SIZE_IN_BYTES = int(arguments["--sectorsize"], 16)
        self.cfg.bit64 = sahara.bit64
        devicemodel = ""
        skipresponse = False
        if "--skipresponse" in arguments:
            if arguments["--skipresponse"]:
                skipresponse = True
        if "--devicemodel" in arguments:
            if arguments["--devicemodel"] is not None:
                devicemodel = arguments["--devicemodel"]
        self.firehose = qualcomm_firehose(cdc, xmlparser(), self.cfg, LOGGER, devicemodel, sahara.serial, skipresponse,
                                          self.getluns(arguments), arguments)
        self.supported_functions = self.firehose.connect(0)
        funcs = "Supported functions:\n-----------------\n"
        for function in self.supported_functions:
            funcs += function + ","
        funcs = funcs[:-1]
        LOGGER.info(funcs)
        self.target_name = self.firehose.cfg.TargetName
        if "hwid" in dir(sahara):
            if sahara.hwid is not None:
                hwid = sahara.hwid >> 32
                if hwid in msmids:
                    self.target_name = msmids[hwid]
                elif hwid in sochw:
                    self.target_name = sochw[hwid].split(",")[0]

    def check_cmd(self, func):
        if not self.supported_functions:
            return True
        for sfunc in self.supported_functions:
            if func.lower() == sfunc.lower():
                return True
        return False



    def getluns(self, argument):
        if argument["--lun"] != "None":
            return [int(argument["--lun"])]

        luns = []
        if not argument["--memory"].lower() == "emmc":
            for i in range(0, 99):
                luns.append(i)
        else:
            luns = [0]
        return luns

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

    def handle_firehose(self, cmd, options):
        if cmd == "gpt":
            luns = self.getluns(options)
            directory = options["<directory>"]
            if directory is None:
                directory = ""
            genxml = False
            if "--genxml" in options:
                if options["--genxml"]:
                    genxml = True
            for lun in luns:
                sfilename = os.path.join(directory, f"gpt_main{str(lun)}.bin")
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                with open(sfilename, "wb") as write_handle:
                    write_handle.write(data)

                self.printer(f"Dumped GPT from Lun {str(lun)} to {sfilename}")
                sfilename = os.path.join(directory, f"gpt_backup{str(lun)}.bin")
                with open(sfilename, "wb") as write_handle:
                    write_handle.write(data[self.firehose.cfg.SECTOR_SIZE_IN_BYTES * 2:])
                self.printer(f"Dumped Backup GPT from Lun {str(lun)} to {sfilename}")
                if genxml:
                    guid_gpt.generate_rawprogram(lun, self.firehose.cfg.SECTOR_SIZE_IN_BYTES, directory)
            return True
        elif cmd == "printgpt":
            luns = self.getluns(options)
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                self.printer(f"\nParsing Lun {str(lun)}:")
                guid_gpt.print()
            return True
        elif cmd == "r":
            if not self.check_param(["<partitionname>", "<filename>"]):
                return False
            partitionname = options["<partitionname>"]
            filename = options["<filename>"]
            filenames = filename.split(",")
            partitions = partitionname.split(",")
            if len(partitions) != len(filenames):
                self.LOGGER.error("You need to gives as many filenames as given partitions.")
                return False
            i = 0
            for partition in partitions:
                partfilename = filenames[i]
                i += 1
                res = self.firehose.detect_partition(options, partition)
                if res[0]:
                    lun = res[1]
                    rpartition = res[2]
                    self.firehose.cmd_read(lun, rpartition.sector, rpartition.sectors, partfilename)
                    self.printer(
                        f"Dumped sector {str(rpartition.sector)} with sector count {str(rpartition.sectors)} " + \
                        f"as {partfilename}.")
                else:
                    fpartitions = res[1]
                    self.LOGGER.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for lun in fpartitions:
                        for rpartition in fpartitions[lun]:
                            if options["--memory"].lower() == "emmc":
                                self.LOGGER.error("\t" + rpartition)
                            else:
                                self.LOGGER.error(lun + ":\t" + rpartition)
                    return False
            return True
        elif cmd == "rl":
            if not self.check_param(["<directory>"]):
                return False
            directory = options["<directory>"]
            if options["--skip"]:
                skip = options["--skip"].split(",")
            else:
                skip = []
            genxml = False
            if "--genxml" in options:
                if options["--genxml"]:
                    genxml = True
            if not os.path.exists(directory):
                os.mkdir(directory)

            luns = self.getluns(options)

            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                if len(luns) > 1:
                    storedir = os.path.join(directory, "lun" + str(lun))
                else:
                    storedir = directory
                if not os.path.exists(storedir):
                    os.mkdir(storedir)
                sfilename = os.path.join(storedir, f"gpt_main{str(lun)}.bin")
                with open(sfilename, "wb") as write_handle:
                    write_handle.write(data)

                sfilename = os.path.join(storedir, f"gpt_backup{str(lun)}.bin")
                with open(sfilename, "wb") as write_handle:
                    write_handle.write(data[self.firehose.cfg.SECTOR_SIZE_IN_BYTES * 2:])

                if genxml:
                    guid_gpt.generate_rawprogram(lun, self.firehose.cfg.SECTOR_SIZE_IN_BYTES, storedir)

                for partition in guid_gpt.partentries:
                    partitionname = partition.name
                    if partition.name in skip:
                        continue
                    filename = os.path.join(storedir, partitionname + ".bin")
                    self.LOGGER.info(
                        f"Dumping partition {str(partition.name)} with sector count {str(partition.sectors)} " +
                        f"as {filename}.")
                    self.firehose.cmd_read(lun, partition.sector, partition.sectors, filename)
            return True
        elif cmd == "rf":
            if not self.check_param(["<filename>"]):
                return False
            filename = options["<filename>"]
            luns = self.getluns(options)
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                if len(luns) > 1:
                    sfilename = f"lun{str(lun)}_" + filename
                else:
                    sfilename = filename
                self.printer(f"Dumping sector 0 with sector count {str(guid_gpt.totalsectors)} as {filename}.")
                self.firehose.cmd_read(lun, 0, guid_gpt.totalsectors, sfilename)
                self.printer(f"Dumped sector 0 with sector count {str(guid_gpt.totalsectors)} as {filename}.")
            return True
        elif cmd == "pbl":
            if not self.check_param(["<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                filename = options["<filename>"]
                if self.target_name in infotbl:
                    target_name = infotbl[self.target_name]
                    if len(target_name[0]) > 0:
                        if self.firehose.cmd_peek(target_name[0][0], target_name[0][1], filename, True):
                            self.printer(f"Dumped pbl at offset {hex(target_name[0][0])} as {filename}.")
                            return True
                    else:
                        self.LOGGER.error("No known pbl offset for this chipset")
                else:
                    self.LOGGER.error("Unknown target chipset")
                self.LOGGER.error("Error on dumping pbl")
            return False
        elif cmd == "qfp":
            if not self.check_param(["<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                filename = options["<filename>"]
                if self.target_name in infotbl:
                    target_name = infotbl[self.target_name]
                    if len(target_name[1]) > 0:
                        if self.firehose.cmd_peek(target_name[1][0], target_name[1][1], filename):
                            self.printer(f"Dumped qfprom at offset {hex(target_name[1][0])} as {filename}.")
                            return True
                    else:
                        self.LOGGER.error("No known qfprom offset for this chipset")
                else:
                    self.LOGGER.error("Unknown target chipset")
                self.LOGGER.error("Error on dumping qfprom")
            return False
        elif cmd == "secureboot":
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                if self.target_name in secureboottbl:
                    self.target_name = secureboottbl[self.target_name]
                    value = unpack("<I", self.firehose.cmd_peek(self.target_name, 4))[0]
                    is_secure = False
                    for area in range(0, 4):
                        sec_boot = (value >> (area * 8)) & 0xFF
                        pk_hashindex = sec_boot & 3
                        oem_pkhash = True if ((sec_boot >> 4) & 1) == 1 else False
                        auth_enabled = True if ((sec_boot >> 5) & 1) == 1 else False
                        use_serial = True if ((sec_boot >> 6) & 1) == 1 else False
                        if auth_enabled:
                            is_secure = True
                        self.printer(f"Sec_Boot{str(area)} " +
                                     f"PKHash-Index:{str(pk_hashindex)} " +
                                     f"OEM_PKHash: {str(oem_pkhash)} " +
                                     f"Auth_Enabled: {str(auth_enabled)}" +
                                     f"Use_Serial: {str(use_serial)}")
                    if is_secure:
                        self.printer("Secure boot enabled.")
                    else:
                        self.printer("Secure boot disabled.")
                    return True
                else:
                    self.LOGGER.error("Unknown target chipset")
                    return False
        elif cmd == "memtbl":
            if not self.check_param(["<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                filename = options["<filename>"]
                if self.target_name in infotbl:
                    self.target_name = infotbl[self.target_name]
                    if len(self.target_name[2]) > 0:
                        if self.firehose.cmd_peek(self.target_name[2][0], self.target_name[2][1], filename):
                            self.printer(f"Dumped memtbl at offset {hex(self.target_name[2][0])} as {filename}.")
                            return True
                    else:
                        self.LOGGER.error("No known memtbl offset for this chipset")
                else:
                    self.LOGGER.error("Unknown target chipset")
                self.LOGGER.error("Error on dumping memtbl")
            return False
        elif cmd == "footer":
            if not self.check_param(["<filename>"]):
                return False
            luns = self.getluns(options)
            filename = options["<filename>"]
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                pnames = ["userdata2", "metadata", "userdata", "reserved1", "reserved2", "reserved3"]
                for partition in guid_gpt.partentries:
                    if partition.name in pnames:
                        self.printer(f"Detected partition: {partition.name}")
                        data = self.firehose.cmd_read_buffer(lun,
                                                             partition.sector +
                                                             (partition.sectors -
                                                              (0x4000 // self.firehose.cfg.SECTOR_SIZE_IN_BYTES)),
                                                             (0x4000 // self.firehose.cfg.SECTOR_SIZE_IN_BYTES), False)
                        if data == b"":
                            continue
                        val = unpack("<I", data[:4])[0]
                        if (val & 0xFFFFFFF0) == 0xD0B5B1C0:
                            with open(filename, "wb") as write_handle:
                                write_handle.write(data)
                                self.printer(f"Dumped footer from {partition.name} as {filename}.")
                                return True
            self.LOGGER.error("Error: Couldn't detect footer partition.")
            return False
        elif cmd == "rs":
            if options["--lun"] != 'None':
                lun = int(options["--lun"])
            else:
                lun = 0
            if not self.check_param(["<filename>", "<sectors>", "<start_sector>"]):
                return False
            start = int(options["<start_sector>"])
            sectors = int(options["<sectors>"])
            filename = options["<filename>"]
            data = self.firehose.cmd_read_buffer(lun, start, sectors, False)
            try:
                with open(filename, "wb") as write_handle:
                    write_handle.write(data)
                    self.printer(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
                    return True
            except Exception as error:
                self.LOGGER.error(f"Error: Couldn't open {filename} for writing: %s" % str(error))
            return False
        elif cmd == "peek":
            if not self.check_param(["<offset>", "<length>", "<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                length = int(options["<length>"], 16)
                filename = options["<filename>"]
                self.firehose.cmd_peek(offset, length, filename, True)
                self.LOGGER.info(
                    f"Peek data from offset {hex(offset)} and length {hex(length)} was written to {filename}")
                return True
        elif cmd == "peekhex":
            if not self.check_param(["<offset>", "<length>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                length = int(options["<length>"], 16)
                resp = self.firehose.cmd_peek(offset, length, "", True)
                self.printer("\n")
                self.printer(hexlify(resp))
                return True
        elif cmd == "peekqword":
            if not self.check_param(["<offset>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                resp = self.firehose.cmd_peek(offset, 8, "", True)
                self.printer("\n")
                self.printer(hex(unpack("<Q", resp[:8])[0]))
                return True
        elif cmd == "peekdword":
            if not self.check_param(["<offset>"]):
                return False
            if not self.check_cmd("peek"):
                self.LOGGER.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                resp = self.firehose.cmd_peek(offset, 4, "", True)
                self.printer("\n")
                self.printer(hex(unpack("<I", resp[:4])[0]))
                return True
        elif cmd == "poke":
            if not self.check_param(["<offset>", "<filename>"]):
                return False
            if not self.check_cmd("poke"):
                self.LOGGER.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                filename = options["<filename>"]
                return self.firehose.cmd_poke(offset, "", filename, True)
        elif cmd == "pokehex":
            if not self.check_param(["<offset>", "<data>"]):
                return False
            if not self.check_cmd("poke"):
                self.LOGGER.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                data = unhexlify(options["<data>"])
                return self.firehose.cmd_poke(offset, data, "", True)
        elif cmd == "pokeqword":
            if not self.check_param(["<offset>", "<data>"]):
                return False
            if not self.check_cmd("poke"):
                self.LOGGER.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                data = pack("<Q", int(options["<data>"], 16))
                return self.firehose.cmd_poke(offset, data, "", True)
        elif cmd == "pokedword":
            if not self.check_param(["<offset>", "<data>"]):
                return False
            if not self.check_cmd("poke"):
                self.LOGGER.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = int(options["<offset>"], 16)
                data = pack("<I", int(options["<data>"], 16))
                return self.firehose.cmd_poke(offset, data, "", True)
        elif cmd == "memcpy":
            if not self.check_param(["<offset>", "<size>"]):
                return False
            if not self.check_cmd("poke"):
                self.printer("Poke command isn't supported by edl loader")
            else:
                srcoffset = int(options["<offset>"], 16)
                size = int(options["<size>"], 16)
                dstoffset = srcoffset + size
                if self.firehose.cmd_memcpy(dstoffset, srcoffset, size):
                    self.printer(f"Memcpy from {hex(srcoffset)} to {hex(dstoffset)} succeeded")
                    return True
                else:
                    return False
        elif cmd == "reset":
            return self.firehose.cmd_reset()
        elif cmd == "nop":
            if not self.check_cmd("nop"):
                self.LOGGER.error("Nop command isn't supported by edl loader")
                return False
            else:
                return self.firehose.cmd_nop()
        elif cmd == "setbootablestoragedrive":
            if not self.check_param(["<lun>"]):
                return False
            if not self.check_cmd("setbootablestoragedrive"):
                self.LOGGER.error("setbootablestoragedrive command isn't supported by edl loader")
                return False
            else:
                return self.firehose.cmd_setbootablestoragedrive(int(options["<lun>"]))
        elif cmd == "getstorageinfo":
            if not self.check_cmd("getstorageinfo"):
                self.LOGGER.error("getstorageinfo command isn't supported by edl loader")
                return False
            else:
                return self.firehose.cmd_getstorageinfo()
        elif cmd == "w":
            if not self.check_param(["<partitionname>", "<filename>"]):
                return False
            partitionname = options["<partitionname>"]
            filename = options["<filename>"]
            if not os.path.exists(filename):
                self.LOGGER.error(f"Error: Couldn't find file: {filename}")
                return False
            res = self.firehose.detect_partition(options, partitionname)
            if res[0]:
                lun = res[1]
                partition = res[2]
                sectors = os.stat(filename).st_size // self.firehose.cfg.SECTOR_SIZE_IN_BYTES
                if (os.stat(filename).st_size % self.firehose.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                    sectors += 1
                if sectors > partition.sectors:
                    self.LOGGER.error(
                        f"Error: {filename} has {sectors} sectors but partition only has {partition.sectors}.")
                    return False
                if self.firehose.modules is not None:
                    self.firehose.modules.prerun()
                if self.firehose.cmd_program(lun, partition.sector, filename):
                    self.printer(f"Wrote {filename} to sector {str(partition.sector)}.")
                    return True
                else:
                    self.printer(f"Error writing {filename} to sector {str(partition.sector)}.")
                    return False
            else:
                fpartitions = res[1]
                self.LOGGER.error(f"Error: Couldn't detect partition: {partitionname}\nAvailable partitions:")
                for lun in fpartitions:
                    for partition in fpartitions[lun]:
                        if options["--memory"].lower() == "emmc":
                            self.LOGGER.error("\t" + partition)
                        else:
                            self.LOGGER.error(lun + ":\t" + partition)
            return False
        elif cmd == "wl":
            if not self.check_param(["<directory>"]):
                return False
            directory = options["<directory>"]
            if options["--skip"]:
                skip = options["--skip"].split(",")
            else:
                skip = []
            luns = self.getluns(options)

            if not os.path.exists(directory):
                self.LOGGER.error(f"Error: Couldn't find directory: {directory}")
                sys.exit()
            filenames = []
            if self.firehose.modules is not None:
                self.firehose.modules.prerun()
            for dirName, subdirList, fileList in os.walk(directory):
                for fname in fileList:
                    filenames.append(os.path.join(dirName, fname))
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                if "partentries" in dir(guid_gpt):
                    for filename in filenames:
                        for partition in guid_gpt.partentries:
                            partname = filename[filename.rfind("/") + 1:]
                            if ".bin" in partname[-4:]:
                                partname = partname[:-4]
                            if partition.name == partname:
                                if partition.name in skip:
                                    continue
                                sectors = os.stat(filename).st_size // self.firehose.cfg.SECTOR_SIZE_IN_BYTES
                                if (os.stat(filename).st_size % self.firehose.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                                    sectors += 1
                                if sectors > partition.sectors:
                                    self.LOGGER.error(f"Error: {filename} has {sectors} sectors but partition " +
                                                      f"only has {partition.sectors}.")
                                    return False
                                self.printer(f"Writing {filename} to partition {str(partition.name)}.")
                                self.firehose.cmd_program(lun, partition.sector, filename)
                else:
                    self.printer("Couldn't write partition. Either wrong memorytype given or no gpt partition.")
                    return False
            return True
        elif cmd == "ws":
            if not self.check_param(["<start_sector>"]):
                return False
            if options["--lun"] is None:
                lun = 0
            else:
                lun = int(options["--lun"])
            start = int(options["<start_sector>"])
            filename = options["<filename>"]
            if not os.path.exists(filename):
                self.LOGGER.error(f"Error: Couldn't find file: {filename}")
                return False
            if self.firehose.modules is not None:
                self.firehose.modules.prerun()
            if self.firehose.cmd_program(lun, start, filename):
                self.printer(f"Wrote {filename} to sector {str(start)}.")
                return True
            else:
                self.LOGGER.error(f"Error on writing {filename} to sector {str(start)}")
                return False
        elif cmd == "wf":
            if not self.check_param(["<filename>"]):
                return False
            if options["--lun"] is None:
                lun = 0
            else:
                lun = int(options["--lun"])
            start = 0
            filename = options["<filename>"]
            if not os.path.exists(filename):
                self.LOGGER.error(f"Error: Couldn't find file: {filename}")
                return False
            if self.firehose.modules is not None:
                self.firehose.modules.prerun()
            if self.firehose.cmd_program(lun, start, filename):
                self.printer(f"Wrote {filename} to sector {str(start)}.")
                return True
            else:
                self.LOGGER.error(f"Error on writing {filename} to sector {str(start)}")
                return False
        elif cmd == "e":
            if not self.check_param(["<partitionname>"]):
                return False
            luns = self.getluns(options)
            partitionname = options["<partitionname>"]
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                if self.firehose.modules is not None:
                    self.firehose.modules.prerun()
                if "partentries" in dir(guid_gpt):
                    for partition in guid_gpt.partentries:
                        if partition.name == partitionname:
                            self.firehose.cmd_erase(lun, partition.sector, partition.sectors)
                            self.printer(
                                f"Erased {partitionname} starting at sector {str(partition.sector)} with sector count " +
                                f"{str(partition.sectors)}.")
                            return True
                else:
                    self.printer("Couldn't erase partition. Either wrong memorytype given or no gpt partition.")
                    return False
            self.LOGGER.error(f"Error: Couldn't detect partition: {partitionname}")
            return False
        elif cmd == "es":
            if not self.check_param(["<start_sector>", "<sectors>"]):
                return False
            if options["--lun"] is None:
                lun = 0
            else:
                lun = int(options["--lun"])
            start = int(options["<start_sector>"])
            sectors = int(options["<sectors>"])
            if self.firehose.modules is not None:
                self.firehose.modules.prerun()
            if self.firehose.cmd_erase(lun, start, sectors):
                self.printer(f"Erased sector {str(start)} with sector count {str(sectors)}.")
                return True
            return False
        elif cmd == "xml":
            if not self.check_param(["<xmlfile>"]):
                return False
            return self.firehose.cmd_xml(options["<xmlfile>"])
        elif cmd == "rawxml":
            if not self.check_param(["<xmlstring>"]):
                return False
            return self.firehose.cmd_rawxml(options["<xmlstring>"])
        elif cmd == "send":
            if not self.check_param(["<command>"]):
                return False
            command = options["<command>"]
            resp = self.firehose.cmd_send(command, True)
            self.printer("\n")
            self.printer(resp)
            return True
        elif cmd == "server":
            return do_tcp_server(self,options,self.handle_firehose)
        elif cmd == "modules":
            if not self.check_param(["<command>", "<options>"]):
                return False
            mcommand = options["<command>"]
            moptions = options["<options>"]
            if self.firehose.modules is None:
                self.LOGGER.error("Feature is not supported")
                return False
            else:
                return self.firehose.modules.run(command=mcommand, args=moptions)
        else:
            self.LOGGER.error("Unknown/Missing command, a command is required.")
            return False
