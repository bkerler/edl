#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import os
import sys
import logging
import json
from binascii import hexlify, unhexlify
from struct import unpack, pack
from edlclient.Library.firehose import firehose
from edlclient.Library.xmlparser import xmlparser
from edlclient.Library.utils import do_tcp_server
from edlclient.Library.utils import LogBase, getint
from edlclient.Library.gpt import AB_FLAG_OFFSET, AB_PARTITION_ATTR_SLOT_ACTIVE
from edlclient.Config.qualcomm_config import memory_type
from edlclient.Config.qualcomm_config import infotbl, msmids, secureboottbl, sochw
import fnmatch

try:
    import xml.etree.cElementTree as ET
    from xml.etree import cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ET
    from xml.etree import ElementTree

try:
    from edlclient.Library.Modules.init import modules
except ImportError as e:
    pass


class firehose_client(metaclass=LogBase):
    def __init__(self, arguments, cdc, sahara, loglevel, printer):
        self.cdc = cdc
        self.sahara = sahara
        self.arguments = arguments
        self.printer = printer
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

        self.cfg = firehose.cfg()
        if not arguments["--memory"] is None:
            self.cfg.MemoryName = arguments["--memory"].lower()
        else:
            self.cfg.MemoryName = ""
        self.cfg.ZLPAwareHost = 1
        self.cfg.SkipStorageInit = arguments["--skipstorageinit"]
        self.cfg.SkipWrite = arguments["--skipwrite"]
        self.cfg.MaxPayloadSizeToTargetInBytes = getint(arguments["--maxpayload"])
        self.cfg.SECTOR_SIZE_IN_BYTES = getint(arguments["--sectorsize"])
        self.cfg.bit64 = sahara.bit64
        devicemodel = ""
        skipresponse = False
        if "--skipresponse" in arguments:
            if arguments["--skipresponse"]:
                skipresponse = True
        if "--devicemodel" in arguments:
            if arguments["--devicemodel"] is not None:
                devicemodel = arguments["--devicemodel"]
        self.cfg.programmer = self.sahara.programmer
        self.firehose = firehose(cdc=cdc, xml=xmlparser(), cfg=self.cfg, loglevel=self.__logger.level,
                                 devicemodel=devicemodel, serial=sahara.serial, skipresponse=skipresponse,
                                 luns=self.getluns(arguments), args=arguments)
        self.connected = False

    def connect(self, sahara):
        self.firehose.connect()
        if "hwid" in dir(sahara):
            if sahara.hwid is not None:
                hwid = (sahara.hwid >> 32) & 0xFFFFFF
                socid = ((sahara.hwid >> 32) >> 16)
                if hwid in msmids:
                    self.target_name = msmids[hwid]
                    self.info(f"Target detected: {self.target_name}")
                    if self.cfg.MemoryName == "":
                        if self.target_name in memory_type.preferred_memory:
                            type = memory_type.preferred_memory[self.target_name]
                            if type == memory_type.nand:
                                self.cfg.MemoryName = "nand"
                            if type == memory_type.spinor:
                                self.cfg.MemoryName = "spinor"
                            elif type == memory_type.emmc:
                                self.cfg.MemoryName = "eMMC"
                            elif type == memory_type.ufs:
                                self.cfg.MemoryName = "UFS"
                            self.warning("Based on the chipset, we assume " +
                                         self.cfg.MemoryName + " as default memory type..., if it fails, try using " +
                                         "--memory\" with \"UFS\",\"NAND\" or \"spinor\" instead !")
                elif socid in sochw:
                    self.target_name = sochw[socid].split(",")[0]
        # We assume ufs is fine (hopefully), set it as default
        if self.cfg.MemoryName == "":
            if "ufs" in self.firehose.supported_functions:
                self.warning(
                    "No --memory option set, we assume \"UFS\" as default ..., if it fails, try using \"--memory\" " +
                    "with \"UFS\",\"NAND\" or \"spinor\" instead !")
                self.cfg.MemoryName = "UFS"
            else:
                self.warning(
                    "No --memory option set, we assume \"eMMC\" as default ..., if it fails, try using \"--memory\" " +
                    "with \"UFS\",\"NAND\" or \"spinor\" instead !")
                self.cfg.MemoryName = "eMMC"
        if self.firehose.configure(0):
            funcs = "Supported functions:\n-----------------\n"
            for function in self.firehose.supported_functions:
                funcs += function + ","
            funcs = funcs[:-1]
            self.info(funcs)
            self.target_name = self.firehose.cfg.TargetName
            self.connected = True
            try:
                if self.firehose.modules is None:
                    self.firehose.modules = modules(fh=self.firehose, serial=self.firehose.serial,
                                                    supported_functions=self.firehose.supported_functions,
                                                    loglevel=self.__logger.level,
                                                    devicemodel=self.firehose.devicemodel, args=self.arguments)
            except Exception as err:  # pylint: disable=broad-except
                self.firehose.modules = None
        return self.connected

    def check_cmd(self, func):
        if not self.firehose.supported_functions:
            return True
        for sfunc in self.firehose.supported_functions:
            if func.lower() == sfunc.lower():
                return True
        return False

    def find_bootable_partition(self, imagedir, rawprogram):
        part = -1
        for xml in rawprogram:
            filename = os.path.join(imagedir, xml)
            with open(filename, "r") as fl:
                for evt, elem in ET.iterparse(fl, events=["end"]):
                    if elem.tag == "program":
                        label = elem.get("label")
                        if label in ['xbl', 'xbl_a', 'sbl1']:
                            if part != -1:
                                self.error("[FIREHOSE] multiple bootloader found!")
                                return -1
                            part = elem.get("physical_partition_number")
        return part

    def getluns(self, argument):
        if argument["--lun"] is not None:
            return [int(argument["--lun"])]

        luns = []
        if self.cfg.MemoryName.lower() == "ufs":
            for i in range(0, self.cfg.maxlun):
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

    def get_storage_info(self):
        storageinfo = self.firehose.cmd_getstorageinfo()
        for info in storageinfo:
            if "storage_info" in info:
                rs = info.replace("INFO: ", "")
                field = json.loads(rs)
                if "storage_info" in field:
                    info = field["storage_info"]
                    return info
        return False

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
                #with open(sfilename, "wb") as write_handle:
                #    #write_handle.write(data)
                #    pass

                self.printer(f"Dumped GPT from Lun {str(lun)} to {sfilename}")
                sfilename = os.path.join(directory, f"gpt_backup{str(lun)}.bin")
                #with open(sfilename, "wb") as write_handle:
                #    #write_handle.write(data[self.firehose.cfg.SECTOR_SIZE_IN_BYTES * 2:])
                #    pass
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
                self.error("You need to gives as many filenames as given partitions.")
                return False
            i = 0
            for partition in partitions:
                if partition == "gpt":
                    luns = self.getluns(options)
                    for lun in luns:
                        partfilename = filenames[i] + ".lun%d" % lun
                        if self.firehose.cmd_read(lun, 0, 32, partfilename):
                            self.printer(
                                f"Dumped sector {str(0)} with sector count {str(32)} " +
                                f"as {partfilename}.")
                    continue
                partfilename = filenames[i]
                i += 1
                res = self.firehose.detect_partition(options, partition)
                if res[0]:
                    lun = res[1]
                    rpartition = res[2]
                    if self.firehose.cmd_read(lun, rpartition.sector, rpartition.sectors, partfilename):
                        self.printer(
                            f"Dumped sector {str(rpartition.sector)} with sector count {str(rpartition.sectors)} " +
                            f"as {partfilename}.")
                else:
                    fpartitions = res[1]
                    self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for lun in fpartitions:
                        for rpartition in fpartitions[lun]:
                            if self.cfg.MemoryName == "emmc":
                                self.error("\t" + rpartition)
                            else:
                                self.error(lun + ":\t" + rpartition)
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
                skipped = []
                for skippart in skip:
                    filtered = fnmatch.filter(guid_gpt.partentries, skippart)
                    if len(filtered) > 0:
                        skipped.append(filtered[0])
                for partitionname in guid_gpt.partentries:
                    partition = guid_gpt.partentries[partitionname]
                    if partitionname in skipped:
                        continue
                    filename = os.path.join(storedir, partitionname + ".bin")
                    self.info(
                        f"Dumping partition {str(partition.name)} with sector count {str(partition.sectors)} " +
                        f"as {filename}.")
                    if self.firehose.cmd_read(lun, partition.sector, partition.sectors, filename):
                        self.info(f"Dumped partition {str(partition.name)} with sector count " +
                                  f"{str(partition.sectors)} as {filename}.")
            return True
        elif cmd == "rf":
            if not self.check_param(["<filename>"]):
                return False
            filename = options["<filename>"]
            #storageinfo = self.firehose.parse_storage()
            if self.cfg.MemoryName.lower() in ["spinor", "nand"]:
                luns = [0]
                totalsectors = (self.cfg.block_size * self.cfg.total_blocks) // self.cfg.SECTOR_SIZE_IN_BYTES
                if self.cfg.num_physical > 0:
                    luns = []
                    for i in range(self.cfg.num_physical):
                        luns.append(i)
                elif 99 > self.cfg.maxlun > 0:
                    luns = []
                    for i in range(self.cfg.maxlun):
                        luns.append(i)
                if totalsectors is not None:
                    for lun in luns:
                        buffer = self.firehose.cmd_read_buffer(physical_partition_number=lun,
                                                               start_sector=0, num_partition_sectors=1, display=False)
                        if self.get_storage_info():
                            totalsectors = (self.cfg.block_size *
                                            self.cfg.total_blocks) // self.cfg.SECTOR_SIZE_IN_BYTES

                            if len(luns) > 1:
                                sfilename = filename + f".lun{str(lun)}"
                            else:
                                sfilename = filename
                            self.printer(f"Dumping sector 0 with sector count {str(totalsectors)} as {filename}.")
                            if self.firehose.cmd_read(lun, 0, totalsectors, sfilename):
                                self.printer(
                                    f"Dumped sector 0 with sector count {str(totalsectors)} as {filename}.")
            else:
                luns = self.getluns(options)
                for lun in luns:
                    data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                           int(options["--gpt-part-entry-size"]),
                                                           int(options["--gpt-part-entry-start-lba"]))
                    if guid_gpt is None:
                        break
                    if len(luns) > 1:
                        sfilename = filename + f".lun{str(lun)}"
                        self.printer(f"Dumping lun {lun} with sector count {str(guid_gpt.totalsectors)} as {filename}.")
                    else:
                        sfilename = filename
                        self.printer(f"Dumping flash with sector count {str(guid_gpt.totalsectors)} as {filename}.")

                    if self.firehose.cmd_read(lun, 0, guid_gpt.totalsectors, sfilename):
                        if len(luns) > 1:
                            self.printer(f"Dumped lun {lun} with sector count " +
                                         f"{str(guid_gpt.totalsectors)} as {filename}.")
                        else:
                            self.printer(f"Dumped flash with sector count {str(guid_gpt.totalsectors)} as {filename}.")
                return True
        elif cmd == "pbl":
            if not self.check_param(["<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
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
                        self.error("No known pbl offset for this chipset")
                else:
                    self.error("Unknown target chipset")
                self.error("Error on dumping pbl")
            return False
        elif cmd == "qfp":
            if not self.check_param(["<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
                return False
            else:
                filename = options["<filename>"]
                if self.target_name not in infotbl:
                    self.error("Unknown target chipset")
                else:
                    target_name = infotbl[self.target_name]
                    if len(target_name[1]) > 0:
                        if self.firehose.cmd_peek(target_name[1][0], target_name[1][1], filename):
                            self.printer(f"Dumped qfprom at offset {hex(target_name[1][0])} as {filename}.")
                            return True
                    else:
                        self.error("No known qfprom offset for this chipset")
                self.error("Error on dumping qfprom")
            return False
        elif cmd == "secureboot":
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
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
                    self.error("Unknown target chipset")
                    return False
        elif cmd == "memtbl":
            if not self.check_param(["<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
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
                        self.error("No known memtbl offset for this chipset")
                else:
                    self.error("Unknown target chipset")
                self.error("Error on dumping memtbl")
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
                for pname in pnames:
                    for partition in guid_gpt.partentries:
                        if partition != pname:
                            continue
                        self.printer(f"Detected partition: {partition}")
                        data = self.firehose.cmd_read_buffer(lun,
                                                             guid_gpt.partentries[partition].sector +
                                                             (guid_gpt.partentries[partition].sectors -
                                                              (0x4000 // self.firehose.cfg.SECTOR_SIZE_IN_BYTES)),
                                                             (0x4000 // self.firehose.cfg.SECTOR_SIZE_IN_BYTES), False)
                        if data == b"":
                            continue
                        val = unpack("<I", data.data[:4])[0]
                        if (val & 0xFFFFFFF0) == 0xD0B5B1C0:
                            with open(filename, "wb") as write_handle:
                                write_handle.write(data)
                                self.printer(f"Dumped footer from {partition} as {filename}.")
                                return True
            self.error("Error: Couldn't detect footer partition.")
            return False
        elif cmd == "rs":
            if options["--lun"] is not None:
                lun = int(options["--lun"])
            else:
                lun = 0
            if not self.check_param(["<filename>", "<sectors>", "<start_sector>"]):
                return False
            start = int(options["<start_sector>"])
            sectors = int(options["<sectors>"])
            filename = options["<filename>"]
            if self.firehose.cmd_read(lun, start, sectors, filename, True):
                self.printer(f"Dumped sector {str(start)} with sector count {str(sectors)} as {filename}.")
                return True
        elif cmd == "peek":
            if not self.check_param(["<offset>", "<length>", "<filename>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                length = getint(options["<length>"])
                filename = options["<filename>"]
                self.firehose.cmd_peek(offset, length, filename, True)
                self.info(
                    f"Peek data from offset {hex(offset)} and length {hex(length)} was written to {filename}")
                return True
        elif cmd == "peekhex":
            if not self.check_param(["<offset>", "<length>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                length = getint(options["<length>"])
                resp = self.firehose.cmd_peek(offset, length, "", True)
                self.printer("\n")
                self.printer(hexlify(resp))
                return True
        elif cmd == "peekqword":
            if not self.check_param(["<offset>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                resp = self.firehose.cmd_peek(offset, 8, "", True)
                self.printer("\n")
                self.printer(hex(unpack("<Q", resp[:8])[0]))
                return True
        elif cmd == "peekdword":
            if not self.check_param(["<offset>"]):
                return False
            if not self.check_cmd("peek"):
                self.error("Peek command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                resp = self.firehose.cmd_peek(offset, 4, "", True)
                self.printer("\n")
                self.printer(hex(unpack("<I", resp[:4])[0]))
                return True
        elif cmd == "poke":
            if not self.check_param(["<offset>", "<filename>"]):
                return False
            if not self.check_cmd("poke"):
                self.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                filename = options["<filename>"]
                return self.firehose.cmd_poke(offset, "", filename, True)
        elif cmd == "pokehex":
            if not self.check_param(["<offset>", "<data>"]):
                return False
            if not self.check_cmd("poke"):
                self.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                data = unhexlify(options["<data>"])
                return self.firehose.cmd_poke(offset, data, "", True)
        elif cmd == "pokeqword":
            if not self.check_param(["<offset>", "<data>"]):
                return False
            if not self.check_cmd("poke"):
                self.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                data = pack("<Q", getint(options["<data>"]))
                return self.firehose.cmd_poke(offset, data, "", True)
        elif cmd == "pokedword":
            if not self.check_param(["<offset>", "<data>"]):
                return False
            if not self.check_cmd("poke"):
                self.error("Poke command isn't supported by edl loader")
                return False
            else:
                offset = getint(options["<offset>"])
                data = pack("<I", getint(options["<data>"]))
                return self.firehose.cmd_poke(offset, data, "", True)
        elif cmd == "memcpy":
            if not self.check_param(["<offset>", "<size>"]):
                return False
            if not self.check_cmd("poke"):
                self.printer("Poke command isn't supported by edl loader")
            else:
                srcoffset = getint(options["<offset>"])
                size = getint(options["<size>"])
                dstoffset = srcoffset + size
                if self.firehose.cmd_memcpy(dstoffset, srcoffset, size):
                    self.printer(f"Memcpy from {hex(srcoffset)} to {hex(dstoffset)} succeeded")
                    return True
                else:
                    return False
        elif cmd == "reset":
            mode = "reset"
            if not self.check_param(["--resetmode"]):
                return False
            return self.firehose.cmd_reset(options["--resetmode"])
        elif cmd == "nop":
            if not self.check_cmd("nop"):
                self.error("Nop command isn't supported by edl loader")
                return False
            else:
                return self.firehose.cmd_nop()
        elif cmd == "setbootablestoragedrive":
            if not self.check_param(["<lun>"]):
                return False
            if not self.check_cmd("setbootablestoragedrive"):
                self.error("setbootablestoragedrive command isn't supported by edl loader")
                return False
            else:
                return self.firehose.cmd_setbootablestoragedrive(int(options["<lun>"]))
        elif cmd == "getactiveslot":
            res = self.firehose.detect_partition(options, "boot_a", send_full=True)
            if res[0]:
                lun = res[1]
                prim_guid_gpt = res[3]
                _, backup_guid_gpt = self.firehose.get_gpt(lun, 0, 0, 0, prim_guid_gpt.header.backup_lba)
                partition = backup_guid_gpt.partentries["boot_a"]
                active = ((partition.flags >> (
                            AB_FLAG_OFFSET * 8)) & 0xFF) & AB_PARTITION_ATTR_SLOT_ACTIVE == AB_PARTITION_ATTR_SLOT_ACTIVE
                if active:
                    self.printer("Current active slot: a")
                    return True
            res = self.firehose.detect_partition(options, "boot_b", send_full=True)
            if res[0]:
                lun = res[1]
                prim_guid_gpt = res[3]
                _, backup_guid_gpt = self.firehose.get_gpt(lun, 0, 0, 0, prim_guid_gpt.header.backup_lba)
                partition = backup_guid_gpt.partentries["boot_b"]
                active = ((partition.flags >> (
                            AB_FLAG_OFFSET * 8)) & 0xFF) & AB_PARTITION_ATTR_SLOT_ACTIVE == AB_PARTITION_ATTR_SLOT_ACTIVE
                if active:
                    self.printer("Current active slot: b")
                    return True
            self.error("Can't detect active slot. Please make sure your device has slot A/B")
            return False
        elif cmd == "setactiveslot":
            if not self.check_param(["<slot>"]):
                return False
            else:
                return self.firehose.cmd_setactiveslot(options["<slot>"])
        elif cmd == "getstorageinfo":
            if not self.check_cmd("getstorageinfo"):
                self.error("getstorageinfo command isn't supported by edl loader")
                return False
            else:
                return self.firehose.cmd_getstorageinfo_string()
        elif cmd == "w":
            if not self.check_param(["<partitionname>", "<filename>"]):
                return False
            pname = options["<partitionname>"]
            fname = options["<filename>"]
            filenames = fname.split(",")
            partitions = pname.split(",")
            if len(partitions) != len(filenames):
                self.error("You need to gives as many filenames as given partitions.")
                return False
            i = 0
            if options["--lun"] is not None:
                lun = int(options["--lun"])
            else:
                lun = 0
            bad = False
            for partitionname in partitions:
                startsector = 0
                filename = filenames[i]
                i += 1
                if not os.path.exists(filename):
                    self.error(f"Error: Couldn't find file: {filename}")
                    bad = True
                    continue
                if partitionname.lower() == "gpt":
                    sectors = os.stat(filename).st_size // self.firehose.cfg.SECTOR_SIZE_IN_BYTES
                    res = [True, lun, sectors]
                else:
                    res = self.firehose.detect_partition(options, partitionname)
                if res[0]:
                    lun = res[1]
                    sectors = os.stat(filename).st_size // self.firehose.cfg.SECTOR_SIZE_IN_BYTES
                    if (os.stat(filename).st_size % self.firehose.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                        sectors += 1
                    if partitionname.lower() != "gpt":
                        partition = res[2]
                        if sectors > partition.sectors:
                            self.error(
                                f"Error: {filename} has {sectors} sectors but partition only has {partition.sectors}.")
                            bad = True
                            continue
                        startsector = partition.sector
                    if self.firehose.modules is not None:
                        self.firehose.modules.writeprepare()
                    if self.firehose.cmd_program(lun, startsector, filename):
                        self.printer(f"Wrote {filename} to sector {str(startsector)}.")
                    else:
                        self.printer(f"Error writing {filename} to sector {str(startsector)}.")
                        bad = True
                else:
                    if len(res) > 0:
                        fpartitions = res[1]
                        self.error(f"Error: Couldn't detect partition: {partitionname}\nAvailable partitions:")
                        for lun in fpartitions:
                            for partition in fpartitions[lun]:
                                if self.cfg.MemoryName == "emmc":
                                    self.error("\t" + partition.name)
                                else:
                                    self.error(lun + ":\t" + partition.name)
            if bad:
                return False
            else:
                return True
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
                self.error(f"Error: Couldn't find directory: {directory}")
                sys.exit()
            filenames = []
            if self.firehose.modules is not None:
                self.firehose.modules.writeprepare()
            for fname in filter(os.path.isfile, [os.path.join(directory, i) for i in os.listdir(directory)]):
                filenames.append(fname)
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    self.error(
                        "Error: Can not fetch GPT table from device, you may need to use `edl w gpt` to write a partition table first.`")
                    break
                for filename in filenames:
                    partname = os.path.basename(filename)
                    if ".bin" in partname[-4:] or ".img" in partname[-4:] or ".mbn" in partname[-4:]:
                        partname = partname[:-4]
                    if partname in skip:
                        continue
                    if partname in guid_gpt.partentries:
                        partition = guid_gpt.partentries[partname]
                        sectors = os.stat(filename).st_size // self.firehose.cfg.SECTOR_SIZE_IN_BYTES
                        if (os.stat(filename).st_size % self.firehose.cfg.SECTOR_SIZE_IN_BYTES) > 0:
                            sectors += 1
                        if sectors > partition.sectors:
                            self.error(f"Error: {filename} has {sectors} sectors but partition " +
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
            if options["--lun"] is not None:
                lun = int(options["--lun"])
            else:
                lun = 0
            start = int(options["<start_sector>"])
            filename = options["<filename>"]
            if not os.path.exists(filename):
                self.error(f"Error: Couldn't find file: {filename}")
                return False
            if self.firehose.modules is not None:
                self.firehose.modules.writeprepare()
            if self.firehose.cmd_program(lun, start, filename):
                self.printer(f"Wrote {filename} to sector {str(start)}.")
                return True
            else:
                self.error(f"Error on writing {filename} to sector {str(start)}")
                return False
        elif cmd == "wf":
            if not self.check_param(["<filename>"]):
                return False
            if options["--lun"] is not None:
                lun = int(options["--lun"])
            else:
                lun = 0
            start = 0
            filename = options["<filename>"]
            if not os.path.exists(filename):
                self.error(f"Error: Couldn't find file: {filename}")
                return False
            if self.firehose.modules is not None:
                self.firehose.modules.writeprepare()
            if self.firehose.cmd_program(lun, start, filename):
                self.printer(f"Wrote {filename} to sector {str(start)}.")
                return True
            else:
                self.error(f"Error on writing {filename} to sector {str(start)}")
                return False
        elif cmd == "e":
            if not self.check_param(["<partitionname>"]):
                return False
            luns = self.getluns(options)
            partitionname = options["<partitionname>"]
            partitions = partitionname.split(",")
            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                if self.firehose.modules is not None:
                    self.firehose.modules.writeprepare()
                for partitionname in partitions:
                    if partitionname in guid_gpt.partentries:
                        partition = guid_gpt.partentries[partitionname]
                        self.firehose.cmd_erase(lun, partition.sector, partition.sectors)
                        self.printer(
                            f"Erased {partitionname} starting at sector {str(partition.sector)} " +
                            f"with sector count {str(partition.sectors)}.")
                        return True
            self.error(
                f"Couldn't erase partition {partitionname}. Either wrong memorytype given or no gpt partition.")
            return False
        elif cmd == "ep":
            if not self.check_param(["<partitionname>", "<sectors>"]):
                return False
            luns = self.getluns(options)
            partitionname = options["<partitionname>"]
            sectors = int(options["<sectors>"])

            for lun in luns:
                data, guid_gpt = self.firehose.get_gpt(lun, int(options["--gpt-num-part-entries"]),
                                                       int(options["--gpt-part-entry-size"]),
                                                       int(options["--gpt-part-entry-start-lba"]))
                if guid_gpt is None:
                    break
                if self.firehose.modules is not None:
                    self.firehose.modules.writeprepare()
                if partitionname in guid_gpt.partentries:
                    partition = guid_gpt.partentries[partitionname]
                    self.firehose.cmd_erase(lun, partition.sector, sectors)
                    self.printer(
                        f"Erased {partitionname} starting at sector {str(partition.sector)} " +
                        f"with sector count {str(sectors)}.")
                    return True
                else:
                    self.printer(f"Couldn't erase partition {partitionname}. Either wrong memorytype " +
                                 f"given or no gpt partition.")
                    return False
            self.error(f"Error: Couldn't detect partition: {partitionname}")
            return False
        elif cmd == "es":
            if not self.check_param(["<start_sector>", "<sectors>"]):
                return False
            if options["--lun"] is not None:
                lun = int(options["--lun"])
            else:
                lun = 0
            start = int(options["<start_sector>"])
            sectors = int(options["<sectors>"])
            if self.firehose.modules is not None:
                self.firehose.modules.writeprepare()
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
            return do_tcp_server(self, options, self.handle_firehose)
        elif cmd == "modules":
            if not self.check_param(["<command>", "<options>"]):
                return False
            mcommand = options["<command>"]
            moptions = options["<options>"]
            if self.firehose.modules is None:
                self.error("Feature is not supported")
                return False
            else:
                return self.firehose.modules.run(command=mcommand, args=moptions)
        elif cmd == "qfil":
            self.info("[qfil] raw programming...")
            rawprogram = options["<rawprogram>"].split(",")
            imagedir = options["<imagedir>"]
            patch = options["<patch>"].split(",")
            for xml in rawprogram:
                filename = os.path.join(imagedir, xml)
                if os.path.exists(filename):
                    self.info("[qfil] programming %s" % xml)
                    fl = open(filename, "r")
                    for evt, elem in ET.iterparse(fl, events=["end"]):
                        if elem.tag == "program":
                            if elem.get("filename", ""):
                                filename = os.path.join(imagedir, elem.get("filename"))
                                if not os.path.isfile(filename):
                                    self.error("%s doesn't exist!" % filename)
                                    continue
                                partition_number = int(elem.get("physical_partition_number"))
                                num_disk_sectors = self.firehose.getlunsize(partition_number)
                                start_sector = elem.get("start_sector")
                                if "NUM_DISK_SECTORS" in start_sector:
                                    start_sector = start_sector.replace("NUM_DISK_SECTORS", str(num_disk_sectors))
                                if "-" in start_sector or "*" in start_sector or "/" in start_sector or \
                                        "+" in start_sector:
                                    start_sector = start_sector.replace(".", "")
                                    start_sector = eval(start_sector)
                                self.info(f"[qfil] programming {filename} to partition({partition_number})" +
                                          f"@sector({start_sector})...")

                                self.firehose.cmd_program(int(partition_number), int(start_sector), filename)
                else:
                    self.warning(f"File : {filename} not found.")
            self.info("[qfil] raw programming ok.")

            self.info("[qfil] patching...")
            for xml in patch:
                filename = os.path.join(imagedir, xml)
                self.info("[qfil] patching with %s" % xml)
                if os.path.exists(filename):
                    fl = open(filename, "r")
                    for evt, elem in ET.iterparse(fl, events=["end"]):
                        if elem.tag == "patch":
                            filename = elem.get("filename")
                            if filename != "DISK":
                                continue
                            start_sector = elem.get("start_sector")
                            size_in_bytes = elem.get("size_in_bytes")
                            self.info(
                                f"[qfil] patching {filename} sector({start_sector}), size={size_in_bytes}".format(
                                    filename=filename, start_sector=start_sector, size_in_bytes=size_in_bytes))
                            content = ElementTree.tostring(elem).decode("utf-8")
                            CMD = "<?xml version=\"1.0\" ?><data>\n {content} </data>".format(
                                content=content)
                            print(CMD)
                            self.firehose.xmlsend(CMD)
                else:
                    self.warning(f"File : {filename} not found.")
            self.info("[qfil] patching ok")

            bootable = self.find_bootable_partition(imagedir, rawprogram)
            if bootable != -1:
                if self.firehose.cmd_setbootablestoragedrive(bootable):
                    self.info("[qfil] partition({partition}) is now bootable\n".format(partition=bootable))
                else:
                    self.info(
                        "[qfil] set partition({partition}) as bootable failed\n".format(partition=bootable))

        else:
            self.error("Unknown/Missing command, a command is required.")
            return False
