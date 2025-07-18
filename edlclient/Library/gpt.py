#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import argparse
import copy
import logging
import logging.config
import os
import sys
from binascii import crc32
from binascii import hexlify
from enum import Enum
from struct import calcsize, unpack, pack

import colorama


class ColorFormatter(logging.Formatter):
    LOG_COLORS = {
        logging.ERROR: colorama.Fore.RED,
        logging.DEBUG: colorama.Fore.LIGHTMAGENTA_EX,
        logging.WARNING: colorama.Fore.YELLOW,
    }

    def format(self, record, *args, **kwargs):
        # if the corresponding logger has children, they may receive modified
        # record, so we want to keep it intact
        new_record = copy.copy(record)
        if new_record.levelno in self.LOG_COLORS:
            pad = ""
            if new_record.name != "root":
                print(new_record.name)
                pad = "[LIB]: "
            # we want levelname to be in different color, so let"s modify it
            new_record.msg = "{pad}{color_begin}{msg}{color_end}".format(
                pad=pad,
                msg=new_record.msg,
                color_begin=self.LOG_COLORS[new_record.levelno],
                color_end=colorama.Style.RESET_ALL,
            )
        # now we can let standart formatting take care of the rest
        return super(ColorFormatter, self).format(new_record, *args, **kwargs)


class LogBase(type):
    debuglevel = logging.root.level

    def __init__(cls, *args):
        super().__init__(*args)
        logger_attribute_name = "_" + cls.__name__ + "__logger"
        logger_debuglevel_name = "_" + cls.__name__ + "__debuglevel"
        logger_name = ".".join([c.__name__ for c in cls.mro()[-2::-1]])
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "root": {
                    "()": ColorFormatter,
                    "format": "%(name)s - %(message)s",
                }
            },
            "handlers": {
                "root": {
                    # "level": cls.__logger.level,
                    "formatter": "root",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                }
            },
            "loggers": {
                "": {
                    "handlers": ["root"],
                    # "level": cls.debuglevel,
                    "propagate": False
                }
            },
        }
        logging.config.dictConfig(log_config)
        logger = logging.getLogger(logger_name)

        setattr(cls, logger_attribute_name, logger)
        setattr(cls, logger_debuglevel_name, cls.debuglevel)
        cls.logsetup = logsetup


def logsetup(self, logger, loglevel):
    self.info = logger.info
    self.debug = logger.debug
    self.error = logger.error
    self.warning = logger.warning
    if loglevel == logging.DEBUG:
        logfilename = os.path.join("logs", "log.txt")
        if os.path.exists(logfilename):
            try:
                os.remove(logfilename)
            except:
                pass
        fh = logging.FileHandler(logfilename, encoding="utf-8")
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    self.loglevel = loglevel
    return logger


def read_object(data: object, definition: object) -> object:
    """
    Unpacks a structure using the given data and definition.
    """
    obj = {}
    object_size = 0
    pos = 0
    for (name, stype) in definition:
        object_size += calcsize(stype)
        obj[name] = unpack(stype, data[pos:pos + calcsize(stype)])[0]
        pos += calcsize(stype)
    obj["object_size"] = object_size
    obj["raw_data"] = data
    return obj


class structhelper:
    pos = 0

    def __init__(self, data, pos=0):
        self.pos = 0
        self.data = data

    def qword(self, big=False):
        e = ">" if big else "<"
        dat = unpack(e + "Q", self.data[self.pos:self.pos + 8])[0]
        self.pos += 8
        return dat

    def dword(self, big=False):
        e = ">" if big else "<"
        dat = unpack(e + "I", self.data[self.pos:self.pos + 4])[0]
        self.pos += 4
        return dat

    def dwords(self, dwords=1, big=False):
        e = ">" if big else "<"
        dat = unpack(e + str(dwords) + "I", self.data[self.pos:self.pos + 4 * dwords])
        self.pos += 4 * dwords
        return dat

    def qwords(self, qwords=1, big=False):
        e = ">" if big else "<"
        dat = unpack(e + str(qwords) + "Q", self.data[self.pos:self.pos + 8 * qwords])
        self.pos += 8 * qwords
        return dat

    def short(self, big=False):
        e = ">" if big else "<"
        dat = unpack(e + "H", self.data[self.pos:self.pos + 2])[0]
        self.pos += 2
        return dat

    def shorts(self, shorts, big=False):
        e = ">" if big else "<"
        dat = unpack(e + str(shorts) + "H", self.data[self.pos:self.pos + 2 * shorts])
        self.pos += 2 * shorts
        return dat

    def bytes(self, rlen=1):
        dat = self.data[self.pos:self.pos + rlen]
        self.pos += rlen
        if rlen == 1: return dat[0]
        return dat

    def string(self, rlen=1):
        dat = self.data[self.pos:self.pos + rlen]
        self.pos += rlen
        return dat

    def getpos(self):
        return self.pos

    def seek(self, pos):
        self.pos = pos


AB_FLAG_OFFSET = 6
AB_PARTITION_ATTR_SLOT_ACTIVE = (0x1 << 2)
AB_PARTITION_ATTR_BOOT_SUCCESSFUL = (0x1 << 6)
AB_PARTITION_ATTR_UNBOOTABLE = (0x1 << 7)
AB_SLOT_ACTIVE_VAL = 0x3F
AB_SLOT_INACTIVE_VAL = 0x0
AB_SLOT_ACTIVE = 1
AB_SLOT_INACTIVE = 0

PART_ATT_PRIORITY_BIT = 48
PART_ATT_ACTIVE_BIT = 50
PART_ATT_MAX_RETRY_CNT_BIT = 51
MAX_PRIORITY = 3
PART_ATT_SUCCESS_BIT = 54
PART_ATT_UNBOOTABLE_BIT = 55

PART_ATT_PRIORITY_VAL = 0x3 << PART_ATT_PRIORITY_BIT
PART_ATT_ACTIVE_VAL = 0x1 << PART_ATT_ACTIVE_BIT
PART_ATT_MAX_RETRY_COUNT_VAL = 0x7 << PART_ATT_MAX_RETRY_CNT_BIT
PART_ATT_SUCCESSFUL_VAL = 0x1 << PART_ATT_SUCCESS_BIT
PART_ATT_UNBOOTABLE_VAL = 0x1 << PART_ATT_UNBOOTABLE_BIT


class gpt(metaclass=LogBase):
    class gpt_header:
        def __init__(self, data):
            sh = structhelper(data)
            self.signature = sh.bytes(8)
            self.revision = sh.dword()
            self.header_size = sh.dword()
            self.crc32 = sh.dword()
            self.reserved = sh.dword()
            self.current_lba = sh.qword()
            self.backup_lba = sh.qword()
            self.first_usable_lba = sh.qword()
            self.last_usable_lba = sh.qword()
            self.disk_guid = sh.bytes(16)
            self.part_entry_start_lba = sh.qword()
            self.num_part_entries = sh.dword()
            self.part_entry_size = sh.dword()
            self.crc32_part_entries = sh.dword()

    class gpt_partition:
        def __init__(self, data):
            sh = structhelper(data)
            self.type = sh.bytes(16)
            self.unique = sh.bytes(16)
            self.first_lba = sh.qword()
            self.last_lba = sh.qword()
            self.flags = sh.qword()
            self.name = sh.string(72)

        def create(self):
            val = pack("<16s16sQQQ72s", self.type, self.unique, self.first_lba, self.last_lba, self.flags, self.name)
            return val

    class efi_type(Enum):
        EFI_UNUSED = 0x00000000
        EFI_MBR = 0x024DEE41
        EFI_SYSTEM = 0xC12A7328
        EFI_BIOS_BOOT = 0x21686148
        EFI_IFFS = 0xD3BFE2DE
        EFI_SONY_BOOT = 0xF4019732
        EFI_LENOVO_BOOT = 0xBFBFAFE7
        EFI_MSR = 0xE3C9E316
        EFI_BASIC_DATA = 0xEBD0A0A2
        EFI_LDM_META = 0x5808C8AA
        EFI_LDM = 0xAF9B60A0
        EFI_RECOVERY = 0xDE94BBA4
        EFI_GPFS = 0x37AFFC90
        EFI_STORAGE_SPACES = 0xE75CAF8F
        EFI_HPUX_DATA = 0x75894C1E
        EFI_HPUX_SERVICE = 0xE2A1E728
        EFI_LINUX_DAYA = 0x0FC63DAF
        EFI_LINUX_RAID = 0xA19D880F
        EFI_LINUX_ROOT32 = 0x44479540
        EFI_LINUX_ROOT64 = 0x4F68BCE3
        EFI_LINUX_ROOT_ARM32 = 0x69DAD710
        EFI_LINUX_ROOT_ARM64 = 0xB921B045
        EFI_LINUX_SWAP = 0x0657FD6D
        EFI_LINUX_LVM = 0xE6D6D379
        EFI_LINUX_HOME = 0x933AC7E1
        EFI_LINUX_SRV = 0x3B8F8425
        EFI_LINUX_DM_CRYPT = 0x7FFEC5C9
        EFI_LINUX_LUKS = 0xCA7D7CCB
        EFI_LINUX_RESERVED = 0x8DA63339
        EFI_FREEBSD_BOOT = 0x83BD6B9D
        EFI_FREEBSD_DATA = 0x516E7CB4
        EFI_FREEBSD_SWAP = 0x516E7CB5
        EFI_FREEBSD_UFS = 0x516E7CB6
        EFI_FREEBSD_VINUM = 0x516E7CB8
        EFI_FREEBSD_ZFS = 0x516E7CBA
        EFI_OSX_HFS = 0x48465300
        EFI_OSX_UFS = 0x55465300
        EFI_OSX_ZFS = 0x6A898CC3
        EFI_OSX_RAID = 0x52414944
        EFI_OSX_RAID_OFFLINE = 0x52414944
        EFI_OSX_RECOVERY = 0x426F6F74
        EFI_OSX_LABEL = 0x4C616265
        EFI_OSX_TV_RECOVERY = 0x5265636F
        EFI_OSX_CORE_STORAGE = 0x53746F72
        EFI_SOLARIS_BOOT = 0x6A82CB45
        EFI_SOLARIS_ROOT = 0x6A85CF4D
        EFI_SOLARIS_SWAP = 0x6A87C46F
        EFI_SOLARIS_BACKUP = 0x6A8B642B
        EFI_SOLARIS_USR = 0x6A898CC3
        EFI_SOLARIS_VAR = 0x6A8EF2E9
        EFI_SOLARIS_HOME = 0x6A90BA39
        EFI_SOLARIS_ALTERNATE = 0x6A9283A5
        EFI_SOLARIS_RESERVED1 = 0x6A945A3B
        EFI_SOLARIS_RESERVED2 = 0x6A9630D1
        EFI_SOLARIS_RESERVED3 = 0x6A980767
        EFI_SOLARIS_RESERVED4 = 0x6A96237F
        EFI_SOLARIS_RESERVED5 = 0x6A8D2AC7
        EFI_NETBSD_SWAP = 0x49F48D32
        EFI_NETBSD_FFS = 0x49F48D5A
        EFI_NETBSD_LFS = 0x49F48D82
        EFI_NETBSD_RAID = 0x49F48DAA
        EFI_NETBSD_CONCAT = 0x2DB519C4
        EFI_NETBSD_ENCRYPT = 0x2DB519EC
        EFI_CHROMEOS_KERNEL = 0xFE3A2A5D
        EFI_CHROMEOS_ROOTFS = 0x3CB8E202
        EFI_CHROMEOS_FUTURE = 0x2E0A753D
        EFI_HAIKU = 0x42465331
        EFI_MIDNIGHTBSD_BOOT = 0x85D5E45E
        EFI_MIDNIGHTBSD_DATA = 0x85D5E45A
        EFI_MIDNIGHTBSD_SWAP = 0x85D5E45B
        EFI_MIDNIGHTBSD_UFS = 0x0394EF8B
        EFI_MIDNIGHTBSD_VINUM = 0x85D5E45C
        EFI_MIDNIGHTBSD_ZFS = 0x85D5E45D
        EFI_CEPH_JOURNAL = 0x45B0969E
        EFI_CEPH_ENCRYPT = 0x45B0969E
        EFI_CEPH_OSD = 0x4FBD7E29
        EFI_CEPH_ENCRYPT_OSD = 0x4FBD7E29
        EFI_CEPH_CREATE = 0x89C57F98
        EFI_CEPH_ENCRYPT_CREATE = 0x89C57F98
        EFI_OPENBSD = 0x824CC7A0
        EFI_QNX = 0xCEF5A9AD
        EFI_PLAN9 = 0xC91818F9
        EFI_VMWARE_VMKCORE = 0x9D275380
        EFI_VMWARE_VMFS = 0xAA31E02A
        EFI_VMWARE_RESERVED = 0x9198EFFC

    def __init__(self, num_part_entries=0, part_entry_size=0, part_entry_start_lba=0, loglevel=logging.INFO, *args,
                 **kwargs):
        self.num_part_entries = num_part_entries
        self.__logger = self.__logger
        self.part_entry_size = part_entry_size
        self.part_entry_start_lba = part_entry_start_lba
        self.totalsectors = None
        self.header = None
        self.sectorsize = None
        self.partentries = []

        self.error = self.__logger.error
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename, encoding="utf-8")
            self.__logger.addHandler(fh)

    def parseheader(self, gptdata, sectorsize=512):
        return self.gpt_header(gptdata[sectorsize:sectorsize + 0x5C])

    def parse(self, gptdata, sectorsize=512):
        self.header = self.gpt_header(gptdata[sectorsize:sectorsize + 0x5C])
        self.sectorsize = sectorsize
        if self.header.signature != b"EFI PART":
            return False
        if self.header.revision != 0x10000:
            self.error("Unknown GPT revision.")
            return False
        if self.part_entry_start_lba != 0:
            start = self.part_entry_start_lba
        else:
            start = 2 * sectorsize  # mbr + header + part_table

        entrysize = self.header.part_entry_size
        self.partentries = {}

        class partf:
            unique = b""
            first_lba = 0
            last_lba = 0
            flags = 0
            sector = 0
            sectors = 0
            type = b""
            name = ""
            entryoffset = 0

        num_part_entries = self.header.num_part_entries

        for idx in range(0, num_part_entries):
            data = gptdata[start + (idx * entrysize):start + (idx * entrysize) + entrysize]
            if int(hexlify(data[16:32]), 16) == 0:
                break
            partentry = self.gpt_partition(data)
            pa = partf()
            guid1 = unpack("<I", partentry.unique[0:0x4])[0]
            guid2 = unpack("<H", partentry.unique[0x4:0x6])[0]
            guid3 = unpack("<H", partentry.unique[0x6:0x8])[0]
            guid4 = unpack("<H", partentry.unique[0x8:0xA])[0]
            guid5 = hexlify(partentry.unique[0xA:0x10]).decode('utf-8')
            pa.unique = "{:08x}-{:04x}-{:04x}-{:04x}-{}".format(guid1, guid2, guid3, guid4, guid5)
            pa.sector = partentry.first_lba
            pa.sectors = partentry.last_lba - partentry.first_lba + 1
            pa.flags = partentry.flags
            pa.entryoffset = (self.header.part_entry_start_lba * sectorsize) + (idx * entrysize)
            type = int(unpack("<I", partentry.type[0:0x4])[0])
            try:
                pa.type = self.efi_type(type).name
            except:
                pa.type = hex(type)
            pa.name = partentry.name.replace(b"\x00\x00", b"").decode('utf-16')
            if pa.type == "EFI_UNUSED":
                continue
            self.partentries[pa.name] = pa
        self.totalsectors = self.header.first_usable_lba + self.header.last_usable_lba
        return True

    def print(self):
        print(self.tostring())

    def tostring(self):
        mstr = "\nGPT Table:\n-------------\n"
        for partitionname in self.partentries:
            partition = self.partentries[partitionname]
            active = ((partition.flags >> (
                        AB_FLAG_OFFSET * 8)) & 0xFF) & AB_PARTITION_ATTR_SLOT_ACTIVE == AB_PARTITION_ATTR_SLOT_ACTIVE
            mstr += ("{:20} Offset 0x{:016x}, Length 0x{:016x}, Flags 0x{:016x}, UUID {}, Type {}, Active {}\n".format(
                partition.name + ":", partition.sector * self.sectorsize, partition.sectors * self.sectorsize,
                partition.flags, partition.unique, partition.type, active))
        mstr += ("\nTotal disk size:0x{:016x}, sectors:0x{:016x}\n".format(self.totalsectors * self.sectorsize,
                                                                           self.totalsectors))
        return mstr

    def generate_rawprogram(self, lun, sectorsize, directory):
        fname = "rawprogram" + str(lun) + ".xml"
        with open(os.path.join(directory, fname), "wb") as wf:
            mstr = "<?xml version=\"1.0\" ?>\n<data>\n"
            partofsingleimage = "false"
            readbackverify = "false"
            sparse = "false"
            for partname in self.partentries:
                partition = self.partentries[partname]
                filename = partition.name + ".bin"
                mstr += f"\t<program SECTOR_SIZE_IN_BYTES=\"{sectorsize}\" " + \
                        f"file_sector_offset=\"0\" " \
                        f"filename=\"{filename}\" " + \
                        f"label=\"{partition.name}\" " \
                        f"num_partition_sectors=\"{partition.sectors}\" " + \
                        f"partofsingleimage=\"{partofsingleimage}\" " \
                        f"physical_partition_number=\"{str(lun)}\" " + \
                        f"readbackverify=\"{readbackverify}\" " \
                        f"size_in_KB=\"{(partition.sectors * sectorsize / 1024):.1f}\" " \
                        f"sparse=\"{sparse}\" " + \
                        f"start_byte_hex=\"{hex(partition.sector * sectorsize)}\" " \
                        f"start_sector=\"{partition.sector}\"/>\n"
            partofsingleimage = "true"
            sectors = self.header.first_usable_lba
            mstr += f"\t<program SECTOR_SIZE_IN_BYTES=\"{sectorsize}\" " + \
                    f"file_sector_offset=\"0\" " + \
                    f"filename=\"gpt_main{str(lun)}.bin\" " + \
                    f"label=\"PrimaryGPT\" " + \
                    f"num_partition_sectors=\"{sectors}\" " + \
                    f"partofsingleimage=\"{partofsingleimage}\" " + \
                    f"physical_partition_number=\"{str(lun)}\" " + \
                    f"readbackverify=\"{readbackverify}\" " + \
                    f"size_in_KB=\"{(sectors * sectorsize / 1024):.1f}\" " + \
                    f"sparse=\"{sparse}\" " + \
                    f"start_byte_hex=\"0x0\" " + \
                    f"start_sector=\"0\"/>\n"
            sectors = self.header.first_usable_lba - 1
            mstr += f"\t<program SECTOR_SIZE_IN_BYTES=\"{sectorsize}\" " + \
                    f"file_sector_offset=\"0\" " + \
                    f"filename=\"gpt_backup{str(lun)}.bin\" " + \
                    f"label=\"BackupGPT\" " + \
                    f"num_partition_sectors=\"{sectors}\" " + \
                    f"partofsingleimage=\"{partofsingleimage}\" " + \
                    f"physical_partition_number=\"{str(lun)}\" " + \
                    f"readbackverify=\"{readbackverify}\" " + \
                    f"size_in_KB=\"{(sectors * sectorsize / 1024):.1f}\" " + \
                    f"sparse=\"{sparse}\" " + \
                    f"start_byte_hex=\"({sectorsize}*NUM_DISK_SECTORS)-{sectorsize * sectors}.\" " + \
                    f"start_sector=\"NUM_DISK_SECTORS-{sectors}.\"/>\n"
            mstr += "</data>"
            wf.write(bytes(mstr, "utf-8"))
            print(f"Wrote partition xml as {fname}")

    def print_gptfile(self, filename):
        try:
            filesize = os.stat(filename).st_size
            with open(filename, "rb") as rf:
                size = min(32 * 4096, filesize)
                data = rf.read(size)
                for sectorsize in [512, 4096]:
                    result = self.parse(data, sectorsize)
                    if result:
                        break
                if result:
                    print(self.tostring())
                return result
        except Exception as e:
            self.error(str(e))
        return ""

    def test_gpt(self):
        res = self.print_gptfile(os.path.join("TestFiles", "gpt_sm8180x.bin"))
        assert res, "GPT Partition wasn't decoded properly"

    def fix_gpt_crc(self, data):
        partentry_size = self.header.num_part_entries * self.header.part_entry_size
        partentry_offset = 2 * self.sectorsize
        partdata = data[partentry_offset:partentry_offset + partentry_size]
        headeroffset = self.sectorsize
        headerdata = bytearray(data[headeroffset:headeroffset + self.header.header_size])
        headerdata[0x58:0x58 + 4] = pack("<I", crc32(partdata))
        headerdata[0x10:0x10 + 4] = pack("<I", 0)
        headerdata[0x10:0x10 + 4] = pack("<I", crc32(headerdata))
        data[headeroffset:headeroffset + self.header.header_size] = headerdata
        return data

    def get_flag(self, filename, imagename):
        if "." in imagename:
            imagename = imagename[:imagename.find(".")]
        try:
            with open(filename, "rb") as rf:
                if os.stat(filename).st_size > 0x200000:
                    print("Error: GPT is too big or no GPT at all.")
                    return None
                data = rf.read()
                return self.get_flag_data(data, imagename)
        except FileNotFoundError:
            print(f"File not found : {filename}")
            return None, None

    def get_flag_data(self, gpt: bytes, imagename: str):
        for sectorsize in [512, 4096]:
            result = self.parse(gpt, sectorsize)
            if result:
                for partition in self.partentries:
                    if imagename in partition.name.lower():
                        return partition.sector, sectorsize
        return None, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GPT utils")
    parser.add_argument("image", help="The path of the GPT disk image")
    subparsers = parser.add_subparsers(dest="command", help="sub-command help")

    parser_print = subparsers.add_parser("print", help="Print the gpt table")
    parser_test = subparsers.add_parser("test", help="Run self-test")
    parser_patch = subparsers.add_parser("patch", help="Set active boot slot")
    parser_patch.add_argument("partition", help="Extract specific partitions (separated by comma)")
    parser_patch.add_argument("-active", action="store_true", help="Set bootable")
    parser_extract = subparsers.add_parser("extract", help="Extract the partitions")
    parser_extract.add_argument("-out", "-o", help="The path to extract the partitions")
    parser_extract.add_argument("-partition", "-p", help="Extract specific partitions (separated by comma)")

    args = parser.parse_args()
    if args.command not in ["print", "extract", "test", "patch"]:
        parser.error("Command is mandatory")

    gp = gpt()
    if args.command == "print":
        if not os.path.exists(args.image):
            print(f"File {args.image} does not exist. Aborting.")
            sys.exit(1)
        gp.print_gptfile(args.image)
    elif args.command == "test":
        gp.test_gpt()
    elif args.command == "patch":
        partitition = args.partition
        active = args.active
        filesize = os.stat(args.image).st_size
        with open(args.image, "rb") as rf:
            size = min(32 * 4096, filesize)
            data = bytearray(rf.read(size))
            pdata, poffset = gp.patch(data, partitition, active=active)
            data[poffset:poffset + len(pdata)] = pdata
            wdata = gp.fix_gpt_crc(data)
            if data is not None:
                wfilename = args.image + ".patched"
                with open(wfilename, "wb") as wf:
                    wf.write(wdata)
                print(f"Successfully wrote patched gpt to {wfilename}")
            else:
                print("Error on setting bootable mode")
    elif args.command == "extract":
        if not os.path.exists(args.image):
            print(f"File {args.image} does not exist. Aborting.")
            sys.exit(1)
        filesize = os.stat(args.image).st_size
        with open(args.image, "rb", buffering=1024 * 1024) as rf:
            data = rf.read(min(32 * 4096, filesize))
            ssize = None
            for sectorsize in [512, 4096]:
                result = gp.parse(data, sectorsize)
                if result:
                    ssize = sectorsize
                    break
            if ssize is not None:
                if args.partition == "gpt":
                    print(f"Extracting gpt to gpt.bin at {hex(0)}, length {hex(32 * ssize)}")
                    rf.seek(0)
                    data = rf.read(32 * ssize)
                    with open("gpt.bin", "wb") as wf:
                        wf.write(data)
                else:
                    for partition in gp.partentries:
                        if args.partition is not None:
                            if partition.name.lower() != args.partition:
                                continue
                        name = partition.name
                        start = partition.sector * ssize
                        length = partition.sectors * ssize
                        out = args.out
                        if out is None:
                            out = "."
                        else:
                            if not os.path.exists(out):
                                os.makedirs(out)
                        filename = os.path.join(out, name) + ".bin"
                        print(f"Extracting {name} to {filename} at {hex(start)}, length {hex(length)}")
                        rf.seek(start)
                        bytestoread = length
                        with open(filename, "wb", buffering=1024 * 1024) as wf:
                            while bytestoread > 0:
                                size = min(bytestoread, 0x200000)
                                data = rf.read(size)
                                wf.write(data)
                                bytestoread -= size
