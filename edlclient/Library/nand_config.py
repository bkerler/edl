#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import ctypes
from enum import Enum
from edlclient.Config.qualcomm_config import secgen, secureboottbl

c_uint8 = ctypes.c_uint8

# nandbase MSM_NAND_BASE
# qfprom SECURITY_CONTROL_BASE_PHYS
config_tbl = {
    #           bam nandbase bcraddr    secureboot          pbl                   qfprom                memtbl
    3: ["9x25", 1, 0xf9af0000, 0xfc401a40, secureboottbl["MDM9x25"], secgen[2][0], secgen[2][1], secgen[2][2]],
    8: ["9x35", 1, 0xf9af0000, 0xfc401a40, secureboottbl["MDM9x35"], secgen[2][0], secgen[2][1], secgen[2][2]],
    10: ["9x45", 1, 0x79B0000, 0x183f000, secureboottbl["MDM9x45"], secgen[2][0], secgen[2][1], secgen[2][2]],
    16: ["9x55", 0, 0x79B0000, 0x183f000, secureboottbl["MDM9x45"], secgen[5][0], secgen[5][1], secgen[5][2]],
    17: ["9x60", 0, 0x79B0000, 0x183f000, secureboottbl["MDM9x60"], secgen[5][0], secgen[5][1], secgen[5][2]],
    12: ["9x07", 0, 0x79B0000, 0x183f000, secureboottbl["MDM9607"], secgen[5][0], secgen[5][1], secgen[5][2]]
}

supported_flash = {
    # Flash ID   Density(MB)  Wid Pgsz  Blksz        oobsz onenand   Manuf */
    0x2690ac2c: [(512 << 20), 0, 4096, (4096 << 6), 224, 0],  # QUECTEL_NAND_FM6BD4G2GXA
    0x2690ac98: [(512 << 20), 0, 4096, (4096 << 6), 256, 0],  # QUECTEL_NAND_NM14FSK2LAXCL
    0x1500aa98: [(256 << 20), 0, 2048, (2048 << 6), 64, 0],
    0x5500ba98: [(256 << 20), 1, 2048, (2048 << 6), 64, 0],
    0xd580b12c: [(256 << 20), 1, 2048, (2048 << 6), 64, 0],
    0x5590bc2c: [(512 << 20), 1, 2048, (2048 << 6), 64, 0],
    0x1580aa2c: [(256 << 20), 0, 2048, (2048 << 6), 64, 0],
    0x1590aa2c: [(256 << 20), 0, 2048, (2048 << 6), 64, 0],
    0x1590ac2c: [(512 << 20), 0, 2048, (2048 << 6), 64, 0],
    0x5580baad: [(256 << 20), 1, 2048, (2048 << 6), 64, 0],
    0x5510baad: [(256 << 20), 1, 2048, (2048 << 6), 64, 0],
    # 0x004000ec: [(256 << 20), 0, 2048, (2048 << 6), 64, 1],
    # 0x005c00ec: [(256 << 20), 0, 2048, (2048 << 6), 64, 1],
    # 0x005800ec: [(256 << 20), 0, 2048, (2048 << 6), 64, 1],
    0x5580ba2c: [(256 << 20), 1, 2048, (2048 << 6), 64, 0],
    0x6600b3ec: [(1024 << 20), 1, 4096, (4096 << 6), 128, 0],
    0x55d1b32c: [(1024 << 20), 1, 2048, (2048 << 6), 64, 0]
    # 0x1500aaec: 0xFF00FFFF, (256 << 20), 0, 2048, (2048 << 6), 64, 0],
    # 0x5500baec: 0xFF00FFFF, (256 << 20), 1, 2048, (2048 << 6), 64, 0},	/*Sams */
    # 0x6600bcec: 0xFF00FFFF, (512 << 20), 1, 4096, (4096 << 6), 128, 0},	/*Sams */
    # 0x2600482c: 0xFF00FFFF, (2048 << 20), 0, 4096, (4096 << 7), 224, 0},	/*8bit bch ecc */
}


class BadFlags(Enum):
    BAD_UNDEF = 0
    BAD_FILL = 1
    BAD_SKIP = 2
    BAD_IGNORE = 3
    BAD_DISABLE = 4


nand_ids = [
    ("NAND 16MiB 1,8V 8-bit", 0x33, 16),
    ("NAND 16MiB 3,3V 8-bit", 0x73, 16),
    ("NAND 16MiB 1,8V 16-bit", 0x43, 16),
    ("NAND 16MiB 3,3V 16-bit", 0x53, 16),

    ("NAND 32MiB 1,8V 8-bit", 0x35, 32),
    ("NAND 32MiB 3,3V 8-bit", 0x75, 32),
    ("NAND 32MiB 1,8V 16-bit", 0x45, 32),
    ("NAND 32MiB 3,3V 16-bit", 0x55, 32),

    ("NAND 64MiB 1,8V 8-bit", 0x36, 64),
    ("NAND 64MiB 3,3V 8-bit", 0x76, 64),
    ("NAND 64MiB 1,8V 16-bit", 0x46, 64),
    ("NAND 64MiB 3,3V 16-bit", 0x56, 64),

    ("NAND 128MiB 1,8V 8-bit", 0x78, 128),
    ("NAND 128MiB 1,8V 8-bit", 0x39, 128),
    ("NAND 128MiB 3,3V 8-bit", 0x79, 128),
    ("NAND 128MiB 1,8V 16-bit", 0x72, 128),
    ("NAND 128MiB 1,8V 16-bit", 0x49, 128),
    ("NAND 128MiB 3,3V 16-bit", 0x74, 128),
    ("NAND 128MiB 3,3V 16-bit", 0x59, 128),
    ("NAND 256MiB 3,3V 8-bit", 0x71, 256),

    # 512 Megabit
    ("NAND 64MiB 1,8V 8-bit", 0xA2, 64),
    ("NAND 64MiB 1,8V 8-bit", 0xA0, 64),
    ("NAND 64MiB 3,3V 8-bit", 0xF2, 64),
    ("NAND 64MiB 3,3V 8-bit", 0xD0, 64),
    ("NAND 64MiB 1,8V 16-bit", 0xB2, 64),
    ("NAND 64MiB 1,8V 16-bit", 0xB0, 64),
    ("NAND 64MiB 3,3V 16-bit", 0xC2, 64),
    ("NAND 64MiB 3,3V 16-bit", 0xC0, 64),

    # 1 Gigabit
    ("NAND 128MiB 1,8V 8-bit", 0xA1, 128),
    ("NAND 128MiB 3,3V 8-bit", 0xF1, 128),
    ("NAND 128MiB 3,3V 8-bit", 0xD1, 128),
    ("NAND 128MiB 1,8V 16-bit", 0xB1, 128),
    ("NAND 128MiB 3,3V 16-bit", 0xC1, 128),
    ("NAND 128MiB 1,8V 16-bit", 0xAD, 128),

    # 2 Gigabit
    ("NAND 256MiB 1.8V 8-bit", 0xAA, 256),
    ("NAND 256MiB 3.3V 8-bit", 0xDA, 256),
    ("NAND 256MiB 1.8V 16-bit", 0xBA, 256),
    ("NAND 256MiB 3.3V 16-bit", 0xCA, 256),

    # 4 Gigabit
    ("NAND 512MiB 1.8V 8-bit", 0xAC, 512),
    ("NAND 512MiB 3.3V 8-bit", 0xDC, 512),
    ("NAND 512MiB 1.8V 16-bit", 0xBC, 512),
    ("NAND 512MiB 3.3V 16-bit", 0xCC, 512),

    # 8 Gigabit
    ("NAND 1GiB 1.8V 8-bit", 0xA3, 1024),
    ("NAND 1GiB 3.3V 8-bit", 0xD3, 1024),
    ("NAND 1GiB 1.8V 16-bit", 0xB3, 1024),
    ("NAND 1GiB 3.3V 16-bit", 0xC3, 1024),

    # 16 Gigabit
    ("NAND 2GiB 1.8V 8-bit", 0xA5, 2048),
    ("NAND 2GiB 3.3V 8-bit", 0xD5, 2048),
    ("NAND 2GiB 1.8V 16-bit", 0xB5, 2048),
    ("NAND 2GiB 3.3V 16-bit", 0xC5, 2048),

    # 32 Gigabit
    ("NAND 4GiB 1.8V 8-bit", 0xA7, 4096),
    ("NAND 4GiB 3.3V 8-bit", 0xD7, 4096),
    ("NAND 4GiB 1.8V 16-bit", 0xB7, 4096),
    ("NAND 4GiB 3.3V 16-bit", 0xC7, 4096),

    # 64 Gigabit
    ("NAND 8GiB 1.8V 8-bit", 0xAE, 8192),
    ("NAND 8GiB 3.3V 8-bit", 0xDE, 8192),
    ("NAND 8GiB 1.8V 16-bit", 0xBE, 8192),
    ("NAND 8GiB 3.3V 16-bit", 0xCE, 8192),

    # 128 Gigabit
    ("NAND 16GiB 1.8V 8-bit", 0x1A, 16384),
    ("NAND 16GiB 3.3V 8-bit", 0x3A, 16384),
    ("NAND 16GiB 1.8V 16-bit", 0x2A, 16384),
    ("NAND 16GiB 3.3V 16-bit", 0x4A, 16384),

    # 256 Gigabit
    ("NAND 32GiB 1.8V 8-bit", 0x1C, 32768),
    ("NAND 32GiB 3.3V 8-bit", 0x3C, 32768),
    ("NAND 32GiB 1.8V 16-bit", 0x2C, 32768),
    ("NAND 32GiB 3.3V 16-bit", 0x4C, 32768),

    # 512 Gigabit
    ("NAND 64GiB 1.8V 8-bit", 0x1E, 65536),
    ("NAND 64GiB 3.3V 8-bit", 0x3E, 65536),
    ("NAND 64GiB 1.8V 16-bit", 0x2E, 65536),
    ("NAND 64GiB 3.3V 16-bit", 0x4E, 65536),
    (0, 0, 0),
]

nand_manuf_ids = [
    (0x98, "Toshiba"),
    (0xec, "Samsung"),
    (0x04, "Fujitsu"),
    (0x8f, "National"),
    (0x07, "Renesas"),
    (0x20, "ST Micro"),
    (0xad, "Hynix"),
    (0x2c, "Micron"),
    (0xc8, "Elite Semiconductor"),
    (0x01, "Spansion/AMD"),
    (0xef, "Winbond"),
    (0x0, "")
]

toshiba_tbl = {
    # small_slc,device_width,density_mbits
    0x36: [True, 8, 512],
    0x46: [True, 16, 512],
    0x79: [True, 8, 1024],
    0xA0: [False, -1, 512],
    0xB0: [False, -1, 512],
    0xC0: [False, -1, 512],
    0xD0: [False, -1, 512],
    0xA1: [False, -1, 1024],
    0xB1: [False, -1, 1024],
    0xC1: [False, -1, 1024],
    0xD1: [False, -1, 1024],
    0xAA: [False, -1, 2048],
    0xBA: [False, -1, 2048],
    0xCA: [False, -1, 2048],
    0xDA: [False, -1, 2048],
    0xAC: [False, -1, 4096],
    0xBC: [False, -1, 4096],
    0xCC: [False, -1, 4096],
    0xDC: [False, -1, 4096],
    0xA3: [False, -1, 8192],
    0xB3: [False, -1, 8192],
    0xC3: [False, -1, 8192],
    0xD3: [False, -1, 8192],
    0xA5: [False, -1, 16384],
    0xB5: [False, -1, 16384],
    0xC5: [False, -1, 16384],
    0xD5: [False, -1, 16384],
}

samsung_tbl = {
    # small_slc,device_width,density_mbits
    0x45: [True, 16, 256],
    0x55: [True, 16, 256],
    0x35: [True, 8, 256],
    0x75: [True, 8, 256],
    0x46: [True, 16, 512],
    0x56: [True, 16, 512],
    0x76: [True, 8, 512],
    0x36: [True, 8, 512],
    0x72: [True, 16, 1024],
    0x74: [True, 16, 1024],
    0x79: [True, 8, 1024],
    0x78: [True, 8, 1024],
    0x71: [True, 8, 2048],
    0xDC: [True, 8, 4096],
    0xA1: [False, -1, 1024],
    0xB1: [False, -1, 1024],
    0xC1: [False, -1, 1024],
    0xD1: [False, -1, 1024],
    0xAA: [False, -1, 2048],
    0xBA: [False, -1, 2048],
    0xCA: [False, -1, 2048],
    0xDA: [False, -1, 2048],
    0xAC: [False, -1, 4096],
    0xBC: [False, -1, 4096],
    0xCC: [False, -1, 4096],
    0xA3: [False, -1, 8192],
    0xB3: [False, -1, 8192],
    0xC3: [False, -1, 8192],
    0xD3: [False, -1, 8192],
    0xA5: [False, -1, 16384],
    0xB5: [False, -1, 16384],
    0xC5: [False, -1, 16384],
    0xD5: [False, -1, 16384]
}


class SettingsOpt:
    def __init__(self, parent, chipset):
        self.PAGESIZE = 4096
        self.parent = parent
        self.bad_loader = 0
        self.sectors_per_page = 0
        self.sectorsize = 512
        self.flash_mfr = ""
        self.flash_descr = ""
        self.flash_fid = 0
        self.flash_pid = 0
        self.IsWideFlash = 0
        self.badsector = 0
        self.badflag = 0
        self.badposition = 0
        self.badplace = 0
        self.bch_mode = 0
        self.ecc_size = 0
        self.ecc_bit = 0
        self.num_pages_per_blk = 64
        self.udflag = 0
        self.sahara = 1
        self.args_disable_ecc = 0  # 0=enable, 1=disable
        self.bad_processing_flag = BadFlags.BAD_SKIP.value
        self.cwsize = 0
        self.rflag = 0
        self.cfg1_enable_bch_ecc = 0
        self.bad_loader = 0
        self.OOBSIZE = 0
        self.MAXBLOCK = 0
        self.UD_SIZE_BYTES = 516
        self.BAD_BLOCK_BYTE_NUM = 0
        self.BAD_BLOCK_IN_SPARE_AREA = 0
        self.ECC_MODE = 0
        self.bad_loader = 1
        self.secureboot = secureboottbl["MDM9607"]
        self.pbl = secgen[5][0]
        self.qfprom = secgen[5][1]
        self.memtbl = secgen[5][2]
        self.chipname = "Unknown"
        if chipset in config_tbl:
            self.chipname, self.bam, self.nandbase, self.bcraddr, self.secureboot, self.pbl, \
                self.qfprom, self.memtbl = config_tbl[chipset]
            self.bad_loader = 0
        else:
            loadername = parent.sahara.programmer.lower()
            for chipid in config_tbl:
                if config_tbl[chipid][0] in loadername:
                    self.chipname, self.bam, self.nandbase, self.bcraddr, self.secureboot, \
                        self.pbl, self.qfprom, self.memtbl = config_tbl[chipid]
                    self.bad_loader = 0
        if chipset == 0xFF:
            self.bad_loader = 0


class nand_toshiba_ids(ctypes.LittleEndianStructure):
    _fields_ = [
        ("mid", c_uint8, 8),
        ("did", c_uint8, 8),
        ("icn", c_uint8, 2),
        ("bpc", c_uint8, 2),
        ("rsvd0", c_uint8, 4),
        ("page_size", c_uint8, 2),
        ("spare_size", c_uint8, 2),
        ("block_size", c_uint8, 2),
        ("org", c_uint8, 1),
        ("rsvd1", c_uint8, 1),
        ("rsvd2", c_uint8, 8),
    ]


class nand_toshiba_id_t(ctypes.Union):
    _anonymous_ = ("bit",)
    _fields_ = [
        ("bit", nand_toshiba_ids),
        ("asDword", ctypes.c_uint32)
    ]


class nand_samsung_ids(ctypes.LittleEndianStructure):
    _fields_ = [
        ("mid", c_uint8, 8),
        ("did", c_uint8, 8),
        ("icn", c_uint8, 2),
        ("bpc", c_uint8, 2),
        ("nspp", c_uint8, 2),
        ("ip", c_uint8, 1),
        ("cp", c_uint8, 1),
        ("page_size", c_uint8, 2),
        ("spare_size", c_uint8, 2),
        ("sam0", c_uint8, 1),
        ("block_size", c_uint8, 2),
        ("org", c_uint8, 1),
        ("sam1", c_uint8, 1),
        ("ecc", c_uint8, 2),
        ("plane", c_uint8, 2),
        ("plane_size", c_uint8, 3),
        ("rsvd", c_uint8, 1),
    ]


class nand_samsung_id_t(ctypes.Union):
    _anonymous_ = ("bit",)
    _fields_ = [
        ("bit", nand_toshiba_ids),
        ("asDword", ctypes.c_uint32)
    ]


class NandDevice:
    # NAND_DEVn_CFG0 bits
    DISABLE_STATUS_AFTER_WRITE = 4
    CW_PER_PAGE = 6
    UD_SIZE_BYTES = 9
    ECC_PARITY_SIZE_BYTES_RS = 19
    SPARE_SIZE_BYTES = 23
    NUM_ADDR_CYCLES = 27
    STATUS_BFR_READ = 30
    SET_RD_MODE_AFTER_STATUS = 31

    # NAND_DEV1_CFG0 bits
    DEV0_CFG1_ECC_DISABLE = 0
    WIDE_FLASH = 1
    NAND_RECOVERY_CYCLES = 2
    CS_ACTIVE_BSY = 5
    BAD_BLOCK_BYTE_NUM = 6
    BAD_BLOCK_IN_SPARE_AREA = 16
    WR_RD_BSY_GAP = 17
    ENABLE_BCH_ECC = 27
    ECC_ENCODER_CGC_EN = 23
    ECC_DECODER_CGC_EN = 24
    DISABLE_ECC_RESET_AFTER_OPDONE = 25
    ENABLE_NEW_ECC = 27
    ECC_MODE_DEV1 = 28  # 28:29

    # NAND_DEV0_ECC_CFG bits
    ECC_CFG_ECC_DISABLE = 0
    ECC_SW_RESET = 1
    ECC_MODE = 4
    ECC_PARITY_SIZE_BYTES_BCH = 8
    ECC_NUM_DATA_BYTES = 16
    ECC_ENC_CLK_SHUTDOWN = 28
    ECC_DEC_CLK_SHUTDOWN = 29
    ECC_FORCE_CLK_OPEN = 30

    # NAND_DEV_CMD1 bits
    READ_ADDR = 0

    # NAND_DEV_CMD_VLD bits
    READ_START_VLD = 0
    READ_STOP_VLD = 1
    WRITE_START_VLD = 2
    ERASE_START_VLD = 3
    SEQ_READ_START_VLD = 4

    NAND_CMD_PARAM = 0xec
    ECC_BCH_4BIT = 2

    def __init__(self, settings):
        self.settings = settings
        # device commands
        self.NAND_CMD_SOFT_RESET = 0x01
        self.NAND_CMD_PAGE_READ = 0x32
        self.NAND_CMD_PAGE_READ_ECC = 0x33
        self.NAND_CMD_PAGE_READ_ALL = 0x34
        self.NAND_CMD_SEQ_PAGE_READ = 0x15
        self.NAND_CMD_PRG_PAGE = 0x36
        self.NAND_CMD_PRG_PAGE_ECC = 0x37
        self.NAND_CMD_PRG_PAGE_ALL = 0x39
        self.NAND_CMD_BLOCK_ERASE = 0x3A
        self.NAND_CMD_FETCH_ID = 0x0B
        self.NAND_CMD_STATUS = 0x0C
        self.NAND_CMD_RESET = 0x0D

        # addr offsets
        self.NAND_FLASH_CMD = settings.nandbase + 0
        self.NAND_ADDR0 = settings.nandbase + 4
        self.NAND_ADDR1 = settings.nandbase + 8
        self.NAND_FLASH_CHIP_SELECT = settings.nandbase + 0xc
        self.NAND_EXEC_CMD = settings.nandbase + 0x10
        self.NAND_FLASH_STATUS = settings.nandbase + 0x14
        self.NAND_BUFFER_STATUS = settings.nandbase + 0x18
        self.NAND_DEV0_CFG0 = settings.nandbase + 0x20
        self.NAND_DEV0_CFG1 = settings.nandbase + 0x24
        self.NAND_DEV0_ECC_CFG = settings.nandbase + 0x28
        self.NAND_DEV1_ECC_CFG = settings.nandbase + 0x2C
        self.NAND_DEV1_CFG0 = settings.nandbase + 0x30
        self.NAND_DEV1_CFG1 = settings.nandbase + 0x34
        self.NAND_SFLASHC_CMD = settings.nandbase + 0x38
        self.NAND_SFLASHC_EXEC = settings.nandbase + 0x3C
        self.NAND_READ_ID = settings.nandbase + 0x40
        self.NAND_READ_STATUS = settings.nandbase + 0x44
        self.NAND_CONFIG_DATA = settings.nandbase + 0x50
        self.NAND_CONFIG = settings.nandbase + 0x54
        self.NAND_CONFIG_MODE = settings.nandbase + 0x58
        self.NAND_CONFIG_STATUS = settings.nandbase + 0x60
        self.NAND_DEV_CMD0 = settings.nandbase + 0xA0
        self.NAND_DEV_CMD1 = settings.nandbase + 0xA4
        self.NAND_DEV_CMD2 = settings.nandbase + 0xA8
        self.NAND_DEV_CMD_VLD = settings.nandbase + 0xAC
        self.SFLASHC_BURST_CFG = settings.nandbase + 0xE0
        self.NAND_EBI2_ECC_BUF_CFG = settings.nandbase + 0xF0
        self.NAND_HW_INFO = settings.nandbase + 0xFC
        self.NAND_FLASH_BUFFER = settings.nandbase + 0x100

        self.PAGE_ACC = 1 << 4
        self.LAST_PAGE = 1 << 5
        self.CW_PER_PAGE = 6
        self.ECC_CFG_ECC_DISABLE = 0
        self.flashinfo = None

    def gettbl(self, nandid, tbl):
        flashinfo = {}
        tid = nand_toshiba_id_t()
        tid.asDword = nandid
        # did,slc_small_device,device_width,density_mbits
        if tid.did in tbl:
            fdev = tbl[tid.did]
            small_slc = fdev[0]
            slc_device_width = fdev[1]
            density_mbits = fdev[2]
        else:
            return None

        if small_slc:
            flashinfo["page_size"] = 512
            flashinfo["feature_flags1_ecc"] = 2
            flashinfo["block_size_kbytes"] = 16
            flashinfo["param_per_block"] = 32
            flashinfo["spare_size"] = 16
            flashinfo["otp_sequence_cfg"] = "FLASH_NAND_OTP_SEQUENCE_CFG6"
            flashinfo["dev_width"] = slc_device_width
        else:
            if tid.org == 0:
                flashinfo["dev_width"] = 8
            else:
                flashinfo["dev_width"] = 16
            if tid.spare_size == 0 or tid.spare_size == 1:
                flashinfo["feature_flags1_ecc"] = 1
            elif tid.spare_size == 2:
                flashinfo["feature_flags1_ecc"] = 8
            else:
                flashinfo["feature_flags1_ecc"] = 0
            flashinfo["page_size"] = 1024 << tid.page_size
            flashinfo["page_size_kb"] = flashinfo["page_size"] >> 10
            flashinfo["block_size_kb"] = 64 << tid.block_size
            flashinfo["pages_per_block"] = flashinfo["block_size_kb"] // flashinfo["page_size_kb"]
            flashinfo["spare_size"] = (8 << tid.spare_size) * (flashinfo["page_size"] // 512)
            if flashinfo["page_size"] == 2048 or flashinfo["page_size"] == 4096:
                flashinfo["otp_sequence_cfg"] = "FLASH_NAND_OTP_SEQUENCE_CFG2"
            else:
                flashinfo["otp_sequence_cfg"] = "FLASH_NAND_OTP_SEQUENCE_UNKNOWN"
            flashinfo["block_count"] = (1024 // 8 * density_mbits) // flashinfo["block_size_kb"]
            if flashinfo["page_size"] == 2048 and flashinfo["feature_flags1_ecc"] > 0:
                flashinfo["bad_block_info_byte_offset"] = 2048
                flashinfo["udata_max"] = 16
                flashinfo["max_corrected_udata_bytes"] = 16
                flashinfo["bad_block_info_byte_length"] = 1 if flashinfo["dev_width"] == 8 else 2
            elif flashinfo["page_size"] == 4096 and flashinfo["feature_flags1_ecc"] > 0:
                flashinfo["bad_block_info_byte_offset"] = 4096
                flashinfo["udata_max"] = 32
                flashinfo["max_corrected_udata_bytes"] = 32
                flashinfo["bad_block_info_byte_length"] = 1 if flashinfo["dev_width"] == 8 else 2
        self.settings.PAGESIZE = flashinfo["page_size"]
        self.settings.BLOCKSIZE = flashinfo["block_size_kb"] * 1024
        if flashinfo["dev_width"] == 8:
            self.settings.IsWideFlash = 0
        else:
            self.settings.IsWideFlash = 1
        self.settings.MAXBLOCK = flashinfo["block_count"]

        self.settings.BAD_BLOCK_IN_SPARE_AREA = flashinfo["bad_block_info_byte_offset"]
        return flashinfo

    def toshiba_config(self, nandid):
        flashinfo = self.gettbl(nandid, toshiba_tbl)
        self.flashinfo = flashinfo
        if (nandid >> 8) & 0xFF == 0xac:
            self.settings.OOBSIZE = 256
            self.settings.PAGESIZE = 4096
            self.settings.MAXBLOCK = 2048
            # 8Bit_HW_ECC
        elif (nandid >> 8) & 0xFF == 0xaa:
            self.settings.OOBSIZE = 128
            self.settings.PAGESIZE = 2048
            self.settings.MAXBLOCK = 2048
            # 8Bit_HW_ECC
        elif (nandid >> 8) & 0xFF == 0xa1:
            self.settings.OOBSIZE = 128
            self.settings.PAGESIZE = 2048
            self.settings.MAXBLOCK = 1024
            # 8Bit_HW_ECC

        self.settings.CW_PER_PAGE = (self.settings.PAGESIZE >> 9) - 1
        self.settings.SPARE_SIZE_BYTES = 0

    def samsung_config(self, nandid):
        flashinfo = self.gettbl(nandid, samsung_tbl)
        self.flashinfo = flashinfo

        # self.settings.SPARE_SIZE_BYTES = flashinfo["spare_size"]
        self.settings.CW_PER_PAGE = (self.settings.PAGESIZE >> 9) - 1
        self.settings.SPARE_SIZE_BYTES = 0

    def generic_config(self, nandid, chipsize):
        devcfg = (nandid >> 24) & 0xff
        self.settings.PAGESIZE = 1024 << (devcfg & 0x3)
        self.settings.BLOCKSIZE = 64 << ((devcfg >> 4) & 0x3)

        if chipsize != 0:
            self.settings.MAXBLOCK = chipsize * 1024 // self.settings.BLOCKSIZE
        else:
            self.settings.MAXBLOCK = 0x800
        self.settings.CW_PER_PAGE = (self.settings.PAGESIZE >> 9) - 1

    def nand_setup(self, nandid):
        """
        qcommand -p%qdl% -k11 -c "m 79b0020 295409c0" #NAND_DEV0_CFG0
        qcommand -p%qdl% -k11 -c "m 79b0024 08065d5d" #NAND_DEV0_CFG1
        qcommand -p%qdl% -k11 -c "m 79b0028 42040d10" #NAND_DEV0_ECC_CFG
        qcommand -p%qdl% -k11 -c "m 79b00f0 00000203" NAND_EBI2_ECC_BUF_CFG
        """

        fid = (nandid >> 8) & 0xff
        pid = nandid & 0xff
        self.settings.flash_fid = fid
        self.settings.flash_pid = pid
        self.settings.flash_mfr = ""
        for info in nand_manuf_ids:
            if info[0] == pid:
                self.settings.flash_mfr = info[1]
                break

        chipsize = 0
        for info in nand_ids:
            if info[1] == fid:
                chipsize = info[2]
                self.settings.flash_descr = info[0]
                break

        self.settings.cfg1_enable_bch_ecc = 1
        self.settings.IsWideFlash = 0
        self.settings.SPARE_SIZE_BYTES = 0
        self.settings.OOBSIZE = 0
        self.settings.ECC_PARITY_SIZE_BYTES = 0
        self.settings.BAD_BLOCK_BYTE_NUM = 0
        self.settings.ecc_bit = 4

        if pid == 0x98:  # Toshiba
            self.toshiba_config(nandid)
            if nandid == 0x2690AC98:
                self.settings.ecc_bit = 8
        elif pid == 0xEC:  # Samsung
            self.samsung_config(nandid)
        elif pid == 0x2C:  # Micron
            self.generic_config(nandid, chipsize)
            # MT29AZ5A3CHHWD
            if nandid == 0x2690AC2C or nandid == 0x26D0A32C:
                self.settings.ecc_bit = 8
        elif pid == 0x01:
            self.generic_config(nandid, chipsize)
            if nandid == 0x1590AC01:  # jsfc 4G
                self.settings.OOBSIZE = 128
                self.settings.PAGESIZE = 2048
                self.settings.SPARE_SIZE_BYTES = 4
        else:
            self.generic_config(nandid, chipsize)

        if nandid in supported_flash:
            nd = supported_flash[nandid]
            # density = nd[]
            # width
            chipsize = nd[0] // 1024
            self.settings.IsWideFlash = nd[1]
            self.settings.PAGESIZE = nd[2]
            self.settings.BLOCKSIZE = nd[3]
            self.settings.OOBSIZE = nd[4]
            self.settings.IsOneNand = nd[5]

        if chipsize != 0:
            self.settings.MAXBLOCK = chipsize * 1024 // self.settings.BLOCKSIZE
        else:
            self.settings.MAXBLOCK = 0x800

        self.settings.sectorsize = 512
        self.settings.sectors_per_page = self.settings.PAGESIZE // self.settings.sectorsize

        if self.settings.ecc_bit == 4:
            self.settings.ECC_MODE = 0  # 0=4 bit ECC error
        elif self.settings.ecc_bit == 8:
            self.settings.ECC_MODE = 1  # 1=8 bit ECC error
        elif self.settings.ecc_bit == 16:
            self.settings.ECC_MODE = 2  # 2=16 bit ECC error

        if self.settings.ecc_size == 0:
            if self.settings.ecc_bit == 4:
                self.settings.ecc_size = 1
            elif self.settings.ecc_bit == 8 or self.settings.ecc_bit == 16:
                self.settings.ecc_size = 2

        if self.settings.OOBSIZE == 0:
            self.settings.OOBSIZE = (8 << self.settings.ecc_size) * (self.settings.CW_PER_PAGE + 1)

        if 256 >= self.settings.OOBSIZE > 128:
            self.settings.OOBSIZE = 256

        if self.settings.SPARE_SIZE_BYTES == 0:
            # HAM1
            if self.settings.ECC_MODE == 0:
                self.settings.SPARE_SIZE_BYTES = 4
            else:
                self.settings.SPARE_SIZE_BYTES = 2

        if self.settings.cfg1_enable_bch_ecc:
            hw_ecc_bytes = 0
            self.settings.UD_SIZE_BYTES = self.settings.SPARE_SIZE_BYTES + self.settings.sectorsize  # 516 or 517
            if self.settings.SPARE_SIZE_BYTES == 2:
                self.settings.UD_SIZE_BYTES += 2
            if self.settings.IsWideFlash:
                self.settings.UD_SIZE_BYTES += 1
        else:
            hw_ecc_bytes = 10
            self.settings.UD_SIZE_BYTES = 512

        if self.settings.ECC_PARITY_SIZE_BYTES == 0:
            self.settings.ECC_PARITY_SIZE_BYTES = 3  # HAM1
            if self.settings.ecc_bit == 4:  # BCH4
                self.settings.ECC_PARITY_SIZE_BYTES = 7
            elif self.settings.ecc_bit == 8:  # BCH8
                self.settings.ECC_PARITY_SIZE_BYTES = 13
            elif self.settings.ecc_bit == 16:  # BCH16
                self.settings.ECC_PARITY_SIZE_BYTES = 26

        linuxcwsize = 528
        if self.settings.cfg1_enable_bch_ecc and self.settings.ecc_bit == 8:
            linuxcwsize = 532
        if nandid == 0x1590AC2C:  # fixme
            linuxcwsize = 532
        if self.settings.BAD_BLOCK_BYTE_NUM == 0:
            self.settings.BAD_BLOCK_BYTE_NUM = (
                    self.settings.PAGESIZE - (linuxcwsize * (self.settings.sectors_per_page - 1)) + 1)

        # UD_SIZE_BYTES must be 512, 516 or 517. If ECC-Protection 516 for x16Bit-Nand and 517 for x8-bit Nand
        cfg0 = 0 << self.SET_RD_MODE_AFTER_STATUS \
            | 0 << self.STATUS_BFR_READ \
            | 5 << self.NUM_ADDR_CYCLES \
            | self.settings.SPARE_SIZE_BYTES << self.SPARE_SIZE_BYTES \
            | hw_ecc_bytes << self.ECC_PARITY_SIZE_BYTES_RS \
            | self.settings.UD_SIZE_BYTES << self.UD_SIZE_BYTES \
            | self.settings.CW_PER_PAGE << self.CW_PER_PAGE \
            | 0 << self.DISABLE_STATUS_AFTER_WRITE

        bad_block_byte = self.settings.BAD_BLOCK_BYTE_NUM
        wide_bus = self.settings.IsWideFlash
        bch_disabled = self.settings.args_disable_ecc  # option in gui, implemented

        cfg1 = 0 << self.ECC_MODE_DEV1 \
            | 1 << self.ENABLE_NEW_ECC \
            | 0 << self.DISABLE_ECC_RESET_AFTER_OPDONE \
            | 0 << self.ECC_DECODER_CGC_EN \
            | 0 << self.ECC_ENCODER_CGC_EN \
            | 2 << self.WR_RD_BSY_GAP \
            | 0 << self.BAD_BLOCK_IN_SPARE_AREA \
            | bad_block_byte << self.BAD_BLOCK_BYTE_NUM \
            | 0 << self.CS_ACTIVE_BSY \
            | 7 << self.NAND_RECOVERY_CYCLES \
            | wide_bus << self.WIDE_FLASH \
            | bch_disabled << self.ENABLE_BCH_ECC

        """
        cfg0_raw = (self.settings.CW_PER_PAGE-1) << CW_PER_PAGE \
                    | self.settings.UD_SIZE_BYTES << UD_SIZE_BYTES \
                    | 5 << NUM_ADDR_CYCLES \
                    | 0 << SPARE_SIZE_BYTES

        cfg1_raw = 7 << NAND_RECOVERY_CYCLES \
                    | 0 << CS_ACTIVE_BSY \
                    | 17 << BAD_BLOCK_BYTE_NUM \
                    | 1 << BAD_BLOCK_IN_SPARE_AREA \
                    | 2 << WR_RD_BSY_GAP \
                    | wide_bus << WIDE_FLASH \
                    | 1 << DEV0_CFG1_ECC_DISABLE
        """
        ecc_bch_cfg = 1 << self.ECC_FORCE_CLK_OPEN \
            | 0 << self.ECC_DEC_CLK_SHUTDOWN \
            | 0 << self.ECC_ENC_CLK_SHUTDOWN \
            | self.settings.UD_SIZE_BYTES << self.ECC_NUM_DATA_BYTES \
            | self.settings.ECC_PARITY_SIZE_BYTES << self.ECC_PARITY_SIZE_BYTES_BCH \
            | self.settings.ECC_MODE << self.ECC_MODE \
            | 0 << self.ECC_SW_RESET \
            | bch_disabled << self.ECC_CFG_ECC_DISABLE

        if self.settings.UD_SIZE_BYTES == 516:
            ecc_buf_cfg = 0x203
        elif self.settings.UD_SIZE_BYTES == 517:
            ecc_buf_cfg = 0x204
        else:
            ecc_buf_cfg = 0x1FF

        return cfg0, cfg1, ecc_buf_cfg, ecc_bch_cfg


class nandregs:
    def __init__(self, parent):
        self.register_mapping = {
        }
        self.reverse_mapping = {}
        self.create_reverse_mapping()
        self.parent = parent

    def __getattribute__(self, name):
        if name in ("register_mapping", "parent"):
            return super(nandregs, self).__getattribute__(name)

        if name in self.register_mapping:
            return self.parent.mempeek(self.register_mapping[name])

        return super(nandregs, self).__getattribute__(name)

    def __setattr__(self, name, value):
        if name in ("register_mapping", "parent"):
            super(nandregs, self).__setattr__(name, value)

        if name in self.register_mapping:
            self.parent.mempoke(self.register_mapping[name], value)
        else:
            super(nandregs, self).__setattr__(name, value)

    def read(self, register):
        if isinstance(register, str):
            register = self.register_mapping.get(register.lower(), None)
        return self.parent.mempeek(register)

    def write(self, register, value):
        if isinstance(register, str):
            register = self.register_mapping.get(register.lower(), None)
        return self.parent.mempoke(register, value)

    def save(self):
        reg_dict = {}
        for reg in self.register_mapping:
            reg_v = self.read(reg)
            reg_dict[reg] = reg_v
        return reg_dict

    def restore(self, value=None):
        if value is None:
            value = {}
        for reg in self.register_mapping:
            reg_v = value[reg]
            self.write(reg, reg_v)

    def create_reverse_mapping(self):
        self.reverse_mapping = {v: k for k, v in self.register_mapping.items()}
