#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2019-2023 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import copy
import sys
import argparse
import time
import serial.tools.list_ports
from Exscript.protocols.telnetlib import Telnet
from binascii import hexlify, unhexlify
import logging
import logging.config
import logging.handlers
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
            # we want levelname to be in different color, so let's modify it
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
        logger_attribute_name = '_' + cls.__name__ + '__logger'
        logger_debuglevel_name = '_' + cls.__name__ + '__debuglevel'
        logger_name = '.'.join([c.__name__ for c in cls.mro()[-2::-1]])
        LOG_CONFIG = {
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
        logging.config.dictConfig(LOG_CONFIG)
        logger = logging.getLogger(logger_name)

        setattr(cls, logger_attribute_name, logger)
        setattr(cls, logger_debuglevel_name, cls.debuglevel)


'''
C7 = 7 0		0	2	7		5 0
C6 = 3 1		7	0	3		0 1
C5 = 0 2		5	3	0		3 2
C8 = 1 3		3	1	5		7 3
C4 = 5 4		1	4	1		1 4					
'''
prodtable = {
    "MDM8200": dict(openlock=0, openmep=1, opencnd=0, clen=8, init=[1, 3, 5, 7, 0],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 2, 4, 1, 3, 0, 3, 4, 0)"),
    # MC878XC_F1.2.3.15 verified, key may be stored in nvitem 0x4e21;MC8700 M3.0.9.0 verified
    "MDM9200": dict(openlock=0, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    # AC881U, EM8805 SWI9X15C_05.05.58.00, at!openlock?6A1F1CEA298A14B0 => AT!OPENLOCK="3A9EA70D86FEE58C"
    "MDM9200_V1": dict(openlock=2, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
                       run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),  # AC710
    "MDM9200_V2": dict(openlock=3, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
                       run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),  # AC775
    "MDM9200_V3": dict(openlock=8, openmep=1, opencnd=8, clen=8, init=[7, 3, 0, 1, 5],
                       run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),  # AC775
    "MDM9x15": dict(openlock=0, openmep=1, opencnd=0, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    # 9x15C 06.03.32.02, AC340U 1.13.12.14 verified, #AT!CUSTOM=\"ADBENABLE\",1
    "MDM9x07": dict(openlock=9, openmep=10, opencnd=9, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    # SWI9X07Y_02.25.02.01
    "MDM9x30": dict(openlock=5, openmep=4, opencnd=5, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    # MC7455_2.30.01.01 #4
    "MDM9x30_V1": dict(openlock=17, openmep=15, opencnd=17, clen=8, init=[7, 3, 0, 1, 5],
                       run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    # AC791L/AC790S NTG9X35C_02.08.29.00
    "MDM9x40": dict(openlock=11, openmep=12, opencnd=11, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),  # AC815s
    "MDM9x50": dict(openlock=7, openmep=6, opencnd=7, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),  # EM7565
    "MDM9x06": dict(openlock=20, openmep=19, opencnd=20, clen=8, init=[7, 3, 0, 1, 5],
                    run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),  # WP77xx
    "SDX55": dict(openlock=22, openmep=21, opencnd=22, clen=8, init=[7, 3, 0, 1, 5],  # MR5100, MR6400 old fw
                  run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    "MDM9x15A": dict(openlock=24, openmep=23, opencnd=24, clen=8, init=[7, 3, 0, 1, 5],  # AC779S
                     run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)"),
    "SDX65": dict(openlock=25, openmep=21, opencnd=26, clen=8, init=[7, 3, 0, 1, 5],  # MR6400 new fw
                  run="resultbuffer[i]=self.SierraAlgo(challenge[i], 4, 2, 1, 0, 3, 2, 0, 0)")
}

infotable = {
    "MDM8200": ["M81A", "M81B", "AC880", "AC881", "MC8780", "MC8781", "AC880E", "AC881E", "EM8780", "EM8781",
                "MC8780V", "MC8781V", "MC8700", "AC308U"],
    "MDM9200": ["AC710", "MC8775", "MC8775V", "AC875", "MC8700", "AC313U", "MC8801", "MC7700", "MC7750", "MC7710",
                "EM7700", "770S", "781S"],
    "MDM9200_V1": ["AC710", "MC8775", "MC8775V", "AC875", "MC8700", "AC313U", "MC8801", "MC7700", "MC7750",
                   "MC7710", "EM7700"],
    "MDM9200_V2": ["AC775", "PC7200"],
    "MDM9200_V3": ["AC775"],
    "MDM9x07": ["SWI9X07Y", "WP76xx"],
    "MDM9x06": ["SWI9X06Y", "WP77xx"],
    "MDM9x15": ["SWI9X15C", "AR7550", "AR7552", "AR7554", "EM7355", "EM7655", "MC7354", "WP7100", "WP7102", "WP7104",
                "MC7305", "EM7305", "MC8805", "EM8805", "MC7350", "MC7350-L", "MC7802", "MC7304", "AR7556", "AR7558",
                "WP75xx", "WP85xx", "WP8548", "WP8548G", "AC340U"],
    "MDM9x15A": ["AC779S"],
    "MDM9x30": ["EM7455", "MC7455", "EM7430", "MC7430"],
    "MDM9x30_V1": ["Netgear AC790/MDM9230"],
    "MDM9x40": ["MR1100", "AC815s", "AC785s", "AC797S"],
    "MDM9x50": ["EM7565", "EM7565-9", "EM7511", "EM7411"],
    "SDX55": ["MR5100", "MR5200", "ac797-100eus", "MR6400"],
    "SDX65": ["MR6400", "MR6500", "MR6110", "MR6150", "MR6450", "MR6550"]
}

# 0 MC8775_H2.0.8.19 !OPENLOCK, !OPENCND .. MC8765V,MC8765,MC8755V,MC8775,MC8775V,MC8775,AC850,
#   AC860,AC875,AC881,AC881U,AC875, AC340U 1.13.12.14
keytable = bytearray([0xF0, 0x14, 0x55, 0x0D, 0x5E, 0xDA, 0x92, 0xB3, 0xA7, 0x6C, 0xCE, 0x84, 0x90, 0xBC, 0x7F, 0xED,
                      # 1 MC8775_H2.0.8.19 AC340U, OPENMEP default
                      0x61, 0x94, 0xCE, 0xA7, 0xB0, 0xEA, 0x4F, 0x0A, 0x73, 0xC5, 0xC3, 0xA6, 0x5E, 0xEC, 0x1C, 0xE2,
                      # 2 AC750,AC710,AC7XX,SB750A,SB750,PC7000,AC313u OPENMEP
                      0x39, 0xC6, 0x7B, 0x04, 0xCA, 0x50, 0x82, 0x1F, 0x19, 0x63, 0x36, 0xDE, 0x81, 0x49, 0xF0, 0xD7,
                      # 3 AC775,PC7200
                      0xDE, 0xA5, 0xAD, 0x2E, 0xBE, 0xE1, 0xC9, 0xEF, 0xCA, 0xF9, 0xFE, 0x1F, 0x17, 0xFE, 0xED, 0x3B,
                      # 4 MC7455_02.30.01.01 OPENMEP
                      0xFE, 0xD4, 0x40, 0x52, 0x2D, 0x4B, 0x12, 0x5C, 0xE7, 0x0D, 0xF8, 0x79, 0xF8, 0xC0, 0xDD, 0x37,
                      # 5 MC7455_02.30.01.01 OPENLOCK
                      0x3B, 0x18, 0x99, 0x6B, 0x57, 0x24, 0x0A, 0xD8, 0x94, 0x6F, 0x8E, 0xD9, 0x90, 0xBC, 0x67, 0x56,
                      # 6 SWI9x50 Openmep Key SWI9X50C_01.08.04.00
                      0x47, 0x4F, 0x4F, 0x44, 0x4A, 0x4F, 0x42, 0x44, 0x45, 0x43, 0x4F, 0x44, 0x49, 0x4E, 0x47, 0x2E,
                      # 7 SWI9x50 Openlock Key SWI9X50C_01.08.04.00
                      0x4F, 0x4D, 0x41, 0x52, 0x20, 0x44, 0x49, 0x44, 0x20, 0x54, 0x48, 0x49, 0x53, 0x2E, 0x2E, 0x2E,
                      # 8 MDM8200 Special
                      0x8F, 0xA5, 0x85, 0x05, 0x5E, 0xCF, 0x44, 0xA0, 0x98, 0x8B, 0x09, 0xE8, 0xBB, 0xC6, 0xF7, 0x65,
                      # 9 SWI9x07 Openlock Key 02.25.02.01
                      0x4D, 0x42, 0xD8, 0xC1, 0x25, 0x44, 0xD8, 0xA0, 0x1D, 0x80, 0xC4, 0x52, 0x8E, 0xEC, 0x8B, 0xE3,
                      # 10 SWI9x07 Openmep Key 02.25.02.01
                      0xED, 0xA9, 0xB7, 0x0A, 0xDB, 0x85, 0x3D, 0xC0, 0x92, 0x49, 0x7D, 0x41, 0x9A, 0x91, 0x09, 0xEE,
                      # 11 NTG9X40C_11.14.08.11 / mdm9x40r11_core AC815s / SWI9x50 MR1100 Openlock Key
                      0x8A, 0x56, 0x03, 0xF0, 0xBB, 0x9C, 0x13, 0xD2, 0x4E, 0xB2, 0x45, 0xAD, 0xC4, 0x0A, 0xE7, 0x52,
                      # 12 SWI9x50 MR1100 Openmep Key
                      0x2A, 0xEF, 0x07, 0x2B, 0x19, 0x60, 0xC9, 0x01, 0x8B, 0x87, 0xF2, 0x6E, 0xC1, 0x42, 0xA8, 0x3A,
                      # 13 SWI9x50/SWI9x65 Unknown key
                      0x28, 0x55, 0x48, 0x52, 0x24, 0x72, 0x63, 0x37, 0x14, 0x26, 0x37, 0x50, 0xBE, 0xFE, 0x00, 0x00,
                      # 14 SWI9x50,SWI9X06Y,SWI9x65 IMEI nv key
                      0x22, 0x63, 0x48, 0x02, 0x24, 0x72, 0x27, 0x37, 0x19, 0x26, 0x37, 0x50, 0xBE, 0xEF, 0xCA, 0xFE,
                      # 15 NTG9X35C_02.08.29.00 Openmep Key AC791L/AC790S Old
                      0x98, 0xE1, 0xC1, 0x93, 0xC3, 0xBF, 0xC3, 0x50, 0x8D, 0xA1, 0x35, 0xFE, 0x50, 0x47, 0xB3, 0xC4,
                      # 16 NTG9X35C_02.08.29.00 Openmep Key AC791/AC790S, NTGX55_10.25.15.02 MR5100 Alternative, NTG9X40C_30.00.12.00 Alternative
                      0x61, 0x94, 0xCE, 0xA7, 0xB0, 0xEA, 0x4F, 0x0A, 0x73, 0xC5, 0xC3, 0xA6, 0x5E, 0xEC, 0x1C, 0xE2,
                      # 17 NTG9X35C_02.08.29.00 Openlock Key AC791/AC790S Old
                      0xC5, 0x50, 0x40, 0xDA, 0x23, 0xE8, 0xF4, 0x4C, 0x29, 0xE9, 0x07, 0xDE, 0x24, 0xE5, 0x2C, 0x1D,
                      # 18 NTG9X35C_02.08.29.00 Openlock Key AC791/AC790S, NTGX55_10.25.15.02 MR5100 Alternative, NTG9X40C_30.00.12.00 Alternative
                      0xF0, 0x14, 0x55, 0x0D, 0x5E, 0xDA, 0x92, 0xB3, 0xA7, 0x6C, 0xCE, 0x84, 0x90, 0xBC, 0x7F, 0xED,
                      # 19 SWI9X06Y_02.14.04.00 Openmep Key WP77xx
                      0x78, 0x19, 0xC5, 0x6D, 0xC3, 0xD8, 0x25, 0x3E, 0x51, 0x60, 0x8C, 0xA7, 0x32, 0x83, 0x37, 0x9D,
                      # 20 SWI9X06Y_02.14.04.00 Openlock Key WP77xx
                      0x12, 0xF0, 0x79, 0x6B, 0x19, 0xC7, 0xF4, 0xEC, 0x50, 0xF3, 0x8C, 0x40, 0x02, 0xC9, 0x43, 0xC8,
                      # 21 NTGX55 Openmep Key, NTGX55_10.25.15.02 MR5100, NTG9X40C_30.00.12.00
                      0x49, 0x42, 0xFF, 0x76, 0x8A, 0x95, 0xCF, 0x7B, 0xA3, 0x47, 0x5F, 0xF5, 0x8F, 0xD8, 0x45, 0xE4,
                      # 22 NTGX55 Openlock Key, NTGX55_10.25.15.02 MR5100, NTG9X40C_30.00.12.00
                      0xF8, 0x1A, 0x3A, 0xCC, 0xAA, 0x2B, 0xA5, 0xE8, 0x8B, 0x53, 0x5A, 0x55, 0xB9, 0x65, 0x57, 0x98,
                      # 23 NTG9X15A Openlock Key, NTG9X15A_01.08.02.00
                      0x54, 0xC9, 0xC7, 0xA4, 0x02, 0x1C, 0xB0, 0x11, 0x05, 0x22, 0x39, 0xB7, 0x84, 0xEF, 0x16, 0xCA,
                      # 24 NTG9X15A Openlock Key, NTG9X15A_01.08.02.00
                      0xC7, 0xE6, 0x39, 0xFE, 0x0A, 0xC7, 0xCA, 0x4D, 0x49, 0x8F, 0xD8, 0x55, 0xEB, 0x1A, 0xCD, 0x8A,
                      # 25 NTGX65 Openlock Key, NTGX65_10.04.13.03
                      0xF2, 0x4A, 0x9A, 0x2C, 0xDA, 0x3D, 0xA5, 0xE2, 0x6B, 0x56, 0x9A, 0x45, 0x29, 0x25, 0x77, 0x9A,
                      # 26 NTGX65 Openadm Key, NTGX65_10.04.13.03
                      0x46, 0x30, 0x33, 0x43, 0x44, 0x36, 0x42, 0x34, 0x41, 0x32, 0x31, 0x32, 0x30, 0x35, 0x39, 0x37
                      ])


class SierraGenerator:
    tbl = bytearray()
    rtbl = bytearray()
    devicegeneration = None

    def __init__(self):
        for _ in range(0, 0x14):
            self.rtbl.append(0x0)
        for _ in range(0, 0x100):
            self.tbl.append(0x0)

    def run(self, devicegeneration, challenge, _type):
        challenge = bytearray(unhexlify(challenge))

        self.devicegeneration = devicegeneration
        if not devicegeneration in prodtable:
            print("Sorry, " + devicegeneration + " not supported.")
            exit(0)

        mepid = prodtable[devicegeneration]["openmep"]
        cndid = prodtable[devicegeneration]["opencnd"]
        lockid = prodtable[devicegeneration]["openlock"]
        clen = prodtable[devicegeneration]["clen"]
        if len(challenge) < clen:
            challenge = [0 for _ in range(0, clen - len(challenge))]

        challengelen = len(challenge)
        if _type == 0:  # lockkey
            idf = lockid
        elif _type == 1:  # mepkey
            idf = mepid
        elif _type == 2:  # cndkey
            idf = cndid

        key = keytable[idf * 16:(idf * 16) + 16]
        resp = self.SierraKeygen(challenge=challenge, key=key, challengelen=challengelen, keylen=16)[:challengelen]
        resp = hexlify(resp).decode('utf-8').upper()
        return resp

    def selftest(self):
        test_table = [
            {"challenge": "8101A18AB3C3E66A", "devicegeneration": "MDM9x15", "response": "D1E128FCA8A963ED"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x40", "response": "1033773720F6EE66"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x30", "response": "1E02CE6A98B7DD2A"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x50", "response": "32AB617DB4B1C205"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x06", "response": "28D718CCD669DEDE"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x07", "response": "F5A4C9A0D402E34E"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM8200", "response": "EE702212D9C12FAB"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9200_V1", "response": "A9A4E76E2653F753"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9200_V2", "response": "8B0FAB4B6F81B080"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9200_V3", "response": "4A69AD8A69F390E0"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9x30_V1", "response": "6A5E4C9CBCBDA7DC"},
            {"challenge": "BE96CBBEE0829BCA", "devicegeneration": "MDM9200", "response": "EEDBF8BFF8DAE346"},
            {"challenge": "20E253156762DACE", "devicegeneration": "SDX55", "response": "03940D7067145323"},
            {"challenge": "2387885E7D290FEE", "devicegeneration": "MDM9x15A", "response": "DC3E51897BAA9C1E"},
            {"challenge": "4B1FEF9FD43C6DAA", "devicegeneration": "SDX65", "response": "1253C1B1E447B697"}
        ]
        for test in test_table:
            challenge = test["challenge"]
            devicegeneration = test["devicegeneration"]
            response = test["response"]
            openlock = self.run(devicegeneration, challenge, 0)
            padding = " " * (16 - len(devicegeneration))
            if openlock != response:
                print(devicegeneration + padding + " FAILED!")
            else:
                print(devicegeneration + padding + " PASSED :)")

    def SierraPreInit(self, counter, key, keylen, challengelen, mcount):
        if counter != 0:
            tmp2 = 0
            i = 1
            while i < counter:
                i = 2 * i + 1
            while True:
                tmp = mcount
                mcount = tmp + 1
                challengelen = (key[tmp & 0xFF] + self.tbl[(challengelen & 0xFF)]) & 0xFF
                if mcount >= keylen:
                    mcount = 0
                    challengelen = ((challengelen & 0xFF) + keylen) & 0xFF
                tmp2 = tmp2 + 1
                tmp3 = ((challengelen & 0xFF) & i) & 0xFF
                if tmp2 >= 0xB:
                    tmp3 = counter % tmp3
                if tmp3 <= counter:
                    break
            counter = tmp3 & 0xFF
        return [counter, challengelen, mcount]

    def SierraInit(self, key, keylen):
        if keylen == 0 or keylen > 0x20:
            retval = [0, keylen]
        elif 1 <= keylen <= 0x20:
            self.tbl = [(i & 0xFF) for i in range(0, 0x100)]
            mcount = 0
            cl = keylen & 0xffffff00
            i = 0xFF
            while i > -1:
                t, cl, mcount = self.SierraPreInit(i, key, keylen, cl, mcount)
                m = self.tbl[i]
                self.tbl[i] = self.tbl[(t & 0xff)]
                i = i - 1
                self.tbl[(t & 0xFF)] = m
            self.rtbl[0] = self.tbl[prodtable[self.devicegeneration]["init"][0]] if \
                prodtable[self.devicegeneration]["init"][0] != 0 else self.tbl[(cl & 0xFF)]
            self.rtbl[1] = self.tbl[prodtable[self.devicegeneration]["init"][1]] if \
                prodtable[self.devicegeneration]["init"][1] != 0 else self.tbl[(cl & 0xFF)]
            self.rtbl[2] = self.tbl[prodtable[self.devicegeneration]["init"][2]] if \
                prodtable[self.devicegeneration]["init"][2] != 0 else self.tbl[(cl & 0xFF)]
            self.rtbl[3] = self.tbl[prodtable[self.devicegeneration]["init"][3]] if \
                prodtable[self.devicegeneration]["init"][3] != 0 else self.tbl[(cl & 0xFF)]
            self.rtbl[4] = self.tbl[prodtable[self.devicegeneration]["init"][4]] if \
                prodtable[self.devicegeneration]["init"][4] != 0 else self.tbl[(cl & 0xFF)]
            retval = [1, keylen]
        return retval

    def sierra_calc8F(self, challenge, a=0, b=1, c=2, d=3, e=4, ret=0, ret2=2):
        # MDM9200
        self.rtbl[b] = (self.rtbl[b] + self.tbl[(self.rtbl[d] & 0xFF)]) & 0xFF
        uVar2 = self.rtbl[c] & 0xFF
        bVar1 = self.tbl[uVar2]
        uVar4 = self.rtbl[b] & 0xFF
        self.tbl[uVar2] = self.tbl[uVar4]
        self.rtbl[d] = (self.rtbl[d] + 1) & 0xFF
        uVar5 = self.rtbl[a] & 0xFF
        self.tbl[uVar4] = self.tbl[uVar5]
        uVar3 = self.rtbl[d] & 0xFF
        self.tbl[uVar5] = self.tbl[uVar3]
        self.tbl[uVar3] = bVar1
        self.rtbl[ret] = challenge  # c
        self.rtbl[ret2] = self.tbl[self.tbl[(self.tbl[(self.rtbl[e] + self.tbl[bVar1]) & 0xFF] + (
                self.tbl[uVar5] & 0xFF) + (self.tbl[uVar2] & 0xFF) & 0xff) & 0xFF] & 0xFF] ^ self.tbl[
                              ((self.tbl[uVar4] & 0xFF) + (bVar1 & 0xff)) & 0xFF] ^ challenge  # a
        self.rtbl[e] = (self.rtbl[e] + self.tbl[bVar1]) & 0xFF
        return self.rtbl[ret2] & 0xFF  # a

    def SierraAlgo(self, challenge, a=0, b=1, c=2, d=3, e=4, ret=3, ret2=1, flag=1):  # M9x15
        v6 = self.rtbl[e]
        v0 = (v6 + 1) & 0xFF
        self.rtbl[e] = v0
        self.rtbl[c] = (self.tbl[v6 + flag & 0xFF] + self.rtbl[c]) & 0xFF
        v4 = self.rtbl[c] & 0xFF
        v2 = self.rtbl[b] & 0xFF
        v1 = self.tbl[(v2 & 0xFF)]
        self.tbl[(v2 & 0xFF)] = self.tbl[(v4 & 0xFF)]
        v5 = self.rtbl[d] & 0xFF
        self.tbl[(v4 & 0xFF)] = self.tbl[(v5 & 0xFF)]
        self.tbl[(v5 & 0xFF)] = self.tbl[(v0 & 0xFF)]
        self.tbl[v0] = v1 & 0xFF
        u = self.tbl[(self.tbl[(
                self.tbl[((self.rtbl[a] + self.tbl[(v1 & 0xFF)]) & 0xFF)] + self.tbl[(v5 & 0xFF)] + self.tbl[
            (v2 & 0xFF)] & 0xff)] & 0xFF)]
        v = self.tbl[((self.tbl[(v4 & 0xFF)] + v1) & 0xFF)]
        self.rtbl[ret] = u ^ v ^ challenge
        self.rtbl[a] = (self.tbl[(v1 & 0xFF)] + self.rtbl[a]) & 0xFF
        self.rtbl[ret2] = challenge & 0xFF
        return self.rtbl[ret] & 0xFF

    def SierraFinish(self):
        self.tbl = [0 for _ in range(0, 0x100)]
        self.rtbl[0] = 0
        self.rtbl[1] = 0
        self.rtbl[2] = 0
        self.rtbl[3] = 0
        self.rtbl[4] = 0
        return 1

    def SierraKeygen(self, challenge: bytearray, key: bytearray, challengelen: int, keylen: int):
        challenge = challenge
        resultbuffer = bytearray([0 for _ in range(0, 0x100 + 1)])
        ret, keylen = self.SierraInit(key, keylen)
        if ret:
            for i in range(0, challengelen):
                exec(prodtable[self.devicegeneration]["run"])  # uses challenge
            self.SierraFinish()
        return resultbuffer


class connection:
    def __init__(self, port="", ip="192.168.1.1"):
        self.serial = None
        self.tn = None
        self.connected = False
        if port == "":
            port = self.detect(port)
            if port == "":
                self.tn = Telnet(ip, 5510)
                if self.tn:
                    self.connected = True
                else:
                    self.connected = False
        if port != "":
            self.serial = serial.Serial(port=port, baudrate=115200, bytesize=8, parity='N', stopbits=1, timeout=1)
            self.connected = self.serial.is_open

    def detect(self, port):
        if port == "":
            for port in serial.tools.list_ports.comports():
                if port.vid == 0x1199:
                    portid = port.location[-1:]
                    if int(portid) == 3:
                        print("Detected Sierra Wireless device at: " + port.device)
                        return port.device
                elif port.vid == 0x8046:
                    portid = port.location[-1:]
                    if int(portid) == 3:
                        print("Detected Netgear device at: " + port.device)
                        return port.device

        return ""

    def readreply(self):
        info = []
        if self.serial is not None:
            while True:
                tmp = self.serial.readline().decode('utf-8').replace('\r', '').replace('\n', '')
                if "OK" in info:
                    return info
                elif ("ERROR" in info) or info == "":
                    return -1
                info.append(tmp)
        return info

    def send(self, cmd):
        if self.tn is not None:
            self.tn.write(bytes(cmd + "\r", 'utf-8'))
            time.sleep(0.05)
            data = ""
            while True:
                tmp = self.tn.read_eager()
                if tmp != "":
                    data += tmp.strip()
                else:
                    break
            return data.split("\r\n")
        elif self.serial is not None:
            self.serial.write(bytes(cmd + "\r", 'utf-8'))
            time.sleep(0.05)
            return self.readreply()

    def close(self):
        if self.tn is not None:
            self.tn.close()
            self.connected = False
        if self.serial is not None:
            self.serial.close()
            self.connected = False


class SierraKeygen(metaclass=LogBase):
    def __init__(self, cn, devicegeneration=None):
        self.cn = cn
        self.keygen = SierraGenerator()
        if devicegeneration is None:
            self.detectdevicegeneration()
        else:
            self.devicegeneration = devicegeneration

    def run_selftest(self):
        print("Running self-test ...")
        self.keygen.selftest()

    def detectdevicegeneration(self):
        if self.cn.connected:
            info = self.cn.send("ATI")
            if info != -1:
                revision = ""
                _model = ""
                for line in info:
                    if "Revision" in line:
                        revision = line.split(":")[1].strip()
                    if "Model" in line:
                        _model = line.split(":")[1].strip()
                if revision != "":
                    if "9200" in revision:
                        devicegeneration = "MDM9200"  # AC762S NTG9200H2_03.05.14.12ap
                    if "9X07" in revision:
                        devicegeneration = "MDM9x07"
                    elif "9X25" in revision:
                        if "NTG9X25C" in revision:
                            devicegeneration = "MDM9200"  # AC781S NTG9X25C_01.00.57.00
                    elif "9X15" in revision:
                        if "NTG9X15A" in revision:
                            devicegeneration = "MDM9x15A"  # Aircard 779S
                        elif "NTG9X15C" in revision:
                            devicegeneration = "MDM9200"  # AC770S NTG9X15C_01.18.02.00
                        elif "9X15A" in revision:
                            devicegeneration = "MDM9x15A"
                        else:
                            devicegeneration = "MDM9x15"
                    elif "9X30" in revision:
                        if "NTG9X35C" in revision:  # 790S NTG9X35C_11.11.15.03
                            devicegeneration = "MDM9x30_V1"
                        else:
                            devicegeneration = "MDM9x30"
                    elif "9X40" in revision and "9X40C" not in revision:
                        devicegeneration = "MDM9x40"
                    elif "9X50" in revision:
                        if "NTG9X50" in revision:
                            devicegeneration = "MDM9x40"  # MR1100,AC797S NTG9X50C_12.06.03.00
                        else:
                            devicegeneration = "MDM9x50"
                    elif "9X06" in revision:
                        devicegeneration = "MDM9x06"
                    elif "X55" in revision or "9X40C" in revision:
                        if "NTGX55" in revision:  # MR5100 NTGX55_10.25.15.02, MR5200 NTGX55_12.04.12.00
                            devicegeneration = "SDX55"
                        devicegeneration = "SDX55"
                    elif "X65" in revision:
                        if "NTGX65" in revision:
                            version = revision[revision.find("_") + 1:revision.find(" ")].split(".")
                            maj = int(version[0]) * 1000000 + int(version[1]) * 10000 + int(version[2]) * 100 + int(
                                version[3])
                            if maj < 10041303:
                                devicegeneration = "SDX55"
                            else:  # MR6400 NTGX65_10.04.13.03
                                devicegeneration = "SDX65"
                                # MR6550 NTGX65_12.01.31.00
                        devicegeneration = "SDX65"
                    else:
                        devicegeneration = ""
                    # Missing:
                    # SDX24 Sierra
                    # MR2100 NTGX24_10.17.03.00
                    # SDX55 Sierra
                    # AC810S NTG9X40C_11.14.08.16
                    # AC800S NTG9X40C_11.14.07.00
                    self.devicegeneration = devicegeneration
            else:
                print("Error on getting ATI modem response. Wrong port? Aborting.")
                self.cn.close()
                exit(0)

    def openlock(self):
        print("Device generation detected: " + self.devicegeneration)
        # print("Sending AT!ENTERCND=\"A710\" request.")
        # info = self.cn.send("AT!ENTERCND=\"A710\"")
        # if info == -1:
        #    print("Uhoh ... invalid entercnd password. Aborting ...")
        #    return
        print("Sending AT!OPENLOCK? request")
        info = self.cn.send("AT!OPENLOCK?")
        challenge = ""
        if info != -1:
            if len(info) > 2:
                challenge = info[1]
                print("Received challenge: " + info[1])
        else:
            print("Error on AT!OPENLOCK? request. Aborting.")
            return False
        if challenge == "":
            print("Error: Couldn't get challenge. Aborting.")
            return False
        resp = self.keygen.run(self.devicegeneration, challenge, 0)
        print("Sending AT!OPENLOCK=\"" + resp + "\" response.")
        info = self.cn.send("AT!OPENLOCK=\"" + resp + "\"")
        if info == -1:
            print("Damn. AT!OPENLOCK failed.")
        else:
            print("Success. Device is now engineer unlocked.")
            return True
        return False


def main(args):
    version = "1.5"
    info = 'Sierra Wireless Generator ' + version + ' (c) B. Kerler 2019-2021'
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=info)

    parser.add_argument(
        '-openlock', '-l',
        help='AT!OPENLOCK? modem response',
        default="")

    parser.add_argument(
        '-openmep', '-m',
        help='AT!OPENMEP? modem response',
        default="")

    parser.add_argument(
        '-opencnd', '-c',
        help='AT!OPENCND? modem response',
        default="")

    parser.add_argument(
        '-devicegeneration', '-d',
        help='device generation',
        default="")

    parser.add_argument(
        '-port', '-p',
        help='use com port for auto unlock',
        default="")

    parser.add_argument(
        '-ip',
        help='ip port for unlock, usually 192.168.1.1 or 192.168.2.1',
        default="192.168.1.1")

    parser.add_argument(
        '-unlock', '-u',
        help='use com port for openlock',
        default=False, action='store_true')

    parser.add_argument(
        '-selftest', '-s',
        help='run selftest',
        default=False, action='store_true')

    args = parser.parse_args()

    openlock = args.openlock
    openmep = args.openmep
    opencnd = args.opencnd
    devicegeneration = args.devicegeneration

    if not args.selftest:
        if (devicegeneration == "" or (openlock == "" and openmep == "" and opencnd == "")) and not args.unlock:
            print(info)
            print("------------------------------------------------------------\n")
            print("Usage: ./sierrakeygen.py [-l,-m,-c] [challenge] -d [devicegeneration]")
            print("Example: ./sierrakeygen.py -l BE96CBBEE0829BCA -d MDM9200")
            print("or: ./sierrakeygen.py -u for auto unlock")
            print("or: ./sierrakeygen.py -u -p [portname] for auto unlock with given portname")
            print("or: ./sierrakeygen.py -s for self-test")
            print("Supported devicegenerations :")
            for key in infotable:
                info = f"\t{key}:\t\t"
                count = 0
                for item in infotable[key]:
                    count += 1
                    if count > 15:
                        info += "\n\t\t\t\t\t"
                        count = 0
                    info += item + ","

                info = info[:-1]
                print(info)
            exit(0)

        if devicegeneration == "" and not args.unlock:
            print("You need to specific a device generation as well. Option -d")
            exit(0)
    if devicegeneration == "":
        devicegeneration = None
    if args.selftest:
        kg = SierraKeygen(None, "selftest")
        kg.run_selftest()
    elif args.unlock:
        cn = connection(args.port, args.ip)
        if cn.connected:
            kg = SierraKeygen(cn, devicegeneration)
            if kg.devicegeneration == "":
                print("Unknown device generation. Please send me details :)")
            else:
                kg.openlock()
        cn.close()
    else:
        kg = SierraKeygen(None, devicegeneration)
        if openlock != "":
            resp = kg.keygen.run(devicegeneration, openlock, 0)
            print("AT!OPENLOCK=\"" + resp + "\"")
        elif openmep != "":
            resp = kg.keygen.run(devicegeneration, openmep, 1)
            print("AT!OPENMEP=\"" + resp + "\"")
        elif opencnd != "":
            resp = kg.keygen.run(devicegeneration, opencnd, 2)
            print("AT!OPENCND=\"" + resp + "\"")


if __name__ == '__main__':
    main(sys.argv)
