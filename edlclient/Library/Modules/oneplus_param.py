#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
"""
Usage:
    oneplus_param.py param <filename> [--mode=mode] [--serial=serial]
    oneplus_param.py ops <filename> [--mode=mode] [--serial=serial]
    oneplus_param.py gencode <imei>
    oneplus_param.py setparam <filename> <sid> <offset> <value> [--mode=mode] [--serial=serial]
"""
import hashlib
import zlib
from enum import Enum
from struct import calcsize, pack, unpack

try:
    from edlclient.Library.cryptutils import cryptutils
except ImportError as e:
    import os, sys, inspect

    current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    try:
        from cryptutils import cryptutils
    except ImportError as e:
        print(str(e))
from binascii import unhexlify, hexlify


class sid(Enum):
    PARAM_SID_PRODUCT = 0,
    PARAM_SID_CONFIG = 1,
    PARAM_SID_LCD = 2,
    PARAM_SID_TP = 3,
    PARAM_SID_TP_KPD = 4,
    PARAM_SID_CAMERA = 5,
    PARAM_SID_SENSORS = 6,
    PARAM_SID_BATTERY = 7,
    PARAM_SID_RTC = 8,
    PARAM_SID_CRASH_RECORD = 9,
    PARAM_SID_SALEINFO = 0xA,
    PARAM_SID_MISC = 0xB,
    PARAM_SID_DOWNLOAD = 0xC,
    PARAM_SID_PHONE_HISTORY = 0xD,
    PARAM_SID_DL_USERINFO = 0xE,
    PARAM_SID_ENC_SECRECY = 0x12C,
    PARAM_SID_ENC_CARRIER = 0x130,
    PARAM_SID_ENC_MOBID = 0x134,
    PARAM_SID_ENC_CVE = 0x138,
    PARAM_SID_INVALID = -1

    ''' 
                CUSTOM_TYPE.NONE = new CUSTOM_TYPE("NONE", 0);
                CUSTOM_TYPE.JCC = new CUSTOM_TYPE("JCC", 1); French edition
                CUSTOM_TYPE.SW = new CUSTOM_TYPE("SW", 2); Star Wars
                CUSTOM_TYPE.AVG = new CUSTOM_TYPE("AVG", 3); Avengers
                CUSTOM_TYPE.MCL = new CUSTOM_TYPE("MCL", 4); McLaren
                CUSTOM_TYPE.OPR_RETAIL = new CUSTOM_TYPE("OPR_RETAIL", 5);
                CUSTOM_TYPE.CYB = new CUSTOM_TYPE("CYB", 6); Cyberpunk
                CUSTOM_TYPE v0 = new CUSTOM_TYPE("CMCC", 7); China Mobile
    '''
    '''
                SW_TYPE.DEFAULT = new SW_TYPE("DEFAULT", 0);
                SW_TYPE.O2 = new SW_TYPE("O2", 1);
                SW_TYPE.H2 = new SW_TYPE("H2", 2);
                SW_TYPE.IN = new SW_TYPE("IN", 3);
                SW_TYPE.EU = new SW_TYPE("EU", 4);
                SW_TYPE.TMO = new SW_TYPE("TMO", 5);
                SW_TYPE.SPRINT = new SW_TYPE("SPRINT", 6);
                SW_TYPE.VERIZON = new SW_TYPE("VERIZON", 7);
                SW_TYPE.ATT = new SW_TYPE("ATT", 8);
                SW_TYPE v0 = new SW_TYPE("C532", 9);

    '''
    '''
                CUSTOM_BACK_COVER_TYPE.NONE = new CUSTOM_BACK_COVER_TYPE("NONE", 0);
                CUSTOM_BACK_COVER_TYPE.LCH = new CUSTOM_BACK_COVER_TYPE("LCH", 1);
                CUSTOM_BACK_COVER_TYPE.MYH = new CUSTOM_BACK_COVER_TYPE("MYH", 2);
                CUSTOM_BACK_COVER_TYPE.YYB = new CUSTOM_BACK_COVER_TYPE("YYB", 3);
                CUSTOM_BACK_COVER_TYPE.HPH = new CUSTOM_BACK_COVER_TYPE("HPH", 4);
                CUSTOM_BACK_COVER_TYPE.DGZ = new CUSTOM_BACK_COVER_TYPE("DGZ", 5);
                CUSTOM_BACK_COVER_TYPE.OPGY = new CUSTOM_BACK_COVER_TYPE("OPGY", 6);
                CUSTOM_BACK_COVER_TYPE.OPBL = new CUSTOM_BACK_COVER_TYPE("OPBL", 7);
                CUSTOM_BACK_COVER_TYPE.OPGL = new CUSTOM_BACK_COVER_TYPE("OPGL", 8);
                CUSTOM_BACK_COVER_TYPE.OPRD = new CUSTOM_BACK_COVER_TYPE("OPRD", 9);
                CUSTOM_BACK_COVER_TYPE.OPHDBL = new CUSTOM_BACK_COVER_TYPE("OPHDBL", 10);
                CUSTOM_BACK_COVER_TYPE.OPHDSL = new CUSTOM_BACK_COVER_TYPE("OPHDSL", 11);
                CUSTOM_BACK_COVER_TYPE.OPHDMCL = new CUSTOM_BACK_COVER_TYPE("OPHDMCL", 12);
                CUSTOM_BACK_COVER_TYPE.OPHDAGBL = new CUSTOM_BACK_COVER_TYPE("OPHDAGBL", 13);
                CUSTOM_BACK_COVER_TYPE.OPINBLK = new CUSTOM_BACK_COVER_TYPE("OPINBLK", 14);
                CUSTOM_BACK_COVER_TYPE.OPINGRN = new CUSTOM_BACK_COVER_TYPE("OPINGRN", 15);
                CUSTOM_BACK_COVER_TYPE.OPINBLU = new CUSTOM_BACK_COVER_TYPE("OPINBLU", 16);
                CUSTOM_BACK_COVER_TYPE.OPINGRD = new CUSTOM_BACK_COVER_TYPE("OPINGRD", 17);
                CUSTOM_BACK_COVER_TYPE.OPINIB = new CUSTOM_BACK_COVER_TYPE("OPINIB", 18);
                CUSTOM_BACK_COVER_TYPE.OPAVICGRIR = new CUSTOM_BACK_COVER_TYPE("OPAVICGRIR", 19);
                CUSTOM_BACK_COVER_TYPE.OPAVICBLIC = new CUSTOM_BACK_COVER_TYPE("OPAVICBLIC", 20);
                CUSTOM_BACK_COVER_TYPE.OPAVICGRFR = new CUSTOM_BACK_COVER_TYPE("OPAVICGRFR", 21);
                CUSTOM_BACK_COVER_TYPE.OPKEBABGD = new CUSTOM_BACK_COVER_TYPE("OPKEBABGD", 22);
                CUSTOM_BACK_COVER_TYPE.OPKEBABBG = new CUSTOM_BACK_COVER_TYPE("OPKEBABBG", 23);
                CUSTOM_BACK_COVER_TYPE.OPKEBABSG = new CUSTOM_BACK_COVER_TYPE("OPKEBABSG", 24);
                CUSTOM_BACK_COVER_TYPE.OPN1MB = new CUSTOM_BACK_COVER_TYPE("OPN1MB", 25);
                CUSTOM_BACK_COVER_TYPE v0 = new CUSTOM_BACK_COVER_TYPE("OPN2GB", 26);

    '''


class paramtools:
    paramitems = {
        sid.PARAM_SID_PRODUCT.value[0]: {
            0x18: ["8c", "project_name"],
            0x20: ["I", "hw_version"],
            0x24: ["I", "rf_version"],
            0x28: ["16c", "rf_config_str"],
            0x38: ["I", "operator_num"],
            0x3C: ["10c", "operator_str"],
            0x4C: ["B", "Length PCBA_number"],
            0x4D: ["27c", "pcba_number"],
            0x68: ["I", "boot_aging_count"],
            0x6C: ["48c", "ota_info"],
            0x9C: ["80c", "firmware_info"],
            0xEC: ["32c", "build_info"],
            0x10C: ["I", "unknown_dword"],
            0x1A0: ["I", "OemCheckResetDevInfo"]  # if 1, then reset dev info. if 2, then do below, wth is this ?
        },
        sid.PARAM_SID_CONFIG.value[0]: {
            0x18: ["B", "dump_enable"],
        },
        sid.PARAM_SID_CRASH_RECORD.value[0]: {
            0x18: ["I", "crash_record_count"],
            0x1c: ["20c", "Crash log 1"],
            0x30: ["20c", "Crash log 2"],
            0x44: ["20c", "Crash log 3"],
            0x58: ["20c", "Crash log 4"],
            0x6c: ["20c", "Crash log 5"],
            0x80: ["20c", "Crash log 6"],
            0x94: ["20c", "Crash log 7"],
            0xa8: ["20c", "Crash log 8"],
            0xbc: ["20c", "Crash log 9"],
            0xd0: ["20c", "Crash log 10"],
            0xe4: ["20c", "Crash log 11"],
            0xf8: ["20c", "Crash log 12"],
            0x10c: ["20c", "Crash log 13"],
            0x120: ["20c", "Crash log 14"],
            0x134: ["20c", "Crash log 15"],
            0x15c: ["I", "restart_08_count"],
            0x160: ["I", "restart_other_count"]
        },
        sid.PARAM_SID_SALEINFO.value[0]: {  # 0xA, Param_saleinfo, PARAM_SID_SALEINFO
            0x18: ["I", "is_rooted"],
            0x1c: ["I", "root_time"],
            0x20: ["16c", "flash_0"],
            0x30: ["16c", "flash_1"],
            0x40: ["16c", "flash_2"],
            0x50: ["16c", "erase_0"],
            0x60: ["16c", "erase_1"],
            0x70: ["16c", "erase_2"],
            0x80: ["I", "is_angela"],
            # adb shell am start -n com.android.engineeringmode/.qualcomm.DiagEnabled --es "code" "angela"
            # adb shell am start -n com.oneplus.factorymode/.qualcomm.DiagEnabled --es "code" "angela"
            # disable: "setprop persist.sys.adb.engineermode 0" and "setprop persist.sys.adbroot 0" or call code *#8011#
            0x88: ["I", "Unknown flag"],
            0x8c: ["I", "Unknown value"],
            0x90: ["I", "Unknown flag"],
        },
        sid.PARAM_SID_MISC.value[0]: {  # 0xB
            0x20: ["I", "Misc flag 1"],
            0x24: ["44c", "Misc log a_1"],
            0x50: ["I", "Misc flag a_2"],
            0x54: ["44c", "Misc log a_2"],
            0x80: ["I", "Misc flag a_3"],
            0x84: ["44c", "Misc log a_3"],
            0xb0: ["I", "Misc flag a_4"],
            0xb4: ["44c", "Misc log a_4"],
            0xe4: ["I", "Misc flag b_1"],
            0xe8: ["44c", "Misc log b_1"],
            0x114: ["I", "Misc flag b_2"],
            0x118: ["44c", "Misc log b_2"],
            0x144: ["I", "Misc flag b_3"],
            0x148: ["44c", "Misc log b_3"],
            0x174: ["I", "Misc flag b_4"],
            0x178: ["44c", "Misc log b_4"],
            0x1a8: ["I", "Misc flag c_1"],
            0x1ac: ["44c", "Misc log c_1"],
            0x1d8: ["I", "Misc flag c_2"],
            0x1dc: ["44c", "Misc log c_2"],
            0x208: ["I", "Misc flag c_3"],
            0x20c: ["44c", "Misc log c_3"],
            0x238: ["I", "Misc flag c_4"],
            0x23c: ["44c", "Misc log c_4"],
        },
        sid.PARAM_SID_DOWNLOAD.value[0]: {  # 0xC
            0x18: ["24c", "Unknown date"],
            0x30: ["B", "SMT_Download_Status"],
            0x32: ["B", "Unknown flag"],
            0x33: ["B", "Unknown flag"],
            0x38: ["32c", "Unknown string_1"],
            0xd8: ["24c", "Unknown date_1"],
            0xF0: ["B", "Upgrade_Download_Status_1"],
            0xF2: ["B", "Unknown flag_1"],

            0xF8: ["32c", "Unknown string_2"],
            0x118: ["24c", "Unknown date_2"],
            0x130: ["B", "Upgrade_Download_Status_2"],
            0x132: ["B", "Unknown flag_2"],

            0x138: ["32c", "Unknown string_3"],
            0x158: ["24c", "Unknown date_3"],
            0x170: ["B", "Upgrade_Download_Status_3"],
            0x172: ["B", "Unknown flag_3"],

            0x178: ["32c", "Unknown string_4"],
            0x188: ["24c", "Unknown date_4"],

            0x198: ["I", "boot_stage"],
            0x19C: ["I", "data_stage"],
            0x1A0: ["B", "reset_devinfo"],  # OemCheckResetRevInfo
            0x1A4: ["B", "intranet_3t"],
            0x1A8: ["B", "bootmode_3t"]
        },

        sid.PARAM_SID_PHONE_HISTORY.value[0]: {  # 0xD
            0x24: ["I", "Update_Count"],
            0x28: ["I", "Unlock_Count"],
            0x2c: ["I", "Unknown value"],
            0x30: ["I", "param_poweroff_count"],
            0x34: ["I", "abl_tamper"],
        },

        sid.PARAM_SID_DL_USERINFO.value[0]: {  # 0xE
            0x20: ["32c", "Computername_1"],
            0x40: ["32c", "Username_1"],
            0x60: ["I", "Flag_1"],
            0x68: ["20c", "IP_1"],
            0x7C: ["I", "Chksum_1_0"],
            0xA0: ["32c", "Computername_2"],
            0xC0: ["32c", "Username_2"],
            0xE0: ["I", "Flag_2"],
            0xE8: ["20c", "IP_2"],
            0xFC: ["I", "Chksum_2"],
            0x120: ["32c", "Computername_2"],
            0x140: ["32c", "Username_2"],
            0x160: ["I", "Flag_2"],
            0x168: ["20c", "IP_2"],
            0x17C: ["I", "Chksum_2"],
            0x1A0: ["32c", "Computername_3"],
            0x1C0: ["32c", "Username_3"],
            0x1E0: ["I", "Flag_3"],
            0x1E8: ["20c", "IP_3"],
            0x1FC: ["I", "Chksum_3"],
        },

        0xB0: {
            0x2b4: ["128B", "Unknown"]
        },

        sid.PARAM_SID_ENC_SECRECY.value[0]: {  # 0x12C
            0x80: ["I", "intranet"],  # Allows factory commands via fastboot ops, *#808# engineermode
            # dumpsys secrecy dump (persist)
            # fastboot ops 4F50040TR18FTR7FSTD5F01
            # fastboot ops help
            0x84: ["I", "boottype"],  # 0xA9E:"sdebug"; 0xB7:"debug";0xA0:"auto";0x0:"normal"
            0x88: ["I", "ONLINE_CFG_TEST_ENV"],
            0x8C: ["I", "TargetSWID"],
            0x90: ["I", "AgingFlag"]
        },

        sid.PARAM_SID_ENC_CARRIER.value[0]: {  # 0x130
            0xA0: ["I", "CustFlag"],
            0xA4: ["I", "CustFlagMigrationPlaintext"],
            0xA8: ["I", "carrier_id"],
            0xAC: ["I", "carrier_init_flag"]
        },
        sid.PARAM_SID_ENC_MOBID.value[0]: {
            0x80: ["16c", "mobid/imei/meid1"],
            0x90: ["I", "mobid/imei_flag"],
            0x94: ["I", "Recondition flag (RCF)"],
            0x98: ["19c", "Unknown date1"],
            0xB0: ["19c", "Unknown date2"],
            0xC8: ["19c", "Unknown date3"],
            0xE0: ["8c", "Unknown_value_000000"],
            0xE8: ["16c", "mobid/imei/meid2"],
            0xF0: ["I", "mobid/meid flag"],
            0xF8: ["I", "Unknown flag"]
        },
        sid.PARAM_SID_ENC_CVE.value[0]: {
            0x80: ["16c", "CVE_SystemBlob_A"],
            0x90: ["16c", "CVE_VendorBlob_A"],
            0xA0: ["16c", "CVE_SystemBlob_B"],
            0xB0: ["16c", "CVE_VendorBlob_B"],
            0xC0: ["16c", "CVE_Current_BootImg_A"],
            0xD0: ["16c", "CVE_Current_BootImg_B"],
            0xE0: ["I", "PWD Index 1"],
            0xE4: ["40c", "PWD Hash 1"],
            0x114: ["40c", "PWD Hash 2"],
            0x144: ["40c", "PWD Hash 3"],
            0x174: ["40c", "PWD Hash 4"],
            0x1a4: ["I", "PWD Index 2"],
            0x1a8: ["40c", "PWD Hash 1"],
            0x1d8: ["40c", "PWD Hash 2"],
            0x208: ["40c", "PWD Hash 3"],
            0x238: ["40c", "PWD Hash 4"],
            0x268: ["I", "PWD Index 3"],
            0x26c: ["40c", "PWD Hash 1"],
            0x29c: ["40c", "PWD Hash 2"],
            0x2cc: ["40c", "PWD Hash 3"],
            0x2fc: ["40c", "PWD Hash 4"],
        }
    }

    def __init__(self, mode, serial):
        self.aes_iv = unhexlify("562E17996D093D28DDB3BA695A2E6F58")
        self.aes_key = unhexlify("3030304F6E65506C7573383138303030")
        if mode == 1:
            derivedkey = bytes.fromhex("a9264fbf8a" + ("%08x" % serial) + "6b4487ea")[:0x1A]
            derivedkey = hashlib.sha256(derivedkey).digest()[:16]
            self.aes_key = derivedkey

    def getparam(self, offset, sidindex):
        if sidindex & 0x1FF in self.paramitems:
            siditems = self.paramitems[sidindex & 0x1FF]
            if offset in siditems:
                return siditems[offset]
        return None

    def decryptsid(self, data):
        aes = cryptutils().aes()
        hash = cryptutils().hash()
        header = data[:4 + 1 + 1]
        magic, hv, cv = unpack("<IBB", header)
        updatecounter = data[0x10]
        if magic != 0xA0AD646A:
            return None, None, None, None

        enchash = data[0x80:0x90]
        encdata = data[0x400:0x400 + 0xC00]
        genenchash = hash.md5(encdata)
        if genenchash != enchash:
            print(
                f"Generated hash doesn't match encrypted hash:\n{hexlify(genenchash).decode('utf-8')}\n{hexlify(enchash).decode('utf-8')}")
            return None, None, None, None
        decdata = aes.aes_cbc(self.aes_key, self.aes_iv, encdata)
        dechash = decdata[:16]
        itemdata = decdata[-0xB80:]
        gendechash = hash.md5(itemdata)
        if gendechash != dechash:
            print(
                f"Generated hash doesn't match decrypted hash:\n{hexlify(gendechash).decode('utf-8')}\n{hexlify(dechash).decode('utf-8')}")
            return None, None, None, None
        return itemdata, hv, cv, updatecounter

    def encryptsid(self, itemdata, hv, cv, updatecounter):
        aes = cryptutils().aes()
        hash = cryptutils().hash()
        magic = 0xA0AD646A
        siddata = bytearray(b"\x00" * 0x1000)
        siddata[:4 + 1 + 1] = pack("<IBB", magic, hv, cv)
        siddata[0x10] = updatecounter + 1

        header = bytearray(b"\00" * 0x80)
        gendechash = hash.md5(itemdata)
        header[0:16] = gendechash
        decdata = header + itemdata
        encdata = aes.aes_cbc(self.aes_key, self.aes_iv, decdata, False)
        genenchash = hash.md5(encdata)

        siddata[0x80:0x90] = genenchash
        siddata[0x400:0x400 + 0xC00] = encdata
        return siddata

    def parse_encrypted(self, rdata, sid):
        data = rdata[(sid * 0x400):(sid * 0x400) + 0x1000]
        itemdata, hv, cv, updatecounter = self.decryptsid(data)
        if itemdata is not None:
            itemdata = bytearray(itemdata)
            print(
                f"Offset {hex(sid * 0x400)}: hv {hex(hv)}, cv {hex(cv)}, increase_enc_update_counter {hex(updatecounter)}.")
            i = 0
            while i < len(itemdata):
                offset = i + 0x80
                param = self.getparam(offset, sid)
                if param is None:
                    if i + 4 < len(itemdata):
                        value = unpack("<I", itemdata[i:i + 4])[0]
                        if value != 0x0:
                            print(f"Encrypted SID_Index {hex(sid)}, Offset {hex(offset)}: {hex(value)}")

                    i += 4
                else:
                    length = self.parse_data(i, itemdata, offset, param, sid, True)
                    i += length
                    if length % 4:
                        i += 4 - (length % 4)
            print()

    def parse_encrypted_fields(self, rdata):
        for sid in range(0x12c, 0x139):
            self.parse_encrypted(rdata, sid)
        # Backup
        """
        for sid in range(0x32c, 0x339):
            self.parse_encrypted(rdata, sid)
        """

    def parse_decrypted_fields(self, rdata):
        for pos in range(0x0, 0x40000, 0x400):
            if pos >= len(rdata):
                break
            data = rdata[pos:pos + 0x18]
            fm = data[0:0x10].replace(b'\x00', b'').decode('utf-8')
            if fm != "":
                print()
                print(f"Offset {hex(pos)}: Field {fm}")
            itemlength = unpack("<I", data[0x14:0x18])[0]
            if itemlength == 0x0:
                itemlength = 0x400
            itemdata = rdata[pos + 0x18:pos + 0x18 + itemlength]
            i = 0
            while i < len(itemdata) - 0x22:
                sidindex = (pos // 0x400) & 0x1FF
                offset = i + 0x18
                # if sidindex==0x334 and offset==0x80:
                #    print(hexlify(itemdata).decode('utf-8'))
                param = self.getparam(offset, sidindex)
                if param is None:
                    if itemdata[i] != 0:
                        if i + 4 < len(itemdata):
                            value = unpack("<I", itemdata[i:i + 4])[0]
                            if value != 0x0:
                                print(f"SID_Index {hex(sidindex)}, Offset {hex(offset)}: {hex(value)}")
                        i += 4
                    else:
                        i += 1
                else:
                    length = self.parse_data(i, itemdata, offset, param, sidindex)
                    i += length
                    if length > 4:
                        if length % 4:
                            i += 4 - (length % 4)

    def parse_data(self, i, itemdata, offset, param, sidindex, encrypted=False):
        stype = param[0]
        name = param[1]
        length = calcsize(stype)
        item = itemdata[i:i + length]
        content = unpack(stype, item)
        try:
            content = "\"" + b"".join(content).replace(b'\x00', b'').decode('utf-8') + "\""
        except:
            if len(content) == 1:
                content = hex(content[0])
            else:
                tm = ""
                for item in content:
                    if item == 0:
                        break
                    tm += hex(item)
                content = tm
        offsetstr = hex(offset)
        while len(offsetstr) < 5:
            offsetstr = offsetstr[:2] + "0" + offsetstr[2:]
        while len(name) < 30:
            name = name + " "
        if "PWD Hash" in name:
            items = content.split(" ")
            pwdhash = items[0][1:9] + "00000000000000000000000000000000000000000000000000000000"
            valid = "True" if items[1] != "-1" else "False"
            flag = items[2]
            date = items[3] + " " + items[4][:-1]
            content = f"{date} ({valid},{flag}): {pwdhash}"
            ff = f"SID_Index {hex(sidindex)}, Offset {offsetstr}: {name}: {content}"
            if encrypted:
                ff = "Encrypted " + ff
        else:
            ff = f"SID_Index {hex(sidindex)}, Offset {offsetstr}: {name}: {content}"
            if encrypted:
                ff = "Encrypted " + ff
        print(ff)
        return length

    def setparamvalue(self, data, sid, offset, value):
        if sid > 0x100:
            rdata = data[sid * 0x400:(sid * 0x400) + 0x1000]
            itemdata, hv, cv, updatecounter = self.decryptsid(rdata)
            if itemdata is not None:
                itemdata = bytearray(itemdata)
                if isinstance(value, int):
                    itemdata[offset - 0x80:(offset + 4) - 0x80] = pack("<I", value)
                elif isinstance(value, bytearray):
                    itemdata[offset - 0x80:(offset + len(value)) - 0x80] = value
                # itemdata[0x84-0x80:(0x84+4)-0x80]=pack("<I",0xB7) #devkmsg_enable
                mdata = self.encryptsid(itemdata, hv, cv, updatecounter)
            data = bytearray(data)
            data[sid * 0x400:(sid * 0x400) + 0x1000] = mdata
            # data[(sid+0x200) * 0x400:((sid+0x200) * 0x400) + 0x1000] = mdata
        else:
            rdata = data[sid * 0x400:(sid * 0x400) + 0x1000]
            data = bytearray(data)
            rdata = bytearray(rdata)
            if isinstance(value, int):
                rdata[offset:offset + 4] = pack("<I", value)
            elif isinstance(value, bytearray):
                rdata[offset:(offset + len(value))] = value
            data[sid * 0x400:(sid * 0x400) + 0x1000] = rdata
        return data

    def gencode(self, inparray):
        res = []
        for input in inparray:
            m = hashlib.sha1()
            m.update(bytes("ONEPLUS_" + input, 'utf-8'))
            hash = m.hexdigest().lower()
            crcdata = hex(zlib.crc32(bytes(hash, 'utf-8')))[2:]
            while len(crcdata) < 8:
                crcdata = '0' + crcdata
            res.append(crcdata)
        return res

    def enable_ops(self, data, enable):
        sid = 0x12C
        offset = 0x80  # intranet
        if enable:
            value = 0x3
        else:
            value = 0x0
        return self.setparamvalue(data, sid, offset, value)


'''
ONEPLUS_358240051111110 => sha1 = 99e489e03107817f14ac06a1bb52de3455423542 => CRC32 -> 
ecec6492
ONEPLUS_YOU_CAN_PASS_NOW => sha1 = 9db4b7338e254669b8c703e77cbc9f119ade7fa6 => CRC32 -> 79707450 (wenn < 8, dann fill mit 0)
'''
'''
com.android.engineeringmode.encrypt

3439 = oem.cust.flag 1 = French custom edition
9339 = oem.cust.flag 2 = Indian edition
3392 = oem.cust.flag 0 = Normal edition
7668 = com.android.engineeringmode.manualtest.CheckRootStatusActivity
5646 = com.android.engineeringmode.manualtest.DecryptActivity
838 =  com.android.engineeringmode.manualtest.CheckRootStatusActivity

com.oneplus.factorymode.CommonCommands
com.oem.engineermode.DoShellCommond
if(!arg18.getAction().equals(v1.mAction) && !arg18.getAction().equals(v1.na)) {
if((arg18.getAction().equals(v1.doshellcommond)) && ("get_config_params".equals(v0.getStringExtra("shell_cmd")))) {
adb shell am start -n com.oem.engineermode.DoShellCommond --es "shell_cmd" "get_config_params"

action android:name
adb shell am start -n com.android.engineeringmode/.qualcomm.DiagEnabled --es "code" "Angela"
79a6a933dfc9b1975e444d4e8481c64c771d8ab40b7ac72f8bc1a1bca1718bef

android.provider.Telephony.SECRET_CODE
*#66# com.android.engineeringmode.IMeiAndPcbCheck
*#99# com.android.engineeringmode.KeepSrceenOn
*#008# com.android.engineeringmode.LanguageSwitchToChineseActivity
*#268# com.android.engineeringmode.qualcomm.QualCommActivity
*#391# com.android.engineeringmode.SwitchSoftwareVersion
*#789# com.android.engineeringmode.qualcomm.ClearTelcelnetlock
*#800# com.android.engineeringmode.qualcomm.LogSwitch
*#800# com.oem.oemlogkit.OEMLogKitMainActivity
*#801# com.android.engineeringmode.qualcomm.DiagEnabled
*#802# com.android.engineeringmode.gps.GpsActivity
*#803# com.android.engineeringmode.wifitest.WifiSettings
*#804# com.android.engineeringmode.NetworkSearch
*#805# com.android.engineeringmode.bluetoothtest.BluetoothTest
*#806# com.android.engineeringmode.autoaging.AutoAgingMainListActivity
*#807# com.android.engineeringmode.autotest.AutoTest
*#808# com.android.engineeringmode.EngineerModeMain
*#808# com.android.engineeringmode.manualtest.ManualTest
*#809# com.android.engineeringmode.echotest.EchoTest
*#810# com.android.engineeringmode.SwitchSetupWizardActivity
*#814# com.android.engineeringmode.TDSNetworkSearch
*#818# com.android.engineeringmode.NetworkSearch_New
*#820# com.android.engineeringmode.DeleteNoNeedFilesActivity
*#824# com.android.engineeringmode.WCDMANetworkSearch
*#834# com.android.engineeringmode.LTENetworkSearch
*#838# com.android.engineeringmode.NetworkSearch_New
*#845# com.android.engineeringmode.wifitest.WifiApSettings
*#888# com.android.engineeringmode.PcbShow
*#899# com.oneplus.factorymode.aftersale.ChooseBackCoverColor
*#900# com.android.engineeringmode.BackCameraAdjusting
*#911# com.android.engineeringmode.PowerOff (Warning: Does factory reset)
*#912# com.android.engineeringmode.qualcomm.RecoverTelcelnetlock
*#912# com.android.engineeringmode.RebootManager
*#928# com.android.engineeringmode.wifitest.WifiFTMActivity
*#1234# com.android.engineeringmode.SHOW_ONEPLUS_VERSION
*#4321# com.android.engineeringmode.LanguageSwitchToZimbabweService
*#6776# com.android.engineeringmode.CheckSoftwareInfo
*#7327# com.oem.rftoolkit.RfToolkitCustomerService
*#7328# com.oem.rftoolkit.RfToolkitAgingTest
*#7332# com.oem.rftoolkit.RfToolkitFactory
*#8011# com.android.engineeringmode.NoUI
*#8017# com.android.engineeringmode.wifitest.WifiAdbHelper
*#8019# com.android.engineeringmode.wifitest.WifiSocketHelper
*#8020# com.android.engineeringmode.wifitest.WifiAdbHelper
*##*8110# com.android.engineeringmode.qualcomm.OtaSwitch
*#8668# com.oneplus.activation.action.STOP_ACTIVATION
*#8669# com.oneplus.activation.action.START_ACTIVATION
*#8778# com.android.engineeringmode.manualtest.MasterClear
*#8888# com.android.engineeringmode.manualtest.MasterClear
*#9886# com.oneplus.screensaver.off
*#9889# com.oneplus.screensaver.on
*#10000# com.android.engineeringmode.MarkResultShow
*#12345# com.android.activation.action.STOP_SERVICE
*#3954391# Switch activated
*##*37847# com.android.engineeringmode.manualtest.DeviceListActivity
*#2288379# com.android.engineeringmode.BatteryExtraInfo
*#36446337# com.android.engineeringmode.EngineeringMode
*#6776001# set_language en_US
*#6776007# set_language ru_RU
*#67760052# set_language es_MX
*#67760055# set_language pt_BR
*#67760066# set_language th_TH
*#67760062# set_language in_IN
*#67760084# set_language vi_VI
*#67760086# set_language zh_CN
*#67760886# set_language zh_TW
*#67760044# com.android.engineeringmode.LanguageSwitchToEnglishActivity
*#67766776# com.android.engineeringmode.oneplusConnectionADBActivity
*#677667764482# com.android.engineeringmode.UserAgentSwitchService
*#*#5646#*#* com.android.engineeringmode.manualtest.DecryptActivity
*#*#7668#*#* com.android.engineeringmode.manualtest.CheckRootStatusActivity
*#3439# = oem.cust.flag=1
*#9339# = oem.cust.flag=2
*#3392# = oem.cust.flag=0

fastboot ops 4F50040TR18FTR7FSTD5F01
fastboot ops help

fastboot ops 4F50040TR18FTR7FSTD5F01
fastboot ops devkmsg on
fastboot ops boottype debug


(bootloader) ops android_log_all
(bootloader) ops kernel_log_all
(bootloader) ops devkmsg
(bootloader) ops boottype [normal, debug, sdebug]
(bootloader) ops set_cust
(bootloader) ops force_adb
(bootloader) ops qeaging_data_img
(bootloader) ops unmount tempfs
(bootloader) ops mount tempfs
(bootloader) ops enable_dm_verity
(bootloader) ops disable_dm_verity
(bootloader) ops boot_mode [rf,ftm,wlan,normal]
(bootloader) ops selinux
(bootloader) ops dump
(bootloader) ops help
(bootloader) ops datafs
(bootloader) ops unforce_training
(bootloader) ops force_training
(bootloader) ops reboot-bootloader
(bootloader) ops reboot-shutdown
(bootloader) ops kmemleak undetect
(bootloader) ops kmemleak detect
(bootloader) ops unconsole
(bootloader) ops console
(bootloader) oem get_unlock_code
(bootloader) oem lock
(bootloader) oem unlock
(bootloader) download:
(bootloader) getvar:
(bootloader) reboot-bootloader
(bootloader) reboot
(bootloader) continue
(bootloader) oem device-info
(bootloader) oem select-display-panel
(bootloader) oem off-mode-charge
(bootloader) oem disable-charger-screen
(bootloader) oem enable-charger-screen
(bootloader) boot
(bootloader) flashing lock
(bootloader) flashing unlock
(bootloader) flashing get_unlock_ability
(bootloader) set_active
(bootloader) erase:
(bootloader) flash:
(bootloader) Varlist

(bootloader) hw-revision:20001
(bootloader) unlocked:no
(bootloader) off-mode-charge:1
(bootloader) charger-screen-enabled:1
(bootloader) battery-soc-ok:yes
(bootloader) battery-voltage:4360
(bootloader) version-baseband:
(bootloader) version-bootloader:
(bootloader) erase-block-size: 0x1000
(bootloader) logical-block-size: 0x1000
(bootloader) variant:SDM UFS
(bootloader) partition-type:fsc:raw
(bootloader) partition-size:fsc: 0x20000
(bootloader) partition-type:fsg:raw
(bootloader) partition-size:fsg: 0x200000
(bootloader) partition-type:modemst2:raw
(bootloader) partition-size:modemst2: 0x200000
(bootloader) partition-type:modemst1:raw
(bootloader) partition-size:modemst1: 0x200000
(bootloader) partition-type:ALIGN_TO_128K_2:raw
(bootloader) partition-size:ALIGN_TO_128K_2: 0x1A000
(bootloader) partition-type:ImageFv:raw
(bootloader) partition-size:ImageFv: 0x200000
(bootloader) partition-type:logdump:raw
(bootloader) partition-size:logdump: 0x4000000
(bootloader) partition-type:sti:raw
(bootloader) partition-size:sti: 0x200000
(bootloader) partition-type:logfs:raw
(bootloader) partition-size:logfs: 0x800000
(bootloader) partition-type:toolsfv:raw
(bootloader) partition-size:toolsfv: 0x100000
(bootloader) partition-type:limits:raw
(bootloader) partition-size:limits: 0x1000
(bootloader) partition-type:splash:raw
(bootloader) partition-size:splash: 0x20A4000
(bootloader) partition-type:spunvm:raw
(bootloader) partition-size:spunvm: 0x800000
(bootloader) partition-type:msadp:raw
(bootloader) partition-size:msadp: 0x40000
(bootloader) partition-type:apdp:raw
(bootloader) partition-size:apdp: 0x40000
(bootloader) partition-type:dip:raw
(bootloader) partition-size:dip: 0x100000
(bootloader) partition-type:devinfo:raw
(bootloader) partition-size:devinfo: 0x1000
(bootloader) partition-type:sec:raw
(bootloader) partition-size:sec: 0x4000
(bootloader) partition-type:op1:raw
(bootloader) partition-size:op1: 0x6400000
(bootloader) partition-type:aging:raw
(bootloader) partition-size:aging: 0x4000000
(bootloader) partition-type:minidump:raw
(bootloader) partition-size:minidump: 0x6400000
(bootloader) partition-type:fw_ufs8_b:raw
(bootloader) partition-size:fw_ufs8_b: 0x200000
(bootloader) partition-type:fw_ufs7_b:raw
(bootloader) partition-size:fw_ufs7_b: 0x200000
(bootloader) partition-type:fw_ufs6_b:raw
(bootloader) partition-size:fw_ufs6_b: 0x200000
(bootloader) partition-type:fw_ufs5_b:raw
(bootloader) partition-size:fw_ufs5_b: 0x200000
(bootloader) partition-type:fw_ufs4_b:raw
(bootloader) partition-size:fw_ufs4_b: 0x200000
(bootloader) partition-type:fw_ufs3_b:raw
(bootloader) partition-size:fw_ufs3_b: 0x200000
(bootloader) partition-type:fw_4u1ea_b:raw
(bootloader) partition-size:fw_4u1ea_b: 0x200000
(bootloader) partition-type:fw_4j1ed_b:raw
(bootloader) partition-size:fw_4j1ed_b: 0x200000
(bootloader) partition-type:LOGO_b:raw
(bootloader) partition-size:LOGO_b: 0x1000000
(bootloader) partition-type:storsec_b:raw
(bootloader) partition-size:storsec_b: 0x20000
(bootloader) partition-type:dtbo_b:raw
(bootloader) partition-size:dtbo_b: 0x800000
(bootloader) partition-type:vbmeta_b:raw
(bootloader) partition-size:vbmeta_b: 0x10000
(bootloader) partition-type:vendor_b:raw
(bootloader) partition-size:vendor_b: 0x40000000
(bootloader) partition-type:qupfw_b:raw
(bootloader) partition-size:qupfw_b: 0x10000
(bootloader) partition-type:devcfg_b:raw
(bootloader) partition-size:devcfg_b: 0x20000
(bootloader) partition-type:cmnlib64_b:raw
(bootloader) partition-size:cmnlib64_b: 0x80000
(bootloader) partition-type:cmnlib_b:raw
(bootloader) partition-size:cmnlib_b: 0x80000
(bootloader) partition-type:boot_b:raw
(bootloader) partition-size:boot_b: 0x4000000
(bootloader) partition-type:keymaster_b:raw
(bootloader) partition-size:keymaster_b: 0x80000
(bootloader) partition-type:dsp_b:raw
(bootloader) partition-size:dsp_b: 0x2000000
(bootloader) partition-type:abl_b:raw
(bootloader) partition-size:abl_b: 0x800000
(bootloader) partition-type:mdtp_b:raw
(bootloader) partition-size:mdtp_b: 0x2000000
(bootloader) partition-type:mdtpsecapp_b:raw
(bootloader) partition-size:mdtpsecapp_b: 0x400000
(bootloader) partition-type:bluetooth_b:raw
(bootloader) partition-size:bluetooth_b: 0x100000
(bootloader) partition-type:modem_b:raw
(bootloader) partition-size:modem_b: 0x7800000
(bootloader) partition-type:hyp_b:raw
(bootloader) partition-size:hyp_b: 0x80000
(bootloader) partition-type:tz_b:raw
(bootloader) partition-size:tz_b: 0x200000
(bootloader) partition-type:aop_b:raw
(bootloader) partition-size:aop_b: 0x80000
(bootloader) partition-type:fw_ufs8_a:raw
(bootloader) partition-size:fw_ufs8_a: 0x200000
(bootloader) partition-type:fw_ufs7_a:raw
(bootloader) partition-size:fw_ufs7_a: 0x200000
(bootloader) partition-type:fw_ufs6_a:raw
(bootloader) partition-size:fw_ufs6_a: 0x200000
(bootloader) partition-type:fw_ufs5_a:raw
(bootloader) partition-size:fw_ufs5_a: 0x200000
(bootloader) partition-type:fw_ufs4_a:raw
(bootloader) partition-size:fw_ufs4_a: 0x200000
(bootloader) partition-type:fw_ufs3_a:raw
(bootloader) partition-size:fw_ufs3_a: 0x200000
(bootloader) partition-type:fw_4u1ea_a:raw
(bootloader) partition-size:fw_4u1ea_a: 0x200000
(bootloader) partition-type:fw_4j1ed_a:raw
(bootloader) partition-size:fw_4j1ed_a: 0x200000
(bootloader) partition-type:LOGO_a:raw
(bootloader) partition-size:LOGO_a: 0x1000000
(bootloader) partition-type:storsec_a:raw
(bootloader) partition-size:storsec_a: 0x20000
(bootloader) partition-type:dtbo_a:raw
(bootloader) partition-size:dtbo_a: 0x800000
(bootloader) partition-type:vbmeta_a:raw
(bootloader) partition-size:vbmeta_a: 0x10000
(bootloader) partition-type:vendor_a:raw
(bootloader) partition-size:vendor_a: 0x40000000
(bootloader) partition-type:qupfw_a:raw
(bootloader) partition-size:qupfw_a: 0x10000
(bootloader) partition-type:devcfg_a:raw
(bootloader) partition-size:devcfg_a: 0x20000
(bootloader) partition-type:cmnlib64_a:raw
(bootloader) partition-size:cmnlib64_a: 0x80000
(bootloader) partition-type:cmnlib_a:raw
(bootloader) partition-size:cmnlib_a: 0x80000
(bootloader) partition-type:boot_a:raw
(bootloader) partition-size:boot_a: 0x4000000
(bootloader) partition-type:keymaster_a:raw
(bootloader) partition-size:keymaster_a: 0x80000
(bootloader) partition-type:dsp_a:raw
(bootloader) partition-size:dsp_a: 0x2000000
(bootloader) partition-type:abl_a:raw
(bootloader) partition-size:abl_a: 0x800000
(bootloader) partition-type:mdtp_a:raw
(bootloader) partition-size:mdtp_a: 0x2000000
(bootloader) partition-type:mdtpsecapp_a:raw
(bootloader) partition-size:mdtpsecapp_a: 0x400000
(bootloader) partition-type:bluetooth_a:raw
(bootloader) partition-size:bluetooth_a: 0x100000
(bootloader) partition-type:modem_a:raw
(bootloader) partition-size:modem_a: 0x7800000
(bootloader) partition-type:hyp_a:raw
(bootloader) partition-size:hyp_a: 0x80000
(bootloader) partition-type:tz_a:raw
(bootloader) partition-size:tz_a: 0x200000
(bootloader) partition-type:aop_a:raw
(bootloader) partition-size:aop_a: 0x80000
(bootloader) partition-type:ddr:raw
(bootloader) partition-size:ddr: 0x100000
(bootloader) partition-type:cdt:raw
(bootloader) partition-size:cdt: 0x20000
(bootloader) partition-type:ALIGN_TO_128K_1:raw
(bootloader) partition-size:ALIGN_TO_128K_1: 0x1A000
(bootloader) partition-type:xbl_config_b:raw
(bootloader) partition-size:xbl_config_b: 0x20000
(bootloader) partition-type:xbl_b:raw
(bootloader) partition-size:xbl_b: 0x380000
(bootloader) partition-type:xbl_config_a:raw
(bootloader) partition-size:xbl_config_a: 0x20000
(bootloader) partition-type:xbl_a:raw
(bootloader) partition-size:xbl_a: 0x380000
(bootloader) partition-type:userdata:ext4
(bootloader) partition-size:userdata: 0x1B800BB000
(bootloader) partition-type:odm_b:raw
(bootloader) partition-size:odm_b: 0x6400000
(bootloader) partition-type:odm_a:raw
(bootloader) partition-size:odm_a: 0x6400000
(bootloader) partition-type:system_b:ext4
(bootloader) partition-size:system_b: 0xB2C00000
(bootloader) partition-type:system_a:ext4
(bootloader) partition-size:system_a: 0xB2C00000
(bootloader) partition-type:config:raw
(bootloader) partition-size:config: 0x80000
(bootloader) partition-type:reserve2:raw
(bootloader) partition-size:reserve2: 0xFD0000
(bootloader) partition-type:reserve1:raw
(bootloader) partition-size:reserve1: 0x7E8000
(bootloader) partition-type:oem_stanvbk:raw
(bootloader) partition-size:oem_stanvbk: 0xA00000
(bootloader) partition-type:oem_dycnvbk:raw
(bootloader) partition-size:oem_dycnvbk: 0xA00000
(bootloader) partition-type:op2:raw
(bootloader) partition-size:op2: 0x10000000
(bootloader) partition-type:frp:raw
(bootloader) partition-size:frp: 0x80000
(bootloader) partition-type:keystore:raw
(bootloader) partition-size:keystore: 0x80000
(bootloader) partition-type:param:raw
(bootloader) partition-size:param: 0x100000
(bootloader) partition-type:misc:raw
(bootloader) partition-size:misc: 0x100000
(bootloader) partition-type:persist:raw
(bootloader) partition-size:persist: 0x2000000
(bootloader) partition-type:ssd:raw
(bootloader) partition-size:ssd: 0x2000
(bootloader) has-slot:modem:yes
(bootloader) has-slot:system:yes
(bootloader) current-slot:b
(bootloader) has-slot:boot:yes
(bootloader) slot-retry-count:b:6
(bootloader) slot-unbootable:b:no
(bootloader) slot-successful:b:yes
(bootloader) slot-retry-count:a:6
(bootloader) slot-unbootable:a:no
(bootloader) slot-successful:a:yes
(bootloader) slot-count:2
(bootloader) secure:yes
(bootloader) serialno:45751efa
(bootloader) product:sdm845
(bootloader) max-download-size:536870912
(bootloader) kernel:uefi

25d52959

am broadcast -n com.oneplus.factorymode/.EngineerModeActionReceiver -a android.provider.Telephony.SECRET_CODE -d android_secret_code://5646 

am broadcast -n com.oneplus.factorymode/.EngineerModeActionReceiver -a com.android.engineeringmode.encrypt

am broadcast -n com.oneplus.factorymode/.EngineerModeActionReceiver -a
com.oem.engineermode.StartOEMLogMain

IMEI:866241047809937
'''


def main():
    from docopt import docopt
    args = docopt(__doc__, version='oneplus 1.1')
    # filename="param_jacob_7pro.bin"
    # filename="chris/param.bin"
    if args["param"]:
        filename = args["<filename>"]
        mode = args["--mode"]
        serial = args["--serial"]
        param = paramtools(mode, serial)
        with open(filename, 'rb') as rf:
            data = rf.read()
            param.parse_decrypted_fields(data)
            print("\nEncrypted Values:\n-----------------\n")
            param.parse_encrypted_fields(data)
            # with open(filename + ".patched", 'wb') as wf:
            #    wf.write(param.setfactoryflags(data))
    elif args["ops"]:
        filename = args["<filename>"]
        mode = args["--mode"]
        serial = args["--serial"]
        param = paramtools(mode, serial)
        with open(filename, 'rb') as rf:
            data = rf.read()
            with open(filename + ".patched", 'wb') as wf:
                try:
                    data = param.setparamvalue(data, 0x12C, 0x80, 0x3)  # >= Oneplus 5
                except:
                    pass
                data = param.setparamvalue(data, 0xC, 0x1A4, 0x1)  # < Oneplus 5
                wf.write(data)
    elif args["setparam"]:
        filename = args["<filename>"]
        sid = int(args["<sid>"], 16)
        offset = int(args["<offset>"], 16)
        value = int(args["<value>"], 16)
        mode = args["--mode"]
        serial = args["--serial"]
        param = paramtools(mode, serial)
        with open(filename, 'rb') as rf:
            data = rf.read()
            with open(filename + ".patched", 'wb') as wf:
                wf.write(param.setparamvalue(data, sid, offset, value))
    elif args["gencode"]:
        imei = args["<imei>"]
        mode = 0
        serial = None
        param = paramtools(mode, serial)
        print("oneplus Factory qr code generator (c) B. Kerler 2019\nGPLv3 License\n----------------------")
        print("Code : *#*#5646#*#* , *#808#, *#36446337# = com.android.engineeringmode.manualtest.DecryptActivity")
        results = param.gencode([imei, "YOU_CAN_PASS_NOW"])
        import qrcode
        img = qrcode.make("op_eng://" + results[0])
        print("Code : " + results[0])
        img.save(imei + ".png")
        print("Image written as " + imei + ".png")


if __name__ == "__main__":
    main()
