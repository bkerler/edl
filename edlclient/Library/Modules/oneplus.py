#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

"""
Usage:
    oneplus.py rawxml [--projid=value] [--serial=value]
    oneplus.py rawnewxml [--projid=value] [--ts=value] [--serial=value]
    oneplus.py setprojmodel_verify <token> <pk> [--projid=value]
    oneplus.py setswprojmodel_verify <token> <pk> [--projid=value] [--ts=value]
    oneplus.py program_verify <token> <prog_token> <pk> [--projid=value]
Options:
    --projid=value   Set the appropriate projid  [default: 18825]
    --serial=value   Set the appropriate serial  [default: 123456]
    --ts=value       Set the device timestamp    [default: 1604949411]
"""

import time
import random
from struct import pack
import logging
from edlclient.Library.utils import LogBase
from edlclient.Library.Modules.oneplus_param import paramtools

try:
    from edlclient.Library.cryptutils import cryptutils
except Exception as e:
    print(e)
    from ..cryptutils import cryptutils
from binascii import unhexlify, hexlify

deviceconfig = {
    # OP5, cheeseburger
    "16859": dict(version=1, cm=None, param_mode=0),
    # OP5t, dumpling
    "17801": dict(version=1, cm=None, param_mode=0),
    # OP6, enchilada
    "17819": dict(version=1, cm=None, param_mode=0),
    # OP6t, fajita
    "18801": dict(version=1, cm=None, param_mode=0),
    # OP6t T-Mo, fajitat
    "18811": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7, guacamoleb
    "18857": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7 Pro, guacamole
    "18821": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7 Pro 5G Sprint, guacamoles
    "18825": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7 Pro 5G EE and Elisa, guacamoleg
    "18827": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7 Pro T-Mo, guacamolet
    "18831": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7t, hotdogb
    "18865": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7t T-Mo, hotdogt
    "19863": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7t Pro, hotdog
    "19801": dict(version=1, cm=None, param_mode=0),
    # Oneplus 7t Pro 5G T-Mo, hotdogg
    "19861": dict(version=1, cm=None, param_mode=0),

    # OP8, instantnoodle
    "19821": dict(version=2, cm="0cffee8a", param_mode=0),
    # OP8 T-Mo, instantnoodlet
    "19855": dict(version=2, cm="6d9215b4", param_mode=0),
    # OP8 Verizon, instantnoodlev
    "19867": dict(version=2, cm="4107b2d4", param_mode=0),
    # OP8 Visible, instantnoodlevis
    "19868": dict(version=2, cm="178d8213", param_mode=0),
    # OP8 Pro, instantnoodlep
    "19811": dict(version=2, cm="40217c07", param_mode=0),
    # OP8t, kebab
    "19805": dict(version=2, cm="1a5ec176", param_mode=0),
    # OP8t T-Mo, kebabt
    "20809": dict(version=2, cm="d6bc8c36", param_mode=0),

    # OP Nord, avicii
    "20801": dict(version=2, cm="eacf50e7", param_mode=0),

    # OP N10 5G Metro, billie8t
    "20885": dict(version=3, cm="3a403a71", param_mode=1),
    # OP N10 5G Global, billie8
    "20886": dict(version=3, cm="b8bd9e39", param_mode=1),
    # billie8t, OP N10 5G TMO
    "20888": dict(version=3, cm="142f1bd7", param_mode=1),
    # OP N10 5G Europe, billie8
    "20889": dict(version=3, cm="f2056ae1", param_mode=1),

    # OP N100 Metro, billie2t
    "20880": dict(version=3, cm="6ccf5913", param_mode=1),
    # OP N100 Global, billie2
    "20881": dict(version=3, cm="fa9ff378", param_mode=1),
    # OP N100 TMO, billie2t
    "20882": dict(version=3, cm="4ca1e84e", param_mode=1),
    # OP N100 Europe, billie2
    "20883": dict(version=3, cm="ad9dba4a", param_mode=1),

    # OP9 Pro, lemonadep
    "19815": dict(version=2, cm="9c151c7f", param_mode=0),
    "20859": dict(version=2, cm="9c151c7f", param_mode=0),
    "20857": dict(version=2, cm="9c151c7f", param_mode=0),
    # OP9, lemonade
    "19825": dict(version=2, cm="0898dcd6", param_mode=0),
    "20851": dict(version=2, cm="0898dcd6", param_mode=0),
    "20852": dict(version=2, cm="0898dcd6", param_mode=0),
    "20853": dict(version=2, cm="0898dcd6", param_mode=0),
    # OP9R, lemonades
    "20828": dict(version=2, cm="f498b60f", param_mode=0),
    "20838": dict(version=2, cm="f498b60f", param_mode=0),
    # OP9 TMO, lemonadet
    "20854": dict(version=2, cm="16225d4e", param_mode=0),
    # OP9 Pro TMO, lemonadept
    "2085A": dict(version=2, cm="7f19519a", param_mode=0),

    # dre8t
    "20818": dict(version=1, cm=None, param_mode=0),
    # dre8m
    "2083C": dict(version=1, cm=None, param_mode=0),
    # dre9
    "2083D": dict(version=1, cm=None, param_mode=0),

    # op nord ce, ebba
    "20813": dict(version=2, cm="48ad7b61", param_mode=0)
}


class oneplus(metaclass=LogBase):
    def __init__(self, fh, projid: str = "18825", serial=123456, ATOBuild=0, Flash_Mode=0, cf=0,
                 supported_functions=None,
                 args=None, loglevel=logging.INFO):
        self.fh = fh
        self.__logger = self.__logger
        self.args = args
        self.ATOBuild = ATOBuild
        self.Flash_Mode = Flash_Mode
        self.cf = cf  # CustFlag
        self.supported_functions = supported_functions
        self.__logger.setLevel(loglevel)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        if projid == "":
            res = self.fh.detect_partition(arguments=args, partitionname="param")
            if res[0]:
                lun = res[1]
                rpartition = res[2]
                data = self.fh.cmd_read_buffer(lun, rpartition.sector, 1, False)
                value = data.data[24:24 + 5]
                try:
                    test = int(value.decode('utf-8'), 16)
                    self.info("Oneplus protection with prjid %d detected" % test)
                    projid = value.decode('utf-8')
                except:
                    pass

        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            filehandler = logging.FileHandler(logfilename)
            self.__logger.addHandler(filehandler)
        try:
            if projid in deviceconfig:
                mode = deviceconfig[projid]["param_mode"]
                self.ops_parm = paramtools(mode=mode, serial=serial)
            else:
                self.ops_parm = paramtools(mode=0, serial=serial)
        except ImportError as e:
            self.__logger.error(str(e))
            self.ops_parm = None
        self.ops = self.convert_projid(fh, projid, serial)

    def getprodkey(self, projid):
        if projid in ["18825", "18801"]:  # key_guacamoles, fajiita
            prodkey = "b2fad511325185e5"
        else:  # key_op7t/op8/N10
            prodkey = "7016147d58e8c038"
        return prodkey

    def convert_projid(self, fh, projid, serial):
        prodkey = self.getprodkey(projid)
        pk = ""
        val = bytearray(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        for i in range(0, 16):
            rand = int(random.randint(0, 0x100))
            nr = (rand & 0xFF) % 0x3E
            pk += chr(val[nr])

        if projid in deviceconfig:
            version = deviceconfig[projid]["version"]
            cm = deviceconfig[projid]["cm"]
            if version == 1:
                return oneplus1(fh, projid, serial, pk, prodkey, self.cf)
            elif version == 2:
                if cm is not None:
                    return oneplus1(fh, cm, serial, pk, prodkey, self.cf)
                else:
                    assert "Device is not supported"
                    exit(0)
            elif version == 3:
                if cm is not None:
                    return oneplus2(fh, cm, serial, pk, prodkey, self.ATOBuild, self.Flash_Mode, self.cf)
                else:
                    assert "Device is not supported"
                    exit(0)
        assert "Unknown projid:" + str(projid)
        return None

    def run(self):
        if self.ops is not None:
            if "demacia" in self.supported_functions:
                if not self.ops.run("demacia"):
                    exit(0)
            if "SetNetType" in self.supported_functions:
                self.fh.cmd_send(f"SetNetType")
            elif "setprojmodel" in self.supported_functions:
                if not self.ops.run(""):
                    exit(0)
            if "setprocstart" in self.supported_functions:
                if not self.ops.run(""):
                    exit(0)
        return True

    def setprojmodel_verify(self, pk, token):
        if self.ops.setprojmodel_verify:
            return self.ops.setprojmodel_verify(pk, token)

    def setswprojmodel_verify(self, pk, token):
        if self.ops.setswprojmodel_verify:
            return self.ops.setswprojmodel_verify(pk, token)

    def program_verify(self, pk, token, tokendata):
        if self.ops.program_verify:
            return self.ops.program_verify(pk, token, tokendata)

    def generatetoken(self, program=False):
        return self.ops.generatetoken(program=program)

    def demacia(self):
        if self.ops.demacia():
            return self.ops.demacia()

    def enable_ops(self, data, enable, projid, serial):
        if self.ops_parm is not None:
            return self.ops_parm.enable_ops(data, enable)
        return None

    def addpatch(self):
        if "setprojmodel" in self.supported_functions or "setswprojmodel" in self.supported_functions:
            pk, token = self.ops.generatetoken(True)
            return f"pk=\"{pk}\" token=\"{token}\" "
        else:
            return ""

    def addprogram(self):
        if "setprojmodel" in self.supported_functions or "setswprojmodel" in self.supported_functions:
            pk, token = self.ops.generatetoken(True)
            return f"pk=\"{pk}\" token=\"{token}\" "
        else:
            return ""


class oneplus1:
    def __init__(self, fh, ModelVerifyPrjName="18825", serial=123456, pk="", prodkey="", cf=0):
        self.pk = pk
        self.prodkey = prodkey
        self.ModelVerifyPrjName = ModelVerifyPrjName
        self.fh = fh
        self.random_postfix = "0iyFR00pPnoqjVNL"
        self.Version = "guacamoles_21_O.22_191107"
        self.cf = str(cf)
        self.soc_sn = str(serial)

    def crypt_token(self, data, pk, decrypt=False, demacia=False):
        aes = cryptutils().aes()
        if demacia:
            aeskey = b"\x01\x63\xA0\xD1\xFD\xE2\x67\x11" + bytes(pk, 'utf-8') + b"\x48\x27\xC2\x08\xFB\xB0\xE6\xF0"
            aesiv = b"\x96\xE0\x79\x0C\xAE\x2B\xB4\xAF\x68\x4C\x36\xCB\x0B\xEC\x49\xCE"
        else:
            aeskey = b"\x10\x45\x63\x87\xE3\x7E\x23\x71" + bytes(pk, 'utf-8') + b"\xA2\xD4\xA0\x74\x0f\xD3\x28\x96"
            aesiv = b"\x9D\x61\x4A\x1E\xAC\x81\xC9\xB2\xD3\x76\xD7\x49\x31\x03\x63\x79"
        if decrypt:
            cdata = unhexlify(data)
            result = aes.aes_cbc(aeskey, aesiv, cdata)
            result = result.rstrip(b'\x00')
            if result[:16] == b"907heavyworkload":
                return result
            else:
                return result.decode('utf-8').split(',')
        else:
            if not demacia:
                while len(data) < 256:
                    data += "\x00"
                pdata = bytes(data, 'utf-8')
            else:
                while len(data) < 256:
                    data += b"\x00"
                pdata = data
            result = aes.aes_cbc(aeskey, aesiv, pdata, False)
            rdata = hexlify(result)
            return rdata.upper().decode('utf-8')

    def cmd_setpro(self):
        pk, token = self.generatetoken(False)
        data = "<?xml version=\"1.0\" ?>\n<data>\n<setprojmodel token=\"" + token + "\" pk=\"" + pk + "\" />\n</data>"
        return data

    def cmd_dem(self):
        pk, token = self.demacia()
        data = "<?xml version=\"1.0\" ?>\n<data>\n<demacia token=\"" + token + "\" pk=\"" + pk + "\" />\n</data>"
        return data

    def generatetoken(self, program=False):
        timestamp = str(int(time.time()))
        ha = cryptutils().hash()
        h1 = self.prodkey + self.ModelVerifyPrjName + self.random_postfix
        ModelVerifyHashToken = hexlify(ha.sha256(bytes(h1, 'utf-8'))).decode('utf-8').upper()
        # ModelVerifyPrjName=0x1C [0]
        # random_postfix=0x2D [1]
        # verify_hash=0x3E [2] Len:0x41
        # ver=0x90 [3]
        # cf=0x4 [4]
        # sn=0x14 [5]
        # ts=0x7f [6] Len:0x11
        # secret=0xd1 (hash store) [7], len:0x41
        # 0x7, Len:0x11
        # 0x24, Len:0x41
        #                         0x1c              0x4       0x14      0x90       0x7f        ModelVerifyHashToken
        h2 = "c4b95538c57df231" + self.ModelVerifyPrjName + self.cf + self.soc_sn + self.Version + \
             timestamp + ModelVerifyHashToken + "5b0217457e49381b"
        secret = hexlify(ha.sha256(bytes(h2, 'utf-8'))).decode('utf-8').upper()  # 0xd1
        if program:
            items = [timestamp, secret]
        else:
            items = [self.ModelVerifyPrjName, self.random_postfix, ModelVerifyHashToken, self.Version, self.cf,
                     self.soc_sn, timestamp, secret]
        data = ""
        for item in items:
            data += item + ","
        data = data[:-1]
        token = self.crypt_token(data, self.pk)
        return self.pk, token

    def setprojmodel_verify(self, pk, token):
        self.pk = pk
        ha = cryptutils().hash()
        items = self.crypt_token(token, pk, True, False)
        info = ["Projid", "ModelVerifyHashToken", "Hash1", "FirmwareString", "CustFlag", "SOC_Serial", "Timestamp",
                "secret"]
        i = 0
        print()
        if len(info) == len(items):
            for item in items:
                print(info[i] + "=" + item)
                i += 1
        # Old
        # 0=ModelVerifyPrjName [param+0x1C]
        # 1=random_postfix [param+0x2D]
        # 2=hash(key+0+1) [ModelVerifyHashToken param+0x3E]
        # 3=ver [param_1+0x90]
        # 4=cf [param_1+4]
        # 5=serial? [param_1+0x14]
        # 6=timestamp [param_1+0x7F]

        hash1 = self.prodkey + items[0] + items[1]
        res1 = hexlify(ha.sha256(bytes(hash1, 'utf-8'))).decode('utf-8').upper()
        if items[2] != res1:
            print("Hash1 failed !")
            return
        #                             ModelVerifyPrjName cf         sn         ver        ts         ModelVerifyHashToken
        secret = "c4b95538c57df231" + items[0] + items[4] + items[5] + items[3] + items[6] + \
                 items[2] + "5b0217457e49381b"
        res2 = hexlify(ha.sha256(bytes(secret, 'utf-8'))).decode('utf-8').upper()
        if items[7] != res2:
            print("secret failed !")
            return
        print("setprojmodel good")
        return items

    def toSigned32(self, n):
        n = n & 0xffffffff
        return (n ^ 0x80000000) - 0x80000000

    def demacia(self):
        """
        return "<?xml version=\"1.0\" ?>\n<data>\n  " + \
               "<program SECTOR_SIZE_IN_BYTES=\"4096\" filename=\"param.bin\" " + \
               "num_partition_sectors=\"256\" partofsingleimage=\"0\" physical_partition_number=\"0\" " + \
               "read_back_verify=\"1\" start_sector=\"8456\" token=\""+token+"\" pk=\""+pk+"\" />\n</data>"
        """
        ha = cryptutils().hash()
        serial = self.soc_sn
        while len(serial) < 10:
            serial = '0' + serial
        hash1 = "2e7006834dafe8ad" + serial + "a6674c6b039707ff"
        data = b"907heavyworkload" + ha.sha256(bytes(hash1, 'utf-8'))
        token = self.crypt_token(data, self.pk, False, True)
        return self.pk, token

    def run(self, flag):
        if flag == "demacia":
            pk, token = self.demacia()
            res = self.fh.cmd_send(f"demacia token=\"{token}\" pk=\"{pk}\"")
            if b"verify_res=\"0\"" not in res:
                print("Demacia failed:")
                print(res)
                return False
        pk, token = self.generatetoken(False)
        res = self.fh.cmd_send(f"setprojmodel token=\"{token}\" pk=\"{pk}\"")
        if b"model_check=\"0\"" not in res or b"auth_token_verify=\"0\"" not in res:
            print("Setprojmodel failed.")
            print(res)
            return False
        return True

    def program_verify(self, pk, token, tokendata):
        print()
        self.pk = pk
        items = self.crypt_token(token, pk, True, False)
        if len(items) == 2:
            print("Timestamp=" + items[0])
            print("secret=" + items[1])
        if items[0] != tokendata[6] or items[1] != tokendata[7]:
            print("Hash failed !")
            return
        print("program good")


class oneplus2(metaclass=LogBase):
    def __init__(self, fh, ModelVerifyPrjName="20889", serial=123456, pk="", prodkey="", ATOBuild=0, Flash_Mode=0,
                 cf=0, loglevel=logging.INFO):
        self.device_timestamp = None
        self.ModelVerifyPrjName = ModelVerifyPrjName
        self.pk = pk
        self.fh = fh
        self.prodkey = prodkey
        self.random_postfix = "c75oVnz8yUgLZObh"  # ModelVerifyRandom
        self.Version = "billie8_14_E.01_201028"  # Version
        self.device_id = str(int(ModelVerifyPrjName, 16))
        self.flash_mode = str(Flash_Mode)
        self.ato_build_state = str(ATOBuild)
        self.soc_sn = str(serial)
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def crypt_token(self, data, pk, device_timestamp: int, decrypt=False):
        aes = cryptutils().aes()
        aeskey = b"\x46\xA5\x97\x30\xBB\x0D\x41\xE8" + bytes(pk, 'utf-8') + \
                 pack("<Q", device_timestamp)  # we get this using setprocstart
        aesiv = b"\xDC\x91\x0D\x88\xE3\xC6\xEE\x65\xF0\xC7\x44\xB4\x02\x30\xCE\x40"
        if decrypt:
            cdata = unhexlify(data)
            result = aes.aes_cbc(aeskey, aesiv, cdata)
            result = result.rstrip(b'\x00')
            return result.decode('utf-8').split(',')
        else:
            while len(data) < 0x200:
                data += "\x00"
            pdata = bytes(data, 'utf-8')
            result = aes.aes_cbc(aeskey, aesiv, pdata, False)
            rdata = hexlify(result)
            return rdata.upper().decode('utf-8')

    def generatetoken(self, program=False):  # setswprojmodel
        timestamp = str(int(time.time()))
        ha = cryptutils().hash()
        h1 = self.prodkey + self.ModelVerifyPrjName + self.random_postfix
        ModelVerifyHashToken = hexlify(ha.sha256(bytes(h1, 'utf-8'))).decode('utf-8').upper()
        #    0x1c[0x10]        0x4           0x90       0x7f        0x3e ModelVerifyHashToken/verify_hash
        h2 = self.prodkey + self.ModelVerifyPrjName + self.soc_sn + self.Version + timestamp + \
             ModelVerifyHashToken + "8f7359c8a2951e8c"
        secret = hexlify(ha.sha256(bytes(h2, 'utf-8'))).decode('utf-8').upper()
        if program:
            items = [timestamp, secret]
        else:  # 0x1C[0x10]              0x2D[0x11]          0x3E[0x41]           0x10[0x4]
            # 0x14[0x4]       0x90[0x40]   0x4[0x4]   0x114[0x4] 0x7F[0x10] 0xD1[0x41]
            items = [self.ModelVerifyPrjName, self.random_postfix, ModelVerifyHashToken, self.ato_build_state,
                     self.flash_mode, self.Version, self.soc_sn, self.device_id, timestamp, secret]
        data = ""
        for item in items:
            data += item + ","
        data = data[:-1]
        token = self.crypt_token(data, self.pk, self.device_timestamp)
        return self.pk, token

    def run(self, flag):
        res = self.fh.cmd_send(f"setprocstart")
        if not b"device_timestamp" in res:
            print("Setprocstart failed.")
            print(res.decode('utf-8'))
            return False
        data = res.decode('utf-8')
        device_timestamp = data[data.rfind("device_timestamp"):].split("\"")[1]
        self.device_timestamp = int(device_timestamp)
        print(self.device_timestamp)
        pk, token = self.generatetoken(False)
        res = self.fh.cmd_send(f"setswprojmodel token=\"{token}\" pk=\"{pk}\"")
        if not b"model_check=\"0\"" in res or not b"auth_token_verify=\"0\"" in res:
            print("Setswprojmodel failed.")
            print(res.decode('utf-8'))
            return False
        return True

    def setswprojmodel_verify(self, pk, token):
        self.pk = pk
        ha = cryptutils().hash()
        items = self.crypt_token(token, pk, self.device_timestamp, True)
        info = ["ModelVerifyPrjName", "random_postfix", "ModelVerifyHashToken", "ato_build_state", "flash_mode",
                "Version", "soc_sn", "cf", "timestamp", "secret"]
        i = 0
        print()
        if len(info) == len(items):
            for item in items:
                print(info[i] + "=" + item)
                i += 1

        # New
        # 0=ModelVerifyPrjName [param+0x1C]
        # 1=random_postfix [param+0x2D]
        # 2=hash [param_1+0xd1]
        # 3=[ATO Build state param+0x3E]
        # 4=[flash mode param_1+0x10]
        # 5=[img ver param+0x14]
        # 6=soc sn [param_1+0x90]
        # 7=cf [param_1+4]
        # 8=timestamp [param_1+0x114]
        # 9=secret [param_1+0x7f]

        hash1 = self.prodkey + items[0] + items[1]
        res1 = hexlify(ha.sha256(bytes(hash1, 'utf-8'))).decode('utf-8').upper()
        if items[2] != res1:
            print("Hash1 failed !")
            return
        #                   ModelVerifyPrjName sn     ver        ts         ModelVerifyHashToken
        secret = self.prodkey + items[0] + items[6] + items[5] + items[8] + items[2] \
                 + "8f7359c8a2951e8c"
        # h2 = self.prodkey + self.ModelVerifyPrjName + self.soc_sn + self.Version + timestamp +
        # ModelVerifyHashToken + "8f7359c8a2951e8c"
        res2 = hexlify(ha.sha256(bytes(secret, 'utf-8'))).decode('utf-8').upper()
        if items[9] != res2:
            print("secret failed !")
            return
        print("setswprojmodel good")
        return items


def main():
    from docopt import docopt
    args = docopt(__doc__, version='oneplus 1.2')
    # filename="param_jacob_7pro.bin"
    # filename="chris/param.bin"
    if args["rawxml"]:
        projid = args["--projid"][0]
        serial = args["--serial"]
        op = oneplus(None, projid=projid, serial=serial)
        # 18831 2799496336,2799496336
        # 18825
        # 18857 7 Europe
        pk, token = op.demacia()
        print(
            f"./edl.py rawxml \"<?xml version=\\\"1.0\\\" ?><data><demacia " +
            f"token=\\\"{token}\\\" pk=\\\"{pk}\\\" /></data>\"")
        pk, token = op.generatetoken(False)
        print(
            f"./edl.py rawxml \"<?xml version=\\\"1.0\\\" ?><data><setprojmodel " +
            f"token=\\\"{token}\\\" pk=\\\"{pk}\\\" /></data>\" --debugmode")
    elif args["rawnewxml"]:
        serial = args["--serial"]
        device_timestamp = args["--ts"]
        op2 = oneplus(None, projid="20889", serial=serial, ATOBuild=0, Flash_Mode=0, cf=0)
        op2.ops.device_timestamp = int(device_timestamp)
        # 20889 OP N10 5G Europe
        print('./edl.py rawxml "<?xml version=\\"1.0\\" ?><data><setprocstart /></data>"')
        # Response should be : <?xml version="1.0" ?><data><response value=1 device_timestamp="%llu" /></data>
        pk, token = op2.generatetoken(False)
        print(
            './edl.py rawxml "<?xml version=\\"1.0\\" ?><data><setswprojmodel ' +
            f"token=\\\"{token}\\\" pk=\\\"{pk}\\\" /></data>\" --debugmode")
    elif args["setprojmodel_verify"]:
        projid = args["--projid"][0]
        op = oneplus(None, projid=projid, serial=123456)
        token = args["<token>"]
        pk = args["<pk>"]
        # setprojmodel_verify 2BA77B345812E4E45DDB5E407CF9B0F20BCD3E4F0C504A86A3DAA7D70643D0D86F4F5DAEE99E21093D26FF8A8A
        #                     7C2CCFED387FA4C7D3BC6D8B8C2CC2D27D398886FC150C98CDC521699568C4A419D7E2F2C1A33F6B57AA7CCB5F
        #                     39D69BB87463986B2CADDD55A41F0F9404C3FB08B0325BFDFCFDE05D1D8314D22F39979A289505D5050D854092
        #                     CFC9FA3C101A267DD3ECA0442BF89066365ABA6607D43743D86B47B228BAAC5538B622644D74FD4049BE37C520
        #                     76DE1B4BFE75187A7B0EE88E6C26E106570B8C0541C4693878BE9B23DEB8E4C530CFBFE9F25597FA3A86223711
        #                     2CAF77F0D1EA4CC41EB201FFAE31036FC9E405BABAE43DE9C7E56FE1DC8E82 KHaJV1TfN45ofeLW 18865
        # setprojmodel_verify 633B7E2BBE68BAC392B3E10FC8FEAC09F152853805A6D91FAADDE5A631C7B5A6081C6156F7344BDF407ABF7598
        #                     0A9E6DA96964D472FE94311FEAADF6A9032C623A1C5D5B9BDD68C5E049F13DF9D893422C1A44047B1AC8E05A0A
        #                     2A942B15B409A933A06BAB09F41FB0A3A5C8FEB86B98D39739FA4E2ABDF471DE181646F7AA228C6EC81DB3BAF2
        #                     F2C3B5381FC9A722F9D11B6A101CAAE31ACD873B83B39AC07B7603EAA38B13F5D0B5E8F9236FB94B967AECE278
        #                     FEA280E9330636F7C6C72C36A6040F6B8BC3C56AEC9CB0C07360E14EA83D2F6DEC4613FA74D79C325A320B88F2
        #                     BF025CF9CE528E13169BA255E68909D7E902CE494B49514F6F57713D6F46BE Tgu1kbDW3NemNNqn 18831
        op.setprojmodel_verify(pk, token)
    elif args["program_verify"]:
        projid = args["--projid"][0]
        op = oneplus(None, projid=projid)
        token = args["<token>"]
        prog_token = args["<prog_token>"]
        pk = args["<pk>"]
        items = op.setprojmodel_verify(pk, token)
        op.program_verify(pk, prog_token, items)
    elif args["setswprojmodel_verify"]:
        projid = args["--projid"][0]
        device_timestamp = args["--ts"]
        op = oneplus(None, projid=projid, serial=123456)
        op.ops.device_timestamp = int(device_timestamp)
        token = args["<token>"]
        pk = args["<pk>"]
        op.setswprojmodel_verify(pk, token)


def test_setswprojmodel_verify():
    deviceresp = b'RX:<?xml version="1.0" encoding="UTF-8" ?>\nRX:<data>\nRX:<response value="ACK" device_timestamp="2507003650" /></data>\n<?xmlversion="1.0" ? ><data><setprocstart /></data>'
    projid = "20889"
    op = oneplus(None, projid=projid, serial=123456)
    data = deviceresp.decode('utf-8')
    device_timestamp = data[data.rfind("device_timestamp"):].split("\"")[1]
    op.ops.device_timestamp = int(device_timestamp)
    pk, token = op.generatetoken(False)
    if not op.setswprojmodel_verify(pk, token):
        assert "Setswprojmodel error"


if __name__ == "__main__":
    main()
