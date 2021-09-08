#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2021
import binascii
import time
import os
import sys
import logging
import inspect
from struct import unpack, pack
current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from edl.Library.utils import read_object, print_progress, rmrf, LogBase
from edl.Config.qualcomm_config import sochw, msmids, root_cert_hash




def convertmsmid(msmid):
    msmiddb = []
    if int(msmid, 16) & 0xFF == 0xe1 or msmid == '00000000':
        return [msmid]
    socid = int(msmid, 16) >> 16
    if socid in sochw:
        names = sochw[socid].split(",")
        for name in names:
            for ids in msmids:
                if msmids[ids] == name:
                    rmsmid = hex(ids)[2:].lower()
                    while len(rmsmid) < 8:
                        rmsmid = '0' + rmsmid
                    msmiddb.append(rmsmid)
    return msmiddb


class sahara(metaclass=LogBase):
    SAHARA_VERSION = 2
    SAHARA_MIN_VERSION = 1

    class cmd:
        SAHARA_HELLO_REQ = 0x1
        SAHARA_HELLO_RSP = 0x2
        SAHARA_READ_DATA = 0x3
        SAHARA_END_TRANSFER = 0x4
        SAHARA_DONE_REQ = 0x5
        SAHARA_DONE_RSP = 0x6
        SAHARA_RESET_REQ = 0x7
        SAHARA_RESET_RSP = 0x8
        SAHARA_MEMORY_DEBUG = 0x9
        SAHARA_MEMORY_READ = 0xA
        SAHARA_CMD_READY = 0xB
        SAHARA_SWITCH_MODE = 0xC
        SAHARA_EXECUTE_REQ = 0xD
        SAHARA_EXECUTE_RSP = 0xE
        SAHARA_EXECUTE_DATA = 0xF
        SAHARA_64BIT_MEMORY_DEBUG = 0x10
        SAHARA_64BIT_MEMORY_READ = 0x11
        SAHARA_64BIT_MEMORY_READ_DATA = 0x12
        SAHARA_RESET_STATE_MACHINE_ID = 0x13

    class exec_cmd:
        SAHARA_EXEC_CMD_NOP = 0x00
        SAHARA_EXEC_CMD_SERIAL_NUM_READ = 0x01
        SAHARA_EXEC_CMD_MSM_HW_ID_READ = 0x02
        SAHARA_EXEC_CMD_OEM_PK_HASH_READ = 0x03
        SAHARA_EXEC_CMD_SWITCH_TO_DMSS_DLOAD = 0x04
        SAHARA_EXEC_CMD_SWITCH_TO_STREAM_DLOAD = 0x05
        SAHARA_EXEC_CMD_READ_DEBUG_DATA = 0x06
        SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL = 0x07

    class sahara_mode:
        SAHARA_MODE_IMAGE_TX_PENDING = 0x0
        SAHARA_MODE_IMAGE_TX_COMPLETE = 0x1
        SAHARA_MODE_MEMORY_DEBUG = 0x2
        SAHARA_MODE_COMMAND = 0x3

    class status:
        SAHARA_STATUS_SUCCESS = 0x00  # Invalid command received in current state
        SAHARA_NAK_INVALID_CMD = 0x01  # Protocol mismatch between host and target
        SAHARA_NAK_PROTOCOL_MISMATCH = 0x02  # Invalid target protocol version
        SAHARA_NAK_INVALID_TARGET_PROTOCOL = 0x03  # Invalid host protocol version
        SAHARA_NAK_INVALID_HOST_PROTOCOL = 0x04  # Invalid packet size received
        SAHARA_NAK_INVALID_PACKET_SIZE = 0x05  # Unexpected image ID received
        SAHARA_NAK_UNEXPECTED_IMAGE_ID = 0x06  # Invalid image header size received
        SAHARA_NAK_INVALID_HEADER_SIZE = 0x07  # Invalid image data size received
        SAHARA_NAK_INVALID_DATA_SIZE = 0x08  # Invalid image type received
        SAHARA_NAK_INVALID_IMAGE_TYPE = 0x09  # Invalid tranmission length
        SAHARA_NAK_INVALID_TX_LENGTH = 0x0A  # Invalid reception length
        SAHARA_NAK_INVALID_RX_LENGTH = 0x0B  # General transmission or reception error
        SAHARA_NAK_GENERAL_TX_RX_ERROR = 0x0C  # Error while transmitting READ_DATA packet
        SAHARA_NAK_READ_DATA_ERROR = 0x0D  # Cannot receive specified number of program headers
        SAHARA_NAK_UNSUPPORTED_NUM_PHDRS = 0x0E  # Invalid data length received for program headers
        SAHARA_NAK_INVALID_PDHR_SIZE = 0x0F  # Multiple shared segments found in ELF image
        SAHARA_NAK_MULTIPLE_SHARED_SEG = 0x10  # Uninitialized program header location
        SAHARA_NAK_UNINIT_PHDR_LOC = 0x11  # Invalid destination address
        SAHARA_NAK_INVALID_DEST_ADDR = 0x12  # Invalid data size received in image header
        SAHARA_NAK_INVALID_IMG_HDR_DATA_SIZE = 0x13  # Invalid ELF header received
        SAHARA_NAK_INVALID_ELF_HDR = 0x14  # Unknown host error received in HELLO_RESP
        SAHARA_NAK_UNKNOWN_HOST_ERROR = 0x15  # Timeout while receiving data
        SAHARA_NAK_TIMEOUT_RX = 0x16  # Timeout while transmitting data
        SAHARA_NAK_TIMEOUT_TX = 0x17  # Invalid mode received from host
        SAHARA_NAK_INVALID_HOST_MODE = 0x18  # Invalid memory read access
        SAHARA_NAK_INVALID_MEMORY_READ = 0x19  # Host cannot handle read data size requested
        SAHARA_NAK_INVALID_DATA_SIZE_REQUEST = 0x1A  # Memory debug not supported
        SAHARA_NAK_MEMORY_DEBUG_NOT_SUPPORTED = 0x1B  # Invalid mode switch
        SAHARA_NAK_INVALID_MODE_SWITCH = 0x1C  # Failed to execute command
        SAHARA_NAK_CMD_EXEC_FAILURE = 0x1D  # Invalid parameter passed to command execution
        SAHARA_NAK_EXEC_CMD_INVALID_PARAM = 0x1E  # Unsupported client command received
        SAHARA_NAK_EXEC_CMD_UNSUPPORTED = 0x1F  # Invalid client command received for data response
        SAHARA_NAK_EXEC_DATA_INVALID_CLIENT_CMD = 0x20  # Failed to authenticate hash table
        SAHARA_NAK_HASH_TABLE_AUTH_FAILURE = 0x21  # Failed to verify hash for a given segment of ELF image
        SAHARA_NAK_HASH_VERIFICATION_FAILURE = 0x22  # Failed to find hash table in ELF image
        SAHARA_NAK_HASH_TABLE_NOT_FOUND = 0x23  # Target failed to initialize
        SAHARA_NAK_TARGET_INIT_FAILURE = 0x24  # Failed to authenticate generic image
        SAHARA_NAK_IMAGE_AUTH_FAILURE = 0x25  # Invalid ELF hash table size.  Too bit or small.
        SAHARA_NAK_INVALID_IMG_HASH_TABLE_SIZE = 0x26
        SAHARA_NAK_MAX_CODE = 0x7FFFFFFF  # To ensure 32-bits wide */

    ErrorDesc = {
        0x00: "Invalid command received in current state",
        0x01: "Protocol mismatch between host and target",
        0x02: "Invalid target protocol version",
        0x03: "Invalid host protocol version",
        0x04: "Invalid packet size received",
        0x05: "Unexpected image ID received",
        0x06: "Invalid image header size received",
        0x07: "Invalid image data size received",
        0x08: "Invalid image type received",
        0x09: "Invalid tranmission length",
        0x0A: "Invalid reception length",
        0x0B: "General transmission or reception error",
        0x0C: "Error while transmitting READ_DATA packet",
        0x0D: "Cannot receive specified number of program headers",
        0x0E: "Invalid data length received for program headers",
        0x0F: "Multiple shared segments found in ELF image",
        0x10: "Uninitialized program header location",
        0x11: "Invalid destination address",
        0x12: "Invalid data size received in image header",
        0x13: "Invalid ELF header received",
        0x14: "Unknown host error received in HELLO_RESP",
        0x15: "Timeout while receiving data",
        0x16: "Timeout while transmitting data",
        0x17: "Invalid mode received from host",
        0x18: "Invalid memory read access",
        0x19: "Host cannot handle read data size requested",
        0x1A: "Memory debug not supported",
        0x1B: "Invalid mode switch",
        0x1C: "Failed to execute command",
        0x1D: "Invalid parameter passed to command execution",
        0x1E: "Unsupported client command received",
        0x1F: "Invalid client command received for data response",
        0x20: "Failed to authenticate hash table",
        0x21: "Failed to verify hash for a given segment of ELF image",
        0x22: "Failed to find hash table in ELF image",
        0x23: "Target failed to initialize",
        0x24: "Failed to authenticate generic image",
        0x25: "Invalid ELF hash table size.  Too bit or small.",
        0x26: "Invalid IMG Hash Table Size"
    }

    def init_loader_db(self):
        loaderdb = {}
        for (dirpath, dirnames, filenames) in os.walk(os.path.join(parent_dir,"..","Loaders")):
            for filename in filenames:
                fn = os.path.join(dirpath, filename)
                found = False
                for ext in [".bin", ".mbn", ".elf"]:
                    if ext in filename[-4:]:
                        found = True
                        break
                if not found:
                    continue
                try:
                    hwid = filename.split("_")[0].lower()
                    msmid = hwid[:8]
                    devid = hwid[8:]
                    pkhash = filename.split("_")[1].lower()
                    for msmid in convertmsmid(msmid):
                        mhwid = msmid + devid
                        mhwid = mhwid.lower()
                        if mhwid not in loaderdb:
                            loaderdb[mhwid] = {}
                        if pkhash not in loaderdb[mhwid]:
                            loaderdb[mhwid][pkhash] = fn
                        else:
                            loaderdb[mhwid][pkhash].append(fn)
                except Exception as e:  # pylint: disable=broad-except
                    self.debug(str(e))
                    continue
        self.loaderdb = loaderdb
        return loaderdb

    def get_error_desc(self, status):
        if status in self.ErrorDesc:
            return "Error: " + self.ErrorDesc[status]
        else:
            return "Unknown error"

    pkt_hello_req = [
        ('cmd', 'I'),
        ('len', 'I'),
        ('version', 'I'),
        ('version_min', 'I'),
        ('max_cmd_len', 'I'),
        ('mode', 'I'),
        ('res1', 'I'),
        ('res2', 'I'),
        ('res3', 'I'),
        ('res4', 'I'),
        ('res5', 'I'),
        ('res6', 'I')]

    pkt_cmd_hdr = [
        ('cmd', 'I'),
        ('len', 'I')
    ]

    pkt_read_data = [
        ('id', 'I'),
        ('data_offset', 'I'),
        ('data_len', 'I')
    ]

    pkt_read_data_64 = [
        ('id', 'Q'),
        ('data_offset', 'Q'),
        ('data_len', 'Q')
    ]

    pkt_memory_debug = [
        ('memory_table_addr', 'I'),
        ('memory_table_length', 'I')
    ]

    pkt_memory_debug_64 = [
        ('memory_table_addr', 'Q'),
        ('memory_table_length', 'Q')
    ]
    '''
    execute_cmd=[
        ('cmd', 'I'),
        ('len', 'I'),
        ('client_cmd','I')
    ]
    '''

    pkt_execute_rsp_cmd = [
        ('cmd', 'I'),
        ('len', 'I'),
        ('client_cmd', 'I'),
        ('data_len', 'I')
    ]

    pkt_image_end = [
        ('id', 'I'),
        ('status', 'I')
    ]

    pkt_done = [
        ('cmd', 'I'),
        ('len', 'I'),
        ('status', 'I')
    ]

    pbl_info = [
        ('serial', 'I'),
        ('msm_id', 'I'),
        ('pk_hash', '32s'),
        ('pbl_sw', 'I')
    ]

    parttbl = [
        ('save_pref', 'I'),
        ('mem_base', 'I'),
        ('length', 'I'),
        ('desc', '20s'),
        ('filename', '20s')
    ]

    parttbl_64bit = [
        ('save_pref', 'Q'),
        ('mem_base', 'Q'),
        ('length', 'Q'),
        ('desc', '20s'),
        ('filename', '20s')
    ]

    def __init__(self, cdc, loglevel):
        self.cdc = cdc
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.id = None
        self.loaderdb = None
        self.version = 2.1
        self.programmer = None
        self.mode = ""
        self.serial = None

        self.serials = None
        self.sblversion = None
        self.hwid = None
        self.pkhash = None
        self.hwidstr = None
        self.msm_id = None
        self.oem_id = None
        self.model_id = None
        self.oem_str = None
        self.msm_str = None
        self.bit64 = False
        self.pktsize = None

        self.init_loader_db()

        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def get_rsp(self):
        data = []
        try:
            v = self.cdc.read()
            if v == b'':
                return [None, None]
            if b"<?xml" in v:
                return ["firehose", None]
            pkt = read_object(v[0:0x2 * 0x4], self.pkt_cmd_hdr)
            if "cmd" in pkt:
                cmd = pkt["cmd"]
                if cmd == self.cmd.SAHARA_HELLO_REQ:
                    data = read_object(v[0x0:0xC * 0x4], self.pkt_hello_req)
                elif cmd == self.cmd.SAHARA_DONE_RSP:
                    data = read_object(v[0x0:0x3 * 4], self.pkt_done)
                elif cmd == self.cmd.SAHARA_END_TRANSFER:
                    data = read_object(v[0x8:0x8 + 0x2 * 0x4], self.pkt_image_end)
                elif cmd == self.cmd.SAHARA_64BIT_MEMORY_READ_DATA:
                    self.bit64 = True
                    data = read_object(v[0x8:0x8 + 0x3 * 0x8], self.pkt_read_data_64)
                elif cmd == self.cmd.SAHARA_READ_DATA:
                    self.bit64 = False
                    data = read_object(v[0x8:0x8 + 0x3 * 0x4], self.pkt_read_data)
                elif cmd == self.cmd.SAHARA_64BIT_MEMORY_DEBUG:
                    self.bit64 = True
                    data = read_object(v[0x8:0x8 + 0x2 * 0x8], self.pkt_memory_debug_64)
                elif cmd == self.cmd.SAHARA_MEMORY_DEBUG:
                    self.bit64 = False
                    data = read_object(v[0x8:0x8 + 0x2 * 0x4], self.pkt_memory_debug)
                elif cmd == self.cmd.SAHARA_EXECUTE_RSP:
                    data = read_object(v[0:0x4 * 0x4], self.pkt_execute_rsp_cmd)
                elif cmd == self.cmd.SAHARA_CMD_READY or cmd == self.cmd.SAHARA_RESET_RSP:
                    data = []
                else:
                    return [None,None]
            return [pkt, data]
        except Exception as e:  # pylint: disable=broad-except
            self.error(str(e))
            return [None,None]

    def cmd_hello(self, mode, version_min=1, max_cmd_len=0):  # CMD 0x1, RSP 0x2
        cmd = self.cmd.SAHARA_HELLO_RSP
        length = 0x30
        version = self.SAHARA_VERSION
        responsedata = pack("<IIIIIIIIIIII", cmd, length, version, version_min, max_cmd_len, mode, 0, 0, 0, 0, 0, 0)
        try:
            self.cdc.write(responsedata)
            return True
        except Exception as e:  # pylint: disable=broad-except
            self.error(str(e))
            return False

    def connect(self):
        try:
            v = self.cdc.read()
            if len(v) > 1:
                if v[0] == 0x01:
                    cmd = read_object(v[0:0x2 * 0x4], self.pkt_cmd_hdr)
                    if cmd['cmd'] == self.cmd.SAHARA_HELLO_REQ:
                        data = read_object(v[0x0:0xC * 0x4], self.pkt_hello_req)
                        self.pktsize = data['max_cmd_len']
                        self.version = float(str(data['version']) + "." + str(data['version_min']))
                        return ["sahara", data]
                elif v[0] == self.cmd.SAHARA_END_TRANSFER:
                    return ["sahara", None]
                elif b"<?xml" in v:
                    return ["firehose", None]
                elif v[0] == 0x7E:
                    return ["nandprg", None]
            else:
                data = b"<?xml version=\"1.0\" ?><data><nop /></data>"
                self.cdc.write(data)
                res = self.cdc.read()
                if res == b"":
                    try:
                        data = b"\x7E\x06\x4E\x95\x7E"  # Streaming nop
                        self.cdc.write(data)
                        res = self.cdc.read()
                        if b"\x7E\x0D\x16\x00\x00\x00\x00" in res or b"Invalid Command" in res:
                            return ["nandprg", None]
                        else:
                            return ["", None]
                    except Exception as e:  # pylint: disable=broad-except
                        self.error(str(e))
                        return ["", None]
                if b"<?xml" in res:
                    return ["firehose", None]
                elif len(res) > 0 and res[0] == self.cmd.SAHARA_END_TRANSFER:
                    print("Device is in Sahara error state, please reboot the device.")
                    return ["sahara", None]
                else:
                    data = b"\x7E\x11\x00\x12\x00\xA0\xE3\x00\x00\xC1\xE5\x01\x40\xA0\xE3\x1E\xFF\x2F\xE1\x4B\xD9\x7E"
                    self.cdc.write(data)
                    res = self.cdc.read()
                    if len(res) > 0 and res[1] == 0x12:
                        return ["nandprg", None]
                    else:
                        self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_COMMAND)
                        return ["sahara", None]

        except Exception as e:  # pylint: disable=broad-except
            self.error(str(e))

        self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_MEMORY_DEBUG)
        cmd, pkt = self.get_rsp()
        if None in [cmd , pkt]:
            return ["", None]
        return ["sahara", pkt]

    def enter_command_mode(self):
        if not self.cmd_hello(self.sahara_mode.SAHARA_MODE_COMMAND):
            return False
        cmd, pkt = self.get_rsp()
        if cmd["cmd"] == self.cmd.SAHARA_CMD_READY:
            return True
        elif "status" in pkt:
            self.error(self.get_error_desc(pkt["status"]))
            return False
        return False

    def cmdexec_nop(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_NOP)
        return res

    def cmdexec_get_serial_num(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_SERIAL_NUM_READ)
        return unpack("<I", res)[0]

    def cmdexec_get_msm_hwid(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_MSM_HW_ID_READ)
        try:
            return unpack("<Q", res[0:0x8])[0]
        except Exception as e:  # pylint: disable=broad-except
            self.debug(str(e))
            return None

    def cmdexec_get_pkhash(self):
        try:
            res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_OEM_PK_HASH_READ)[0:0x20]
            return binascii.hexlify(res).decode('utf-8')
        except Exception as e:  # pylint: disable=broad-except
            self.error(str(e))
            return None

    def cmdexec_get_sbl_version(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL)
        return unpack("<I", res)[0]

    def cmdexec_switch_to_dmss_dload(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_SWITCH_TO_DMSS_DLOAD)
        return res

    def cmdexec_switch_to_stream_dload(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_SWITCH_TO_STREAM_DLOAD)
        return res

    def cmdexec_read_debug_data(self):
        res = self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_READ_DEBUG_DATA)
        return res

    def cmd_info(self):
        if self.enter_command_mode():
            self.serial = self.cmdexec_get_serial_num()
            self.serials = "{:08x}".format(self.serial)
            self.hwid = self.cmdexec_get_msm_hwid()
            self.pkhash = self.cmdexec_get_pkhash()
            # if self.version>=2.4:
            #    self.sblversion = "{:08x}".format(self.cmdexec_get_sbl_version())
            if self.hwid is not None:
                self.hwidstr = "{:016x}".format(self.hwid)
                self.msm_id = int(self.hwidstr[2:8], 16)
                self.oem_id = int(self.hwidstr[-8:-4], 16)
                self.model_id = int(self.hwidstr[-4:], 16)
                self.oem_str = "{:04x}".format(self.oem_id)
                self.model_id = "{:04x}".format(self.model_id)
                self.msm_str = "{:08x}".format(self.msm_id)
                if self.msm_id in msmids:
                    cpustr = f"CPU detected:      \"{msmids[self.msm_id]}\"\n"
                else:
                    cpustr = "Unknown CPU, please send log as issue to https://github.com/bkerler/edl\n"
                """
                if self.version >= 2.4:
                    self.info(f"\n------------------------\n" +
                                f"HWID:              0x{self.hwidstr} (MSM_ID:0x{self.msm_str}," +
                                f"OEM_ID:0x{self.oem_str}," +
                                f"MODEL_ID:0x{self.model_id})\n" +
                                f"PK_HASH:           0x{self.pkhash}\n" +
                                f"Serial:            0x{self.serials}\n" +
                                f"SBL Version:       0x{self.sblversion}\n")
                else:
                """
                self.info(f"\n------------------------\n" +
                          f"HWID:              0x{self.hwidstr} (MSM_ID:0x{self.msm_str}," +
                          f"OEM_ID:0x{self.oem_str}," +
                          f"MODEL_ID:0x{self.model_id})\n" +
                          cpustr +
                          f"PK_HASH:           0x{self.pkhash}\n" +
                          f"Serial:            0x{self.serials}\n")
            if self.programmer == "":
                if self.hwidstr in self.loaderdb:
                    mt = self.loaderdb[self.hwidstr]
                    unfused = False
                    for rootcert in root_cert_hash:
                        if self.pkhash[0:16] in root_cert_hash[rootcert]:
                            unfused = True
                    if unfused:
                        self.info("Possibly unfused device detected, so any loader should be fine...")
                        if self.pkhash[0:16] in mt:
                            self.programmer = mt[self.pkhash[0:16]]
                            self.info(f"Trying loader: {self.programmer}")
                        else:
                            for loader in mt:
                                self.programmer = mt[loader]
                                self.info(f"Possible loader available: {self.programmer}")
                            for loader in mt:
                                self.programmer = mt[loader]
                                self.info(f"Trying loader: {self.programmer}")
                                break
                    elif self.pkhash[0:16] in mt:
                        self.programmer = self.loaderdb[self.hwidstr][self.pkhash[0:16]]
                        self.info(f"Detected loader: {self.programmer}")
                    else:
                        for loader in self.loaderdb[self.hwidstr]:
                            self.programmer = self.loaderdb[self.hwidstr][loader]
                            self.info(f"Trying loader: {self.programmer}")
                            break
                        # print("Couldn't find a loader for given hwid and pkhash :(")
                        # exit(0)
                elif self.hwidstr is not None and self.pkhash is not None:
                    msmid = self.hwidstr[:8]
                    for hwidstr in self.loaderdb:
                        if msmid == hwidstr[:8]:
                            for pkhash in self.loaderdb[hwidstr]:
                                if self.pkhash[0:16] == pkhash:
                                    self.programmer = self.loaderdb[hwidstr][pkhash]
                                    self.info(f"Trying loader: {self.programmer}")
                                    self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_COMMAND)
                                    return True
                    self.error(
                        f"Couldn't find a loader for given hwid and pkhash ({self.hwidstr}_{self.pkhash[0:16]}" +
                        "_[FHPRG/ENPRG].bin) :(")
                    return False
                else:
                    self.error(f"Couldn't find a suitable loader :(")
                    return False

            self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_COMMAND)
            return True
        return False

    def streaminginfo(self):
        if self.enter_command_mode():
            self.serial = self.cmdexec_get_serial_num()
            self.info(f"Device serial : {hex(self.serial)}")
            self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_COMMAND)
            return True
        return False

    def cmd_done(self):
        if self.cdc.write(pack("<II", self.cmd.SAHARA_DONE_REQ, 0x8)):
            cmd, pkt = self.get_rsp()
            time.sleep(0.3)
            if cmd["cmd"] == self.cmd.SAHARA_DONE_RSP:
                return True
            elif cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER:
                if pkt["status"] == self.status.SAHARA_NAK_INVALID_CMD:
                    self.error("Invalid Transfer command received.")
                    return False
            return True
        return False

    def cmd_reset(self):
        self.cdc.write(pack("<II", self.cmd.SAHARA_RESET_REQ, 0x8))
        try:
            cmd, pkt = self.get_rsp()
        except Exception as e:  # pylint: disable=broad-except
            self.debug(str(e))
            return False
        if cmd["cmd"] == self.cmd.SAHARA_RESET_RSP:
            return True
        elif "status" in pkt:
            self.error(self.get_error_desc(pkt["status"]))
            return False
        return False

    def read_memory(self, addr, bytestoread, display=False, wf=None):
        data = b""
        old = 0
        pos = 0
        total = bytestoread
        if display:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        while bytestoread > 0:
            if bytestoread > 0x080000:
                length = 0x080000
            else:
                length = bytestoread
            bytesread = 0
            try:
                self.cdc.read(1, 1)
            except Exception as e:  # pylint: disable=broad-except
                self.debug(str(e))
                pass
            if self.bit64:
                if not self.cdc.write(pack("<IIQQ", self.cmd.SAHARA_64BIT_MEMORY_READ, 0x8 + 8 + 8, addr + pos,
                                           length)):
                    return None
            else:
                if not self.cdc.write(
                        pack("<IIII", self.cmd.SAHARA_MEMORY_READ, 0x8 + 4 + 4, addr + pos, length)):
                    return None
            while length > 0:
                try:
                    tmp = self.cdc.read(length)
                except Exception as e:  # pylint: disable=broad-except
                    self.debug(str(e))
                    return None
                length -= len(tmp)
                pos += len(tmp)
                bytesread += len(tmp)
                if wf is not None:
                    wf.write(tmp)
                else:
                    data += tmp
                if display:
                    prog = round(float(pos) / float(total) * float(100), 1)
                    if prog > old:
                        if display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                            old = prog
            bytestoread -= bytesread
        if display:
            print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        '''
        try:
            self.cdc.read(0)
        except:
            return data
        '''
        return data

    def dump_partitions(self, partition):
        for part in partition:
            filename = part["filename"]
            desc = part["desc"]
            mem_base = part["mem_base"]
            length = part["length"]
            print(f"Dumping {filename}({desc}) at {hex(mem_base)}, length {hex(length)}")
            fname = os.path.join("memory", filename)
            with open(fname, "wb") as wf:
                self.read_memory(mem_base, length, True, wf)
                if wf.tell() == length:
                    print("Done dumping memory")
                else:
                    self.error("Error dumping memory")
        self.cmd_reset()
        return True

    def debug_mode(self):
        if not self.cmd_hello(self.sahara_mode.SAHARA_MODE_MEMORY_DEBUG):
            return False
        if os.path.exists("memory"):
            rmrf("memory")
        os.mkdir("memory")
        cmd, pkt = self.get_rsp()
        if cmd["cmd"] == self.cmd.SAHARA_MEMORY_DEBUG or cmd["cmd"] == self.cmd.SAHARA_64BIT_MEMORY_DEBUG:
            memory_table_addr = pkt["memory_table_addr"]
            memory_table_length = pkt["memory_table_length"]
            if self.bit64:
                pktsize = 8 + 8 + 8 + 20 + 20
                if memory_table_length % pktsize == 0:
                    if memory_table_length != 0:
                        print(
                            f"Reading 64-Bit partition from {hex(memory_table_addr)} with length of " +
                            "{hex(memory_table_length)}")
                        ptbldata = self.read_memory(memory_table_addr, memory_table_length)
                        num_entries = len(ptbldata) // pktsize
                        partitions = []
                        for id_entry in range(0, num_entries):
                            pd = read_object(ptbldata[id_entry * pktsize:(id_entry * pktsize) + pktsize],
                                             self.parttbl_64bit)
                            desc = pd["desc"].replace(b"\x00", b"").decode('utf-8')
                            filename = pd["filename"].replace(b"\x00", b"").decode('utf-8')
                            mem_base = pd["mem_base"]
                            save_pref = pd["save_pref"]
                            length = pd["length"]
                            partitions.append(dict(desc=desc, filename=filename, mem_base=mem_base, length=length,
                                                   save_pref=save_pref))
                            print(
                                f"{filename}({desc}): Offset {hex(mem_base)}, Length {hex(length)}, " +
                                "SavePref {hex(save_pref)}")

                        self.dump_partitions(partitions)
                        return True

                    return True
            else:
                pktsize = (4 + 4 + 4 + 20 + 20)
                if memory_table_length % pktsize == 0:
                    if memory_table_length != 0:
                        print(f"Reading 32-Bit partition from {hex(memory_table_addr)} " +
                              f"with length of {hex(memory_table_length)}")
                        ptbldata = self.read_memory(memory_table_addr, memory_table_length)
                        num_entries = len(ptbldata) // pktsize
                        partitions = []
                        for id_entry in range(0, num_entries):
                            pd = read_object(ptbldata[id_entry * pktsize:(id_entry * pktsize) + pktsize], self.parttbl)
                            desc = pd["desc"].replace(b"\x00", b"").decode('utf-8')
                            filename = pd["filename"].replace(b"\x00", b"").decode('utf-8')
                            mem_base = pd["mem_base"]
                            save_pref = pd["save_pref"]
                            length = pd["length"]
                            partitions.append(dict(desc=desc, filename=filename, mem_base=mem_base, length=length,
                                                   save_pref=save_pref))
                            print(f"{filename}({desc}): Offset {hex(mem_base)}, " +
                                  f"Length {hex(length)}, SavePref {hex(save_pref)}")

                        self.dump_partitions(partitions)
                    return True
        elif "status" in pkt:
            self.error(self.get_error_desc(pkt["status"]))
            return False
        return False

    def upload_loader(self):
        if self.programmer == "":
            return ""
        try:
            self.info(f"Uploading loader {self.programmer} ...")
            with open(self.programmer, "rb") as rf:
                programmer = rf.read()
        except Exception as e:  # pylint: disable=broad-except
            self.error(str(e))
            sys.exit()

        if not self.cmd_hello(self.sahara_mode.SAHARA_MODE_IMAGE_TX_PENDING):
            return ""

        try:
            datalen = len(programmer)
            done = False
            while datalen > 0 or done:
                cmd, pkt = self.get_rsp()
                if cmd == -1 or pkt == -1:
                    if self.cmd_done():
                        return self.mode  # Do NOT remove
                    else:
                        self.error("Timeout while uploading loader. Wrong loader ?")
                        return ""
                if cmd["cmd"] == self.cmd.SAHARA_64BIT_MEMORY_READ_DATA:
                    self.bit64 = True
                elif cmd["cmd"] == self.cmd.SAHARA_READ_DATA:
                    self.bit64 = False
                elif cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER:
                    if pkt["status"] == self.status.SAHARA_STATUS_SUCCESS:
                        self.cmd_done()
                        return self.mode
                    else:
                        return ""
                elif "status" in pkt:
                    self.error(self.get_error_desc(pkt["status"]))
                    return ""
                else:
                    self.error("Unexpected error on uploading")
                    return ""
                self.id = pkt["id"]
                if self.id == 0x7:
                    self.mode = "nandprg"
                elif self.id == 0xB:
                    self.mode = "enandprg"
                elif self.id >= 0xC:
                    self.mode = "firehose"

                data_offset = pkt["data_offset"]
                data_len = pkt["data_len"]
                if data_offset + data_len > len(programmer):
                    while len(programmer) < data_offset + data_len:
                        programmer += b"\xFF"
                data_to_send = programmer[data_offset:data_offset + data_len]
                self.cdc.write(data_to_send)
                datalen -= data_len
            self.info("Loader uploaded.")
            cmd, pkt = self.get_rsp()
            if cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER:
                if pkt["status"] == self.status.SAHARA_STATUS_SUCCESS:
                    self.cmd_done()
                    return self.mode
            return ""
        except Exception as e:  # pylint: disable=broad-except
            self.error("Unexpected error on uploading, maybe signature of loader wasn't accepted ?\n" + str(e))
            return ""

    def cmd_modeswitch(self, mode):
        data = pack("<III", self.cmd.SAHARA_SWITCH_MODE, 0xC, mode)
        self.cdc.write(data)

    def cmd_exec(self, mcmd):  # CMD 0xD, RSP 0xE, CMD2 0xF
        # Send request
        data = pack("<III", self.cmd.SAHARA_EXECUTE_REQ, 0xC, mcmd)
        self.cdc.write(data)
        # Get info about request
        cmd, pkt = self.get_rsp()
        if cmd["cmd"] == self.cmd.SAHARA_EXECUTE_RSP:
            # Ack
            data = pack("<III", self.cmd.SAHARA_EXECUTE_DATA, 0xC, mcmd)
            self.cdc.write(data)
            payload = self.cdc.read(pkt["data_len"])
            return payload
        elif "status" in pkt:
            self.error(self.get_error_desc(pkt["status"]))
            return None
        return [cmd, pkt]
