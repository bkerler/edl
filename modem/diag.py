#!/usr/bin/env python3
'''
Licensed under MIT License, (c) B. Kerler 2018-2019
'''
default_vid_pid = [
    [0x2c7c, 0x0125, -1],  # Quectel EC25
    [0x1199, 0x9071, -1],  # Sierra Wireless
    [0x1199, 0x9091, -1],  # Sierra Wireless
    [0x0846, 0x68e2,  2],  # Netgear
    [0x05C6, 0x9008, -1],  # QC EDL
    [0x05C6, 0x676C, 0],   # QC Handset
    [0x19d2, 0x0016, -1],  # ZTE Diag
    [0x19d2, 0x0076, -1],  # ZTE Download
    [0x12d1, 0x1506, -1],
    [0x413c, 0x81d7, 5],  # Telit LN940
]

import argparse
import json
import logging
from xml.etree import ElementTree
from enum import Enum

from struct import unpack, pack
from binascii import hexlify, unhexlify

try:
    from Library.utils import print_progress, read_object, write_object, LogBase
    from Library.usblib import usb_class
    from Library.hdlc import hdlc
except Exception as e:
    import os,sys,inspect
    current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from Library.utils import print_progress, read_object, write_object, LogBase
    from Library.usblib import usb_class
    from Library.hdlc import hdlc


qcerror = {
    1: "None",
    2: "Unknown",
    3: "Open Port Fail",
    4: "Port not open",
    5: "Buffer too small",
    6: "Read data fail",
    7: "Open file fail",
    8: "File not open",
    9: "Invalid parameter",
    10: "Send write ram failed",
    11: "Send command failed",
    12: "Offline phone failed",
    13: "Erase rom failed",
    14: "Timeout",
    15: "Go cmd failed",
    16: "Set baudrate failed",
    17: "Say hello failed",
    18: "Write port failed",
    19: "Failed to read nv",
    20: "Failed to write nv",
    21: "Last failed but not recovery",
    22: "Backup file wasn't found",
    23: "Incorrect SPC Code",
    24: "Hello pkt isn't needed",
    25: "Not active"
}

diagerror = {
    20: "Generic error",
    21: "Bad argument",
    22: "Data too large",
    24: "Not connected",
    25: "Send pkt failed",
    26: "Receive pkt failed",
    27: "Extract pkt failed",
    29: "Open port failed",
    30: "Bad command",
    31: "Protected",
    32: "No media",
    33: "Empty",
    34: "List done"
}

nvitem_type = [
    ('item', 'H'),
    ('rawdata', '128s'),
    ('status', 'H')
]


class fs_factimage_read_info():
    def_fs_factimage_read_info = [
        ('stream_state', 'B'),  # 0 indicates no more data to be sent, otherwise set to 1
        ('info_cluster_sent', 'B'),  # 0 indicates if info_cluster was not sent, else 1
        ('cluster_map_seqno', 'H'),  # Sequence number of cluster map pages
        ('cluster_data_seqno', 'I')  # Sequence number of cluster data pages
    ]

    def __init__(self, stream_state, info_cluster_sent, cluster_map_seqno, cluster_data_seqno):
        self.stream_state = stream_state
        self.info_cluster_sent = info_cluster_sent
        self.cluster_map_seqno = cluster_map_seqno
        self.cluster_data_seqno = cluster_data_seqno

    def fromdata(self, data):
        tmp = read_object(data[0:0x10], self.def_fs_factimage_read_info)
        self.stream_state = tmp["stream_state"]
        self.info_cluster_sent = tmp["info_cluster_sent"]
        self.cluster_map_seqno = tmp["cluster_map_seqno"]
        self.cluster_data_seqno = tmp["cluster_data_seqno"]

    def todata(self):
        data = write_object(self.def_fs_factimage_read_info, self.stream_state, self.info_cluster_sent,
                            self.cluster_map_seqno, self.cluster_data_seqno)
        return data


class FactoryHeader():
    def_factory_header = [
        ('magic1', 'I'),
        ('magic2', 'I'),
        ('fact_version', 'H'),  # Version of this cluster
        # #Fields needed for the superblock
        ('version', 'H'),  # Superblock version
        ('block_size', 'I'),  # Pages per block.
        ('page_size', 'I'),  # Page size in bytes.
        ('block_count', 'I'),  # Total blocks in device.
        ('space_limit', 'I'),  # Total number of used pages (defines the size of the map)
        ('upper_data', '32I')
    ]

    def __init__(self):
        self.magic1 = 0
        self.magic2 = 0
        self.fact_version = 0
        self.version = 0
        self.block_size = 0
        self.page_size = 0
        self.block_count = 0
        self.space_limit = 0
        self.upper_data = [0 * 32]

    def fromdata(self, data):
        tmp = read_object(data[0:0x9C], self.def_factory_header)
        self.magic1 = tmp["magic1"]
        self.magic2 = tmp["magic2"]
        self.fact_version = tmp["fact_version"]
        self.version = tmp["version"]
        self.block_size = tmp["block_size"]
        self.page_size = tmp["page_size"]
        self.block_count = tmp["block_count"]
        self.space_limit = tmp["space_limit"]
        self.upper_data = tmp["upper_data"]

    def todata(self):
        data = write_object(self.magic1, self.magic2, self.fact_version, self.version, self.block_size, self.page_size,
                            self.block_count, self.space_limit, self.upper_data)
        return data


class nvitem():
    item = 0x0
    data = b""
    status = 0x0
    name = ""

    def __init__(self, item, data, status, name):
        self.item = item
        self.data = data
        self.status = status
        self.name = name


class diag_cmds(Enum):
    DIAG_VERNO_F = 0
    DIAG_ESN_F = 1
    DIAG_PEEKB_F = 2
    DIAG_PEEKW_F = 3
    DIAG_PEEKD_F = 4
    DIAG_POKEB_F = 5
    DIAG_POKEW_F = 6
    DIAG_POKED_F = 7
    DIAG_OUTP_F = 8
    DIAG_OUTPW_F = 9
    DIAG_INP_F = 0xA
    DIAG_INPW_F = 0xB
    DIAG_STATUS_F = 0xC
    DIAG_LOGMASK_F = 0xF
    DIAG_LOG_F = 0x10
    DIAG_NV_PEEK_F = 0x11
    DIAG_NV_POKE_F = 0x12
    DIAG_BAD_CMD_F = 0x13
    DIAG_BAD_PARM_F = 0x14
    DIAG_BAD_LEN_F = 0x15
    DIAG_BAD_MODE_F = 0x18
    DIAG_TAGRAPH_F = 0x19
    DIAG_MARKOV_F = 0x1a
    DIAG_MARKOV_RESET_F = 0x1b
    DIAG_DIAG_VER_F = 0x1c
    DIAG_TS_F = 0x1d
    DIAG_TA_PARM_F = 0x1E
    DIAG_MSG_F = 0x1f
    DIAG_HS_KEY_F = 0x20
    DIAG_HS_LOCK_F = 0x21
    DIAG_HS_SCREEN_F = 0x22
    DIAG_PARM_SET_F = 0x24
    DIAG_NV_READ_F = 0x26
    DIAG_NV_WRITE_F = 0x27
    DIAG_CONTROL_F = 0x29
    DIAG_ERR_READ_F = 0x2a
    DIAG_ERR_CLEAR_F = 0x2b
    DIAG_SER_RESET_F = 0x2c
    DIAG_SER_REPORT_F = 0x2d
    DIAG_TEST_F = 0x2e
    DIAG_GET_DIPSW_F = 0x2f
    DIAG_SET_DIPSW_F = 0x30
    DIAG_VOC_PCM_LB_F = 0x31
    DIAG_VOC_PKT_LB_F = 0x32
    DIAG_ORIG_F = 0x35
    DIAG_END_F = 0x36
    DIAG_SW_VERSION_F = 0x38
    DIAG_DLOAD_F = 0x3a
    DIAG_TMOB_F = 0x3b
    DIAG_STATE_F = 0x3f
    DIAG_PILOT_SETS_F = 0x40
    DIAG_SPC_F = 0x41
    DIAG_BAD_SPC_MODE_F = 0x42
    DIAG_PARM_GET2_F = 0x43
    DIAG_SERIAL_CHG_F = 0x44
    DIAG_PASSWORD_F = 0x46
    DIAG_BAD_SEC_MODE_F = 0x47
    DIAG_PR_LIST_WR_F = 0x48
    DIAG_PR_LIST_RD_F = 0x49
    DIAG_SUBSYS_CMD_F = 0x4b
    DIAG_FEATURE_QUERY_F = 0x51
    DIAG_SMS_READ_F = 0x53
    DIAG_SMS_WRITE_F = 0x54
    DIAG_SUP_FER_F = 0x55
    DIAG_SUP_WALSH_CODES_F = 0x56
    DIAG_SET_MAX_SUP_CH_F = 0x57
    DIAG_PARM_GET_IS95B_F = 0x58
    DIAG_FS_OP_F = 0x59
    # DIAG_RAM_RW_F = 0x59
    DIAG_AKEY_VERIFY_F = 0x5A
    # DIAG_CPU_RW_F = 0x5a
    DIAG_BMP_HS_SCREEN_F = 0x5b
    DIAG_CONFIG_COMM_F = 0x5c
    DIAG_EXT_LOGMASK_F = 0x5d
    DIAG_EVENT_REPORT_F = 0x60
    DIAG_STREAMING_CONFIG_F = 0x61
    DIAG_PARM_RETRIEVE_F = 0x62
    DIAG_STATUS_SNAPSHOT_F = 0x63
    DIAG_RPC_F = 0x64
    DIAG_GET_PROPERTY_F = 0x65
    DIAG_PUT_PROPERTY_F = 0x66
    DIAG_GET_GUID_F = 0x67
    DIAG_USER_CMD_F = 0x68
    DIAG_GET_PERM_PROPERTY_F = 0x69
    DIAG_PUT_PERM_PROPERTY_F = 0x6a
    DIAG_PERM_USER_CMD_F = 0x6b
    DIAG_GPS_SESS_CTRL_F = 0x6c
    DIAG_GPS_GRID_F = 0x6d
    DIAG_GPS_STATISTICS_F = 0x6E
    DIAG_TUNNEL_F = 0x6f
    DIAG_MAX_F = 0x70
    DIAG_SET_FTM_TEST_MODE = 0x72
    DIAG_EXT_BUILD_ID_F = 0x7c


class efs_cmds(Enum):
    EFS2_DIAG_HELLO = 0  # Parameter negotiation packet
    EFS2_DIAG_QUERY = 1  # Send information about EFS2 params
    EFS2_DIAG_OPEN = 2  # Open a file
    EFS2_DIAG_CLOSE = 3  # Close a file
    EFS2_DIAG_READ = 4  # Read a file
    EFS2_DIAG_WRITE = 5  # Write a file
    EFS2_DIAG_SYMLINK = 6  # Create a symbolic link
    EFS2_DIAG_READLINK = 7  # Read a symbolic link
    EFS2_DIAG_UNLINK = 8  # Remove a symbolic link or file
    EFS2_DIAG_MKDIR = 9  # Create a directory
    EFS2_DIAG_RMDIR = 10  # Remove a directory
    EFS2_DIAG_OPENDIR = 11  # Open a directory for reading
    EFS2_DIAG_READDIR = 12  # Read a directory
    EFS2_DIAG_CLOSEDIR = 13  # Close an open directory
    EFS2_DIAG_RENAME = 14  # Rename a file or directory
    EFS2_DIAG_STAT = 15  # Obtain information about a named file
    EFS2_DIAG_LSTAT = 16  # Obtain information about a symbolic link
    EFS2_DIAG_FSTAT = 17  # Obtain information about a file descriptor
    EFS2_DIAG_CHMOD = 18  # Change file permissions
    EFS2_DIAG_STATFS = 19  # Obtain file system information
    EFS2_DIAG_ACCESS = 20  # Check a named file for accessibility
    EFS2_DIAG_NAND_DEV_INFO = 21  # Get NAND device info
    EFS2_DIAG_FACT_IMAGE_START = 22  # Start data output for Factory Image
    EFS2_DIAG_FACT_IMAGE_READ = 23  # Get data for Factory Image
    EFS2_DIAG_FACT_IMAGE_END = 24  # End data output for Factory Image
    EFS2_DIAG_PREP_FACT_IMAGE = 25  # Prepare file system for image dump
    EFS2_DIAG_PUT_DEPRECATED = 26  # Write an EFS item file
    EFS2_DIAG_GET_DEPRECATED = 27  # Read an EFS item file
    EFS2_DIAG_ERROR = 28  # Send an EFS Error Packet back through DIAG
    EFS2_DIAG_EXTENDED_INFO = 29  # Get Extra information.
    EFS2_DIAG_CHOWN = 30  # Change ownership
    EFS2_DIAG_BENCHMARK_START_TEST = 31  # Start Benchmark
    EFS2_DIAG_BENCHMARK_GET_RESULTS = 32  # Get Benchmark Report
    EFS2_DIAG_BENCHMARK_INIT = 33  # Init/Reset Benchmark
    EFS2_DIAG_SET_RESERVATION = 34  # Set group reservation
    EFS2_DIAG_SET_QUOTA = 35  # Set group quota
    EFS2_DIAG_GET_GROUP_INFO = 36  # Retrieve Q&R values
    EFS2_DIAG_DELTREE = 37  # Delete a Directory Tree
    EFS2_DIAG_PUT = 38  # Write a EFS item file in order
    EFS2_DIAG_GET = 39  # Read a EFS item file in order
    EFS2_DIAG_TRUNCATE = 40  # Truncate a file by the name
    EFS2_DIAG_FTRUNCATE = 41  # Truncate a file by a descriptor
    EFS2_DIAG_STATVFS_V2 = 42  # Obtains extensive file system info


O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
O_ACCMODE = O_RDONLY | O_WRONLY | O_RDWR
FS_DIAG_MAX_READ_REQ = 1024


# define DIAG_NV_WRITE_F 0x27
# define DIAG_NV_READ_F 0x26

class qcdiag(metaclass=LogBase):
    def __init__(self, loglevel, portconfig, ep_in=-1, ep_out=-1):
        self.portconfig = portconfig
        self.nvlist = {}
        self.ep_in = ep_in
        self.ep_out = ep_out
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
        import os, sys, inspect
        current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

        nvxml = os.path.join(current_dir, "Config", "nvitems.xml")
        e = ElementTree.parse(nvxml).getroot()
        for atype in e.findall("nv"):
            name = atype.get("name")
            identifier = int(atype.get("id"))
            self.nvlist[identifier] = name

    def prettyprint(self, data):
        recv = ""
        plain = ""
        for i in range(len(data)):
            inf = "%02X " % data[i]
            recv += inf
            if data[i] == 0x0D or data[i] == 0x0A or (0x20 <= data[i] <= 0x9A):
                plain += chr(data[i])
            else:
                plain += " "
            if ((i + 1) % 16) == 0:
                recv += "\n"
                plain += "\n"
        res = recv + "\n-----------------------------------------------\n"
        if len(plain.replace(" ", "").replace("\n", "")) > 0:
            res += plain
        return res

    def decodestatus(self, data):
        info = data[0]
        if info == 0x13:
            return "Invalid Command Response"
        elif info == 0x14:
            return "Invalid parameter Response"
        elif info == 0x15:
            return "Invalid packet length Response"
        elif info == 0x17:
            return "Send Security Mode"
        elif info == 0x18:
            return "Packet not allowed in this mode ( online vs offline )"
        elif info == 0x42:
            return "Invalid nv_read/write because SP is locked"
        elif info == diag_cmds.DIAG_BAD_SEC_MODE_F.value:
            return "Security privileges required"
        else:
            return True

    def connect(self):
        self.cdc = usb_class(portconfig=self.portconfig, loglevel=self.__logger.level)
        self.hdlc = None
        if self.cdc.connect(self.ep_in, self.ep_out):
            self.hdlc = hdlc(self.cdc)
            data = self.hdlc.receive_reply(1)
            return True
        return False

    def disconnect(self):
        self.cdc.close(True)

    def send(self, cmd):
        if self.hdlc != None:
            return self.hdlc.send_cmd_np(cmd)

    def info(self):
        reply = self.send(b"\x00")
        return self.prettyprint(reply)

    def enforce_crash(self):
        # ./diag.py -nvwrite 1027,01 enable adsp log NV_MDSP_MEM_DUMP_ENABLED_I
        # ./diag.py -nvwrite 4399,01 enable download on reboot NV_DETECT_HW_RESET_I
        res = self.send(b"\x4B\x25\x03\x00")
        print(self.decodestatus(res))

    def enter_downloadmode(self):
        res = self.send(b"\x3A")
        print(self.decodestatus(res))

    def enter_saharamode(self):
        self.hdlc.receive_reply()
        res = self.send(b"\x4b\x65\x01\x00")
        self.disconnect()
        print("Done")

    def send_sp(self, sp="FFFFFFFFFFFFFFFFFFFE"):
        if type(sp) == str:
            sp = unhexlify(sp)
        else:
            sp = bytes(sp)
        if len(sp) < 8:
            print("SP length must be 8 bytes")
            return
        res = self.send(b"\x46" + sp)
        if res[0] != 0x46:
            res = self.send(b"\x25" + sp)
        if res[0] != 0x25:
            print(self.decodestatus(res))
        else:
            if res[1] == 0x0:
                print("Security Password is wrong")
            elif res[1] == 0x1:
                print("Security Password accepted.")
        return res

    def send_spc(self, spc="303030303030"):
        if type(spc) == str:
            spc = unhexlify(spc)
        else:
            spc = bytes(spc)
        if len(spc) < 6:
            print("SPC length must be 6 bytes")
            return
        res = self.send(b"\x41" + spc)
        if res[0] != 0x41:
            print(self.decodestatus(res))
        else:
            if res[1] == 0x0:
                print("SPC is wrong")
            elif res[1] == 0x1:
                print("SPC accepted.")
        return res

    def DecodeNVItems(self, nvitem):
        if nvitem.status == 0x1:
            return "Internal DMSS use"
        elif nvitem.status == 0x2:
            return "Unrecognized command"
        elif nvitem.status == 0x3:
            return "NV memory full"
        elif nvitem.status == 0x4:
            return "Command failed"
        elif nvitem.status == 0x5:
            return "Inactive Item"
        elif nvitem.status == 0x6:
            return "Bad Parameter"
        elif nvitem.status == 0x7:
            return "Item was read-only"
        elif nvitem.status == 0x8:
            return "Item not defined for this target"
        elif nvitem.status == 0x9:
            return "No more free memory"
        elif nvitem.status == 0xA:
            return "Internal use"
        elif nvitem.status == 0x0:
            return "OK"
        return ""

    def print_nvitem(self, item):
        res, nvitem = self.read_nvitem(item)
        info = self.DecodeNVItems(nvitem)
        if res != False:
            if nvitem.name != "":
                ItemNumber = f"{hex(item)} ({nvitem.name}): "
            else:
                ItemNumber = hex(item) + ": "
            returnanswer = "NVItem " + ItemNumber + info
            print(returnanswer)
            if nvitem.status == 0:
                print("-----------------------------------------")
                print(self.prettyprint(nvitem.data))
        else:
            print(nvitem)

    def backup_nvitems(self, filename, errorlog=""):
        nvitems = []
        pos = 0
        old = 0
        errors = ""
        print("Dumping nvitems 0x0 to 0xFFFF.")
        for item in range(0, 0xFFFF):
            prog = int(float(pos) / float(0xFFFF) * float(100))
            if prog > old:
                print_progress(prog, 100, prefix='Progress:', suffix=f'Complete, item {hex(item)}', bar_length=50)
                old = prog
            res, nvitem = self.read_nvitem(item)
            if res != False:
                if nvitem.status != 0x5:
                    nvitem.status = self.DecodeNVItems(nvitem)
                    nvitems.append(dict(id=nvitem.item, name=nvitem.name, data=hexlify(nvitem.data).decode('utf-8'),
                                        status=nvitem.status))
            else:
                errors += nvitem + "\n"
            pos += 1
        js = json.dumps(nvitems)
        with open(filename, "w") as write_handle:
            write_handle.write(js)
        if errorlog == "":
            print(errors)
        else:
            with open(errorlog, "w") as write_handle:
                write_handle.write(errors)
        print("Done.")

    def read_nvitem(self, item):
        rawdata = 128 * b'\x00'
        status = 0x0000
        nvrequest = b'\x26' + write_object(nvitem_type, item, rawdata, status)['raw_data']
        data = self.send(nvrequest)
        if len(data) == 0:
            data = self.send(nvrequest)
        if len(data) > 0:
            if data[0] == 0x26:
                res = read_object(data[1:], nvitem_type)
                name = ""
                if item in self.nvlist:
                    name = self.nvlist[item]
                data = bytearray()
                for byte in res["rawdata"]:
                    if byte == 0:
                        break
                    data.append(byte)
                res = nvitem(res["item"], data, res["status"], name)
                return [True, res]
            elif data[0] == 0x14:
                return [False, f"Error 0x14 trying to read nvitem {hex(item)}."]
            else:
                return [False, f"Error {hex(data[0])} trying to read nvitem {hex(item)}."]
        return [False, f"Empty request for nvitem {hex(item)}"]

    def write_nvitem(self, item, data):
        rawdata = bytes(data)
        while len(rawdata) < 128:
            rawdata += b"\x00"
        status = 0x0000
        nvrequest = b"\x27" + write_object(nvitem_type, item, rawdata, status)['raw_data']
        res = self.send(nvrequest)
        if len(res) > 0:
            if res[0] == 0x27:
                res, nvitem = self.read_nvitem(item)
                if res == False:
                    print(f"Error while writing nvitem {hex(item)} data, %s" % data)
                else:
                    if nvitem.data != data:
                        print(f"Error while writing nvitem {hex(item)} data, verified data doesn't match")
                    else:
                        print(f"Successfully wrote nvitem {hex(item)}.")
                        return True
                return False
            else:
                print(f"Error while writing nvitem {hex(item)} data, %s" % data)

    def efsread(self, filename):
        alternateefs = b"\x4B\x3E\x19\x00"
        standardefs = b"\x4B\x13\x19\x00"
        resp = self.send(alternateefs)
        if resp[0] == 0x4B:
            efsmethod = 0x3E
        else:
            resp = self.send(standardefs)
            if resp[0] == 0x4B:
                efsmethod = 0x13
            else:
                print("No known efs method detected for reading.")
                return

        if filename == "":
            return False
        write_handle = open(filename, 'wb')
        if write_handle is None:
            print("Error on writing file ....")
            return False

        print("Reading EFS ....")
        fefs = fs_factimage_read_info(0, 0, 0, 0)

        # EFS Cmd
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_PREP_FACT_IMAGE.value, 0x00)  # prepare factory image

        resp = self.send(buf)
        if len(resp) == 0:
            print("Phone does not respond. Maybe another software is blocking the port.")
            return False

        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_FACT_IMAGE_START.value,
                   0x00)  # indicate start read out factory image

        resp = self.send(buf)

        # EFS Cmd
        buf = pack('<BBBBBBHI', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_FACT_IMAGE_READ.value, 0x00, fefs.stream_state,
                   fefs.info_cluster_sent,
                   fefs.cluster_map_seqno, fefs.cluster_data_seqno)

        resp = self.send(buf)
        if resp == 0 or resp == -1:
            info = ("Page %08X error !\n" % fefs.cluster_data_seqno)
            print(info)
            resp = self.send(buf)
            if resp == 0 or resp == -1:
                print("Data Error occured, ") + info

        error = unpack("<I", resp[4:8])[0]

        if (resp[0] == 0x13) or (resp[0] == 0x14) or (resp[0] == 0x15) or (error != 0x0):
            print("EFS Read not supported by phone. Aborting")
            write_handle.close()
            return False
        elif resp[0] == 0x47:
            print("Send Security Password (SP) first !")
            write_handle.close()
            return False

        efserr = False
        fh = FactoryHeader()
        if len(resp) > 0:
            write_handle.write(resp[0x10:-0x1])
            fefs.fromdata(resp[0x8:0x10])
            fh.fromdata(resp[0x10:0x10 + (39 * 4)])

        old = 0
        print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        total = fh.block_size * fh.block_count * (fh.page_size // 0x200)

        # Real start
        for page in range(0, total):
            # EFS Cmd
            buf = pack('<BBBBBBHI', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_FACT_IMAGE_READ.value, 0x00,
                       fefs.stream_state, fefs.info_cluster_sent,
                       fefs.cluster_map_seqno, fefs.cluster_data_seqno)

            pos = int(page / total * 100)
            if pos > old:
                print_progress(pos, 100, prefix='Progress:', suffix='Page %d of %d' % (page, total), bar_length=50)
                old = pos

            resp = self.send(buf)
            if resp == 0:
                resp = self.send(buf)

            if resp == 0 or resp == -1:
                info = ("Page %08X !\n" % fefs.cluster_data_seqno)
                print(info)
                resp = self.send(buf)
                if resp == 0 or resp == -1:
                    print("Data Error occured, " + info)
            else:
                dlen = len(resp) - 0x11
                if dlen == 0x200 or dlen == 0x800:
                    if resp[0x0] == 0x4B:
                        write_handle.write(resp[0x10:0x10 + dlen])
                        fefs.fromdata(resp[0x8:0x10])
                    else:
                        if (resp[0x0] == 0x13) and (resp[0x1] == 0x62) and (len(resp) > 0x200):
                            write_handle.write(resp[0x14:-4])
                            fefs.fromdata(resp[0xc:0x14])
                            if fefs.stream_state == 0x0:
                                break
                        else:
                            print("EFS Read error : Wrong size recieved at page %X" % page)
                            efserr = True
                            break

        print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)

        buf = bytearray()
        buf.append(0x4B)
        buf.append(efsmethod)
        buf.append(efs_cmds.EFS2_DIAG_FACT_IMAGE_END.value)  # end factory image
        buf.append(0x00)

        resp = self.send(buf)
        if len(resp) == 0:
            print("Phone does not respond. Maybe another software is blocking the port.")
            return False

        write_handle.close()
        if efserr == False:
            print("Successfully read EFS.")
            return True
        else:
            print("Error on reading EFS.")
            return False

    def send_cmd(self, cmd):
        cmdtosend = unhexlify(cmd)
        reply = self.send(cmdtosend)
        if reply[0] != cmdtosend[0]:
            print(self.decodestatus(reply))
        result = self.prettyprint(reply)
        return result

    def efsdiagerror(self, errcode):
        if errcode == 0x40000001:
            print("Inconsistent state.")
        elif errcode == 0x40000002:
            print("Invalid seq no.")
        elif errcode == 0x40000003:
            print("Directory not open.")
        elif errcode == 0x40000004:
            print("Directory entry not found.")
        elif errcode == 0x40000005:
            print("Invalid path.")
        elif errcode == 0x40000006:
            print("Path too long")
        elif errcode == 0x40000007:
            print("Too many open directories.")
        elif errcode == 0x40000008:
            print("Invalid directory entry.")
        elif errcode == 0x40000009:
            print("Too many open files.")
        elif errcode == 0x4000000a:
            print("Unknown filetype")
        elif errcode == 0x4000000b:
            print("Not nand falsh")
        elif errcode == 0x4000000c:
            print("Unavailable info")
        else:
            return 0
        return -1

    def efs_closedir(self, efsmethod, dirp):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_CLOSEDIR.value, 0x00)  # list efs dir
        buf += pack("<I", dirp)
        resp = self.send(buf)
        diagerror = unpack("<I", resp[0x4:0x8])[0]
        return self.efsdiagerror(diagerror)

    def efs_opendir(self, efsmethod, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_OPENDIR.value, 0x00)  # open efs dir
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            dirp = unpack("<I", resp[0x4:0x8])[0]
            diagerror = unpack("<I", resp[0x8:0xC])[0]
            if self.efsdiagerror(diagerror) != 0:
                return -1
            return dirp

    def efslistdir(self, path):
        alternateefs = b"\x4B\x3E\x00\x00" + b"\x00" * 0x28
        standardefs = b"\x4B\x13\x00\x00" + b"\x00" * 0x28
        resp = self.send(alternateefs)
        if resp[0] == 0x4B:
            efsmethod = 0x3E
        else:
            resp = self.send(standardefs)
            if resp[0] == 0x4B:
                efsmethod = 0x13
            else:
                print("No known efs method detected for reading.")
                return

        dirp = self.efs_opendir(efsmethod, path)
        if dirp == -1:
            return

        info = ""
        for seqno in range(1, 0xFFFFFFFF):
            buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_READDIR.value, 0x00)  # list efs dir
            buf += pack("<II", dirp, seqno)
            resp = self.send(buf)
            if len(resp) > 0:
                [dirp, seqno, diag_errno, entry_type, mode, size, atime, mtime, ctime] = unpack("<Iiiiiiiii",
                                                                                                resp[4:4 + (9 * 4)])
                entry_name = resp[4 + (9 * 4):-1]
                if entry_name == b'':
                    break
                info += f"\"{path}{entry_name.decode('utf-8')}\" mode:{hex(mode)}, size:{hex(size)}, atime:{hex(atime)}, mtime:{hex(mtime)}, ctime:{hex(ctime)}\n"

        if self.efs_closedir(efsmethod, dirp) == 0:
            print("Successfully listed directory")
        else:
            print("Error on listing directory")
        return info

    def efs_open(self, efsmethod, oflag, mode, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_OPEN.value, 0x00)  # open efs dir
        buf += pack('<II', oflag, mode)
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            fdata = unpack("<i", resp[0x4:0x8])[0]
            diagerror = unpack("<I", resp[0x8:0xC])[0]
            if self.efsdiagerror(diagerror) != 0:
                return -1
            return fdata

    def efs_close(self, efsmethod, fdata):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_CLOSE.value, 0x00)  # list efs dir
        buf += pack("<i", fdata)
        resp = self.send(buf)
        diag_error = unpack("<I", resp[0x4:0x8])[0]
        return self.efsdiagerror(diag_error)

    def efs_stat(self, efsmethod, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_STAT.value, 0x00)  # open efs file
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            diag_error = unpack("<I", resp[0x4:0x8])[0]
            mode = unpack("<I", resp[0x8:0xC])[0]
            size = unpack("<I", resp[0xC:0x10])[0]
            nlink = unpack("<I", resp[0x10:0x14])[0]
            atime = unpack("<I", resp[0x14:0x18])[0]
            mtime = unpack("<I", resp[0x18:0x1C])[0]
            ctime = unpack("<I", resp[0x1C:0x20])[0]
            if self.efsdiagerror(diag_error) != 0:
                return -1
            return [mode, size, nlink, atime, mtime, ctime]

    def efs_fstat(self, efsmethod, fdata):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_FSTAT.value, 0x00)  # open efs file
        buf += pack("<I", fdata)
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            diag_error = unpack("<I", resp[0x4:0x8])[0]
            mode = unpack("<I", resp[0x8:0xC])[0]
            size = unpack("<I", resp[0xC:0x10])[0]
            nlink = unpack("<I", resp[0x10:0x14])[0]
            atime = unpack("<I", resp[0x14:0x18])[0]
            mtime = unpack("<I", resp[0x18:0x1C])[0]
            ctime = unpack("<I", resp[0x1C:0x20])[0]
            if self.efsdiagerror(diag_error) != 0:
                return -1
            return [mode, size, nlink, atime, mtime, ctime]

    def efs_lstat(self, efsmethod, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_LSTAT.value, 0x00)  # open efs file
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            diag_error = unpack("<I", resp[0x4:0x8])[0]
            mode = unpack("<I", resp[0x8:0xC])[0]
            atime = unpack("<I", resp[0xC:0x10])[0]
            mtime = unpack("<I", resp[0x10:0x14])[0]
            ctime = unpack("<I", resp[0x14:0x18])[0]
            if self.efsdiagerror(diag_error) != 0:
                return -1
            return [mode, atime, mtime, ctime]

    def efs_get(self, efsmethod, path, data_length, sequence_number):
        path_length = len(path) + 1
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_GET.value, 0x00)  # open efs file
        buf += pack('<IIH', data_length, path_length, sequence_number)
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            num_bytes = unpack("<I", resp[0x4:0x8])[0]
            diag_error = unpack("<I", resp[0x8:0xC])[0]
            seq_no = unpack("<H", resp[0xC:0xE])[0]
            data = resp[0xE:]
            if self.efsdiagerror(diag_error) != 0:
                return -1
            return [num_bytes, seq_no, data]

    def efs_write(self, efsmethod, fdata, offset, data):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_WRITE.value, 0x00)  # open efs file
        buf += pack('<II', fdata, offset)
        buf += data
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            fdata = unpack("<i", resp[0x4:0x8])[0]
            offset = unpack("<I", resp[0x8:0xC])[0]
            bytes_written = unpack("<I", resp[0xC:0x10])[0]
            diag_error = unpack("<I", resp[0x10:0x14])[0]
            if self.efsdiagerror(diag_error) != 0:
                return -1
            return [fdata, offset, bytes_written]

    def handle_error(self, resp):
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            diagerror = unpack("<I", resp[0x4:0x8])[0]
            if self.efsdiagerror(diagerror) != 0:
                return -1
            return 0

    def efs_rmdir(self, efsmethod, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_RMDIR.value, 0x00)  # open efs file
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        return self.handle_error(resp)

    def efs_unlink(self, efsmethod, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_UNLINK.value, 0x00)  # open efs file
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        return self.handle_error(resp)

    def efs_chown(self, efsmethod, uid_val, gid_val, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_CHOWN.value, 0x00)  # open efs file
        buf += pack('<ii', uid_val, gid_val)
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        return self.handle_error(resp)

    def efs_chmod(self, efsmethod, mode, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_CHMOD.value, 0x00)  # open efs file
        buf += pack('<H', mode)
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        return self.handle_error(resp)

    def efs_mkdir(self, efsmethod, mode, path):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_MKDIR.value, 0x00)  # open efs file
        buf += pack('<H', mode)
        buf += bytes(path, 'utf-8') + b"\x00"
        resp = self.send(buf)
        return self.handle_error(resp)

    def efs_read(self, efsmethod, fdata, nbytes, offset):
        buf = pack('<BBBB', 0x4B, efsmethod, efs_cmds.EFS2_DIAG_WRITE.value, 0x00)  # open efs file
        buf += pack('<III', fdata, nbytes, offset)
        resp = self.send(buf)
        if resp[0] != diag_cmds.DIAG_BAD_SEC_MODE_F.value and resp[0] != diag_cmds.DIAG_BAD_LEN_F.value:
            fdata = unpack("<i", resp[0x4:0x8])[0]
            offset = unpack("<I", resp[0x8:0xC])[0]
            bytes_read = unpack("<I", resp[0xC:0x10])[0]
            diag_error = unpack("<I", resp[0x10:0x14])[0]
            data = resp[0x14:]
            if self.efsdiagerror(diag_error) != 0:
                return -1
            return [fdata, offset, bytes_read, data]

    def efsreadfile(self, srcpath, dstpath):
        alternateefs = b"\x4B\x3E\x00\x00" + b"\x00" * 0x28
        standardefs = b"\x4B\x13\x00\x00" + b"\x00" * 0x28
        resp = self.send(alternateefs)
        if resp[0] == 0x4B:
            efsmethod = 0x3E
        else:
            resp = self.send(standardefs)
            if resp[0] == 0x4B:
                efsmethod = 0x13
            else:
                logging.error("No known efs method detected for reading.")
                return 0

        fdata = self.efs_open(efsmethod, O_RDONLY, 0, srcpath)
        if fdata == -1:
            return 0
        mode, size, nlink, atime, mtime, ctime = self.efs_fstat(efsmethod, fdata)
        if size == 0:
            self.efs_close(efsmethod, fdata)
            return 0
        acr = (mode & O_ACCMODE)
        if acr == O_WRONLY:
            logging.error("File can only be written. Aborting.")
            self.efs_close(efsmethod, fdata)
            return 0

        num_bytes = 0
        offset = 0
        fname = srcpath[srcpath.rfind("/") + 1:]
        fname = os.path.join(dstpath, fname)
        with open(fname, 'wb') as write_handle:
            dataleft = size
            while dataleft > 0:
                rsize = dataleft
                if rsize > FS_DIAG_MAX_READ_REQ:
                    rsize = FS_DIAG_MAX_READ_REQ
                finfo = self.efs_read(efsmethod, fdata, rsize, offset)
                if finfo == -1:
                    break
                fdata, offset, bytes_read, data = finfo
                write_handle.write(data)
                offset += rsize
                dataleft -= rsize
        self.efs_close(efsmethod, fdata)
        return num_bytes

    def efswritefile(self, srcpath, dstpath):
        alternateefs = b"\x4B\x3E\x00\x00" + b"\x00" * 0x28
        standardefs = b"\x4B\x13\x00\x00" + b"\x00" * 0x28
        resp = self.send(alternateefs)
        if resp[0] == 0x4B:
            efsmethod = 0x3E
        else:
            resp = self.send(standardefs)
            if resp[0] == 0x4B:
                efsmethod = 0x13
            else:
                logging.error("No known efs method detected for reading.")
                return 0
        with open(srcpath, 'rb') as rf:
            fdata = self.efs_open(efsmethod, O_RDONLY, 0, srcpath)
            if fdata == -1:
                return 0
            mode, size, nlink, atime, mtime, ctime = self.efs_fstat(efsmethod, fdata)
            if size == 0:
                self.efs_close(efsmethod, fdata)
                return 0
            '''
            acr=(mode & O_ACCMODE)
            if acr==O_RDONLY:
                print("File can only be read. Aborting.")
                self.efs_close(efsmethod, fdata)
                return
            '''
            num_bytes = 0
            offset = 0
            size = os.fstat(srcpath).st_size
            dataleft = size
            while dataleft > 0:
                rsize = dataleft
                if rsize > FS_DIAG_MAX_READ_REQ:
                    rsize = FS_DIAG_MAX_READ_REQ
                data = rf.read(rsize)
                finfo = self.efs_write(efsmethod, fdata, offset, data)
                if finfo == -1:
                    break
                fdata, offset, bytes_written = finfo
                offset += rsize
                dataleft -= rsize
            self.efs_close(efsmethod, fdata)
        return num_bytes


class DiagTools(metaclass=LogBase):
    def run(self, args):
        if args.vid != "":
            self.vid = int(args.vid, 16)
        if args.pid != "":
            self.pid = int(args.pid, 16)
        if args.interface != "":
            self.interface = int(args.interface, 16)
        self.interface = -1
        self.vid = None
        self.pid = None

        logfilename = "diag.txt"
        if args.debugmode:
            if os.path.exists(logfilename):
                os.remove(logfilename)
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
            self.__logger.setLevel(logging.DEBUG)
        else:
            self.__logger.setLevel(logging.INFO)

        connected = False
        diag = None
        if self.vid == None or self.pid == None:
            diag = qcdiag(loglevel=self.__logger.level, portconfig=default_vid_pid)
            connected = diag.connect()
        else:
            diag = qcdiag(loglevel=self.__logger.level, portconfig=[[self.vid, self.pid, self.interface]])
            connected = diag.connect()
        if connected:
            if args.sp:
                diag.send_sp(args.sp)
            elif args.spc:
                diag.send_spc(args.spc)
            elif args.cmd:
                print(diag.send_cmd(args.cmd))
            elif args.info:
                print(diag.info())
            elif args.download:
                diag.enter_downloadmode()
            elif args.sahara:
                diag.enter_saharamode()
            elif args.crash:
                diag.enforce_crash()
            elif args.efslistdir:
                print(diag.efslistdir(args.efslistdir))
            elif args.nvread:
                if "0x" in args.nvread:
                    nvitem = int(args.nvread, 16)
                else:
                    nvitem = int(args.nvread)
                diag.print_nvitem(nvitem)
            elif args.nvwrite:
                if not "," in args.nvwrite:
                    print("NvWrite requires data to write")
                    sys.exit()
                nv = args.nvwrite.split(",")
                if "0x" in args.nvwrite:
                    nvitem = int(nv[0], 16)
                else:
                    nvitem = int(nv[0])
                data = unhexlify(nv[1])
                diag.write_nvitem(nvitem, data)
            elif args.nvbackup:
                diag.backup_nvitems(args.nvbackup, "error.log")
            elif args.efsread:
                diag.efsread(args.efsread)
            else:
                print("A command is required. Use -cmd \"data\" for sending requests.")
            diag.disconnect()
            sys.exit()
        else:
            print("No diag device detected. Use -pid and -vid options. See -h for help.")
            diag.disconnect()
            sys.exit()


def main():
    info = 'Qualcomm Diag Client (c) B.Kerler 2019-2021.'
    parser = argparse.ArgumentParser(description=info)
    print("\n" + info + "\n---------------------------------------\n")
    parser.add_argument('-vid', metavar="<vid>", help='[Option] Specify vid, default=0x05c6)', default="")
    parser.add_argument('-pid', metavar="<pid>", help='[Option] Specify pid, default=0x9008)', default="")
    parser.add_argument('-interface', metavar="<pid>", help='[Option] Specify interface number, default=0)',
                        default="0")
    parser.add_argument('-info', help='[Option] Get diag info', action='store_true')
    parser.add_argument('-cmd', metavar=("<command>"), help='[Option] Command to send', default="")
    parser.add_argument('-sp', metavar=("<SP>"), help='[Option] Security password to send, default: FFFFFFFFFFFFFFFE',
                        default="", const='FFFFFFFFFFFFFFFE', nargs="?")
    parser.add_argument('-spc', metavar=("<SPC>"), help='[Option] Security code to send, default: 303030303030',
                        default="", const='303030303030', nargs="?")
    parser.add_argument('-nvread', metavar=("<nvitem>"), help='[Option] Read nvitem', default="")
    parser.add_argument('-nvwrite', metavar=("<nvitem,data>"), help='[Option] Write nvitem', default="")
    parser.add_argument('-nvbackup', metavar=("<filename>"), help='[Option] Make nvitem backup as json', default="")
    parser.add_argument('-efsread', metavar=("<filename>"), help='[Option] Read efs', default="")
    parser.add_argument('-efslistdir', metavar=("<path>"), help='[Option] List efs directory', default="")
    parser.add_argument('-download', help='[Option] Switch to sahara mode', action='store_true')
    parser.add_argument('-sahara', help='[Option] Switch to sahara mode', action='store_true')
    parser.add_argument('-crash', help='[Option] Enforce crash', action='store_true')
    parser.add_argument('--debugmode', help='[Option] Enable verbose logging', action='store_true')

    args = parser.parse_args()
    dg = DiagTools()
    dg.run(args)


if __name__ == '__main__':
    main()
