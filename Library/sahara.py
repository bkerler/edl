import binascii
import os
import time
from Library.utils import *
from Library.firehose import qualcomm_firehose

class qualcomm_sahara():
    SAHARA_VERSION=2
    SAHARA_MIN_VERSION=1

    class cmd:
      SAHARA_HELLO_REQ=0x1
      SAHARA_HELLO_RSP=0x2
      SAHARA_READ_DATA=0x3
      SAHARA_END_TRANSFER=0x4
      SAHARA_DONE_REQ=0x5
      SAHARA_DONE_RSP=0x6
      SAHARA_RESET_REQ=0x7
      SAHARA_RESET_RSP=0x8
      SAHARA_MEMORY_DEBUG=0x9
      SAHARA_MEMORY_READ=0xA
      SAHARA_CMD_READY=0xB
      SAHARA_SWITCH_MODE=0xC
      SAHARA_EXECUTE_REQ=0xD
      SAHARA_EXECUTE_RSP=0xE
      SAHARA_EXECUTE_DATA=0xF
      SAHARA_64BIT_MEMORY_DEBUG=0x10
      SAHARA_64BIT_MEMORY_READ=0x11
      SAHARA_64BIT_MEMORY_READ_DATA=0x12

    class exec_cmd:
      SAHARA_EXEC_CMD_NOP=0x00
      SAHARA_EXEC_CMD_SERIAL_NUM_READ=0x01
      SAHARA_EXEC_CMD_MSM_HW_ID_READ=0x02
      SAHARA_EXEC_CMD_OEM_PK_HASH_READ=0x03
      SAHARA_EXEC_CMD_SWITCH_TO_DMSS_DLOAD=0x04
      SAHARA_EXEC_CMD_SWITCH_TO_STREAM_DLOAD=0x05
      SAHARA_EXEC_CMD_READ_DEBUG_DATA=0x06
      SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL=0x07

    class mode:
      SAHARA_MODE_IMAGE_TX_PENDING=0x0
      SAHARA_MODE_IMAGE_TX_COMPLETE=0x1
      SAHARA_MODE_MEMORY_DEBUG=0x2
      SAHARA_MODE_COMMAND=0x3

    class status:
      SAHARA_STATUS_SUCCESS =                     0x00  # Invalid command received in current state
      SAHARA_NAK_INVALID_CMD =                    0x01  # Protocol mismatch between host and target
      SAHARA_NAK_PROTOCOL_MISMATCH =              0x02  # Invalid target protocol version
      SAHARA_NAK_INVALID_TARGET_PROTOCOL =        0x03  # Invalid host protocol version
      SAHARA_NAK_INVALID_HOST_PROTOCOL =          0x04  # Invalid packet size received
      SAHARA_NAK_INVALID_PACKET_SIZE =            0x05  # Unexpected image ID received
      SAHARA_NAK_UNEXPECTED_IMAGE_ID =            0x06  # Invalid image header size received
      SAHARA_NAK_INVALID_HEADER_SIZE =            0x07  # Invalid image data size received
      SAHARA_NAK_INVALID_DATA_SIZE =              0x08  # Invalid image type received
      SAHARA_NAK_INVALID_IMAGE_TYPE =             0x09  # Invalid tranmission length
      SAHARA_NAK_INVALID_TX_LENGTH =              0x0A  # Invalid reception length
      SAHARA_NAK_INVALID_RX_LENGTH =              0x0B  # General transmission or reception error
      SAHARA_NAK_GENERAL_TX_RX_ERROR =            0x0C  # Error while transmitting READ_DATA packet
      SAHARA_NAK_READ_DATA_ERROR =                0x0D  # Cannot receive specified number of program headers
      SAHARA_NAK_UNSUPPORTED_NUM_PHDRS =          0x0E  # Invalid data length received for program headers
      SAHARA_NAK_INVALID_PDHR_SIZE =              0x0F  # Multiple shared segments found in ELF image
      SAHARA_NAK_MULTIPLE_SHARED_SEG =            0x10  # Uninitialized program header location
      SAHARA_NAK_UNINIT_PHDR_LOC =                0x11  # Invalid destination address
      SAHARA_NAK_INVALID_DEST_ADDR =              0x12  # Invalid data size received in image header
      SAHARA_NAK_INVALID_IMG_HDR_DATA_SIZE =      0x13  # Invalid ELF header received
      SAHARA_NAK_INVALID_ELF_HDR =                0x14  # Unknown host error received in HELLO_RESP
      SAHARA_NAK_UNKNOWN_HOST_ERROR =             0x15  # Timeout while receiving data
      SAHARA_NAK_TIMEOUT_RX =                     0x16  # Timeout while transmitting data
      SAHARA_NAK_TIMEOUT_TX =                     0x17  # Invalid mode received from host
      SAHARA_NAK_INVALID_HOST_MODE =              0x18  # Invalid memory read access
      SAHARA_NAK_INVALID_MEMORY_READ =            0x19  # Host cannot handle read data size requested
      SAHARA_NAK_INVALID_DATA_SIZE_REQUEST =      0x1A  # Memory debug not supported
      SAHARA_NAK_MEMORY_DEBUG_NOT_SUPPORTED =     0x1B  # Invalid mode switch
      SAHARA_NAK_INVALID_MODE_SWITCH =            0x1C  # Failed to execute command
      SAHARA_NAK_CMD_EXEC_FAILURE =               0x1D  # Invalid parameter passed to command execution
      SAHARA_NAK_EXEC_CMD_INVALID_PARAM =         0x1E  # Unsupported client command received
      SAHARA_NAK_EXEC_CMD_UNSUPPORTED =           0x1F  # Invalid client command received for data response
      SAHARA_NAK_EXEC_DATA_INVALID_CLIENT_CMD =   0x20  # Failed to authenticate hash table
      SAHARA_NAK_HASH_TABLE_AUTH_FAILURE =        0x21  # Failed to verify hash for a given segment of ELF image
      SAHARA_NAK_HASH_VERIFICATION_FAILURE =      0x22  # Failed to find hash table in ELF image
      SAHARA_NAK_HASH_TABLE_NOT_FOUND =           0x23  # Target failed to initialize
      SAHARA_NAK_TARGET_INIT_FAILURE =            0x24  # Failed to authenticate generic image
      SAHARA_NAK_IMAGE_AUTH_FAILURE  =            0x25  # Invalid ELF hash table size.  Too bit or small.
      SAHARA_NAK_INVALID_IMG_HASH_TABLE_SIZE =    0x26
      SAHARA_NAK_MAX_CODE = 0x7FFFFFFF                  # To ensure 32-bits wide */

    ErrorDesc={
        0x00:"Invalid command received in current state",
        0x01:"Protocol mismatch between host and target",
        0x02:"Invalid target protocol version",
        0x03:"Invalid host protocol version",
        0x04:"Invalid packet size received",
        0x05:"Unexpected image ID received",
        0x06:"Invalid image header size received",
        0x07:"Invalid image data size received",
        0x08:"Invalid image type received",
        0x09:"Invalid tranmission length",
        0x0A:"Invalid reception length",
        0x0B:"General transmission or reception error",
        0x0C:"Error while transmitting READ_DATA packet",
        0x0D:"Cannot receive specified number of program headers",
        0x0E:"Invalid data length received for program headers",
        0x0F:"Multiple shared segments found in ELF image",
        0x10:"Uninitialized program header location",
        0x11:"Invalid destination address",
        0x12:"Invalid data size received in image header",
        0x13:"Invalid ELF header received",
        0x14:"Unknown host error received in HELLO_RESP",
        0x15:"Timeout while receiving data",
        0x16:"Timeout while transmitting data",
        0x17:"Invalid mode received from host",
        0x18:"Invalid memory read access",
        0x19:"Host cannot handle read data size requested",
        0x1A:"Memory debug not supported",
        0x1B:"Invalid mode switch",
        0x1C:"Failed to execute command",
        0x1D:"Invalid parameter passed to command execution",
        0x1E:"Unsupported client command received",
        0x1F:"Invalid client command received for data response",
        0x20:"Failed to authenticate hash table",
        0x21:"Failed to verify hash for a given segment of ELF image",
        0x22:"Failed to find hash table in ELF image",
        0x23:"Target failed to initialize",
        0x24:"Failed to authenticate generic image",
        0x25:"Invalid ELF hash table size.  Too bit or small.",
        0x26:"Invalid IMG Hash Table Size"
    }

    def init_loader_db(self):
        self.loaderdb = {}
        for (dirpath, dirnames, filenames) in os.walk("Loaders"):
            for filename in filenames:
                fn = os.path.join(dirpath, filename)
                try:
                    hwid = filename.split("_")[0].lower()
                    pkhash = filename.split("_")[1].lower()
                    if hwid not in self.loaderdb:
                        self.loaderdb[hwid] = {}
                    if pkhash not in self.loaderdb[hwid]:
                        self.loaderdb[hwid][pkhash] = fn
                except:
                    continue
        return self.loaderdb

    def get_error_desc(self,status):
        if status in self.ErrorDesc:
            return "Error: "+self.ErrorDesc[status]
        else:
            return "Unknown error"

    pkt_hello_req=[
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

    pkt_cmd_hdr=[
        ('cmd', 'I'),
        ('len', 'I')
    ]

    pkt_read_data=[
        ('id', 'I'),
        ('data_offset', 'I'),
        ('data_len', 'I')
    ]

    pkt_read_data_64=[
        ('id', 'Q'),
        ('data_offset', 'Q'),
        ('data_len', 'Q')
    ]

    '''
    execute_cmd=[
        ('cmd', 'I'),
        ('len', 'I'),
        ('client_cmd','I')
    ]
    '''

    pkt_execute_rsp_cmd=[
        ('cmd', 'I'),
        ('len', 'I'),
        ('client_cmd','I'),
        ('data_len','I')
    ]

    pkt_image_end=[
        ('id', 'I'),
        ('status', 'I')
    ]

    pkt_done=[
        ('cmd', 'I'),
        ('len', 'I'),
        ('status','I')
    ]

    pbl_info=[
        ('serial', 'I'),
        ('msm_id', 'I'),
        ('pk_hash','32s'),
        ('pbl_sw','I')
    ]

    def __init__(self,cdc):
        self.cdc = cdc
        self.init_loader_db()
        self.programmer=None

    def get_rsp(self):
        v = self.cdc.read()
        if b"<?xml" in v:
            return [-1,-1]
        pkt = read_object(v[0:0x2*0x4], self.pkt_cmd_hdr)
        if pkt['cmd'] == self.cmd.SAHARA_HELLO_REQ:
            data = read_object(v[0x0:0xC*0x4], self.pkt_hello_req)
        elif pkt["cmd"] == self.cmd.SAHARA_DONE_RSP:
            data = read_object(v[0x0:0x3*4], self.pkt_done)
        elif pkt["cmd"] == self.cmd.SAHARA_END_TRANSFER:
            data = read_object(v[0x8:0x8+0x2*0x4], self.pkt_image_end)
        elif pkt["cmd"] == self.cmd.SAHARA_RESET_RSP:
            data = []
        elif (pkt["cmd"] == self.cmd.SAHARA_64BIT_MEMORY_READ_DATA):
            self.bit64 = True
            data = read_object(v[0x8:0x8 + 0x3 * 0x8], self.pkt_read_data_64)
        elif (pkt["cmd"] == self.cmd.SAHARA_READ_DATA):
            self.bit64 = False
            data = read_object(v[0x8:0x8 + 0x3 * 0x4], self.pkt_read_data)
        elif (pkt["cmd"] == self.cmd.SAHARA_EXECUTE_RSP):
            data =read_object(v[0:0x4*0x4], self.pkt_execute_rsp_cmd)
        elif (pkt["cmd"] == self.cmd.SAHARA_CMD_READY):
            data=[]
        else:
            return None
        return [pkt,data]

    def cmd_hello(self,mode,version_min=1, max_cmd_len=0):    #CMD 0x1, RSP 0x2
        cmd = self.cmd.SAHARA_HELLO_RSP
        len = 0x30
        version = self.SAHARA_VERSION
        responsedata=struct.pack("<IIIIIIIIIIII",cmd,len,version,version_min,max_cmd_len,mode,0,0,0,0,0,0)
        try:
            self.cdc.write(responsedata)
            return True
        except:
            return False
        return False

    def connect(self):
        try:
            v = self.cdc.read()
            if b"<?xml" in v:
                return "Firehose"
            elif v[0]==0x01:
                cmd = read_object(v[0:0x2 * 0x4], self.pkt_cmd_hdr)
                if cmd['cmd'] == self.cmd.SAHARA_HELLO_REQ:
                    data = read_object(v[0x0:0xC * 0x4], self.pkt_hello_req)
                    self.pktsize = data['max_cmd_len']
                    self.version_min = data['version_min']
                    return "Sahara"
        except:
            try:
                data = "<?xml version=\"1.0\" ?><data><nop /></data>"
                val = self.cdc.write(data,4096)
                res = self.cdc.read()
                if (b"<?xml" in res):
                    return "Firehose"
            except:
                return "Unknown"
        return "Unknown"

    def enter_command_mode(self):
        if self.cmd_hello(self.mode.SAHARA_MODE_COMMAND)==False:
            return False
        cmd, pkt = self.get_rsp()
        if (cmd["cmd"] == self.cmd.SAHARA_CMD_READY):
            return True
        elif "status" in pkt:
            print(self.get_error_desc(pkt["status"]))
            return False
        return False

    def cmdexec_nop(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_NOP)
        return res

    def cmdexec_get_serial_num(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_SERIAL_NUM_READ)
        return struct.unpack("<I", res)[0]

    def cmdexec_get_msm_hwid(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_MSM_HW_ID_READ)
        return struct.unpack("<Q", res[0:0x8])[0]

    def cmdexec_get_pkhash(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_OEM_PK_HASH_READ)[0:0x20]
        return binascii.hexlify(res).decode('utf-8')

    def cmdexec_get_sbl_version(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL)
        return struct.unpack("<I", res)[0]

    def cmdexec_switch_to_dmss_dload(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_SWITCH_TO_DMSS_DLOAD)
        return res

    def cmdexec_switch_to_stream_dload(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_SWITCH_TO_STREAM_DLOAD)
        return res

    def cmdexec_read_debug_data(self):
        res=self.cmd_exec(self.exec_cmd.SAHARA_EXEC_CMD_READ_DEBUG_DATA)
        return res

    def info(self):
        if self.enter_command_mode()==True:
            self.serial = "{:08x}".format(self.cmdexec_get_serial_num())
            self.sblversion = "{:08x}".format(self.cmdexec_get_sbl_version())
            self.hwid = self.cmdexec_get_msm_hwid()
            self.pkhash = self.cmdexec_get_pkhash()
            self.hwidstr="{:016x}".format(self.hwid)
            self.msm_id = int(self.hwidstr[0:8],16)
            self.oem_id = int(self.hwidstr[-8:-4],16)
            self.model_id = int(self.hwidstr[-4:],16)
            self.oem_str="{:04x}".format(self.oem_id)
            self.model_id = "{:04x}".format(self.model_id)
            self.msm_str="{:08x}".format(self.msm_id)

            print(f"\n------------------------\n" +
                  f"HWID:              0x{self.hwidstr} (MSM_ID:0x{self.msm_str},OEM_ID:0x{self.oem_str},MODEL_ID:0x{self.model_id})\n" +
                  f"PK_HASH:           0x{self.pkhash}\n" +
                  f"Serial:            0x{self.serial}\n" +
                  f"SBL Version:       0x{self.sblversion}\n")
            if self.programmer==None:
                if self.hwidstr in self.loaderdb:
                    if self.pkhash[0:16]=="cc3153a80293939b":
                        print("Unfused device detected, so any loader should be fine...")
                        for loader in self.loaderdb[self.hwidstr]:
                            fname = self.loaderdb[self.hwidstr][loader]
                            print(f"Possible loader available: {fname}")
                        for loader in self.loaderdb[self.hwidstr]:
                            fname = self.loaderdb[self.hwidstr][loader]
                            print(f"Trying loader: {fname}")
                            break
                    elif self.pkhash[0:16] in self.loaderdb[self.hwidstr]:
                        fname=self.loaderdb[self.hwidstr][self.pkhash[0:16]]
                        print(f"Detected loader: {fname}")
                else:
                    print("Couldn't find a loader for given hwid and pkhash :(")
                    exit(0)
                with open(fname,"rb") as rf:
                    self.programmer=rf.read()
            return True
        return False

    def cmd_done(self):
        self.cdc.write(struct.pack("<II", self.cmd.SAHARA_DONE_REQ, 0x8))
        cmd,pkt=self.get_rsp()
        time.sleep(0.3)
        if cmd["cmd"]==self.cmd.SAHARA_DONE_RSP:
            return True
        elif cmd["cmd"]==self.cmd.SAHARA_END_TRANSFER:
            if pkt["status"] == self.status.SAHARA_NAK_INVALID_CMD:
                print("Invalid Transfer command received.")
                return False
        return True

    def cmd_reset(self):
        self.cdc.write(struct.pack("<II", self.cmd.SAHARA_RESET_REQ, 0x8))
        cmd, pkt = self.get_rsp()
        if cmd["cmd"]==self.cmd.SAHARA_RESET_RSP:
            return True
        elif "status" in pkt:
            print(self.get_error_desc(pkt["status"]))
            return False
        return False

    def debug_mode(self):
        self.cmd_modeswitch(self.mode.SAHARA_MODE_COMMAND)
        if self.connect()==False:
            return False
        if self.cmd_hello(self.mode.SAHARA_MODE_MEMORY_DEBUG)==False:
            return False
        cmd, pkt = self.get_rsp()
        if (cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER):
            if pkt["status"]==self.status.SAHARA_NAK_MEMORY_DEBUG_NOT_SUPPORTED:
                print("Sorry, Memory Debug is not supported !")
                return False
            else:
                state=str(pkt["status"])
                print(f"Error occured on memory debug: {state}")
                return False
        elif (cmd["cmd"]==self.cmd.SAHARA_MEMORY_DEBUG or cmd["cmd"]==self.cmd.SAHARA_64BIT_MEMORY_DEBUG):
            return True
        elif "status" in pkt:
            print(self.get_error_desc(pkt["status"]))
            return False
        return False

    def upload_firehoseloader(self):
        self.cmd_modeswitch(self.mode.SAHARA_MODE_COMMAND)
        if self.connect()==False:
            return False
        if self.cmd_hello(self.mode.SAHARA_MODE_IMAGE_TX_PENDING)==False:
            return False

        try:
            datalen=len(self.programmer)
            done=False
            while (datalen>0 or done==True):
                cmd, pkt = self.get_rsp()
                if (cmd["cmd"] == self.cmd.SAHARA_64BIT_MEMORY_READ_DATA):
                    self.bit64=True
                elif (cmd["cmd"] == self.cmd.SAHARA_READ_DATA):
                    self.bit64=False
                elif (cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER):
                    if pkt["status"] == self.status.SAHARA_STATUS_SUCCESS:
                        self.cmd_done()
                        return True
                    else:
                        return False
                elif "status" in pkt:
                    print(self.get_error_desc(pkt["status"]))
                    return False
                else:
                    print("Unexpected error on uploading")
                    return False
                data_offset=pkt["data_offset"]
                data_len=pkt["data_len"]
                data_to_send=self.programmer[data_offset:data_offset+data_len]
                self.cdc.write(data_to_send,self.pktsize)
                datalen-=data_len

            cmd, pkt = self.get_rsp()
            if (cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER):
                if pkt["status"] == self.status.SAHARA_STATUS_SUCCESS:
                    self.cmd_done()
                    return True
            return False
        except:
            print("Unexpected error on uploading, maybe signature of loader wasn't accepted ?")
            return False


    def cmd_modeswitch(self,mode):
        data = struct.pack("<III", self.cmd.SAHARA_SWITCH_MODE, 0xC, mode)
        self.cdc.write(data)

    def cmd_exec(self,mcmd): #CMD 0xD, RSP 0xE, CMD2 0xF
        #Send request
        data=struct.pack("<III",self.cmd.SAHARA_EXECUTE_REQ,0xC,mcmd)
        self.cdc.write(data)
        #Get info about request
        cmd, pkt = self.get_rsp()
        if (cmd["cmd"]==self.cmd.SAHARA_EXECUTE_RSP):
            #Ack
            data = struct.pack("<III", self.cmd.SAHARA_EXECUTE_DATA, 0xC, mcmd)
            self.cdc.write(data)
            payload=self.cdc.read(pkt["data_len"])
            return payload
        elif "status" in pkt:
            print(self.get_error_desc(pkt["status"]))
            return None
        return None
