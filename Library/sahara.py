import binascii
import time
from Library.utils import *
logger = logging.getLogger(__name__)

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
      SAHARA_RESET_STATE_MACHINE_ID=0x13

    class exec_cmd:
      SAHARA_EXEC_CMD_NOP=0x00
      SAHARA_EXEC_CMD_SERIAL_NUM_READ=0x01
      SAHARA_EXEC_CMD_MSM_HW_ID_READ=0x02
      SAHARA_EXEC_CMD_OEM_PK_HASH_READ=0x03
      SAHARA_EXEC_CMD_SWITCH_TO_DMSS_DLOAD=0x04
      SAHARA_EXEC_CMD_SWITCH_TO_STREAM_DLOAD=0x05
      SAHARA_EXEC_CMD_READ_DEBUG_DATA=0x06
      SAHARA_EXEC_CMD_GET_SOFTWARE_VERSION_SBL=0x07

    class sahara_mode:
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
                found=False
                for ext in [".bin",".mbn",".elf"]:
                    if ext in filename[-4:]:
                        found=True
                        break
                if found==False:
                    continue  
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

    pkt_memory_debug=[
        ('memory_table_addr', 'I'),
        ('memory_table_length', 'I')
    ]

    pkt_memory_debug_64=[
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

    parttbl = [
        ('save_pref', 'I'),
        ('mem_base', 'I'),
        ('length', 'I'),
        ('desc', '20s'),
        ('filename', '20s')
    ]

    parttbl_64bit=[
        ('save_pref','Q'),
        ('mem_base','Q'),
        ('length','Q'),
        ('desc', '20s'),
        ('filename', '20s')
    ]

    def __init__(self,cdc):
        self.cdc = cdc
        self.init_loader_db()
        self.programmer=None
        self.mode=""
        self.serial=None

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
        elif (pkt["cmd"] == self.cmd.SAHARA_64BIT_MEMORY_DEBUG):
            self.bit64 = True
            data = read_object(v[0x8:0x8 + 0x2 * 0x8], self.pkt_memory_debug_64)
        elif (pkt["cmd"] == self.cmd.SAHARA_MEMORY_DEBUG):
            self.bit64 = False
            data = read_object(v[0x8:0x8 + 0x2 * 0x4], self.pkt_memory_debug)
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
                return ["firehose",None]
            elif v[0]==0x01:
                cmd = read_object(v[0:0x2 * 0x4], self.pkt_cmd_hdr)
                if cmd['cmd'] == self.cmd.SAHARA_HELLO_REQ:
                    data = read_object(v[0x0:0xC * 0x4], self.pkt_hello_req)
                    self.pktsize = data['max_cmd_len']
                    self.version_min = data['version_min']
                    return ["sahara", data]
            elif v[0] == 0x04:
                    return ["sahara", v]
        except:
            try:
                    data = b"<?xml version=\"1.0\" ?><data><nop /></data>"
                    val = self.cdc.write(data, 4096)
                    res = self.cdc.read()
                    if (b"<?xml" in res):
                        return ["firehose", None]
            except:
                self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_COMMAND)
                data = b"<?xml version=\"1.0\" ?><data><nop /></data>"
                val = self.cdc.write(data, 4096)
                res = self.cdc.read()
                if (b"<?xml" in res):
                    return ["firehose", None]
                else:
                    return ["",None]
        self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_MEMORY_DEBUG)
        cmd, pkt = self.get_rsp()
        return ["sahara",pkt]

    def enter_command_mode(self):
        if self.cmd_hello(self.sahara_mode.SAHARA_MODE_COMMAND)==False:
            return False
        cmd, pkt = self.get_rsp()
        if (cmd["cmd"] == self.cmd.SAHARA_CMD_READY):
            return True
        elif "status" in pkt:
            logger.error(self.get_error_desc(pkt["status"]))
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
            self.serial = self.cmdexec_get_serial_num()
            self.serials= "{:08x}".format(self.serial)
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

            logger.info(f"\n------------------------\n" +
                  f"HWID:              0x{self.hwidstr} (MSM_ID:0x{self.msm_str},OEM_ID:0x{self.oem_str},MODEL_ID:0x{self.model_id})\n" +
                  f"PK_HASH:           0x{self.pkhash}\n" +
                  f"Serial:            0x{self.serials}\n" +
                  f"SBL Version:       0x{self.sblversion}\n")
            if self.programmer==None:
                if self.hwidstr in self.loaderdb:
                    mt=self.loaderdb[self.hwidstr]
                    if self.pkhash[0:16]=="cc3153a80293939b":
                        logger.info("Unfused device detected, so any loader should be fine...")
                        if self.pkhash[0:16] in mt:
                            fname=mt[self.pkhash[0:16]]
                            logger.info(f"Trying loader: {fname}")
                        else:
                            for loader in mt:
                                fname = mt[loader]
                                logger.info(f"Possible loader available: {fname}")
                            for loader in mt:
                                fname = mt[loader]
                                logger.info(f"Trying loader: {fname}")
                                break
                    elif self.pkhash[0:16] in mt:
                        fname=self.loaderdb[self.hwidstr][self.pkhash[0:16]]
                        logger.info(f"Detected loader: {fname}")
                    else:
                        for loader in self.loaderdb[self.hwidstr]:
                            fname = self.loaderdb[self.hwidstr][loader]
                            logger.info(f"Trying loader: {fname}")
                            break
                        #print("Couldn't find a loader for given hwid and pkhash :(")
                        #exit(0)
                else:
                    logger.error("Couldn't find a loader for given hwid and pkhash :(")
                    exit(0)
                with open(fname,"rb") as rf:
                    self.programmer=rf.read()
            self.cmd_modeswitch(self.sahara_mode.SAHARA_MODE_COMMAND)
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
                logger.error("Invalid Transfer command received.")
                return False
        return True

    def cmd_reset(self):
        self.cdc.write(struct.pack("<II", self.cmd.SAHARA_RESET_REQ, 0x8))
        cmd, pkt = self.get_rsp()
        if cmd["cmd"]==self.cmd.SAHARA_RESET_RSP:
            return True
        elif "status" in pkt:
            logger.error(self.get_error_desc(pkt["status"]))
            return False
        return False

    def read_memory(self,addr,bytestoread,Display=False, wf=None):
        data = b""
        old = 0
        pos = 0
        total = bytestoread
        if Display:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        while (bytestoread>0):
            if bytestoread>0x080000:
                length=0x080000
            else:
                length=bytestoread
            bytesread = 0
            try:
                self.cdc.read(1,1)
            except:
                pass
            if self.bit64:
                if self.cdc.write(struct.pack("<IIQQ", self.cmd.SAHARA_64BIT_MEMORY_READ, 0x8+8+8, addr+pos,length))==False:
                    return None
            else:
                if self.cdc.write(struct.pack("<IIII", self.cmd.SAHARA_MEMORY_READ, 0x8+4+4, addr+pos, length))==False:
                    return None
            while (length>0):
                try:
                    tmp=self.cdc.read(length)
                except:
                    return None
                length-=len(tmp)
                pos+=len(tmp)
                bytesread+=len(tmp)
                if wf!=None:
                    wf.write(tmp)
                else:
                    data+=tmp
                if Display:
                    prog = int(float(pos) / float(total) * float(100))
                    if (prog > old):
                        if Display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                            old=prog
            bytestoread-=bytesread
            if Display:
                print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        '''
        try:
            self.cdc.read(0)
        except:
            return data
        '''
        return data


    def debug_mode(self):
        if self.cmd_hello(self.sahara_mode.SAHARA_MODE_MEMORY_DEBUG)==False:
            return False
        if os.path.exists("memory"):
            rmrf("memory")
        os.mkdir("memory")
        cmd, pkt = self.get_rsp()
        if (cmd["cmd"]==self.cmd.SAHARA_MEMORY_DEBUG or cmd["cmd"]==self.cmd.SAHARA_64BIT_MEMORY_DEBUG):
            memory_table_addr=pkt["memory_table_addr"]
            memory_table_length=pkt["memory_table_length"]
            if self.bit64:
                pktsize=8+8+8+20+20
                if memory_table_length%pktsize==0:
                    if memory_table_length!=0:
                        print(f"Reading 64-Bit partition from {hex(memory_table_addr)} with length of {hex(memory_table_length)}")
                        ptbldata=self.read_memory(memory_table_addr,memory_table_length)
                        num_entries=len(ptbldata)//pktsize
                        partition=[]
                        for id in range(0,num_entries):
                            pd=read_object(ptbldata[id*pktsize:(id*pktsize)+pktsize],self.parttbl_64bit)
                            desc=pd["desc"].replace(b"\x00",b"").decode('utf-8')
                            filename=pd["filename"].replace(b"\x00",b"").decode('utf-8')
                            mem_base=pd["mem_base"]
                            save_pref=pd["save_pref"]
                            length=pd["length"]
                            partition.append(dict(desc=desc,filename=filename,mem_base=mem_base,length=length,save_pref=save_pref))
                            print(f"{filename}({desc}): Offset {hex(mem_base)}, Length {hex(length)}, SavePref {hex(save_pref)}")


                        for part in partition:
                            filename=part["filename"]
                            desc=part["desc"]
                            mem_base=part["mem_base"]
                            length=part["length"]
                            print(f"Dumping {filename}({desc}) at {hex(mem_base)}, length {hex(length)}")
                            fname=os.path.join("memory",filename)
                            with open(fname,"wb") as wf:
                                self.read_memory(mem_base,length,True,wf)
                            self.cmd_reset()
                        print("Done dumping memory")
                        return True

                    return True
            else:
                pktsize=(4+4+4+20+20)
                if memory_table_length%pktsize==0:
                    if memory_table_length!=0:
                        print(f"Reading 32-Bit partition from {hex(memory_table_addr)} with length of {hex(memory_table_length)}")
                        ptbldata=self.read_memory(memory_table_addr, memory_table_length)
                        num_entries=len(ptbldata)//pktsize
                        partition = []
                        for id in range(0,num_entries):
                            pd=read_object(ptbldata[id * pktsize:(id * pktsize) + pktsize], self.parttbl)
                            desc=pd["desc"].replace(b"\x00",b"").decode('utf-8')
                            filename=pd["filename"].replace(b"\x00",b"").decode('utf-8')
                            mem_base=pd["mem_base"]
                            save_pref=pd["save_pref"]
                            length=pd["length"]
                            partition.append(dict(desc=desc,filename=filename,mem_base=mem_base,length=length,save_pref=save_pref))
                            print(f"{filename}({desc}): Offset {hex(mem_base)}, Length {hex(length)}, SavePref {hex(save_pref)}")

                        for part in partition:
                            filename=part["filename"]
                            desc=part["desc"]
                            mem_base=part["mem_base"]
                            length=part["length"]
                            print(f"Dumping {filename}({desc}) at {hex(mem_base)}, length {hex(length)}")
                            fname=os.path.join("memory",filename)
                            with open(fname,"wb") as wf:
                                ret=self.read_memory(mem_base,length,True,wf)
                        print("Done dumping memory")
                        self.cmd_reset()
                        return True
                    return True
        elif "status" in pkt:
            logger.error(self.get_error_desc(pkt["status"]))
            return False
        return False

    def upload_loader(self):
        if self.cmd_hello(self.sahara_mode.SAHARA_MODE_IMAGE_TX_PENDING)==False:
            return ""

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
                        return self.mode
                    else:
                        return ""
                elif "status" in pkt:
                    logger.error(self.get_error_desc(pkt["status"]))
                    return ""
                else:
                    logger.error("Unexpected error on uploading")
                    return ""
                self.id = pkt["id"]
                if self.id==0x7:
                    self.mode="nandprg"
                elif self.id==0xB:
                    self.mode="enandprg"
                elif self.id>=0xC:
                    self.mode="firehose"
                data_offset=pkt["data_offset"]
                data_len=pkt["data_len"]
                data_to_send=self.programmer[data_offset:data_offset+data_len]
                self.cdc.write(data_to_send,self.pktsize)
                datalen-=data_len
            print("Ended")
            cmd, pkt = self.get_rsp()
            if (cmd["cmd"] == self.cmd.SAHARA_END_TRANSFER):
                if pkt["status"] == self.status.SAHARA_STATUS_SUCCESS:
                    self.cmd_done()
                    return self.mode
            return ""
        except:
            logger.error("Unexpected error on uploading, maybe signature of loader wasn't accepted ?")
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
            logger.error(self.get_error_desc(pkt["status"]))
            return None
        return [cmd, pkt]
