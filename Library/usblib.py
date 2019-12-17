import usb.core                 # pyusb
import usb.util
import struct
from enum import Enum
from binascii import hexlify,unhexlify
import usb.core                 # pyusb
import usb.util
import time
import inspect
import platform
import logging
logger = logging.getLogger(__name__)

USB_DIR_OUT=0		# to device
USB_DIR_IN=0x80		# to host

# USB types, the second of three bRequestType fields
USB_TYPE_MASK=(0x03 << 5)
USB_TYPE_STANDARD=(0x00 << 5)
USB_TYPE_CLASS=(0x01 << 5)
USB_TYPE_VENDOR=(0x02 << 5)
USB_TYPE_RESERVED=(0x03 << 5)

# USB recipients, the third of three bRequestType fields
USB_RECIP_MASK=0x1f
USB_RECIP_DEVICE=0x00
USB_RECIP_INTERFACE=0x01
USB_RECIP_ENDPOINT=0x02
USB_RECIP_OTHER=0x03
#From Wireless USB 1.0
USB_RECIP_PORT=	0x04
USB_RECIP_RPIPE=0x05

tag=0

class usb_class():

    def __init__(self,vid=0x05c6, pid=0x9008, interface=-1, devclass=-1, verbose=10):
        self.vid=vid
        self.pid=pid
        self.interface=interface
        logger.setLevel(verbose)
        if verbose==logging.DEBUG:
            fh = logging.FileHandler('log.txt')
            fh.setLevel(logging.DEBUG)
            logger.addHandler(fh)
            # ch = logging.StreamHandler()
            # ch.setLevel(logging.ERROR)
        self.connected=False
        self.devclass=devclass
        self.timeout=None

    def getInterfaceCount(self):
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.device is None:
            logger.debug("Couldn't detect the device. Is it connected ?")
            return False
        try:
            self.device.set_configuration()
        except:
            pass
        self.configuration = self.device.get_active_configuration()
        logger.debug(2, self.configuration)
        return self.configuration.bNumInterfaces

    def connect(self, EP_IN=-1, EP_OUT=-1):
        if self.connected==True:
            self.close()
            self.connected=False
        self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.device is None:
            logger.debug("Couldn't detect the device. Is it connected ?")
            return False
        try:
            self.device.set_configuration()
        except:
            pass
        self.configuration = self.device.get_active_configuration()
        if self.interface==-1:
            for interfacenum in range(0,self.configuration.bNumInterfaces):
                itf = usb.util.find_descriptor(self.configuration,bInterfaceNumber=interfacenum)
                if self.devclass!=-1:
                    if itf.bInterfaceClass==self.devclass: #MassStorage
                        self.interface=interfacenum
                        break
                else:
                    self.interface=interfacenum
                    break

        logger.debug(self.configuration)
        if self.interface>self.configuration.bNumInterfaces:
            print("Invalid interface, max number is %d" % self.configuration.bNumInterfaces)
            return False
        if self.interface!=-1:
            itf = usb.util.find_descriptor(self.configuration, bInterfaceNumber=self.interface)
            try:
                if self.device.is_kernel_driver_active(self.interface):
                    logger.debug("Detaching kernel driver")
                    self.device.detach_kernel_driver(self.interface)
            except:
                logger.debug("No kernel driver supported.")

            usb.util.claim_interface(self.device, self.interface)
            if EP_OUT==-1:
                self.EP_OUT = usb.util.find_descriptor(itf,
                                                   # match the first OUT endpoint
                                                   custom_match= \
                                                       lambda e: \
                                                           usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                           usb.util.ENDPOINT_OUT)
            else:
                self.EP_OUT=EP_OUT
            if EP_IN==-1:
                self.EP_IN = usb.util.find_descriptor(itf,
                                                  # match the first OUT endpoint
                                                  custom_match= \
                                                      lambda e: \
                                                          usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                          usb.util.ENDPOINT_IN)
            else:
                self.EP_IN=EP_IN

            self.connected=True
            return True
        else:
            print("Couldn't find MassStorage interface. Aborting.")
            self.connected=False
            return False

    def close(self):
        if (self.connected==True):
            usb.util.dispose_resources(self.device)
            try:
                if self.device.is_kernel_driver_active(self.interface):
                        self.device.attach_kernel_driver(self.interface)
            except:
                pass

    def write(self,command,pktsize=64):
        pos=0
        if command==b'':
            self.device.write(self.EP_OUT, b'')
        else:
            i=0
            while pos<len(command):
                try:
                    self.device.write(self.EP_OUT,command[pos:pos+pktsize])
                    pos += pktsize
                except:
                    #print("Error while writing")
                    time.sleep(0.05)
                    i+=1
                    if i==5:
                        return False
                    pass
        try:
            logger.debug("TX: "+command.decode('utf-8'))
        except:
            logger.debug("TX: "+hexlify(command).decode('utf-8'))
        return True

    def read(self,length=0x80000, timeout=None):
        tmp=b''
        logger.debug(inspect.currentframe().f_back.f_code.co_name+":"+hex(length))
        if timeout==None:
            timeout=self.timeout
        while (bytearray(tmp) == b''):
                try:
                    tmp=self.device.read(self.EP_IN, length,timeout)
                except usb.core.USBError as e:
                    if "timed out" in e.strerror:
                        #if platform.system()=='Windows':
                            #time.sleep(0.05)
                        #print("Waiting...")
                        logger.debug("Timed out")
                        logger.debug(tmp)
                        return bytearray(tmp)
                    elif e.errno != None:
                        print(repr(e), type(e), e.errno)
                        raise(e)
                    else:
                        break
        try:
            logger.debug("RX: "+tmp.decode('utf-8'))
        except:
            logger.debug("RX: "+hexlify(tmp).decode('utf-8'))
        return bytearray(tmp)

    def ctrl_transfer(self,bmRequestType,bRequest,wValue,wIndex,data_or_wLength):
        ret=self.device.ctrl_transfer(bmRequestType=bmRequestType,bRequest=bRequest,wValue=wValue,wIndex=wIndex,data_or_wLength=data_or_wLength)
        return ret[0] | (ret[1] << 8)


class scsi_cmds(Enum):
    SC_TEST_UNIT_READY=0x00,
    SC_REQUEST_SENSE=0x03,
    SC_FORMAT_UNIT=0x04,
    SC_READ_6=0x08,
    SC_WRITE_6=0x0a,
    SC_INQUIRY=0x12,
    SC_MODE_SELECT_6=0x15,
    SC_RESERVE=0x16,
    SC_RELEASE=0x17,
    SC_MODE_SENSE_6=0x1a,
    SC_START_STOP_UNIT=0x1b,
    SC_SEND_DIAGNOSTIC=0x1d,
    SC_PREVENT_ALLOW_MEDIUM_REMOVAL=0x1e,
    SC_READ_FORMAT_CAPACITIES=0x23,
    SC_READ_CAPACITY=0x25,
    SC_WRITE_10=0x2a,
    SC_VERIFY=0x2f,
    SC_READ_10=0x28,
    SC_SYNCHRONIZE_CACHE=0x35,
    SC_READ_TOC=0x43,
    SC_READ_HEADER=0x44,
    SC_MODE_SELECT_10=0x55,
    SC_MODE_SENSE_10=0x5a,
    SC_READ_12=0xa8,
    SC_WRITE_12=0xaa,
    SC_PASCAL_MODE=0xff

command_block_wrapper=[
        ('dCBWSignature', '4s'),
        ('dCBWTag', 'I'),
        ('dCBWDataTransferLength', 'I'),
        ('bmCBWFlags', 'B'),
        ('bCBWLUN', 'B'),
        ('bCBWCBLength', 'B'),
        ('CBWCB', '16s'),
]
command_block_wrapper_len=31

command_status_wrapper=[
        ('dCSWSignature', '4s'),
        ('dCSWTag', 'I'),
        ('dCSWDataResidue', 'I'),
        ('bCSWStatus', 'B')
]
command_status_wrapper_len=13

def write_object(definition,*args):
    '''
    Unpacks a structure using the given data and definition.
    '''
    obj = {}
    object_size = 0
    data=b""
    i=0
    for (name, stype) in definition:
        object_size += struct.calcsize(stype)
        arg=args[i]
        try:
            data += struct.pack(stype, arg)
        except Exception as e:
            print("Error:"+str(e))
            break
        i+=1
    obj['object_size'] = len(data)
    obj['raw_data'] = data
    return obj

class scsi():
    '''
    FIHTDC, PCtool
    '''
    SC_READ_NV=0xf0
    SC_SWITCH_STATUS=0xf1
    SC_SWITCH_PORT=0xf2
    SC_MODEM_STATUS=0xf4
    SC_SHOW_PORT=0xf5
    SC_MODEM_DISCONNECT=0xf6
    SC_MODEM_CONNECT=0xf7
    SC_DIAG_RUT=0xf8
    SC_READ_BATTERY=0xf9
    SC_READ_IMAGE=0xfa
    SC_ENABLE_ALL_PORT=0xfd
    SC_MASS_STORGE=0xfe
    SC_ENTER_DOWNLOADMODE=0xff
    SC_ENTER_FTMMODE=0xe0
    SC_SWITCH_ROOT=0xe1
    '''
    //Div2-5-3-Peripheral-LL-ADB_ROOT-00+/* } FIHTDC, PCtool */
    //StevenCPHuang 2011/08/12 porting base on 1050 --
    //StevenCPHuang_20110820,add Moto's mode switch cmd to support PID switch function ++
    '''
    SC_MODE_SWITCH=0xD6
    #/StevenCPHuang_20110820,add Moto's mode switch cmd to support PID switch function --

    def __init__(self,vid,pid,interface=-1):
        self.vid=vid
        self.pid=pid
        self.interface=interface
        self.Debug=False
        self.usb=None

    def connect(self):
        self.usb = usb_class(vid=self.vid, pid=self.pid, interface=self.interface, devclass=8)
        if self.usb.connect():
            return True
        return False

    #htcadb = "55534243123456780002000080000616687463800100000000000000000000"; // Len 0x6, Command 0x16, "HTC" 01 = Enable, 02 = Disable
    def send_mass_storage_command(self,lun, cdb, direction, data_length):
        global tag
        cmd=cdb[0]
        if cmd>=0 and cmd<0x20:
            cdb_len=6
        elif cmd>=0x20 and cmd<0x60:
            cdb_len=10
        elif cmd>=0x60 and cmd<0x80:
            cdb_len=0
        elif cmd>=0x80 and cmd<0xA0:
            cdb_len=16
        elif cmd>=0xA0 and cmd<0xC0:
            cdb_len=12
        else:
            cdb_len=6

        if len(cdb)!=cdb_len:
            print("Error, cdb length doesn't fit allowed cbw packet length")
            return 0

        if (cdb_len==0) or (cdb_len > command_block_wrapper_len):
            print("Error, invalid data packet length, should be max of 31 bytes.")
            return 0
        else:
            data=write_object(command_block_wrapper,b"USBC",tag, data_length, direction, lun, cdb_len,cdb)['raw_data']
            print(hexlify(data))
            if len(data)!=31:
                print("Error, invalid data packet length, should be 31 bytes, but length is %d" % len(data))
                return 0
            tag+=1
            self.usb.write(data,31)
        return tag

    def send_htc_adbenable(self):
        #do_reserve from f_mass_storage.c
        print("Sending HTC adb enable command")
        common_cmnd=b"\x16htc\x80\x01" #reserve_cmd + 'htc' + len + flag
        '''
        Flag values:
            1: Enable adb daemon from mass_storage
            2: Disable adb daemon from mass_storage
            3: cancel unmount BAP cdrom
            4: cancel unmount HSM rom
        '''
        lun=0
        datasize=common_cmnd[4]
        timeout=5000
        ret_tag=self.send_mass_storage_command(lun,common_cmnd,USB_DIR_IN,datasize)
        ret_tag+=self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, datasize)
        if datasize>0:
            data=self.usb.read(datasize,timeout)
            print("DATA: "+hexlify(data))
        print("Sent HTC adb enable command")

    def send_htc_ums_adbenable(self):#HTC10
        #ums_ctrlrequest from f_mass_storage.c
        print("Sending HTC ums adb enable command")
        bRequestType=USB_DIR_IN|USB_TYPE_VENDOR|USB_RECIP_DEVICE
        bRequest=0xa0
        wValue=1
        '''
        wValue:
            0: Disable adb daemon
            1: Enable adb daemon
        '''
        wIndex=0
        w_length=1
        ret=self.usb.ctrl_transfer(bRequestType,bRequest,wValue,wIndex,w_length)
        print("Sent HTC ums adb enable command: %x" % ret)

    def send_zte_adbenable(self): #zte blade
        common_cmnd=b"\x86zte\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" #reserve_cmd + 'zte' + len + flag
        common_cmnd2=b"\x86zte\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # reserve_cmd + 'zte' + len + flag
        '''
        Flag values:
            0: disable adbd ---for 736T
            1: enable adbd ---for 736T
            2: disable adbd ---for All except 736T
            3: enable adbd ---for All except 736T
        '''
        lun=0
        datasize=common_cmnd[4]
        timeout=5000
        ret_tag=self.send_mass_storage_command(lun,common_cmnd,USB_DIR_IN,datasize)
        ret_tag+=self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, datasize)
        ret_tag=self.send_mass_storage_command(lun, common_cmnd2, USB_DIR_IN, datasize)
        ret_tag+=self.send_mass_storage_command(lun, common_cmnd2, USB_DIR_IN, datasize)
        if datasize>0:
            data=self.usb.read(datasize,timeout)
            print("DATA: "+hexlify(data))
        print("Send HTC adb enable command")

    def send_fih_adbenable(self): #motorola xt560, nokia 3.1, #f_mass_storage.c
        if self.usb.connect():
            print("Sending FIH adb enable command")
            datasize=0x24
            common_cmnd=bytes([self.SC_SWITCH_PORT])+b"FI1"+struct.pack("<H",datasize) #reserve_cmd + 'FI' + flag + len + none
            '''
            Flag values:
                common_cmnd[3]->1: Enable adb daemon from mass_storage
                common_cmnd[3]->0: Disable adb daemon from mass_storage
            '''
            lun=0
            #datasize=common_cmnd[4]
            timeout=5000
            ret_tag=self.send_mass_storage_command(lun,common_cmnd,USB_DIR_IN,0x600)
            #ret_tag+=self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            if datasize>0:
                data=self.usb.read(datasize,timeout)
                print("DATA: "+str(hexlify(data)))
            print("Sent FIH adb enable command")
            self.usb.close()


    def send_fih_root(self):  # motorola xt560, nokia 3.1, huawei u8850, huawei Ideos X6, lenovo s2109, triumph M410, viewpad 7, #f_mass_storage.c
        if self.usb.connect():
            print("Sending FIH root command")
            datasize=0x24
            common_cmnd = bytes([self.SC_SWITCH_ROOT]) + b"FIH"+struct.pack("<H",datasize)  # reserve_cmd + 'FIH' + len + flag + none
            lun = 0
            #datasize = common_cmnd[4]
            timeout = 5000
            ret_tag = self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            ret_tag += self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            if datasize > 0:
                data = self.usb.read(datasize, timeout)
                print("DATA: " + str(hexlify(data)))
            print("Sent FIH root command")
            self.usb.close()

    def close(self):
        self.usb.close()
