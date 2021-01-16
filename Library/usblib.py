import usb.core  # pyusb
import usb.util
from enum import Enum
import usb.core  # pyusb
import usb.util
import time
import inspect
from Library.utils import *

USB_DIR_OUT = 0  # to device
USB_DIR_IN = 0x80  # to host

# USB types, the second of three bRequestType fields
USB_TYPE_MASK = (0x03 << 5)
USB_TYPE_STANDARD = (0x00 << 5)
USB_TYPE_CLASS = (0x01 << 5)
USB_TYPE_VENDOR = (0x02 << 5)
USB_TYPE_RESERVED = (0x03 << 5)

# USB recipients, the third of three bRequestType fields
USB_RECIP_MASK = 0x1f
USB_RECIP_DEVICE = 0x00
USB_RECIP_INTERFACE = 0x01
USB_RECIP_ENDPOINT = 0x02
USB_RECIP_OTHER = 0x03
# From Wireless USB 1.0
USB_RECIP_PORT = 0x04
USB_RECIP_RPIPE = 0x05

tag = 0

CDC_CMDS = {
    "SEND_ENCAPSULATED_COMMAND": 0x00,
    "GET_ENCAPSULATED_RESPONSE": 0x01,
    "SET_COMM_FEATURE": 0x02,
    "GET_COMM_FEATURE": 0x03,
    "CLEAR_COMM_FEATURE": 0x04,
    "SET_LINE_CODING": 0x20,
    "GET_LINE_CODING": 0x21,
    "SET_CONTROL_LINE_STATE": 0x22,
    "SEND_BREAK": 0x23,  # wValue is break time
}


class usb_class(metaclass=LogBase):

    def __init__(self, loglevel=logging.INFO, portconfig=None, devclass=-1):
        self.portconfig = portconfig
        self.connected = False
        self.devclass = devclass
        self.timeout = None
        self.vid = None
        self.pid = None
        self.__logger.setLevel(loglevel)
        if loglevel==logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def verify_data(self, data, pre="RX:"):
        self.__logger.debug("",stack_info=True)
        if isinstance(data, bytes) or isinstance(data, bytearray):
            if data[:5] == b"<?xml":
                try:
                    rdata = b""
                    for line in data.split(b"\n"):
                        try:
                            self.__logger.debug(pre + line.decode('utf-8'))
                            rdata += line + b"\n"
                        except:
                            v = hexlify(line)
                            self.__logger.debug(pre + v.decode('utf-8'))
                    return rdata
                except:
                    pass
            if logging.DEBUG >= self.__logger.level:
                self.__logger.debug(pre + hexlify(data).decode('utf-8'))
        else:
            if logging.DEBUG >= self.__logger.level:
                self.__logger.debug(pre + data)
        return data

    def getInterfaceCount(self):
        if self.vid is not None:
            self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid)
            if self.device is None:
                self.__logger.debug("Couldn't detect the device. Is it connected ?")
                return False
            try:
                self.device.set_configuration()
            except:
                pass
            self.configuration = self.device.get_active_configuration()
            self.__logger.debug(2, self.configuration)
            return self.configuration.bNumInterfaces
        else:
            self.__logger.error("No device detected. Is it connected ?")
        return 0

    def setLineCoding(self, baudrate=None, parity=None, databits=None, stopbits=None):
        sbits = {1: 0, 1.5: 1, 2: 2}
        dbits = {5, 6, 7, 8, 16}
        pmodes = {0, 1, 2, 3, 4}
        brates = {300, 600, 1200, 2400, 4800, 9600, 14400,
                  19200, 28800, 38400, 57600, 115200, 230400}

        if stopbits is not None:
            if stopbits not in sbits.keys():
                valid = ", ".join(str(k) for k in sorted(sbits.keys()))
                raise ValueError("Valid stopbits are " + valid)
            self.stopbits = stopbits
        else:
            self.stopbits = 0

        if databits is not None:
            if databits not in dbits:
                valid = ", ".join(str(d) for d in sorted(dbits))
                raise ValueError("Valid databits are " + valid)
            self.databits = databits
        else:
            self.databits = 0

        if parity is not None:
            if parity not in pmodes:
                valid = ", ".join(str(pm) for pm in sorted(pmodes))
                raise ValueError("Valid parity modes are " + valid)
            self.parity = parity
        else:
            self.parity = 0

        if baudrate is not None:
            if baudrate not in brates:
                brs = sorted(brates)
                dif = [abs(br - baudrate) for br in brs]
                best = brs[dif.index(min(dif))]
                raise ValueError(
                    "Invalid baudrates, nearest valid is {}".format(best))
            self.baudrate = baudrate

        linecode = [
            self.baudrate & 0xff,
            (self.baudrate >> 8) & 0xff,
            (self.baudrate >> 16) & 0xff,
            (self.baudrate >> 24) & 0xff,
            sbits[self.stopbits],
            self.parity,
            self.databits]

        txdir = 0  # 0:OUT, 1:IN
        req_type = 1  # 0:std, 1:class, 2:vendor
        recipient = 1  # 0:device, 1:interface, 2:endpoint, 3:other
        req_type = (txdir << 7) + (req_type << 5) + recipient
        data = bytearray(linecode)
        wlen = self.device.ctrl_transfer(
            req_type, CDC_CMDS["SET_LINE_CODING"],
            data_or_wLength=data, wIndex=1)
        self.__logger.debug("Linecoding set, {}b sent".format(wlen))

    def connect(self, EP_IN=-1, EP_OUT=-1):
        if self.connected:
            self.close()
            self.connected = False
        for usbid in self.portconfig:
            vid = usbid[0]
            pid = usbid[1]
            interface = usbid[2]
            self.device = usb.core.find(idVendor=vid, idProduct=pid)
            if self.device is not None:
                self.vid = vid
                self.pid = pid
                self.interface = interface
                break

        if self.device is None:
            self.__logger.debug("Couldn't detect the device. Is it connected ?")
            return False
        # try:
        #    self.device.set_configuration()
        # except:
        #    pass
        self.configuration = self.device.get_active_configuration()
        if self.interface == -1:
            for interfacenum in range(0, self.configuration.bNumInterfaces):
                itf = usb.util.find_descriptor(self.configuration, bInterfaceNumber=interfacenum)
                if self.devclass != -1:
                    if itf.bInterfaceClass == self.devclass:  # MassStorage
                        self.interface = interfacenum
                        break
                else:
                    self.interface = interfacenum
                    break

        self.__logger.debug(self.configuration)
        if self.interface > self.configuration.bNumInterfaces:
            print("Invalid interface, max number is %d" % self.configuration.bNumInterfaces)
            return False
        if self.interface != -1:
            itf = usb.util.find_descriptor(self.configuration, bInterfaceNumber=self.interface)
            try:
                if self.device.is_kernel_driver_active(self.interface):
                    self.__logger.debug("Detaching kernel driver")
                    self.device.detach_kernel_driver(self.interface)
            except:
                self.__logger.debug("No kernel driver supported.")

            usb.util.claim_interface(self.device, self.interface)
            if EP_OUT == -1:
                self.EP_OUT = usb.util.find_descriptor(itf,
                                                       # match the first OUT endpoint
                                                       custom_match= \
                                                           lambda e: \
                                                               usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                               usb.util.ENDPOINT_OUT)
            else:
                self.EP_OUT = EP_OUT
            if EP_IN == -1:
                self.EP_IN = usb.util.find_descriptor(itf,
                                                      # match the first OUT endpoint
                                                      custom_match= \
                                                          lambda e: \
                                                              usb.util.endpoint_direction(e.bEndpointAddress) == \
                                                              usb.util.ENDPOINT_IN)
            else:
                self.EP_IN = EP_IN

            self.connected = True
            return True
        else:
            print("Couldn't find MassStorage interface. Aborting.")
            self.connected = False
            return False

    def close(self,reset=False):
        if self.connected:
            usb.util.dispose_resources(self.device)
            try:
                if not self.device.is_kernel_driver_active(self.interface):
                    self.device.attach_kernel_driver(self.interface)
                if reset:
                    self.device.reset()
            except:
                pass

    def write(self, command, pktsize=64):
        if isinstance(command, str):
            command = bytes(command, 'utf-8')
        pos = 0
        if command == b'':
            self.device.write(self.EP_OUT, b'')
        else:
            i = 0
            while pos < len(command):
                try:
                    self.device.write(self.EP_OUT, command[pos:pos + pktsize])
                    pos += pktsize
                except:
                    # print("Error while writing")
                    time.sleep(0.05)
                    i += 1
                    if i == 5:
                        return False
                    pass
        self.verify_data(bytearray(command), "TX:")
        return True

    def read(self, length=0x80, timeout=None):
        tmp = b''
        self.__logger.debug(inspect.currentframe().f_back.f_code.co_name + ":" + hex(length))
        if timeout is None:
            timeout = self.timeout
        while bytearray(tmp) == b'':
            try:
                tmp = self.device.read(self.EP_IN, length, timeout)
            except usb.core.USBError as e:
                error = str(e.strerror)
                if "timed out" in error:
                    # if platform.system()=='Windows':
                    # time.sleep(0.05)
                    # print("Waiting...")
                    self.__logger.debug("Timed out")
                    self.__logger.debug(tmp)
                    return bytearray(tmp)
                elif e.errno is not None:
                    print(repr(e), type(e), e.errno)
                    sys.exit(0)
                else:
                    break
        self.verify_data(bytearray(tmp), "RX:")
        return bytearray(tmp)

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data_or_wLength):
        ret = self.device.ctrl_transfer(bmRequestType=bmRequestType, bRequest=bRequest, wValue=wValue, wIndex=wIndex,
                                        data_or_wLength=data_or_wLength)
        return ret[0] | (ret[1] << 8)


class scsi_cmds(Enum):
    SC_TEST_UNIT_READY = 0x00,
    SC_REQUEST_SENSE = 0x03,
    SC_FORMAT_UNIT = 0x04,
    SC_READ_6 = 0x08,
    SC_WRITE_6 = 0x0a,
    SC_INQUIRY = 0x12,
    SC_MODE_SELECT_6 = 0x15,
    SC_RESERVE = 0x16,
    SC_RELEASE = 0x17,
    SC_MODE_SENSE_6 = 0x1a,
    SC_START_STOP_UNIT = 0x1b,
    SC_SEND_DIAGNOSTIC = 0x1d,
    SC_PREVENT_ALLOW_MEDIUM_REMOVAL = 0x1e,
    SC_READ_FORMAT_CAPACITIES = 0x23,
    SC_READ_CAPACITY = 0x25,
    SC_WRITE_10 = 0x2a,
    SC_VERIFY = 0x2f,
    SC_READ_10 = 0x28,
    SC_SYNCHRONIZE_CACHE = 0x35,
    SC_READ_TOC = 0x43,
    SC_READ_HEADER = 0x44,
    SC_MODE_SELECT_10 = 0x55,
    SC_MODE_SENSE_10 = 0x5a,
    SC_READ_12 = 0xa8,
    SC_WRITE_12 = 0xaa,
    SC_PASCAL_MODE = 0xff


command_block_wrapper = [
    ('dCBWSignature', '4s'),
    ('dCBWTag', 'I'),
    ('dCBWDataTransferLength', 'I'),
    ('bmCBWFlags', 'B'),
    ('bCBWLUN', 'B'),
    ('bCBWCBLength', 'B'),
    ('CBWCB', '16s'),
]
command_block_wrapper_len = 31

command_status_wrapper = [
    ('dCSWSignature', '4s'),
    ('dCSWTag', 'I'),
    ('dCSWDataResidue', 'I'),
    ('bCSWStatus', 'B')
]
command_status_wrapper_len = 13

class scsi:
    """
    FIHTDC, PCtool
    """
    SC_READ_NV = 0xf0
    SC_SWITCH_STATUS = 0xf1
    SC_SWITCH_PORT = 0xf2
    SC_MODEM_STATUS = 0xf4
    SC_SHOW_PORT = 0xf5
    SC_MODEM_DISCONNECT = 0xf6
    SC_MODEM_CONNECT = 0xf7
    SC_DIAG_RUT = 0xf8
    SC_READ_BATTERY = 0xf9
    SC_READ_IMAGE = 0xfa
    SC_ENABLE_ALL_PORT = 0xfd
    SC_MASS_STORGE = 0xfe
    SC_ENTER_DOWNLOADMODE = 0xff
    SC_ENTER_FTMMODE = 0xe0
    SC_SWITCH_ROOT = 0xe1
    """
    //Div2-5-3-Peripheral-LL-ADB_ROOT-00+/* } FIHTDC, PCtool */
    //StevenCPHuang 2011/08/12 porting base on 1050 --
    //StevenCPHuang_20110820,add Moto's mode switch cmd to support PID switch function ++
    """
    SC_MODE_SWITCH = 0xD6

    # /StevenCPHuang_20110820,add Moto's mode switch cmd to support PID switch function --

    def __init__(self, loglevel=logging.INFO, vid=None, pid=None, interface=-1):
        self.vid = vid
        self.pid = pid
        self.interface = interface
        self.Debug = False
        self.usb = None
        self.loglevel=loglevel

    def connect(self):
        self.usb = usb_class(loglevel=self.loglevel,portconfig=[self.vid, self.pid,self.interface], devclass=8)
        if self.usb.connect():
            return True
        return False

    # htcadb = "55534243123456780002000080000616687463800100000000000000000000"; // Len 0x6, Command 0x16, "HTC" 01 = Enable, 02 = Disable
    def send_mass_storage_command(self, lun, cdb, direction, data_length):
        global tag
        cmd = cdb[0]
        if 0 <= cmd < 0x20:
            cdb_len = 6
        elif 0x20 <= cmd < 0x60:
            cdb_len = 10
        elif 0x60 <= cmd < 0x80:
            cdb_len = 0
        elif 0x80 <= cmd < 0xA0:
            cdb_len = 16
        elif 0xA0 <= cmd < 0xC0:
            cdb_len = 12
        else:
            cdb_len = 6

        if len(cdb) != cdb_len:
            print("Error, cdb length doesn't fit allowed cbw packet length")
            return 0

        if (cdb_len == 0) or (cdb_len > command_block_wrapper_len):
            print("Error, invalid data packet length, should be max of 31 bytes.")
            return 0
        else:
            data = write_object(command_block_wrapper, b"USBC", tag, data_length, direction, lun, cdb_len, cdb)[
                'raw_data']
            print(hexlify(data))
            if len(data) != 31:
                print("Error, invalid data packet length, should be 31 bytes, but length is %d" % len(data))
                return 0
            tag += 1
            self.usb.write(data, 31)
        return tag

    def send_htc_adbenable(self):
        # do_reserve from f_mass_storage.c
        print("Sending HTC adb enable command")
        common_cmnd = b"\x16htc\x80\x01"  # reserve_cmd + 'htc' + len + flag
        '''
        Flag values:
            1: Enable adb daemon from mass_storage
            2: Disable adb daemon from mass_storage
            3: cancel unmount BAP cdrom
            4: cancel unmount HSM rom
        '''
        lun = 0
        datasize = common_cmnd[4]
        timeout = 5000
        ret_tag = self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, datasize)
        ret_tag += self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, datasize)
        if datasize > 0:
            data = self.usb.read(datasize, timeout)
            print("DATA: " + hexlify(data).decode('utf-8'))
        print("Sent HTC adb enable command")

    def send_htc_ums_adbenable(self):  # HTC10
        # ums_ctrlrequest from f_mass_storage.c
        print("Sending HTC ums adb enable command")
        bRequestType = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE
        bRequest = 0xa0
        wValue = 1
        '''
        wValue:
            0: Disable adb daemon
            1: Enable adb daemon
        '''
        wIndex = 0
        w_length = 1
        ret = self.usb.ctrl_transfer(bRequestType, bRequest, wValue, wIndex, w_length)
        print("Sent HTC ums adb enable command: %x" % ret)

    def send_zte_adbenable(self):  # zte blade
        common_cmnd = b"\x86zte\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # reserve_cmd + 'zte' + len + flag
        common_cmnd2 = b"\x86zte\x80\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # reserve_cmd + 'zte' + len + flag
        '''
        Flag values:
            0: disable adbd ---for 736T
            1: enable adbd ---for 736T
            2: disable adbd ---for All except 736T
            3: enable adbd ---for All except 736T
        '''
        lun = 0
        datasize = common_cmnd[4]
        timeout = 5000
        ret_tag = self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, datasize)
        ret_tag += self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, datasize)
        ret_tag = self.send_mass_storage_command(lun, common_cmnd2, USB_DIR_IN, datasize)
        ret_tag += self.send_mass_storage_command(lun, common_cmnd2, USB_DIR_IN, datasize)
        if datasize > 0:
            data = self.usb.read(datasize, timeout)
            print("DATA: " + hexlify(data).decode('utf-8'))
        print("Send HTC adb enable command")

    def send_fih_adbenable(self):  # motorola xt560, nokia 3.1, #f_mass_storage.c
        if self.usb.connect():
            print("Sending FIH adb enable command")
            datasize = 0x24
            common_cmnd = bytes([self.SC_SWITCH_PORT]) + b"FI1" + struct.pack("<H",
                                                                              datasize)  # reserve_cmd + 'FI' + flag + len + none
            '''
            Flag values:
                common_cmnd[3]->1: Enable adb daemon from mass_storage
                common_cmnd[3]->0: Disable adb daemon from mass_storage
            '''
            lun = 0
            # datasize=common_cmnd[4]
            timeout = 5000
            ret_tag = self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            # ret_tag+=self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            if datasize > 0:
                data = self.usb.read(datasize, timeout)
                print("DATA: " + hexlify(data).decode('utf-8'))
            print("Sent FIH adb enable command")
            self.usb.close()

    def send_alcatel_adbenable(self):  # Alcatel MW41
        if self.usb.connect():
            print("Sending alcatel adb enable command")
            datasize = 0x24
            common_cmnd = b"\x16\xf9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            lun=0
            timeout = 5000
            ret_tag = self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            if datasize > 0:
                data = self.usb.read(datasize, timeout)
                print("DATA: " + hexlify(data).decode('utf-8'))
            print("Sent alcatel adb enable command")
            self.usb.close()

    def send_fih_root(
            self):  # motorola xt560, nokia 3.1, huawei u8850, huawei Ideos X6, lenovo s2109, triumph M410, viewpad 7, #f_mass_storage.c
        if self.usb.connect():
            print("Sending FIH root command")
            datasize = 0x24
            common_cmnd = bytes([self.SC_SWITCH_ROOT]) + b"FIH" + struct.pack("<H",
                                                                              datasize)  # reserve_cmd + 'FIH' + len + flag + none
            lun = 0
            # datasize = common_cmnd[4]
            timeout = 5000
            ret_tag = self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            ret_tag += self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            if datasize > 0:
                data = self.usb.read(datasize, timeout)
                print("DATA: " + hexlify(data).decode('utf-8'))
            print("Sent FIH root command")
            self.usb.close()

    def close(self):
        self.usb.close()
