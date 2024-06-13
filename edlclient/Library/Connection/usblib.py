#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import array
import inspect
import logging
from binascii import hexlify
from ctypes import c_void_p, c_int
from enum import Enum

import usb.backend.libusb0
import usb.core  # pyusb
import usb.util

try:
    from edlclient.Library.utils import *
except:
    from Library.utils import *
if not is_windows():
    import usb.backend.libusb1
from struct import pack

try:
    from edlclient.Library.Connection.devicehandler import DeviceClass
except:
    from Library.Connection.devicehandler import DeviceClass
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

MAX_USB_BULK_BUFFER_SIZE = 16384

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


class usb_class(DeviceClass):

    def __init__(self, loglevel=logging.INFO, portconfig=None, devclass=-1, serial_number=None):
        super().__init__(loglevel, portconfig, devclass)
        self.serial_number = serial_number
        self.load_windows_dll()
        self.EP_IN = None
        self.EP_OUT = None
        self.is_serial = False
        self.buffer = array.array('B', [0]) * 1048576
        if sys.platform.startswith('freebsd') or sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
            self.backend = usb.backend.libusb1.get_backend(find_library=lambda x: "libusb-1.0.so")
        elif is_windows():
            self.backend = None
        if self.backend is not None:
            try:
                self.backend.lib.libusb_set_option.argtypes = [c_void_p, c_int]
                self.backend.lib.libusb_set_option(self.backend.ctx, 1)
            except:
                self.backend = None

    def load_windows_dll(self):
        if os.name == 'nt':
            windows_dir = None
            try:
                # add pygame folder to Windows DLL search paths
                windows_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../..", "Windows")
                try:
                    os.add_dll_directory(windows_dir)
                except Exception:
                    pass
                os.environ['PATH'] = windows_dir + ';' + os.environ['PATH']
            except Exception:
                pass
            del windows_dir

    def getInterfaceCount(self):
        if self.vid is not None:
            self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=self.backend)
            if self.device is None:
                self.debug("Couldn't detect the device. Is it connected ?")
                return False
            try:
                self.device.set_configuration()
            except Exception as err:
                self.debug(str(err))
                pass
            self.configuration = self.device.get_active_configuration()
            self.debug(2, self.configuration)
            return self.configuration.bNumInterfaces
        else:
            self.__logger.error("No device detected. Is it connected ?")
        return 0

    def setLineCoding(self, baudrate=None, parity=0, databits=8, stopbits=1):
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
        self.debug("Linecoding set, {}b sent".format(wlen))

    def setbreak(self):
        txdir = 0  # 0:OUT, 1:IN
        req_type = 1  # 0:std, 1:class, 2:vendor
        recipient = 1  # 0:device, 1:interface, 2:endpoint, 3:other
        req_type = (txdir << 7) + (req_type << 5) + recipient
        wlen = self.device.ctrl_transfer(
            bmRequestType=req_type, bRequest=CDC_CMDS["SEND_BREAK"],
            wValue=0, data_or_wLength=0, wIndex=1)
        self.debug("Break set, {}b sent".format(wlen))

    def setcontrollinestate(self, RTS=None, DTR=None, isFTDI=False):
        ctrlstate = (2 if RTS else 0) + (1 if DTR else 0)
        if isFTDI:
            ctrlstate += (1 << 8) if DTR is not None else 0
            ctrlstate += (2 << 8) if RTS is not None else 0
        txdir = 0  # 0:OUT, 1:IN
        req_type = 2 if isFTDI else 1  # 0:std, 1:class, 2:vendor
        # 0:device, 1:interface, 2:endpoint, 3:other
        recipient = 0 if isFTDI else 1
        req_type = (txdir << 7) + (req_type << 5) + recipient

        wlen = self.device.ctrl_transfer(
            bmRequestType=req_type,
            bRequest=1 if isFTDI else CDC_CMDS["SET_CONTROL_LINE_STATE"],
            wValue=ctrlstate,
            wIndex=1,
            data_or_wLength=0)
        self.debug("Linecoding set, {}b sent".format(wlen))

    def flush(self):
        return

    def connect(self, EP_IN=-1, EP_OUT=-1, portname: str = ""):
        if self.connected:
            self.close()
            self.connected = False
        self.device = None
        self.EP_OUT = None
        self.EP_IN = None
        devices = usb.core.find(find_all=True, backend=self.backend)
        for dev in devices:
            for usbid in self.portconfig:
                if dev.idProduct == usbid[1] and dev.idVendor == usbid[0]:
                    if self.serial_number is not None:
                        if dev.serial_number != self.serial_number:
                            continue
                    self.device = dev
                    self.vid = dev.idVendor
                    self.pid = dev.idProduct
                    self.serial_number = dev.serial_number
                    self.interface = usbid[2]
                    break
            if self.device is not None:
                break

        if self.device is None:
            self.debug("Couldn't detect the device. Is it connected ?")
            return False

        try:
            self.configuration = self.device.get_active_configuration()
        except usb.core.USBError as e:
            if e.strerror == "Configuration not set":
                self.device.set_configuration()
                self.configuration = self.device.get_active_configuration()
            if e.errno == 13:
                self.backend = usb.backend.libusb0.get_backend()
                self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=self.backend)
        if self.configuration is None:
            self.error("Couldn't get device configuration.")
            return False
        if self.interface > self.configuration.bNumInterfaces:
            print("Invalid interface, max number is %d" % self.configuration.bNumInterfaces)
            return False
        for itf in self.configuration:
            if self.devclass == -1:
                self.devclass = 0xFF
            if itf.bInterfaceClass == self.devclass:
                if self.interface == -1 or self.interface == itf.bInterfaceNumber:
                    self.interface = itf
                    self.EP_OUT = EP_OUT
                    self.EP_IN = EP_IN
                    for ep in itf:
                        edir = usb.util.endpoint_direction(ep.bEndpointAddress)
                        if (edir == usb.util.ENDPOINT_OUT and EP_OUT == -1) or ep.bEndpointAddress == (EP_OUT & 0xF):
                            self.EP_OUT = ep
                        elif (edir == usb.util.ENDPOINT_IN and EP_IN == -1) or ep.bEndpointAddress == (EP_OUT & 0xF):
                            self.EP_IN = ep
                    break

        if self.EP_OUT is not None and self.EP_IN is not None:
            self.maxsize = self.EP_IN.wMaxPacketSize
            try:
                if self.device.is_kernel_driver_active(0):
                    self.debug("Detaching kernel driver")
                    self.device.detach_kernel_driver(0)
            except Exception as err:
                self.debug("No kernel driver supported: " + str(err))

            try:
                usb.util.claim_interface(self.device, 0)
            except:
                pass
            """
            self.debug(self.configuration)
            if self.interface != 0:
                try:
                    usb.util.claim_interface(self.device, 0)
                except:
                    try:
                        if self.device.is_kernel_driver_active(0):
                            self.debug("Detaching kernel driver")
                            self.device.detach_kernel_driver(0)
                    except Exception as err:
                        self.debug("No kernel driver supported: " + str(err))
                    try:
                        usb.util.claim_interface(self.device, 0)
                    except:
                        pass
            try:
                    usb.util.claim_interface(self.device, self.interface)
            except:
                try:
                    if self.device.is_kernel_driver_active(self.interface):
                        self.debug("Detaching kernel driver")
                        self.device.detach_kernel_driver(self.interface)
                except Exception as err:
                    self.debug("No kernel driver supported: " + str(err))
                try:
                    if self.interface != 0:
                        usb.util.claim_interface(self.device, self.interface)
                except:
                    pass
            """
            self.connected = True
            return True
        print("Couldn't find CDC interface. Aborting.")
        self.connected = False
        return False

    def close(self, reset=False):
        if self.connected:
            try:
                if reset:
                    self.device.reset()
                if not self.device.is_kernel_driver_active(self.interface):
                    # self.device.attach_kernel_driver(self.interface) #Do NOT uncomment
                    self.device.attach_kernel_driver(0)
            except Exception as err:
                self.debug(str(err))
                pass
            usb.util.dispose_resources(self.device)
            del self.device
            if reset:
                time.sleep(2)
            self.connected = False

    def write(self, command, pktsize=None):
        if pktsize is None:
            # pktsize = self.EP_OUT.wMaxPacketSize
            pktsize = MAX_USB_BULK_BUFFER_SIZE
        if isinstance(command, str):
            command = bytes(command, 'utf-8')
        pos = 0
        if command == b'':
            try:
                self.EP_OUT.write(b'')
            except usb.core.USBError as err:
                error = str(err.strerror)
                if "timeout" in error:
                    # time.sleep(0.01)
                    try:
                        self.EP_OUT.write(b'')
                    except Exception as err:
                        self.debug(str(err))
                        return False
                return True
        else:
            i = 0
            while pos < len(command):
                try:
                    ctr = self.EP_OUT.write(command[pos:pos + pktsize])
                    if ctr <= 0:
                        self.info(ctr)
                    pos += pktsize
                except Exception as err:
                    self.debug(str(err))
                    # print("Error while writing")
                    # time.sleep(0.01)
                    i += 1
                    if i == 3:
                        return False
                    pass
        self.verify_data(bytearray(command), "TX:")
        return True

    def usbread(self, resplen=None, timeout=0):
        if timeout == 0:
            timeout = 1
        if resplen is None:
            resplen = self.maxsize
        if resplen <= 0:
            self.info("Warning !")
        res = bytearray()
        loglevel = self.loglevel
        buffer = self.buffer[:resplen]
        epr = self.EP_IN.read
        extend = res.extend
        while len(res) < resplen:
            try:
                resplen = epr(buffer, timeout)
                extend(buffer[:resplen])
                if resplen == self.EP_IN.wMaxPacketSize:
                    break
            except usb.core.USBError as e:
                error = str(e.strerror)
                if "timed out" in error:
                    if timeout is None:
                        return b""
                    self.debug("Timed out")
                    if timeout == 10:
                        return b""
                    timeout += 1
                    pass
                elif "Overflow" in error:
                    self.error("USB Overflow")
                    return b""
                else:
                    self.info(repr(e))
                    return b""

        if loglevel == logging.DEBUG:
            self.debug(inspect.currentframe().f_back.f_code.co_name + ":" + hex(resplen))
            if self.loglevel == logging.DEBUG:
                self.verify_data(res[:resplen], "RX:")
        return res[:resplen]

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data_or_wLength):
        ret = self.device.ctrl_transfer(bmRequestType=bmRequestType, bRequest=bRequest, wValue=wValue, wIndex=wIndex,
                                        data_or_wLength=data_or_wLength)
        return ret[0] | (ret[1] << 8)

    class deviceclass:
        vid = 0
        pid = 0

        def __init__(self, vid, pid):
            self.vid = vid
            self.pid = pid

    def detectdevices(self):
        dev = usb.core.find(find_all=True, backend=self.backend)
        ids = [self.deviceclass(cfg.idVendor, cfg.idProduct) for cfg in dev]
        return ids

    def usbwrite(self, data, pktsize=None):
        if pktsize is None:
            pktsize = len(data)
        res = self.write(data, pktsize)
        # port->flush()
        return res

    def usbreadwrite(self, data, resplen):
        self.usbwrite(data)  # size
        # port->flush()
        res = self.usbread(resplen)
        return res


class ScsiCmds(Enum):
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


class Scsi:
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
        self.loglevel = loglevel

    def connect(self):
        self.usb = usb_class(loglevel=self.loglevel, portconfig=[self.vid, self.pid, self.interface], devclass=8)
        if self.usb.connect():
            return True
        return False

    # htcadb = "55534243123456780002000080000616687463800100000000000000000000";
    # Len 0x6, Command 0x16, "HTC" 01 = Enable, 02 = Disable
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
        brequesttype = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE
        brequest = 0xa0
        wvalue = 1
        '''
        wValue:
            0: Disable adb daemon
            1: Enable adb daemon
        '''
        windex = 0
        w_length = 1
        ret = self.usb.ctrl_transfer(brequesttype, brequest, wvalue, windex, w_length)
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
            # reserve_cmd + 'FI' + flag + len + none
            common_cmnd = bytes([self.SC_SWITCH_PORT]) + b"FI1" + pack("<H", datasize)
            '''
            Flag values:
                common_cmnd[3]->1: Enable adb daemon from mass_storage
                common_cmnd[3]->0: Disable adb daemon from mass_storage
            '''
            lun = 0
            # datasize=common_cmnd[4]
            timeout = 5000
            ret_tag = None
            ret_tag += self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
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
            lun = 0
            timeout = 5000
            ret_tag = None
            ret_tag += self.send_mass_storage_command(lun, common_cmnd, USB_DIR_IN, 0x600)
            if datasize > 0:
                data = self.usb.read(datasize, timeout)
                print("DATA: " + hexlify(data).decode('utf-8'))
            print("Sent alcatel adb enable command")
            self.usb.close()

    def send_fih_root(self):
        # motorola xt560, nokia 3.1, huawei u8850, huawei Ideos X6,
        # lenovo s2109, triumph M410, viewpad 7, #f_mass_storage.c
        if self.usb.connect():
            print("Sending FIH root command")
            datasize = 0x24
            # reserve_cmd + 'FIH' + len + flag + none
            common_cmnd = bytes([self.SC_SWITCH_ROOT]) + b"FIH" + pack("<H", datasize)
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
        return True
