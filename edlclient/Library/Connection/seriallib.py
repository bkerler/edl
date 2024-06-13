#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import sys

if not sys.platform.startswith('win32'):
    import termios


def _reset_input_buffer():
    return


def _reset_input_buffer_org(self):
    if not sys.platform.startswith('win32'):
        return termios.tcflush(self.fd, termios.TCIFLUSH)


import serial
import serial.tools.list_ports
import inspect

try:
    from edlclient.Library.utils import *
    from edlclient.Library.Connection.devicehandler import DeviceClass
except:
    from Library.utils import *
    from Library.Connection.devicehandler import DeviceClass


class serial_class(DeviceClass):

    def __init__(self, loglevel=logging.INFO, portconfig=None, devclass=-1):
        super().__init__(loglevel, portconfig, devclass)
        self.is_serial = True

    def connect(self, EP_IN=-1, EP_OUT=-1, portname: str = ""):
        if self.connected:
            self.close()
            self.connected = False
        if portname == "":
            devices = self.detectdevices()
            if len(devices) > 0:
                portname = devices[0]
        if portname != "":
            self.device = serial.Serial(baudrate=115200, bytesize=serial.EIGHTBITS,
                                        parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
                                        timeout=50,
                                        xonxoff=False, dsrdtr=True, rtscts=True)
            self.device._reset_input_buffer = _reset_input_buffer
            self.device.setPort(port=portname)
            self.device.open()
            self.device._reset_input_buffer = _reset_input_buffer_org
            self.connected = self.device.is_open
            if self.connected:
                return True
        return False

    def close(self, reset=False):
        if self.connected:
            self.device.close()
            del self.device
            self.connected = False

    def detectdevices(self):
        ids = []
        for port in serial.tools.list_ports.comports():
            for usbid in self.portconfig:
                if port.pid == usbid[1] and port.vid == usbid[0]:
                    portid = port.location[-1:]
                    print(f"Detected {hex(port.vid)}:{hex(port.pid)} device at: " + port.device)
                    ids.append(port.device)
        return sorted(ids)

    def setLineCoding(self, baudrate=None, parity=0, databits=8, stopbits=1):
        self.device.baudrate = baudrate
        self.device.parity = parity
        self.device.stopbbits = stopbits
        self.device.bytesize = databits
        self.debug("Linecoding set")

    def setbreak(self):
        self.device.send_break()
        self.debug("Break set")

    def setcontrollinestate(self, RTS=None, DTR=None, isFTDI=False):
        if RTS == 1:
            self.device.setRTS(RTS)
        if DTR == 1:
            self.device.setDTR(DTR)
        self.debug("Linecoding set")

    def write(self, command, pktsize=None):
        if pktsize is None:
            pktsize = 512
        if isinstance(command, str):
            command = bytes(command, 'utf-8')
        pos = 0
        if command == b'':
            try:
                self.device.write(b'')
            except Exception as err:
                error = str(err.strerror)
                if "timeout" in error:
                    # time.sleep(0.01)
                    try:
                        self.device.write(b'')
                    except Exception as err:
                        self.debug(str(err))
                        return False
                return True
        else:
            i = 0
            while pos < len(command):
                try:
                    ctr = self.device.write(command[pos:pos + pktsize])
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
        self.device.flushOutput()
        timeout = 0
        time.sleep(0.005)
        """
        while self.device.in_waiting == 0:
            time.sleep(0.005)
            timeout+=1
            if timeout==10:
                break
        """
        return True

    def read(self, length=None, timeout=-1):
        if timeout == -1:
            timeout = self.timeout
        if length is None:
            length = self.device.in_waiting
            if length == 0:
                return b""
        if self.xmlread:
            if length > self.device.in_waiting:
                length = self.device.in_waiting
        return self.usbread(length, timeout)

    def flush(self):
        return self.device.flush()

    def usbread(self, resplen=None, timeout=0):
        if resplen is None:
            resplen = self.device.in_waiting
        if resplen <= 0:
            self.info("Warning !")
        res = bytearray()
        loglevel = self.loglevel
        self.device.timeout = timeout
        epr = self.device.read
        extend = res.extend
        if self.xmlread:
            info = self.device.read(6)
            bytestoread = resplen - len(info)
            extend(info)
            if b"<?xml " in info:
                while b"response " not in res or res[-7:] != b"</data>":
                    extend(epr(1))
                return res
        bytestoread = resplen
        while len(res) < bytestoread:
            try:
                val = epr(bytestoread)
                if len(val) == 0:
                    break
                extend(val)
            except Exception as e:
                error = str(e)
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

    def usbwrite(self, data, pktsize=None):
        if pktsize is None:
            pktsize = len(data)
        res = self.write(data, pktsize)
        self.device.flush()
        return res

    def usbreadwrite(self, data, resplen):
        self.usbwrite(data)  # size
        self.device.flush()
        res = self.usbread(resplen)
        return res
