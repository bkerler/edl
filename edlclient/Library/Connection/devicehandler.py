#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import inspect
import logging
from typing import Any
import os
import traceback
from binascii import hexlify
from struct import unpack

try:
    from edlclient.Library.utils import LogBase
except ImportError:  # pragma: no cover - legacy in-tree layout
    from Library.utils import LogBase  # type: ignore[import-not-found]


class DeviceClass(metaclass=LogBase):
    __logger: logging.Logger

    def __init__(self, loglevel=logging.INFO, portconfig: list | None = None, devclass=-1):
        self.connected = False
        # None means "wait forever", which is why it is optional
        self.timeout: int | None = 1000
        self.maxsize = 512
        self.vid = None
        self.pid = None
        self.stopbits = None
        self.databits = None
        self.parity = None
        self.baudrate = None
        self.configuration = None
        # PyUSB device (usb_class) or pyserial Serial instance (serial_class)
        self.device: Any = None
        self.devclass = -1
        self.loglevel = loglevel
        self.xmlread = True
        self.portconfig = portconfig
        self.__logger = self.__logger
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.debug = self.__logger.debug
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = os.path.join("logs", "log.txt")
            fh = logging.FileHandler(logfilename, encoding='utf-8')
            self.__logger.addHandler(fh)

    def connect(self, EP_IN=-1, EP_OUT=-1, portname: str = ""):
        raise NotImplementedError()

    def close(self, reset=False):
        raise NotImplementedError()

    def flush(self):
        raise NotImplementedError()

    def detectdevices(self):
        raise NotImplementedError()

    def getInterfaceCount(self):
        raise NotImplementedError()

    def setLineCoding(self, baudrate=None, parity=0, databits=8, stopbits=1):
        raise NotImplementedError()

    def setbreak(self):
        raise NotImplementedError()

    def setcontrollinestate(self, RTS=None, DTR=None, isFTDI=False):
        raise NotImplementedError()

    def write(self, command, pktsize=None):
        raise NotImplementedError()

    def usbwrite(self, data, pktsize=None):
        raise NotImplementedError()

    def usbread(self, resplen=None, timeout=0):
        raise NotImplementedError()

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data_or_wLength):
        raise NotImplementedError()

    def usbreadwrite(self, data, resplen):
        raise NotImplementedError()

    def read(self, length=None, timeout=-1):
        if timeout == -1:
            timeout = self.timeout
        if length is None:
            length = self.maxsize
        return self.usbread(length, timeout or 0)

    def rdword(self, count=1, little=False):
        rev = "<" if little else ">"
        value = self.usbread(4 * count)
        data = unpack(rev + "I" * count, value)
        if count == 1:
            return data[0]
        return data

    def rword(self, count=1, little=False):
        rev = "<" if little else ">"
        data = []
        for _ in range(count):
            v = self.usbread(2)
            if len(v) == 0:
                return data
            data.append(unpack(rev + "H", v)[0])
        if count == 1:
            return data[0]
        return data

    def rbyte(self, count=1):
        return self.usbread(count)

    def verify_data(self, data, pre="RX:"):
        if self.__logger.level == logging.DEBUG:
            frame = inspect.currentframe()
            stack_trace = traceback.format_stack(frame)
            td = []
            for trace in stack_trace:
                if "verify_data" not in trace and "Port" not in trace:
                    td.append(trace)
            self.debug(td[:-1])

        if isinstance(data, bytes) or isinstance(data, bytearray):
            if data[:5] == b"<?xml":
                try:
                    rdata = b""
                    for line in data.split(b"\n"):
                        try:
                            self.debug(pre + line.decode('utf-8'))
                            rdata += line + b"\n"
                        except:
                            v = hexlify(line)
                            self.debug(pre + v.decode('utf-8'))
                    return rdata
                except Exception as err:
                    self.debug(str(err))
                    pass
            if logging.DEBUG >= self.__logger.level:
                self.debug(pre + hexlify(data).decode('utf-8'))
        else:
            if logging.DEBUG >= self.__logger.level:
                self.debug(pre + hexlify(data).decode('utf-8'))
        return data
