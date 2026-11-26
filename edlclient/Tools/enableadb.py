#!/usr/bin/env python3
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import argparse
import copy
import hashlib
import logging
import logging.config
import logging.handlers
import os
import sys
import time
from enum import Enum
from typing import Any

import colorama
import requests
import serial
import serial.tools.list_ports
import usb.core
from Exscript.protocols.telnetlib import Telnet
from passlib.hash import md5_crypt  # type: ignore[import-not-found]

# Optional in-tree tools; the legacy (non package) layout needs a sys.path tweak first
qcdiag: Any = None
SierraKeygen: Any = None

try:
    from edlclient.Tools.qc_diag import qcdiag
    from edlclient.Tools.sierrakeygen import SierraKeygen
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from edlclient.Tools.qc_diag import qcdiag
        from edlclient.Tools.sierrakeygen import SierraKeygen
    except ImportError as err:
        print(f"ImportError: {err}")


class ColorFormatter(logging.Formatter):
    LOG_COLORS = {
        logging.ERROR: colorama.Fore.RED,
        logging.DEBUG: colorama.Fore.LIGHTMAGENTA_EX,
        logging.WARNING: colorama.Fore.YELLOW,
    }

    def format(self, record, *args, **kwargs):
        # if the corresponding logger has children, they may receive modified
        # record, so we want to keep it intact
        new_record = copy.copy(record)
        if new_record.levelno in self.LOG_COLORS:
            pad = ""
            if new_record.name != "root":
                print(new_record.name)
                pad = "[LIB]: "
            # we want levelname to be in different color, so let's modify it
            new_record.msg = f"{pad}{self.LOG_COLORS[new_record.levelno]}{new_record.msg}{colorama.Style.RESET_ALL}"
        # now we can let standart formatting take care of the rest
        return super().format(new_record, *args, **kwargs)


class LogBase(type):
    debuglevel = logging.root.level

    def __init__(cls, *args):
        super().__init__(*args)
        logger_attribute_name = '_' + cls.__name__ + '__logger'
        logger_debuglevel_name = '_' + cls.__name__ + '__debuglevel'
        logger_name = '.'.join([c.__name__ for c in cls.mro()[-2::-1]])
        LOG_CONFIG = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "root": {
                    "()": ColorFormatter,
                    "format": "%(name)s - %(message)s",
                }
            },
            "handlers": {
                "root": {
                    # "level": cls.__logger.level,
                    "formatter": "root",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                }
            },
            "loggers": {
                "": {
                    "handlers": ["root"],
                    # "level": cls.debuglevel,
                    "propagate": False
                }
            },
        }
        logging.config.dictConfig(LOG_CONFIG)
        logger = logging.getLogger(logger_name)

        setattr(cls, logger_attribute_name, logger)
        setattr(cls, logger_debuglevel_name, cls.debuglevel)


class vendor(Enum):
    sierra = 0x1199
    quectel = 0x2c7c
    zte = 0x19d2
    telit = 0x413c
    netgear = 0x0846


class deviceclass:
    vid = 0
    pid = 0

    def __init__(self, vid, pid):
        self.vid = vid
        self.pid = pid


class connection:
    def __init__(self, port=""):
        self.serial = None
        self.tn = None
        self.connected = False
        if port == "":
            port = self.detect(port)
        if port != "":
            try:
                self.serial = serial.Serial(port=port, baudrate=115200, bytesize=8, parity='N', stopbits=1, timeout=1)
                self.connected = self.serial.is_open
            except (OSError, serial.SerialException) as err:
                print(f"Failed to open {port}: {err}")
                self.connected = False

    def waitforusb(self, vid, pid):
        timeout = 0
        while timeout < 10:
            for device in self.detectusbdevices():
                if device.vid == vid and device.pid == pid:
                    return True
            time.sleep(1)
            timeout += 1
        return False

    def websend(self, url):
        headers = {'Referer': 'http://192.168.0.1/index.html', 'Accept-Charset': 'UTF-8'}
        r = requests.get(url, headers=headers, timeout=10)
        if b"FACTORY:ok" in r.content or b"success" in r.content:
            print(
                "Detected a ZTE in web mode .... switching mode success (convert back by sending \"AT+ZCDRUN=F\" via AT port)")
            return self.waitforusb(vendor.zte.value, 0x0016)
        return False

    def getserialports(self):
        return [port for port in serial.tools.list_ports.comports()]

    def detectusbdevices(self):
        dev: Any = usb.core.find(find_all=True)
        ids = [deviceclass(cfg.idVendor, cfg.idProduct) for cfg in dev or []]
        return ids

    def detect(self, port):
        atvendortable = {
            0x1199: ["Sierra Wireless", 3],
            0x2c7c: ["Quectel", 3],
            0x19d2: ["ZTE", 2],
            0x413c: ["Telit", 3],
            0x0846: ["Netgear", 2],
            0x04E8: ["Samsung", -1]
        }
        mode = "Unknown"
        try:
            for device in self.detectusbdevices():
                if device.vid == vendor.zte.value:
                    if device.pid == 0x0016:
                        print(f"Detected a {atvendortable[device.vid][0]} device with pid {hex(device.pid)} in AT mode")
                        mode = "AT"
                        break
                    elif device.pid == 0x1403:
                        print(
                            f"Detected a {atvendortable[device.vid][0]} device with pid {hex(device.pid)} in Web mode")
                        mode = "Web"
                        self.ZTE_Web()
                        break
                elif device.vid == vendor.netgear.value:
                    try:
                        # vid 0846, netgear mr1100, mr5100
                        self.tn = Telnet("192.168.1.1", 5510)
                        self.connected = True
                    except (OSError, Exception) as err:
                        print(f"Telnet connection failed: {err}")
                        self.connected = False
        except Exception:
            print("No libusb driver found. Trying Telnet instead.")
            try:
                # vid 0846, netgear mr1100, mr5100
                self.tn = Telnet("192.168.1.1", 5510)
                self.connected = True
            except Exception as err:
                self.connected = False
                print(f"Failed to connect to Telnet: {err}")
                return
        if mode in ["AT", "Unknown"]:
            for port in self.getserialports():
                if port.location and port.vid in atvendortable:
                    portid = port.location[-1:]
                    if int(portid) == atvendortable[port.vid][1]:
                        print(f"Detected a {atvendortable[port.vid][0]} at interface at: " + port.device)
                        return port.device
        return ""

    def ZTE_Web(self):
        url = 'http://192.168.0.1/goform/goform_set_cmd_process?goformId=USB_MODE_SWITCH&usb_mode=6'
        if self.websend(url):
            print("Successfully enabled adb.")

    def readreply(self) -> list[str] | None:
        info = []
        timeout = 0
        if self.serial is not None:
            while True:
                tmp = self.serial.readline().decode('utf-8').replace('\r', '').replace('\n', '')
                if "OK" in tmp:
                    info.append(tmp)
                    return info
                elif "ERROR" in tmp:
                    return None
                if tmp != "":
                    info.append(tmp)
                else:
                    timeout += 1
                    if timeout == 4:
                        break
        return info

    def send(self, cmd) -> list[str] | None:
        if self.tn is not None:
            self.tn.write(bytes(cmd + "\r", 'utf-8'))
            time.sleep(0.05)
            data = ""
            while True:
                tmp = self.tn.read_eager()
                if tmp != "":
                    data += tmp.strip()
                else:
                    break
            if "ERROR" in data:
                return None
            return data.split("\r\n")
        elif self.serial is not None:
            self.serial.write(bytes(cmd + "\r", 'utf-8'))
            time.sleep(0.05)
            return self.readreply()
        return None

    def close(self):
        if self.tn is not None:
            self.tn.close()
            self.connected = False
        if self.serial is not None:
            self.serial.close()
            self.connected = False

    def ati(self):
        data = {}
        info = self.send("ATI")
        if info is not None:
            for line in info:
                if "Revision" in line:
                    data["revision"] = line.split(":")[1].strip()
                if "Model" in line:
                    data["model"] = line.split(":")[1].strip()
                if "Quectel" in line:
                    data["vendor"] = "Quectel"
                if "Manufacturer" in line:
                    data["manufacturer"] = line.split(":")[1].strip()
                    if "Sierra Wireless" in data["manufacturer"]:
                        data["vendor"] = "Sierra Wireless"
                    elif "ZTE CORPORATION" in data["manufacturer"]:
                        data["vendor"] = "ZTE"
                    elif "SIMCOM INCORPORATED" in data["manufacturer"]:
                        data["vendor"] = "Simcom"
                    elif "Alcatel" in data["manufacturer"]:
                        data["vendor"] = "Alcatel"
                    elif "Netgear" in data["manufacturer"]:
                        data["vendor"] = "Netgear"
                    elif "SAMSUNG" in data["manufacturer"]:
                        data["vendor"] = "Samsung"
        info = self.send("AT+CGMI")
        if info is not None:
            for line in info:
                if "Quectel" in line:
                    data["vendor"] = "Quectel"
                    break
                elif "Fibucom" in line:
                    data["vendor"] = "Fibucom"
                    break
                elif "Netgear" in line:
                    data["vendor"] = "Netgear"
                    break
                elif "SAMSUNG" in line:
                    data["vendor"] = "Samsung"
                    break
        info = self.send("AT+CGMR")
        if info is not None and len(info) > 1:
            data["model"] = info[1]
        return data


class adbtools(metaclass=LogBase):
    __logger: logging.Logger

    def sendcmd(self, tn, cmd):
        tn.write(bytes(cmd, 'utf-8') + b"\n")
        time.sleep(0.05)
        return tn.read_eager().strip().decode('utf-8')

    def qc_diag_auth(self, diag):
        if diag.connect():
            res = diag.send(b"\x4B\xA3\x06\x00")
            if res[0] == 0x4B:
                challenge = res[4:4 + 8]
                response = hashlib.md5(challenge).digest()
                res = diag.send(b"\x4B\xA3\x07\x00" + response)
                if res[0] == 0x4B and res[3] == 0x00:
                    print("Auth success")
            res = diag.send(b"\x41" + b"\x30\x30\x30\x30\x30\x30")
            if res[1] == 0x01:
                print("SPC success")
            sp = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE"
            res = diag.send(b"\x46" + sp)
            if res[0] == 0x46 and res[1] == 0x01:
                print("SP success")
                return True
            else:
                res = diag.send(b"\x25" + sp)
                if res[0] == 0x46 and res[1] == 0x01:
                    print("SP success")
                    return True
        return False

    def meta(self, port, mode=b"METAMETA"):
        while True:
            cn = connection(port)
            if cn.connected:
                while True:
                    if cn.serial is None:
                        break
                    resp2 = cn.serial.read(8)
                    if len(resp2) > 0:
                        break
                if cn.serial is None:
                    break
                cn.serial.write(mode)
                response = cn.serial.read(8)
                if len(response) == 0:
                    print("Read timeout while switching to META mode")
                elif response == b'ATEMATEM' or response == b'READYATE':
                    print("META Mode enabled")
                elif response == b'METAFORB':
                    print("META mode forbidden")
                else:
                    print("Invalid response: ", response)

    def run(self, port, enable):
        cn = connection(port)
        if cn.connected:
            info = cn.ati()
            res = False
            if "vendor" in info:
                if info["vendor"] == "Sierra Wireless" or info["vendor"] == "Netgear":
                    res = self.SierraWireless(cn, info, enable)
                elif info["vendor"] == "Quectel":
                    print("Sending at switch command")
                    res = self.Quectel(cn, enable)
                elif info["vendor"] == "ZTE":
                    print("Sending switch command via diag")
                    res = self.ZTE(cn, enable)
                elif info["vendor"] == "Simcom":
                    res = self.Simcom(cn, enable)
                elif info["vendor"] == "Fibocom":
                    res = self.Fibocom(cn, enable)
                elif info["vendor"] == "Alcatel":
                    res = self.Alcatel(enable)
                elif info["vendor"] == "Samsung":
                    res = self.Samsung(cn, enable)
            mode = "enabled" if enable else "disabled"
            if res:
                print("ADB successfully " + mode)
            else:
                print("ADB couldn't be " + mode)
            cn.close()
        else:
            print("No device detected")

    def SierraWireless(self, cn, info, enable):
        print("Sending at switch command")
        kg = SierraKeygen(cn=cn, devicegeneration=None)
        kg.detectdevicegeneration()
        if kg.openlock():
            if enable:
                if cn.send('AT!CUSTOM="ADBENABLE",1\r') != -1:
                    return True
                kg.openlock()
                if cn.send('AT!CUSTOM="TELNETENABLE",1\r') != -1:
                    time.sleep(5)
                    tn = Telnet("192.168.1.1", 23)
                    tn.write(b"adbd &\r\n")
                    info = tn.read_eager()
                    print(info)
                    return True
                if kg.openlock() and info["vendor"] == "Netgear":
                    print("Enabling new port config")
                    if cn.send("AT!UDPID=68E2"):
                        print("Successfully enabled PID 68E2")
                        return True

            index = -1
            type = -1
            bitmask = -1
            resp = cn.send("AT!USBCOMP?")
            if resp is not None:
                print(resp)
                for val in resp:
                    if "Config Index" in val:
                        index = val[val.find("Config Index: ") + 14:]
                    elif "Config Type" in val:
                        type = val[val.find("Config Type: ") + 14:].replace(" (Generic)", "")
                    elif "Interface bitmask" in val:
                        bitmask = val[val.find("Interface bitmask: ") + 19:]
                        if " " in bitmask:
                            bitmask = "0x" + bitmask.split(" ")[0]
                if index is not None and type is not None and bitmask != 1:
                    index = int(index)
                    type = int(type)
                    bitmask = int(bitmask, 16) if isinstance(bitmask, str) else bitmask
                    # AT!USBCOMP=<Config Index>,<Config Type>,<Interface bitmask>
                    #  <Config Index>      - configuration index to which the composition applies, should be 1
                    #  <Config Type>       - 1:Generic, 2:USBIF-MBIM, 3:RNDIS
                    #                        config type 2/3 should only be used for specific Sierra PIDs: 68B1, 9068
                    #                        customized VID/PID should use config type 1
                    #  <Interface bitmask> - DIAG     - 0x00000001,
                    #                        ADB      - 0x00000002,
                    #                        NMEA     - 0x00000004,
                    #                        MODEM    - 0x00000008,
                    #                        RMNET0   - 0x00000100,
                    #                        RMNET1   - 0x00000400,
                    #                        RMNET2   - 0x00000800,
                    #                        MBIM     - 0x00001000,
                    #                        RNDIS    - 0x00004000,
                    #                        AUDIO    - 0x00010000,
                    #                        ECM      - 0x00080000,
                    #                        UBIST    - 0x00200000
                    #if enable:
                    cmd = f"AT!USBCOMP={index},{type},%08X" % 0x0080010E
                    #else:
                    #    cmd = f"AT!USBCOMP={index},{type},%08X" % 0x0000010D
                    resp = cn.send(cmd)
                    if resp is not None:
                        resp = cn.send("AT!RESET")
                        if resp is not None:
                            return True
                    return False
                return True
            else:
                if cn.send('AT!CUSTOM="ADBENABLE",0\r') != -1:
                    return True
                kg.openlock()
                if cn.send('AT!CUSTOM="TELNETENABLE",0\r') != -1:
                    return True
        return False

    def Samsung(self, cn, enable):
        if enable:
            if cn.send("AT+USBMODEM=1") or cn.send("AT+SYSSCOPE=1,0,0"):
                return True
        else:
            if cn.send("AT+USBMODEM=0") or cn.send("AT+SYSSCOPE=1,0,0"):
                return True
        return False

    def Alcatel(self, enable):
        print("Send scsi switch command")
        print("Run \"sudo sg_raw /dev/sg0 16 f9 00 00 00 00 00 00 00 00 00 00 00 00 00 00 -v\" to enable adb")

    def Fibocom(self, cn, enable):
        print("Sending at switch command")
        if enable:
            # FibocomL718:
            if cn.send("AT+ADBDEBUG=1") != -1:
                return True
        else:
            if cn.send("AT+ADBDEBUG=0") != -1:
                return True
        return False

    def Simcom(self, cn, enable):
        print("Sending at switch command")
        if enable:
            # Simcom7600
            if cn.send("AT+CUSBADB=1,1") != -1:
                return True
        else:
            if cn.send("AT+CUSBADB=1,1") != -1:
                return True
        return False

    def ZTE(self, cn, enable):
        if enable:
            if cn.send("AT+ZMODE=1") != -1:
                return True
            else:
                interface = 0
                diag = qcdiag(loglevel=self.__logger.level, portconfig=[[0x19d2, 0x0016, interface]])
                if self.qc_diag_auth(diag):
                    res = diag.send(b"\x4B\xFA\x0B\x00\x01")  # Enable adb serial
                    if res[0] != 0x13:
                        print("Success enabling adb serial")
                    res = diag.send(b"\x4B\x5D\x05\x00")  # Operate ADB
                    if res[0] != 0x13:
                        print("Success enabling adb")
                    return True
                diag.disconnect()
        else:
            if cn.send("AT+ZMODE=F") != -1:
                return True
            else:
                interface = 0
                diag = qcdiag(loglevel=self.__logger.level, portconfig=[[0x19d2, 0x0016, interface]])
                if self.qc_diag_auth(diag):
                    res = diag.send(b"\x4B\xFA\x0B\x00\x00")  # Enable adb serial
                    if res[0] != 0x13:
                        print("Success enabling adb serial")
                    res = diag.send(b"\x4B\x5D\x05\x00")  # Operate ADB
                    if res[0] != 0x13:
                        print("Success enabling adb")
                diag.disconnect()
                return True
        return False

    def Quectel(self, cn, enable: bool = True):
        sn = cn.send("AT+QADBKEY?\r")
        if sn != -1:
            if len(sn) > 1:
                sn = sn[1]
            cc = md5_crypt(salt="")
            code = cc.encrypt("SH_adb_quectel", salt=str(sn))
            code = code[12:28]
            cn.send(f"AT+QADBKEY=\"{code}\"\r")
        if enable:
            if cn.send("AT+QCFG=\"usbcfg\",0x2C7C,0x125,1,1,1,1,1,1,0\r") == -1:
                if cn.send("AT+QLINUXCMD=\"adbd\"") != -1:  # echo test > /dev/ttyGS0
                    return True
            else:
                return True
        else:
            if cn.send("AT+QCFG=\"usbcfg\",0x2C7C,0x125,1,1,1,1,1,0,0\r") != -1:
                return True
        return False


def main():
    version = "1.2"
    info = '\nModem Gimme-ADB ' + version + ' (c) B. Kerler 2020-2023\n-------------------------------------------\n'
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=info)
    parser.add_argument(
        '-mode', help='Mode: enable or disable',
        default="enable")
    parser.add_argument(
        '-port', '-p',
        help='[Optional] use com port for at',
        default="")
    parser.add_argument(
        '-logfile', '-l',
        help='use logfile for debug log',
        default="")
    args = parser.parse_args()
    ad = adbtools()
    print(info)
    print("Supported modules: ZTE,Netgear,Sierra Wireless,Samsung,Alcatel,Quectel,Fibucom")
    if args.mode.lower() == "enable":
        enable = True
    else:
        enable = False
    ad.run(port=args.port, enable=enable)
    # ad.meta(port=args.port)


if __name__ == "__main__":
    main()
