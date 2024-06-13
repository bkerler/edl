#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import logging
from edlclient.Library.utils import LogBase

try:
    from edlclient.Library.Modules.generic import generic
except ImportError as e:
    print(e)
    generic = None
    pass

try:
    from edlclient.Library.Modules.oneplus import oneplus
except ImportError as e:
    print(e)
    oneplus = None
    pass

try:
    from edlclient.Library.Modules.xiaomi import xiaomi
except ImportError as e:
    print(e)
    xiaomi = None
    pass

try:
    from edlclient.Library.Modules.nothing import nothing
except ImportError as e:
    nothing = None
    pass


class modules(metaclass=LogBase):
    def __init__(self, fh, serial: int, supported_functions, loglevel, devicemodel: str, args):
        self.fh = fh
        self.args = args
        self.serial = serial
        self.error = self.__logger.error
        self.info = self.__logger.info
        self.supported_functions = supported_functions
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
        self.options = {}
        self.devicemodel = devicemodel
        self.generic = None
        try:
            self.generic = generic(fh=self.fh, serial=self.serial, args=self.args, loglevel=loglevel)
        except Exception as e:
            self.error(e)
            pass
        self.ops = None
        try:
            self.ops = oneplus(fh=self.fh, projid=self.devicemodel, serial=self.serial,
                               supported_functions=self.supported_functions, args=self.args, loglevel=loglevel)
        except Exception as e:
            self.error(e)
            pass
        self.xiaomi = None
        try:
            self.xiaomi = xiaomi(fh=self.fh)
        except Exception as e:
            self.error(e)
            pass

    def addpatch(self):
        if self.ops is not None:
            return self.ops.addpatch()
        return ""

    def addprogram(self):
        if self.ops is not None:
            return self.ops.addprogram()
        return ""

    def edlauth(self):
        if self.xiaomi is not None:
            return self.xiaomi.edl_auth()
        return True

    def writeprepare(self):
        if self.ops is not None:
            return self.ops.run()
        return True

    def run(self, command, args):
        args = args.split(",")
        options = {}
        for i in range(len(args)):
            if "=" in args[i]:
                option = args[i].split("=")
                if len(option) > 1:
                    options[option[0]] = option[1]
            else:
                options[args[i]] = True
        if command == "":
            print("Valid commands are:\noemunlock, ops\n")
            return False
        if self.generic is not None and command == "oemunlock":
            if "enable" in options:
                enable = True
            elif "disable" in options:
                enable = False
            else:
                self.error("Unknown mode given. Available are: enable, disable.")
                return False
            return self.generic.oem_unlock(enable)
        elif self.ops is not None and command == "ops":
            if self.devicemodel is not None:
                enable = False
                partition = "param"
                if "enable" in options:
                    enable = True
                elif "disable" in options:
                    enable = False
                else:
                    self.error("Unknown mode given. Available are: enable, disable.")
                    return False
                res = self.fh.detect_partition(self.args, partition)
                if res[0]:
                    lun = res[1]
                    rpartition = res[2]
                    paramdata = self.fh.cmd_read_buffer(lun, rpartition.sector, rpartition.sectors, False)
                    if paramdata.data == b"":
                        self.error("Error on reading param partition.")
                        return False
                    wdata = self.ops.enable_ops(paramdata.data, enable, self.devicemodel, self.serial)
                    if wdata is not None:
                        self.ops.run()
                        if self.fh.cmd_program_buffer(lun, rpartition.sector, wdata, False):
                            self.info("Successfully set mode")
                            return True
                        else:
                            self.error("Error on writing param partition")
                            return False
                    else:
                        self.error("No param info generated, did you provide the devicemodel ?")
                        return False
                else:
                    fpartitions = res[1]
                    self.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for lun in fpartitions:
                        for rpartition in fpartitions[lun]:
                            if self.args["--memory"].lower() == "emmc":
                                self.error("\t" + rpartition)
                            else:
                                self.error(lun + ":\t" + rpartition)
            else:
                self.error("A devicemodel is needed for this command")
        return False
