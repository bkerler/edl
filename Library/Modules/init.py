from Library.utils import LogBase

import logging
try:
    from Library.Modules.generic import generic
except Exception as e:
    pass

try:
    from Library.Modules.xiaomi import xiaomi
except Exception as e:
    pass

class modules(metaclass=LogBase):
    def __init__(self, fh, serial, supported_functions, loglevel, devicemodel, args):
        self.fh = fh
        self.args = args
        self.serial = serial
        self.supported_functions = supported_functions
        self.__logger.setLevel(loglevel)
        if loglevel==logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
        self.options = {}
        self.devicemodel = devicemodel
        self.generic = generic(fh=self.fh, serial=self.serial, args=self.args, logger=self.__logger)
        self.ops = None
        self.xiaomi=None
        try:
            self.xiaomi = xiaomi(fh=self.fh)
        except Exception as e:
            pass

    def addpatch(self):
        return ""

    def addprogram(self):
        return ""

    def edlauth(self):
        if self.xiaomi is not None:
            return self.xiaomi.edl_auth()
        return True

    def writeprepare(self):
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
        if command=="":
            print("Valid commands are:\noemunlock\n")
            return False
        if self.generic is not None and command == "oemunlock":
            if "enable" in options:
                enable = True
            elif "disable" in options:
                enable = False
            else:
                self.__logger.error("Unknown mode given. Available are: enable, disable.")
                return False
            return self.generic.oem_unlock(enable)
        return False
