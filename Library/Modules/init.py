try:
    from Library.Modules.oneplus import oneplus
    from Library.Modules.generic import generic
except Exception as e:
    pass


class modules():
    def __init__(self, fh, serial, supported_functions, log, devicemodel, args):
        self.fh = fh
        self.args = args
        self.serial = serial
        self.supported_functions = supported_functions
        self.log = log
        self.options = {}
        self.devicemodel = devicemodel
        self.generic = None
        try:
            self.generic = generic(fh=self.fh, serial=self.serial, args=self.args, logger=self.log)
        except Exception as e:
            pass
        self.ops = None
        try:
            self.ops = oneplus(fh=self.fh, projid=self.devicemodel, serial=self.serial,
                               supported_functions=self.supported_functions)
        except Exception as e:
            pass

    def addpatch(self):
        if self.ops is not None:
            return self.ops.addpatch()
        return ""

    def addprogram(self):
        if self.ops is not None:
            return self.ops.addprogram()
        return ""

    def prerun(self):
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
        if command=="":
            print("Valid commands are:\noemunlock\n")
            return False
        if self.generic is not None and command == "oemunlock":
            if "enable" in options:
                enable = True
            elif "disable" in options:
                enable = False
            else:
                self.log.error("Unknown mode given. Available are: enable, disable.")
                return False
            return self.generic.oem_unlock(enable)
        return False
