try:
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
        self.xiaomi=None

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
        if command=="":
            print("Valid commands are:\noemunlock, ops\n")
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
        elif self.ops is not None and command == "ops":
            if self.devicemodel is not None:
                enable = False
                partition = "param"
                if "enable" in options:
                    enable = True
                elif "disable" in options:
                    enable = False
                else:
                    self.log.error("Unknown mode given. Available are: enable, disable.")
                    return False
                res = self.fh.detect_partition(self.args, partition)
                if res[0]:
                    lun = res[1]
                    rpartition = res[2]
                    paramdata = self.fh.cmd_read_buffer(lun, rpartition.sector, rpartition.sectors, False)
                    if paramdata == b"":
                        self.log.error("Error on reading param partition.")
                        return False
                    paramdata = self.ops.enable_ops(paramdata, enable)
                    self.ops.run()
                    if self.fh.cmd_program_buffer(lun, rpartition.sector, paramdata, False):
                        print("Successfully set mode")
                        return True
                    else:
                        self.log.error("Error on writing param partition")
                        return False
                else:
                    fpartitions = res[1]
                    self.log.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for lun in fpartitions:
                        for rpartition in fpartitions[lun]:
                            if self.args["--memory"].lower() == "emmc":
                                self.log.error("\t" + rpartition)
                            else:
                                self.log.error(lun + ":\t" + rpartition)
            else:
                self.log.error("A devicemodel is needed for this command")
        return False
