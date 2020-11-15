try:
    from Library.Modules.oneplus import oneplus
except Exception as e:
    pass

class modules():
    def __init__(self,fh,serial,supported_functions,log,devicemodel):
        self.fh=fh
        self.serial=serial
        self.supported_functions=supported_functions
        self.log = log
        self.options={}
        self.devicemodel=devicemodel
        self.ops=None
        try:
            self.ops = oneplus(fh=self.fh, projid=self.devicemodel, serial=self.serial,supported_functions=self.supported_functions)
        except Exception as e:
            pass

    def addpatch(self):
        if self.ops!=None:
            return self.ops.addpatch()
        return ""

    def addprogram(self):
        if self.ops!=None:
            return self.ops.addprogram()
        return ""

    def prerun(self):
        if self.ops!=None:
            return self.ops.run()
        return True

    def run(self,mainargs,command,args):
        args=args.split(",")
        options={}
        for i in range(len(args)):
            if "=" in args[i]:
                option=args[i].split("=")
                if len(option)>1:
                    options[option[0]]=option[1]
            else:
                options[args[i]]=True

        if command=="ops":
            if self.devicemodel!=None and self.ops!=None:
                enable=False
                partition = "param"
                if "enable" in options:
                    enable = True
                elif "disable" in options:
                    enable = False
                else:
                    self.log.error("Unknown mode given. Available are: enable, disable.")
                    exit(0)
                res = self.fh.detect_partition(mainargs, partition)
                if res[0] == True:
                    lun = res[1]
                    rpartition = res[2]
                    paramdata = self.fh.cmd_read_buffer(lun, rpartition.sector, rpartition.sectors, False)
                    if paramdata == b"":
                        self.log.error("Error on reading param partition.")
                        exit(1)
                    paramdata = self.ops.enable_ops(paramdata, enable)
                    self.ops.run()
                    if self.fh.cmd_program_buffer(lun, rpartition.sector, paramdata, False):
                        print("Successfully set mode")
                    else:
                        self.log.error("Error on writing param partition")
                else:
                    fpartitions = res[1]
                    self.log.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                    for lun in fpartitions:
                        for rpartition in fpartitions[lun]:
                            if mainargs["--memory"].lower() == "emmc":
                                self.log.error("\t" + rpartition)
                            else:
                                self.log.error(lun + ":\t" + rpartition)
            else:
                self.log.error("A devicemodel is needed for this command")
                exit(0)
        elif command=="oemunlock":
            partition = "config"
            res=self.fh.detect_partition(mainargs, partition)
            if res[0]==True:
                lun=res[1]
                rpartition=res[2]
                offsettopatch=0x7FFFF
                sector=rpartition.sector + (offsettopatch//self.fh.cfg.SECTOR_SIZE_IN_BYTES)
                offset=offsettopatch%self.fh.cfg.SECTOR_SIZE_IN_BYTES
                value=0x1
                size_in_bytes=1
                if self.fh.cmd_patch(lun, sector, offset, value, size_in_bytes, True):
                    print(f"Patched sector {str(rpartition.sector)}, offset {str(offset)} with value {value}, size in bytes {size_in_bytes}.")
                else:
                	print(f"Error on writing sector {str(rpartition.sector)}, offset {str(offset)} with value {value}, size in bytes {size_in_bytes}.")
            else:
                fpartitions=res[1]
                self.log.error(f"Error: Couldn't detect partition: {partition}\nAvailable partitions:")
                for lun in fpartitions:
                    for rpartition in fpartitions[lun]:
                        if mainargs["--memory"].lower() == "emmc":
                            self.log.error("\t" + rpartition)
                        else:
                            self.log.error(lun + ":\t" + rpartition)
        exit(0)
