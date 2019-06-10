import xml.etree.ElementTree as ET
import binascii
import time
import os
from Library.utils import *

class xmlparser():
    def getresponse(self,input):
        lines=input.split(b"<?xml")
        content = {}
        for line in lines:
            if line==b'':
                continue
            line=b"<?xml"+line
            parser = ET.XMLParser(encoding="utf-8")
            tree = ET.fromstring(line, parser=parser)
            e = ET.ElementTree(tree).getroot()
            for atype in e.findall('response'):
                for field in atype.attrib:
                    content[field]=atype.attrib[field]
        return content

    def getlog(self,input):
        lines=input.split(b"<?xml")
        data = ''
        for line in lines:
            if line==b'':
                continue
            line=b"<?xml"+line
            parser = ET.XMLParser(encoding="utf-8")
            tree = ET.fromstring(line, parser=parser)
            e = ET.ElementTree(tree).getroot()
            for atype in e.findall('log'):
                if 'value' in atype.attrib:
                    data+=atype.attrib['value']
        return data

class qualcomm_firehose:
    class cfg:
        MemoryName = "eMMC"
        TargetName = ""
        Version = ""
        ZLPAwareHost = 1
        SkipStorageInit = 0
        SkipWrite = 0
        MaxPayloadSizeToTargetInBytes = 0x100000
        SECTOR_SIZE_IN_BYTES=512
        MaxXMLSizeInBytes=4096
        bit64=True

    def __init__(self,cdc,xml,cfg):
        self.cdc=cdc
        self.xml=xml
        self.cfg=cfg
        if self.cfg.MemoryName=="UFS":
            self.cfg.SECTOR_SIZE_IN_BYTES=4096

    def getstatus(self,resp):
        if "value" in resp:
            value = resp["value"]
            if value == "ACK":
                return True
        return False

    def xmlsend(self,data):
        self.cdc.write(data,self.cfg.MaxXMLSizeInBytes)
        data=bytearray()
        while b"<response" not in data:
            try:
                data+=self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            except:
                break
        resp = self.xml.getresponse(data)
        return [self.getstatus(resp),resp,data]

    def cmd_reset(self):
        data = "<?xml version=\"1.0\" ?><data><power value=\"reset\"/></data>"
        val=self.xmlsend(data)
        if val[0]==True:
            print("Reset succeeded.")
            return True
        else:
            print("Reset failed.")
            return False

    def cmd_xml(self,data):
        val=self.xmlsend(data)
        if val[0]==True:
            print("Command succeeded.")
            print(val[2])
            return val[2]
        else:
            print("Command failed:")
            print(val[2])
            return val[2]

    def cmd_nop(self):
        data="<?xml version=\"1.0\" ?><data><nop /></data>"
        val=self.xmlsend(data)
        if val[0]==True:
            print("Nop succeeded.")
            return True
        else:
            print("Nop failed.")
            return False

    def cmd_getsha256digest(self,physical_partition_number,start_sector,num_partition_sectors):
        data=f"<?xml version=\"1.0\" ?><data><getsha256digest SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\""+\
             f" num_partition_sectors=\"{num_partition_sectors}\""+\
             f" physical_partition_number=\"{physical_partition_number}\""+\
             f" start_sector=\"{start_sector}\"/>\n</data>"
        val=self.xmlsend(data)
        if val[0]==True:
            res = self.xml.getlog(val[2])
            print(res)
            if "Digest " in res:
                return res.split("Digest ")[1]
            else:
                return res
        else:
            print("GetSha256Digest failed.")
            return False

    def cmd_setbootablestoragedrive(self,partition_number):
        data=f"<?xml version=\"1.0\" ?><data>\n<setbootablestoragedrive value=\"{hex(partition_number)}\" /></data>"
        val=self.xmlsend(data)
        if val[0]==True:
            print("Setbootablestoragedrive succeeded.")
            return True
        else:
            print("Setbootablestoragedrive failed.")
            return False


    def cmd_write(self,physical_partition_number,start_sector,filename,Display=True):
        size = os.stat(filename).st_size
        with open(filename,"rb") as rf:
            #Make sure we fill data up to the sector size
            num_partition_sectors=size // self.cfg.SECTOR_SIZE_IN_BYTES
            if (size%self.cfg.SECTOR_SIZE_IN_BYTES)!=0:
                num_partition_sectors+=1
            if Display:
                print(
                    f"\nWriting to physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
            data=f"<?xml version=\"1.0\" ?><data>\n"+\
                 f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\""+\
                 f" num_partition_sectors=\"{num_partition_sectors}\""+\
                 f" physical_partition_number=\"{physical_partition_number}\""+\
                 f" start_sector=\"{start_sector}\"/>\n</data>"
            rsp = self.xmlsend(data)
            pos=0
            prog=0
            if Display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            if (rsp[0]) == True:
                bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                total=self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                old=0
                while (bytesToWrite>0):
                    wdata=rf.read(self.cfg.MaxPayloadSizeToTargetInBytes)
                    wlen=len(wdata)
                    if (wlen % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
                        filllen=(wlen//self.cfg.SECTOR_SIZE_IN_BYTES*self.cfg.SECTOR_SIZE_IN_BYTES)+self.cfg.SECTOR_SIZE_IN_BYTES
                        wdata+=b"\x00"*(filllen-wlen)
                        wlen=len(wdata)
                    self.cdc.write(wdata,self.cfg.MaxPayloadSizeToTargetInBytes)
                    prog = int(float(pos) / float(total) * float(100))
                    if (prog > old):
                        if Display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    bytesToWrite -= wlen
                    pos+=wlen
                    #time.sleep(0.05)
                if Display and prog!=100:
                    print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                self.cdc.write(b'',self.cfg.MaxPayloadSizeToTargetInBytes)
                time.sleep(0.2)
                info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                rsp=self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                if rsp["value"]=="ACK":
                    return True
                else:
                    print(f"Error:{info[1]}")
            else:
                print(f"Error:{rsp}")
                return False
            return False

    def cmd_erase(self,physical_partition_number,start_sector,num_partition_sectors,Display=True):
        if Display:
            print(f"\nErasing from physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
            data=f"<?xml version=\"1.0\" ?><data>\n"+\
                 f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\""+\
                 f" num_partition_sectors=\"{num_partition_sectors}\""+\
                 f" physical_partition_number=\"{physical_partition_number}\""+\
                 f" start_sector=\"{start_sector}\"/>\n</data>"
            rsp = self.xmlsend(data)
            empty = b"\x00" * self.cfg.MaxPayloadSizeToTargetInBytes
            pos=0
            prog=0
            if Display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            if (rsp[0]) == True:
                bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                total=self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                old=0
                while (bytesToWrite>0):
                    wlen=self.cfg.MaxPayloadSizeToTargetInBytes
                    if bytesToWrite<wlen:
                        wlen=bytesToWrite
                    self.cdc.write(empty[0:wlen],self.cfg.MaxPayloadSizeToTargetInBytes)
                    prog = int(float(pos) / float(total) * float(100))
                    if (prog > old):
                        if Display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    bytesToWrite -= wlen
                    pos+=wlen
                    #time.sleep(0.05)
                if Display and prog!=100:
                    print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                self.cdc.write(b'',self.cfg.MaxPayloadSizeToTargetInBytes)
                time.sleep(0.2)
                info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                rsp=self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                if rsp["value"]=="ACK":
                    return True
                else:
                    print(f"Error:{info[1]}")
            else:
                print(f"Error:{rsp}")
                return False
            return False

    def cmd_read_buffer(self,physical_partition_number,start_sector,num_partition_sectors,Display=True):
        if Display:
            print(f"\nReading from physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
        data=f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\""+\
             f" num_partition_sectors=\"{num_partition_sectors}\""+\
             f" physical_partition_number=\"{physical_partition_number}\""+\
             f" start_sector=\"{start_sector}\"/>\n</data>"
        rsp=self.xmlsend(data)
        resData=bytearray()
        if (rsp[0])==True:
            bytesToRead=self.cfg.SECTOR_SIZE_IN_BYTES*num_partition_sectors
            total=bytesToRead
            dataread=0
            old=0
            prog=0
            if Display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            while(bytesToRead>0):
                tmp=self.cdc.read(self.cfg.MaxPayloadSizeToTargetInBytes)
                bytesToRead-=len(tmp)
                dataread+=len(tmp)
                resData+=tmp
                prog = int(float(dataread) / float(total) * float(100))
                if (prog > old):
                    if Display:
                        print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog
            if Display and prog!=100:
                print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            time.sleep(0.2)
            info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
            rsp=self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
            if rsp["value"]=="ACK":
                return resData
            else:
                print(f"Error:{info[1]}")
                return ""
        else:
            print(f"Error:{rsp[2]}")
            return ""
        return ""

    def cmd_read(self,physical_partition_number,start_sector,num_partition_sectors,filename,Display=True):
        if Display:
            print(f"\nReading from physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
        with open(filename,"wb") as wf:
            data=f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\""+\
                 f" num_partition_sectors=\"{num_partition_sectors}\""+\
                 f" physical_partition_number=\"{physical_partition_number}\""+\
                 f" start_sector=\"{start_sector}\"/>\n</data>"
            rsp=self.xmlsend(data)
            if (rsp[0])==True:
                bytesToRead=self.cfg.SECTOR_SIZE_IN_BYTES*num_partition_sectors
                total=bytesToRead
                dataread=0
                old=0
                prog=0
                if Display:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                while(bytesToRead>0):
                    tmp=self.cdc.read(self.cfg.MaxPayloadSizeToTargetInBytes)
                    bytesToRead-=len(tmp)
                    dataread+=len(tmp)
                    #resData+=tmp
                    wf.write(tmp)
                    prog = int(float(dataread) / float(total) * float(100))
                    if (prog > old):
                        if Display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                        old = prog
                    #time.sleep(0.05)
                if Display and prog!=100:
                    print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                time.sleep(0.2)
                info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                rsp = self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                if rsp["value"]=="ACK":
                    return tmp
                else:
                    print(f"Error:{tmp}")
                    return ""
            else:
                print(f"Error:{rsp[1]}")
                return ""
            return ""

    def connect(self,lvl):
        v = b'-1'
        try:
            while v != b'':
                v = self.cdc.read()
                info=self.xml.getlog(v)
                print(info)
        except:
            lvl=lvl
        data=f"<?xml version =\"1.0\" ?><data>"+\
             f"<configure MemoryName=\"{self.cfg.MemoryName}\" ZLPAwareHost=\"{str(self.cfg.ZLPAwareHost)}\" "+\
             f"SkipStorageInit=\"{str(int(self.cfg.SkipStorageInit))}\" SkipWrite=\"{str(int(self.cfg.SkipWrite))}\" "+\
             f"MaxPayloadSizeToTargetInBytes=\"{str(self.cfg.MaxPayloadSizeToTargetInBytes)}\"/>"+\
             "</data>"
        '''
                "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><response value=\"ACK\" MinVersionSupported=\"1\"" \
                "MemoryName=\"eMMC\" MaxPayloadSizeFromTargetInBytes=\"4096\" MaxPayloadSizeToTargetInBytes=\"1048576\" " \
                "MaxPayloadSizeToTargetInBytesSupported=\"1048576\" MaxXMLSizeInBytes=\"4096\" Version=\"1\" TargetName=\"8953\" />" \
                "</data>"
        '''
        rsp=self.xmlsend(data)
        try:
            self.cdc.read()
        except:
            lvl=lvl

        if rsp[0]==True:
            self.cfg.MemoryName=rsp[1]["MemoryName"]
            self.cfg.MaxPayloadSizeToTargetInBytes=int(rsp[1]["MaxPayloadSizeToTargetInBytes"])
            self.cfg.MaxPayloadSizeToTargetInBytesSupported=int(rsp[1]["MaxPayloadSizeToTargetInBytesSupported"])
            self.cfg.MaxXMLSizeInBytes=int(rsp[1]["MaxXMLSizeInBytes"])
            if "MaxPayloadSizeFromTargetInBytes" in rsp[1]:
                 self.cfg.MaxPayloadSizeFromTargetInBytes=int(rsp[1]["MaxPayloadSizeFromTargetInBytes"])
            else:
                 #print("Unknown cmd structure, please issue this to github: "+str(rsp[1]))
                 self.cfg.MaxPayloadSizeFromTargetInBytes=self.cfg.MaxXMLSizeInBytes
            self.cfg.TargetName=rsp[1]["TargetName"]
            if "MSM" not in self.cfg.TargetName:
                self.cfg.TargetName="MSM"+self.cfg.TargetName
            self.cfg.Version=rsp[1]["Version"]
        else:
            if "MaxPayloadSizeToTargetInBytes" in rsp[1]:
                self.cfg.MemoryName = rsp[1]["MemoryName"]
                self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp[1]["MaxPayloadSizeToTargetInBytes"])
                self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(rsp[1]["MaxPayloadSizeToTargetInBytesSupported"])
                self.cfg.MaxXMLSizeInBytes = int(rsp[1]["MaxXMLSizeInBytes"])
                self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp[1]["MaxPayloadSizeFromTargetInBytes"])
                self.cfg.TargetName = rsp[1]["TargetName"]
                if "MSM" not in self.cfg.TargetName:
                    self.cfg.TargetName = "MSM" + self.cfg.TargetName
                self.cfg.Version = rsp[1]["Version"]
                if lvl==0:
                    return self.connect(lvl+1)
                else:
                    print(f"Error:{rsp}")
                    exit(0)
        print(f"TargetName={self.cfg.TargetName}")
        print(f"MemoryName={self.cfg.MemoryName}")
        print(f"Version={self.cfg.Version}")
        if self.cfg.MemoryName.lower()=="emmc":
            self.cfg.SECTOR_SIZE_IN_BYTES=512
        elif self.cfg.MemoryName.lower()=="ufs":
            self.cfg.SECTOR_SIZE_IN_BYTES = 4096
        return True

# OEM Stuff here below --------------------------------------------------

    def cmd_writeimei(self,imei):
        if len(imei)!=16:
            print("IMEI must be 16 digits")
            return False
        data="<?xml version=\"1.0\" ?><data><writeIMEI len=\"16\"/></data>"
        val=self.xmlsend(data)
        if val[0]==True:
            print("writeIMEI succeeded.")
            return True
        else:
            print("writeIMEI failed.")
            return False

    def cmd_getstorageinfo(self):
        data="<?xml version=\"1.0\" ?><data><getstorageinfo /></data>"
        val=self.xmlsend(data)
        if val[0]==True:
            print(f"GetStorageInfo:\n--------------------\n")
            print(val[1])
            return True
        else:
            print("GetStorageInfo command isn't supported.")
            return False

    def cmd_peek(self,address,SizeInBytes,filename):
        print(f"Peek: Address({hex(address)}),Size({hex(SizeInBytes)})")
        with open(filename,"wb") as wf:
            '''
            <?xml version="1.0" ?><data><peek address64="1048576" SizeInBytes="90112" /></data>
            '''
            data=f"<?xml version=\"1.0\" ?><data><peek address64=\"{address}\" SizeInBytes=\"{SizeInBytes}\" /></data>\n"
            '''
            <?xml version="1.0" encoding="UTF-8" ?><data><log value="Using address 00100000" /></data> 
            <?xml version="1.0" encoding="UTF-8" ?><data><log value="0x22 0x00 0x00 0xEA 0x70 0x00 0x00 0xEA 0x74 0x00 0x00 0xEA 0x78 0x00 0
            x00 0xEA 0x7C 0x00 0x00 0xEA 0x80 0x00 0x00 0xEA 0x84 0x00 0x00 0xEA 0x88 0x00 0x00 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA
            0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0x
            FF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 
            0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF " /></data>
            '''
            try:
                self.cdc.write(data, self.cfg.MaxXMLSizeInBytes)
            except:
                data=data
            addrinfo=self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if (b"size_in_bytes" in addrinfo):
                tmp=b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp+=self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                data = f"<?xml version=\"1.0\" ?><data><peek address64=\"{hex(address)}\" size_in_bytes=\"{hex(SizeInBytes)}\" /></data>"
                self.cdc.write(data, self.cfg.MaxXMLSizeInBytes)
                addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if b'<response' in addrinfo and 'NAK' in addrinfo:
                    print(f"Error:{addrinfo}")
                    return
            if (b"address" in addrinfo and b"can\'t" in addrinfo):
                tmp=b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp+=self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                print(f"Error:{addrinfo}")
                return

            data=bytearray()
            dataread=0
            old=0
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            while (True):
                tmp=self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if b'<response' in tmp or b"ERROR" in tmp:
                    break
                tmp2=binascii.unhexlify(self.xml.getlog(tmp).replace("0x","").replace(" ",""))
                dataread+=len(tmp2)
                wf.write(tmp2)
                prog = int(float(dataread) / float(SizeInBytes) * float(100))
                if (prog > old):
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old=prog

            if b'<response' in tmp and b'ACK' in tmp:
                print(f"Bytes from {hex(address)}, bytes read {hex(dataread)}, written to {filename}.")
                return True
            else:
                print(f"Error:{addrinfo}")
            return True
