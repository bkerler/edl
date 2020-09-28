import binascii
import platform
import time
from Library.utils import *
from Library.gpt import gpt
try:
    from Library.oppo import oppo
except Exception as e:
    pass

logger = logging.getLogger(__name__)
from queue import Queue
from threading import Thread


def writefile(wf, q, stop):
    while True:
        data = q.get()
        if len(data) > 0:
            wf.write(data)
            q.task_done()
        if stop() and q.empty():
            break


class asyncwriter():
    def __init__(self, wf):
        self.writequeue = Queue()
        self.worker = Thread(target=writefile, args=(wf, self.writequeue, lambda: self.stopthreads,))
        self.worker.setDaemon(True)
        self.stopthreads = False
        self.worker.start()

    def write(self, data):
        self.writequeue.put_nowait(data)

    def stop(self):
        self.stopthreads = True
        self.writequeue.join()


class qualcomm_firehose:
    class cfg:
        MemoryName = "eMMC"
        TargetName = ""
        Version = ""
        ZLPAwareHost = 1
        SkipStorageInit = 0
        SkipWrite = 0
        MaxPayloadSizeToTargetInBytes = 1048576
        MaxPayloadSizeFromTargetInBytes = 8192
        SECTOR_SIZE_IN_BYTES = 512
        MaxXMLSizeInBytes = 4096
        bit64 = True

    def __init__(self, cdc, xml, cfg, verbose, oppoprjid, serial, skipresponse):
        self.cdc = cdc
        self.xml = xml
        self.cfg = cfg
        self.pk = None
        self.ops = None
        self.serial = serial
        self.oppoprjid = oppoprjid
        self.skipresponse = skipresponse
        logger.setLevel(verbose)
        if verbose==logging.DEBUG:
            fh = logging.FileHandler('log.txt')
            fh.setLevel(logging.DEBUG)
            logger.addHandler(fh)
            # ch = logging.StreamHandler()
            # ch.setLevel(logging.ERROR)
        if self.cfg.MemoryName == "UFS":
            self.cfg.SECTOR_SIZE_IN_BYTES = 4096

    def getstatus(self, resp):
        if "value" in resp:
            value = resp["value"]
            if value == "ACK":
                return True
            else:
                return False
        return True

    def xmlsend(self, data, skipresponse=False):
        self.cdc.write(bytes(data,'utf-8'), self.cfg.MaxXMLSizeInBytes)
        data = bytearray()
        counter = 0
        timeout = 3
        resp = {"value": "NAK"}
        status = False
        if not skipresponse:
            while b"<response" not in data:
                try:
                    tmp = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                    if tmp == b"":
                        counter += 1
                        time.sleep(0.3)
                        if counter > timeout:
                            break
                    data+=tmp
                except Exception as e:
                    logger.error(e)
                    return [False, resp, data]
            try:
                logger.debug("RX:"+data.decode('utf-8'))
            except:
                logger.debug("RX:" + hexlify(data).decode('utf-8'))
            try:
                resp = self.xml.getresponse(data)
                status = self.getstatus(resp)
            except:
                status = True
                logger.debug("Error on getting xml response:" + data.decode('utf-8'))
                return [status, {"value": "NAK"}, data]
        else:
            status = True
        return [status, resp, data]

    def cmd_reset(self):
        data = "<?xml version=\"1.0\" ?><data><power value=\"reset\"/></data>"
        val = self.xmlsend(data)
        try:
            v = None
            while (v != b''):
                v = self.cdc.read()
                if v != b'':
                    resp = self.xml.getlog(v)[0]
                else:
                    break
                print(resp)
        except:
            pass
        if val[0]:
            logger.info("Reset succeeded.")
            return True
        else:
            logger.error("Reset failed.")
            return False

    def cmd_xml(self, filename):
        with open(filename, 'rb') as rf:
            data = rf.read()
            val = self.xmlsend(data)
            if val[0]:
                logger.info("Command succeeded." + str(val[2]))
                return val[2]
            else:
                logger.error("Command failed:" + str(val[2]))
                return val[2]

    def cmd_nop(self):
        data = "<?xml version=\"1.0\" ?><data><nop /></data>"
        val = self.xmlsend(data)
        if val[0]:
            logger.info("Nop succeeded.")
            return self.xml.getlog(val[2])
        else:
            logger.error("Nop failed.")
            return False

    def cmd_getsha256digest(self, physical_partition_number, start_sector, num_partition_sectors):
        data = f"<?xml version=\"1.0\" ?><data><getsha256digest SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\"/>\n</data>"
        val = self.xmlsend(data)
        if val[0]:
            res = self.xml.getlog(val[2])
            for line in res:
                logger.info(line)
            if "Digest " in res:
                return res.split("Digest ")[1]
            else:
                return res
        else:
            logger.error("GetSha256Digest failed.")
            return False

    def cmd_setbootablestoragedrive(self, partition_number):
        data = f"<?xml version=\"1.0\" ?><data>\n<setbootablestoragedrive value=\"{str(partition_number)}\" /></data>"
        val = self.xmlsend(data)
        if val[0]:
            logger.info("Setbootablestoragedrive succeeded.")
            return True
        else:
            logger.error("Setbootablestoragedrive failed: %s" % val[2])
            return False

    def cmd_send(self, content, response=True):
        data = f"<?xml version=\"1.0\" ?><data>\n<{content} /></data>"
        if response:
            val = self.xmlsend(data)
            if val[0] and not b"log value=\"ERROR\"" in val[1]:
                logger.info(f"{content} succeeded.")
                return val[2]
            else:
                logger.error(f"{content} failed.")
                logger.error(f"{val[2]}")
                return False
        else:
            self.xmlsend(data, True)
            return True

    def cmd_patch(self, physical_partition_number, start_sector, byte_offset, value, size_in_bytes, display=True):
        '''
        <patch SECTOR_SIZE_IN_BYTES="512" byte_offset="16" filename="DISK" physical_partition_number="0" size_in_bytes="4" start_sector="NUM_DISK_SECTORS-1." value="0" what="Zero Out Header CRC in Backup Header."/>
        '''

        data = f"<?xml version=\"1.0\" ?><data>\n" + \
               f"<patch SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" byte_offset=\"{byte_offset}\"" + \
               f" filename=\"DISK\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" size_in_bytes=\"{size_in_bytes}\" " + \
               f" start_sector=\"{start_sector}\" " + \
               f" value=\"{value}\" "
        data += f"/>\n</data>"

        if self.ops is not None and "setprojmodel" in self.supported_functions:
            pk, token = self.ops.generatetoken(True)
            data += f"pk=\"{pk}\" token=\"{token}\" "

        rsp = self.xmlsend(data)
        if rsp[0] == True:
            if display:
                logger.info(f"Patch:\n--------------------\n")
                logger.info(rsp[1])
            return True
        else:
            logger.warning("Patch command isn't supported.")
            return False


    def cmd_program(self, physical_partition_number, start_sector, filename, display=True):
        size = os.stat(filename).st_size
        fsize=os.stat(filename).st_size
        fname=os.path.basename(filename)
        with open(filename, "rb") as rf:
            # Make sure we fill data up to the sector size
            num_partition_sectors = size // self.cfg.SECTOR_SIZE_IN_BYTES
            if (size % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
                num_partition_sectors += 1
            if display:
                logger.info(
                    f"\nWriting {fname} to physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
            data = f"<?xml version=\"1.0\" ?><data>\n" + \
                   f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
                   f" num_partition_sectors=\"{num_partition_sectors}\"" + \
                   f" physical_partition_number=\"{physical_partition_number}\"" + \
                   f" start_sector=\"{start_sector}\" "

            if self.ops is not None and "setprojmodel" in self.supported_functions:
                pk, token = self.ops.generatetoken(True)
                data += f"pk=\"{pk}\" token=\"{token}\" "

            data += f"/>\n</data>"
            rsp = self.xmlsend(data)
            pos = 0
            prog = 0
            if display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            if rsp[0]:
                bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                old = 0
                while fsize > 0:
                    wlen=self.cfg.MaxPayloadSizeToTargetInBytes//self.cfg.SECTOR_SIZE_IN_BYTES*self.cfg.SECTOR_SIZE_IN_BYTES
                    if fsize<wlen:
                        wlen=fsize
                    wdata = rf.read(wlen)
                    bytesToWrite -= wlen
                    fsize-=wlen
                    pos += wlen
                    if (wlen % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
                        filllen = (wlen // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES) + self.cfg.SECTOR_SIZE_IN_BYTES
                        wdata += b"\x00" * (filllen - wlen)
                        wlen = len(wdata)

                    self.cdc.write(wdata, wlen)

                    prog = int(float(pos) / float(total) * float(100))
                    if (prog > old):
                        if display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)

                if display and prog != 100:
                    print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                self.cdc.write(b'', self.cfg.MaxPayloadSizeToTargetInBytes)
                time.sleep(0.2)
                info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                if not self.skipresponse:
                    rsp = self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                    if "value" in rsp:
                        if rsp["value"] == "ACK":
                            return True
                        else:
                            logger.error(f"Error:")
                            for line in info:
                                logger.error(line)
                            return False
                    else:
                        return True
                else:
                    return True
            else:
                logger.error(f"Error:{rsp}")
                return False
            return False

    def cmd_program_buffer(self, physical_partition_number, start_sector, wfdata, display=True):
        size=len(wfdata)

        # Make sure we fill data up to the sector size
        num_partition_sectors = size // self.cfg.SECTOR_SIZE_IN_BYTES
        if (size % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
            num_partition_sectors += 1
        if display:
            logger.info(
                f"\nWriting to physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
        data = f"<?xml version=\"1.0\" ?><data>\n" + \
               f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\" "

        if self.ops is not None and "setprojmodel" in self.supported_functions:
            pk, token = self.ops.generatetoken(True)
            data += f"pk=\"{pk}\" token=\"{token}\" "

        data += f"/>\n</data>"
        rsp = self.xmlsend(data)
        pos = 0
        prog = 0
        if display:
            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        if rsp[0]:
            bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            old = 0
            fpos=0
            fsize=len(wfdata)
            while fsize > 0:
                wlen = self.cfg.MaxPayloadSizeToTargetInBytes // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES
                if fsize < wlen:
                    wlen = fsize
                wdata = wfdata[fpos:fpos+wlen]
                bytesToWrite -= wlen
                fsize -= wlen
                pos += wlen
                fpos += wlen
                if (wlen % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
                    filllen = (wlen // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES) + self.cfg.SECTOR_SIZE_IN_BYTES
                    wdata += b"\x00" * (filllen - wlen)
                    wlen = len(wdata)
                self.cdc.write(wdata, wlen)
                prog = int(float(pos) / float(total) * float(100))
                if (prog > old):
                    if display:
                        print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)

            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            self.cdc.write(b'', self.cfg.MaxPayloadSizeToTargetInBytes)
            time.sleep(0.2)
            info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
            rsp = self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
            if "value" in rsp:
                if rsp["value"] == "ACK":
                    return True
                else:
                    logger.error(f"Error:")
                    for line in info:
                        logger.error(line)
                    return False
            else:
                return True
        else:
            logger.error(f"Error:{rsp}")
            return False
        return False

    def cmd_erase(self, physical_partition_number, start_sector, num_partition_sectors, display=True):
        if display:
            logger.info(
                f"\nErasing from physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
            data = f"<?xml version=\"1.0\" ?><data>\n" + \
                   f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
                   f" num_partition_sectors=\"{num_partition_sectors}\"" + \
                   f" physical_partition_number=\"{physical_partition_number}\"" + \
                   f" start_sector=\"{start_sector}\" "

            if self.ops is not None and "setprojmodel" in self.supported_functions:
                pk, token = self.ops.generatetoken(True)
                data += f"pk=\"{pk}\" token=\"{token}\" "
            data += f"/>\n</data>"

            rsp = self.xmlsend(data)
            empty = b"\x00" * self.cfg.MaxPayloadSizeToTargetInBytes
            pos = 0
            prog = 0
            if display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            if (rsp[0]) == True:
                bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                old = 0
                while (bytesToWrite > 0):
                    wlen = self.cfg.MaxPayloadSizeToTargetInBytes
                    if bytesToWrite < wlen:
                        wlen = bytesToWrite
                    self.cdc.write(empty[0:wlen], self.cfg.MaxPayloadSizeToTargetInBytes)
                    prog = int(float(pos) / float(total) * float(100))
                    if (prog > old):
                        if display:
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    bytesToWrite -= wlen
                    pos += wlen
                if display and prog != 100:
                    print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                self.cdc.write(b'', self.cfg.MaxPayloadSizeToTargetInBytes)
                time.sleep(0.2)
                info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                rsp = self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                if "value" in rsp:
                    if rsp["value"] == "ACK":
                        return True
                    else:
                        logger.error(f"Error:")
                        for line in info:
                            logger.error(line)
                else:
                    return True
            else:
                logger.error(f"Error:{rsp}")
                return False
            return False

    def cmd_read(self, physical_partition_number, start_sector, num_partition_sectors, filename, display=True):
        if display:
            logger.info(
                f"\nReading from physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
        with open(filename, "wb") as wr:
            #wr = asyncwriter(wf)
            data = f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
                   f" num_partition_sectors=\"{num_partition_sectors}\"" + \
                   f" physical_partition_number=\"{physical_partition_number}\"" + \
                   f" start_sector=\"{start_sector}\"/>\n</data>"
            rsp = self.xmlsend(data,self.skipresponse)
            if rsp[0]:
                if "value" in rsp[1]:
                    if rsp[1]["value"] == "NAK":
                        if display:
                            logger.error(rsp[2].decode('utf-8'))
                        return b""
                bytesToRead = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                total = bytesToRead
                dataread = 0
                old = 0
                prog = 0
                if display:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                while bytesToRead > 0:
                    tmp = self.cdc.read(self.cfg.MaxPayloadSizeToTargetInBytes)
                    bytesToRead -= len(tmp)
                    dataread += len(tmp)
                    wr.write(tmp)
                    if display:
                        prog = int(float(dataread) / float(total) * float(100))
                        if (prog > old):
                            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                            old = prog
                if display and prog != 100:
                    print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                # time.sleep(0.2)
                info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                rsp = self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
                #wr.stop()
                if "value" in rsp:
                    if rsp["value"] == "ACK":
                        return tmp
                    else:
                        logger.error(f"Error:")
                        for line in info:
                            logger.error(line)
                        return b""
                else:
                    return tmp
            else:
                logger.error(f"Error:{rsp[1]}")
                return b""

    def cmd_read_buffer(self, physical_partition_number, start_sector, num_partition_sectors, display=True):
        if display:
            logger.info(
                f"\nReading from physical partition {str(physical_partition_number)}, sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
        data = f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\"/>\n</data>"

        rsp = self.xmlsend(data,self.skipresponse)
        resData = bytearray()
        if rsp[0]:
            if "value" in rsp[1]:
                if rsp[1]["value"] == "NAK":
                    if display:
                        logger.error(rsp[2].decode('utf-8'))
                    return b""
            bytesToRead = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = bytesToRead
            dataread = 0
            old = 0
            prog = 0
            if display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            while bytesToRead > 0:
                tmp = self.cdc.read(self.cfg.MaxPayloadSizeToTargetInBytes)
                bytesToRead -= len(tmp)
                dataread += len(tmp)
                resData += tmp
                prog = int(float(dataread) / float(total) * float(100))
                if (prog > old):
                    if display:
                        print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog
            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            # time.sleep(0.2)
            info = self.xml.getlog(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
            rsp = self.xml.getresponse(self.cdc.read(self.cfg.MaxXMLSizeInBytes))
            if "value" in rsp:
                if rsp["value"] == "ACK":
                    return resData
                else:
                    logger.error(f"Error:")
                    for line in info:
                        logger.error(line)
                    return b""
            else:
                return resData
        else:
            logger.error(f"Error:{rsp[2]}")
            return b""
        return resData  #Do not remove, needed for oppo

    def get_gpt(self, lun, gpt_num_part_entries, gpt_part_entry_size, gpt_part_entry_start_lba):
        data = self.cmd_read_buffer(lun, 0, 2, False)
        if data == b"":
            return None, None
        guid_gpt = gpt(
            num_part_entries=gpt_num_part_entries,
            part_entry_size=gpt_part_entry_size,
            part_entry_start_lba=gpt_part_entry_start_lba,
        )
        header = guid_gpt.parseheader(data, self.cfg.SECTOR_SIZE_IN_BYTES)
        if "first_usable_lba" in header:
            sectors = header["first_usable_lba"]
            if sectors==0:
                return None, None
            data = self.cmd_read_buffer(lun, 0, sectors, False)
            if data==b"":
                return None, None
            guid_gpt.parse(data, self.cfg.SECTOR_SIZE_IN_BYTES)
            return data, guid_gpt
        else:
            return None, None

    def get_backup_gpt(self, lun, gpt_num_part_entries, gpt_part_entry_size, gpt_part_entry_start_lba):
        data = self.cmd_read_buffer(lun, 0, 2, False)
        if data == b"":
            return None
        guid_gpt = gpt(
            num_part_entries=gpt_num_part_entries,
            part_entry_size=gpt_part_entry_size,
            part_entry_start_lba=gpt_part_entry_start_lba,
        )
        header = guid_gpt.parseheader(data, self.cfg.SECTOR_SIZE_IN_BYTES)
        if "backup_lba" in header:
            sectors = header["first_usable_lba"] - 1
            data = self.cmd_read_buffer(lun, header["backup_lba"], sectors, False)
            if data==b"":
                return None
            return data
        else:
            return None

    def connect(self, lvl):
        v = b'-1'
        if lvl != 1:
            if platform.system() == 'Windows':
                self.cdc.timeout = 10
            else:
                self.cdc.timeout = 10
            info = []
            while v != b'':
                try:
                    v = self.cdc.read()
                    if v == b'':
                        break
                    data = self.xml.getlog(v)
                    if len(data) > 0:
                        info.append(data[0])
                    if info == []:
                        break
                except:
                    break
            supfunc=False
            if info==[]:
                info=self.cmd_nop()
            if info==[]:
                logger.info("No supported functions detected, configuring qc generic commands")
                self.supported_functions = ['configure','program','firmwarewrite','patch','setbootablestoragedrive','ufs','emmc','power','benchmark','read','getstorageinfo','getcrc16digest','getsha256digest','erase','peek','poke','nop','xml']
            else:
                self.supported_functions = []
                for line in info:
                    if "chip serial num" in line.lower():
                        logger.info(line)
                        try:
                            serial = line.split("0x")[1][:-1]
                            self.serial = int(serial,16)
                        except:
                            serial = line.split(": ")[2]
                            self.serial = int(serial.split(" ")[0])
                    if supfunc and "end of supported functions" not in line.lower():
                        rs = line.replace("\n", "")
                        if rs != "":
                            self.supported_functions.append(rs)
                    if "supported functions" in line.lower():
                        supfunc = True

            '''
            self.supported_functions = []
            for line in info:
                if "chip serial num" in line.lower():
                    logger.info(line)
                    try:
                        serial=line.split(": ")[1]
                        self.serial=int(serial.split(" ")[0])
                    except:
                        serial=line.split(": ")[2]
                        self.serial=int(serial.split(" ")[0])
                if supfunc and "end of supported functions" not in line.lower():
                    rs=line.replace("\n", "")
                    if rs!="":
                        self.supported_functions.append(rs)
                if "supported functions" in line.lower():
                    supfunc = True
            '''
        try:
            self.ops = oppo(self,projid=self.oppoprjid, serials=[self.serial, self.serial])
        except Exception as e:
            self.ops = None
        data=self.cdc.read() #logbuf
        try:
            logger.info(data.decode('utf-8'))
        except:
            pass
        connectcmd = f"<?xml version =\"1.0\" ?><data>" + \
                     f"<configure MemoryName=\"{self.cfg.MemoryName}\" ZLPAwareHost=\"{str(self.cfg.ZLPAwareHost)}\" " + \
                     f"SkipStorageInit=\"{str(int(self.cfg.SkipStorageInit))}\" SkipWrite=\"{str(int(self.cfg.SkipWrite))}\" " + \
                     f"MaxPayloadSizeToTargetInBytes=\"{str(self.cfg.MaxPayloadSizeToTargetInBytes)}\"/>" + \
                     "</data>"
        '''
                "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><response value=\"ACK\" MinVersionSupported=\"1\"" \
                "MemoryName=\"eMMC\" MaxPayloadSizeFromTargetInBytes=\"4096\" MaxPayloadSizeToTargetInBytes=\"1048576\" " \
                "MaxPayloadSizeToTargetInBytesSupported=\"1048576\" MaxXMLSizeInBytes=\"4096\" Version=\"1\" TargetName=\"8953\" />" \
                "</data>"
        '''
        rsp = self.xmlsend(connectcmd)

        if rsp[0] == True:
            data=self.cdc.read()
            if not "MemoryName" in rsp[1]:
                #print(rsp[1])
                rsp[1]["MemoryName"]="eMMC"
            if not "MaxXMLSizeInBytes" in rsp[1]:
                rsp[1]["MaxXMLSizeInBytes"]="4096"
                logging.warning("Couldn't detect MaxPayloadSizeFromTargetinBytes")
            if not "MaxPayloadSizeToTargetInBytes" in rsp[1]:
                rsp[1]["MaxPayloadSizeToTargetInBytes"] = "1038576"
            if not "MaxPayloadSizeToTargetInBytesSupported" in rsp[1]:
                rsp[1]["MaxPayloadSizeToTargetInBytesSupported"] = "1038576"
            self.cfg.MemoryName = rsp[1]["MemoryName"]
            self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp[1]["MaxPayloadSizeToTargetInBytes"])
            self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(rsp[1]["MaxPayloadSizeToTargetInBytesSupported"])
            self.cfg.MaxXMLSizeInBytes = int(rsp[1]["MaxXMLSizeInBytes"])
            if "MaxPayloadSizeFromTargetInBytes" in rsp[1]:
                self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp[1]["MaxPayloadSizeFromTargetInBytes"])
            else:
                self.cfg.MaxPayloadSizeFromTargetInBytes = self.cfg.MaxXMLSizeInBytes
                logging.warning("Couldn't detect MaxPayloadSizeFromTargetinBytes")
            if "TargetName" in rsp[1]:
                self.cfg.TargetName = rsp[1]["TargetName"]
                if "MSM" not in self.cfg.TargetName:
                    self.cfg.TargetName = "MSM" + self.cfg.TargetName
            else:
                self.cfg.TargetName = "Unknown"
                logger.warning("Couldn't detect TargetName")
            if "Version" in rsp[1]:
                self.cfg.Version = rsp[1]["Version"]
            else:
                self.cfg.Version = 0
                logger.warning("Couldn't detect Version")
        else:
            if "MaxPayloadSizeToTargetInBytes" in rsp[1]:
                try:
                    self.cfg.MemoryName = rsp[1]["MemoryName"]
                    self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp[1]["MaxPayloadSizeToTargetInBytes"])
                    self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(rsp[1]["MaxPayloadSizeToTargetInBytesSupported"])
                    self.cfg.MaxXMLSizeInBytes = int(rsp[1]["MaxXMLSizeInBytes"])
                    self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp[1]["MaxPayloadSizeFromTargetInBytes"])
                    self.cfg.TargetName = rsp[1]["TargetName"]
                    if "MSM" not in self.cfg.TargetName:
                        self.cfg.TargetName = "MSM" + self.cfg.TargetName
                    self.cfg.Version = rsp[1]["Version"]
                    if lvl == 0:
                        return self.connect(lvl + 1)
                    else:
                        logger.error(f"Error:{rsp}")
                        exit(0)
                except:
                    pass
        logger.info(f"TargetName={self.cfg.TargetName}")
        logger.info(f"MemoryName={self.cfg.MemoryName}")
        logger.info(f"Version={self.cfg.Version}")
        if self.cfg.MemoryName.lower() == "emmc":
            self.cfg.SECTOR_SIZE_IN_BYTES = 512
        elif self.cfg.MemoryName.lower() == "ufs":
            self.cfg.SECTOR_SIZE_IN_BYTES = 4096
        return self.supported_functions

    # OEM Stuff here below --------------------------------------------------

    def cmd_writeimei(self, imei):
        if len(imei) != 16:
            logger.info("IMEI must be 16 digits")
            return False
        data = "<?xml version=\"1.0\" ?><data><writeIMEI len=\"16\"/></data>"
        val = self.xmlsend(data)
        if val[0] == True:
            logger.info("writeIMEI succeeded.")
            return True
        else:
            logger.error("writeIMEI failed.")
            return False

    def cmd_getstorageinfo(self):
        data = "<?xml version=\"1.0\" ?><data><getstorageinfo /></data>"
        val = self.xmlsend(data)
        if val[0] == True:
            logger.info(f"GetStorageInfo:\n--------------------\n")
            logger.info(val[1])
            return True
        else:
            logger.warning("GetStorageInfo command isn't supported.")
            return False

    def cmd_getstorageinfo_string(self):
        data = "<?xml version=\"1.0\" ?><data><getstorageinfo /></data>"
        val = self.xmlsend(data)
        resp = ""
        if val[0] == True:
            resp += (f"GetStorageInfo:\n--------------------\n")
            resp += (val[1])
            return resp
        else:
            return ""

    def cmd_poke(self, address, data, filename="", info=False):
        rf = None
        if filename != "":
            rf = open(filename, "rb")
            SizeInBytes = os.stat(filename).st_size
        else:
            SizeInBytes = len(data)
        if info:
            logger.info(f"Poke: Address({hex(address)}),Size({hex(SizeInBytes)})")
        '''
        <?xml version="1.0" ?><data><poke address64="1048576" SizeInBytes="90112" value="0x22 0x00 0x00"/></data>
        '''
        maxsize = 8
        lengthtowrite = SizeInBytes
        if lengthtowrite < maxsize:
            maxsize = lengthtowrite
        pos = 0
        old = 0
        datawritten = 0
        mode = 0
        if info:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        while (lengthtowrite > 0):
            if rf != None:
                content = hex(int(hexlify(rf.read(maxsize)).decode('utf-8'), 16))
            else:
                content = 0
                if lengthtowrite < maxsize:
                    maxsize = lengthtowrite
                for i in range(0, maxsize):
                    content = (content << 8) + int(
                        hexlify(data[pos + maxsize - i - 1:pos + maxsize - i]).decode('utf-8'), 16)
                # content=hex(int(hexlify(data[pos:pos+maxsize]).decode('utf-8'),16))
                content = hex(content)
            if mode == 0:
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" size_in_bytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
            else:
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" SizeInBytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
            try:
                self.cdc.write(xdata, self.cfg.MaxXMLSizeInBytes)
            except:
                pass
            addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if (b"SizeInBytes" in addrinfo or b"Invalid parameters" in addrinfo):
                tmp = b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" SizeInBytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
                self.cdc.write(xdata, self.cfg.MaxXMLSizeInBytes)
                addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if b'<response' in addrinfo and 'NAK' in addrinfo:
                    print(f"Error:{addrinfo}")
                    return
            if (b"address" in addrinfo and b"can\'t" in addrinfo):
                tmp = b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                logger.error(f"Error:{addrinfo}")
                return

            addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if b'<response' in addrinfo and b'NAK' in addrinfo:
                print(f"Error:{addrinfo}")
                return
            pos += maxsize
            datawritten += maxsize
            lengthtowrite -= maxsize
            if info:
                prog = int(float(datawritten) / float(SizeInBytes) * float(100))
                if (prog > old):
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog
            if info:
                logger.info("Done writing.")
        return True

    def cmd_peek(self, address, SizeInBytes, filename="", info=False):
        if info:
            logger.info(f"Peek: Address({hex(address)}),Size({hex(SizeInBytes)})")
        wf = None
        if filename != "":
            wf = open(filename, "wb")
        '''
            <?xml version="1.0" ?><data><peek address64="1048576" SizeInBytes="90112" /></data>
            '''
        data = f"<?xml version=\"1.0\" ?><data><peek address64=\"{address}\" size_in_bytes=\"{SizeInBytes}\" /></data>\n"
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
            pass
        addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
        if (b"SizeInBytes" in addrinfo or b"Invalid parameters" in addrinfo):
            tmp = b""
            while b"NAK" not in tmp and b"ACK" not in tmp:
                tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            data = f"<?xml version=\"1.0\" ?><data><peek address64=\"{hex(address)}\" SizeInBytes=\"{hex(SizeInBytes)}\" /></data>"
            self.cdc.write(data, self.cfg.MaxXMLSizeInBytes)
            addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if b'<response' in addrinfo and 'NAK' in addrinfo:
                print(f"Error:{addrinfo}")
                return
        if (b"address" in addrinfo and b"can\'t" in addrinfo):
            tmp = b""
            while b"NAK" not in tmp and b"ACK" not in tmp:
                tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            logger.error(f"Error:{addrinfo}")
            return False

        resp = b""
        dataread = 0
        old = 0
        if info:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        while (True):
            tmp = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if b'<response' in tmp or b"ERROR" in tmp:
                break
            rdata = self.xml.getlog(tmp)[0].replace("0x", "").replace(" ", "")
            try:
                tmp2 = binascii.unhexlify(rdata)
            except:
                print(rdata)
                exit(0)
            dataread += len(tmp2)
            if wf != None:
                wf.write(tmp2)
            else:
                resp += tmp2
            if info:
                prog = int(float(dataread) / float(SizeInBytes) * float(100))
                if (prog > old):
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog

        if wf != None:
            wf.close()
            if b'<response' in tmp and b'ACK' in tmp:
                if info:
                    logger.info(f"Bytes from {hex(address)}, bytes read {hex(dataread)}, written to {filename}.")
                return True
            else:
                logger.error(f"Error:{addrinfo}")
                return False
        else:
            return resp

    def cmd_memcpy(self, destaddress, sourceaddress, size):
        data = self.cmd_peek(sourceaddress, size)
        if data != b"" and data != False:
            if self.cmd_poke(destaddress, data):
                return True
        return False

    def cmd_setprojmodel(self):
        if self.ops is not None:
            pk, token = self.ops.generatetoken(False)
            self.pk = pk
            data = "<?xml version=\"1.0\" ?>\n<data>\n<setprojmodel token=\"" + token + "\" pk=\"" + pk + "\" />\n</data>"
            return self.cmd_rawxml(data,False)
        else:
            print("Setprojmodel command isn't yet implemented")
            return False

    def cmd_demacia(self):
        if self.ops is not None:
            pk, token = self.ops.demacia()
            self.pk = pk
            data = "<?xml version=\"1.0\" ?>\n<data>\n<demacia token=\"" + token + "\" pk=\"" + pk + "\" />\n</data>"
            return self.cmd_rawxml(data,False)
        else:
            print("Demacia command isn't yet implemented")
            return False

    def cmd_rawxml(self, data, response=True):
        if response:
            val = self.xmlsend(data)
            if val[0] == True:
                logger.info(f"{data} succeeded.")
                return val[2]
            else:
                logger.error(f"{data} failed.")
                logger.error(f"{val[2]}")
                return False
        else:
            self.xmlsend(data, False)
            return True
