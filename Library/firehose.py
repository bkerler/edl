import binascii
import platform
import time
import json
from struct import unpack
from binascii import hexlify
from Library.utils import *
from Library.gpt import gpt
from Library.sparse import QCSparse

try:
    from Library.Modules.init import modules as init_modules
except ImportError as e:
    init_modules = None

from queue import Queue
from threading import Thread


class nand_partition:
    partentries = []

    def __init__(self, parent, printer=None):
        if printer is None:
            self.printer = print
        else:
            self.printer = printer
        self.partentries = []
        self.partitiontblsector = None
        self.parent = parent
        self.storage_info = {}

    def parse(self, partdata):
        self.partentries = []

        class partf:
            sector = 0
            sectors = 0
            name = ""
            attr1 = 0
            attr2 = 0
            attr3 = 0
            which_flash = 0

        magic1, magic2, version, numparts = unpack("<IIII", partdata[0:0x10])
        if magic1 == 0x55EE73AA or magic2 == 0xE35EBDDB:
            data = partdata[0x10:]
            for i in range(0, len(data) // 0x1C):
                name, offset, length, attr1, attr2, attr3, which_flash = unpack("16sIIBBBB",
                                                                                data[i * 0x1C:(i * 0x1C) + 0x1C])
                if name[1] != 0x3A:
                    break
                np = partf()
                np.name = name[2:].rstrip(b"\x00").decode('utf-8').lower()
                np.sector = offset * self.parent.cfg.block_size // self.parent.cfg.SECTOR_SIZE_IN_BYTES
                np.sectors = (length & 0xFFFF) * self.parent.cfg.block_size // self.parent.cfg.SECTOR_SIZE_IN_BYTES
                np.attr1 = attr1
                np.attr2 = attr2
                np.attr3 = attr3
                np.which_flash = which_flash
                self.partentries.append(np)
            return True
        return False

    def print(self):
        self.printer("Name            Offset\t\tLength\t\tAttr\t\t\tFlash")
        self.printer("-------------------------------------------------------------")
        for partition in self.partentries:
            name = partition.name
            for i in range(0x10 - len(partition.name)):
                name += " "
            offset = partition.sector * self.parent.cfg.SECTOR_SIZE_IN_BYTES
            length = partition.sectors * self.parent.cfg.SECTOR_SIZE_IN_BYTES
            attr1 = partition.attr1
            attr2 = partition.attr2
            attr3 = partition.attr3
            which_flash = partition.which_flash
            self.printer(
                f"{name}\t%08X\t%08X\t{hex(attr1)}/{hex(attr2)}/{hex(attr3)}\t{which_flash}" % (offset, length))


def writefile(wf, q, stop):
    while True:
        data = q.get()
        if len(data) > 0:
            wf.write(data)
            q.task_done()
        if stop() and q.empty():
            break


class asyncwriter:
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


class firehose(metaclass=LogBase):
    class cfg:
        TargetName = ""
        Version = ""
        ZLPAwareHost = 1
        SkipStorageInit = 0
        SkipWrite = 0
        MaxPayloadSizeToTargetInBytes = 1048576
        MaxPayloadSizeFromTargetInBytes = 8192
        MaxXMLSizeInBytes = 4096
        bit64 = True

        total_blocks = 0
        block_size = 0
        SECTOR_SIZE_IN_BYTES = 0
        MemoryName = "eMMC"
        prod_name = "Unknown"
        maxlun = 99

    def __init__(self, cdc, xml, cfg, loglevel, devicemodel, serial, skipresponse, luns, args):
        self.cdc = cdc
        self.lasterror = b""
        self.loglevel = loglevel
        self.args = args
        self.xml = xml
        self.cfg = cfg
        self.pk = None
        self.modules = None
        self.serial = serial
        self.devicemodel = devicemodel
        self.skipresponse = skipresponse
        self.luns = luns
        self.supported_functions = []
        self.lunsizes = {}
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.debug = self.__logger.debug
        self.warning = self.__logger.warning

        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)
        self.nandparttbl = None
        self.nandpart = nand_partition(parent=self, printer=print)

    def detect_partition(self, arguments, partitionname):
        fpartitions = {}
        for lun in self.luns:
            lunname = "Lun" + str(lun)
            fpartitions[lunname] = []
            data, guid_gpt = self.get_gpt(lun, int(arguments["--gpt-num-part-entries"]),
                                          int(arguments["--gpt-part-entry-size"]),
                                          int(arguments["--gpt-part-entry-start-lba"]))
            if guid_gpt is None:
                break
            else:
                for partition in guid_gpt.partentries:
                    fpartitions[lunname].append(partition.name)
                    if partition.name == partitionname:
                        return [True, lun, partition]
        return [False, fpartitions]

    def getstatus(self, resp):
        if "value" in resp:
            value = resp["value"]
            if value == "ACK":
                return True
            else:
                return False
        return True

    def decoder(self, data):
        if isinstance(data, bytes) or isinstance(data, bytearray):
            if data[:5] == b"<?xml":
                try:
                    rdata = ""
                    for line in data.split(b"\n"):
                        try:
                            rdata += line.decode('utf-8') + "\n"
                        except Exception:
                            rdata += hexlify(line).decode('utf-8') + "\n"
                    return rdata
                except Exception:
                    pass
        return data

    def xmlsend(self, data, skipresponse=False):
        if isinstance(data, bytes) or isinstance(data, bytearray):
            self.cdc.write(data, self.cfg.MaxXMLSizeInBytes)
        else:
            self.cdc.write(bytes(data, 'utf-8'), self.cfg.MaxXMLSizeInBytes)
        # time.sleep(0.01)
        rdata = bytearray()
        counter = 0
        timeout = 30
        resp = {"value": "NAK"}
        if not skipresponse:
            while b"<response" not in rdata:
                try:
                    tmp = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                    if tmp == b"":
                        counter += 1
                        time.sleep(0.05)
                        if counter > timeout:
                            break
                    rdata += tmp
                except Exception as e:
                    self.error(e)
                    return [False, resp, data]
            try:
                if b"raw hex token" in rdata:
                    rdata = rdata
                try:
                    resp = self.xml.getresponse(rdata)
                except Exception:
                    rdata = bytes(self.decoder(rdata), 'utf-8')
                    resp = self.xml.getresponse(rdata)
                status = self.getstatus(resp)
            except Exception as e:
                status = True
                self.debug(str(e))
                if isinstance(rdata, bytes) or isinstance(rdata, bytearray):
                    try:
                        self.debug("Error on getting xml response:" + rdata.decode('utf-8'))
                    except Exception:
                        self.debug("Error on getting xml response:" + hexlify(rdata).decode('utf-8'))
                elif isinstance(rdata, str):
                    self.debug("Error on getting xml response:" + rdata)
                return [status, {"value": "NAK"}, rdata]
        else:
            status = True
            resp = {"value": "ACK"}
        return [status, resp, rdata]

    def cmd_reset(self):
        data = "<?xml version=\"1.0\" ?><data><power value=\"reset\"/></data>"
        val = self.xmlsend(data)
        try:
            v = None
            while v != b'':
                v = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if v != b'':
                    resp = self.xml.getlog(v)[0]
                else:
                    break
                print(resp)
        except Exception as err:
            self.error(str(err))
            pass
        if val[0]:
            self.info("Reset succeeded.")
            return True
        else:
            self.error("Reset failed.")
            return False

    def cmd_xml(self, filename):
        with open(filename, 'rb') as rf:
            data = rf.read()
            val = self.xmlsend(data)
            if val[0]:
                self.info("Command succeeded." + str(val[2]))
                return val[2]
            else:
                self.error("Command failed:" + str(val[2]))
                return val[2]

    def cmd_nop(self):
        data = "<?xml version=\"1.0\" ?><data><nop /></data>"
        val = self.xmlsend(data)
        if val[0] and val[1] != {}:
            self.info("Nop succeeded.")
            return self.xml.getlog(val[2])
        else:
            self.error("Nop failed.")
            return False

    def cmd_getsha256digest(self, physical_partition_number, start_sector, num_partition_sectors):
        data = f"<?xml version=\"1.0\" ?><data><getsha256digest" + \
               f" SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\"/>\n</data>"
        val = self.xmlsend(data)
        if val[0]:
            res = self.xml.getlog(val[2])
            for line in res:
                self.info(line)
            if "Digest " in res:
                return res.split("Digest ")[1]
            else:
                return res
        else:
            self.error("GetSha256Digest failed.")
            return False

    def cmd_setbootablestoragedrive(self, partition_number):
        data = f"<?xml version=\"1.0\" ?><data>\n<setbootablestoragedrive value=\"{str(partition_number)}\" /></data>"
        val = self.xmlsend(data)
        if val[0]:
            self.info("Setbootablestoragedrive succeeded.")
            return True
        else:
            self.error("Setbootablestoragedrive failed: %s" % val[2])
            return False

    def cmd_send(self, content, response=True):
        data = f"<?xml version=\"1.0\" ?><data>\n<{content} /></data>"
        if response:
            val = self.xmlsend(data)
            if val[0] and b"log value=\"ERROR\"" not in val[1]:
                return val[2]
            else:
                self.error(f"{content} failed.")
                self.error(f"{val[2]}")
                return val[1]
        else:
            self.xmlsend(data, True)
            return True

    def cmd_patch(self, physical_partition_number, start_sector, byte_offset, value, size_in_bytes, display=True):
        """
        <patch SECTOR_SIZE_IN_BYTES="512" byte_offset="16" filename="DISK" physical_partition_number="0"
        size_in_bytes="4" start_sector="NUM_DISK_SECTORS-1." value="0" what="Zero Out Header CRC in Backup Header."/>
        """

        data = f"<?xml version=\"1.0\" ?><data>\n" + \
               f"<patch SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" byte_offset=\"{byte_offset}\"" + \
               f" filename=\"DISK\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" size_in_bytes=\"{size_in_bytes}\" " + \
               f" start_sector=\"{start_sector}\" " + \
               f" value=\"{value}\" "
        if self.modules is not None:
            data += self.modules.addpatch()
        data += f"/>\n</data>"

        rsp = self.xmlsend(data)
        if rsp[0]:
            if display:
                self.info(f"Patch:\n--------------------\n")
                self.info(rsp[1])
            return True
        else:
            self.error(f"Error:{rsp}")
            return False

    def wait_for_data(self):
        tmp = bytearray()
        timeout = 0
        while b'response value' not in tmp:
            res = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if res == b'':
                timeout += 1
                if timeout == 4:
                    break
                time.sleep(0.1)
            tmp += res
        return tmp

    def cmd_program(self, physical_partition_number, start_sector, filename, display=True):
        size = os.stat(filename).st_size
        sparse = QCSparse(filename, self.loglevel)
        sparseformat = False
        if sparse.readheader():
            sparseformat = True
            size = sparse.getsize()
        fsize = size
        with open(filename, "rb") as rf:
            # Make sure we fill data up to the sector size
            num_partition_sectors = size // self.cfg.SECTOR_SIZE_IN_BYTES
            if (size % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
                num_partition_sectors += 1
            if display:
                self.info(f"\nWriting to physical partition {str(physical_partition_number)}, " +
                          f"sector {str(start_sector)}, sectors {str(num_partition_sectors)}")

            data = f"<?xml version=\"1.0\" ?><data>\n" + \
                   f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
                   f" num_partition_sectors=\"{num_partition_sectors}\"" + \
                   f" physical_partition_number=\"{physical_partition_number}\"" + \
                   f" start_sector=\"{start_sector}\" "
            if self.modules is not None:
                data += self.modules.addprogram()
            data += f"/>\n</data>"
            rsp = self.xmlsend(data, self.skipresponse)
            pos = 0
            prog = 0
            if display:
                print_progress(prog, 100, prefix='Progress:', suffix='Complete (Sector %d)' % start_sector,
                               bar_length=50)
            if rsp[0]:
                bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
                old = 0
                while fsize > 0:
                    wlen = self.cfg.MaxPayloadSizeToTargetInBytes // self.cfg.SECTOR_SIZE_IN_BYTES \
                           * self.cfg.SECTOR_SIZE_IN_BYTES
                    wlen = min(fsize, wlen)
                    if sparseformat:
                        wdata = sparse.read(wlen)
                    else:
                        wdata = rf.read(wlen)
                    bytesToWrite -= wlen
                    fsize -= wlen
                    pos += wlen
                    pv = wlen % self.cfg.SECTOR_SIZE_IN_BYTES
                    if pv != 0:
                        filllen = (wlen // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES) + \
                                  self.cfg.SECTOR_SIZE_IN_BYTES
                        wdata += b"\x00" * (filllen - wlen)
                        wlen = len(wdata)

                    self.cdc.write(wdata, wlen)

                    prog = int(float(pos) / float(total) * float(100))
                    if prog > old:
                        if display:
                            print_progress(prog, 100, prefix='Progress:',
                                           suffix='Complete (Sector %d)' % (pos // self.cfg.SECTOR_SIZE_IN_BYTES),
                                           bar_length=50)

                self.cdc.write(b'', self.cfg.MaxPayloadSizeToTargetInBytes)
                # time.sleep(0.2)

                wd = self.wait_for_data()
                log = self.xml.getlog(wd)
                rsp = self.xml.getresponse(wd)
                if "value" in rsp:
                    if rsp["value"] != "ACK":
                        self.error(f"Error:")
                        for line in log:
                            self.error(line)
                        return False
                else:
                    self.error(f"Error:{rsp}")
                    return False
            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Done', bar_length=50)
        return True

    def cmd_program_buffer(self, physical_partition_number, start_sector, wfdata, display=True):
        size = len(wfdata)
        # Make sure we fill data up to the sector size
        num_partition_sectors = size // self.cfg.SECTOR_SIZE_IN_BYTES
        if (size % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
            num_partition_sectors += 1
        if display:
            self.info(f"\nWriting to physical partition {str(physical_partition_number)}, " +
                      f"sector {str(start_sector)}, sectors {str(num_partition_sectors)}")

        data = f"<?xml version=\"1.0\" ?><data>\n" + \
               f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\" "

        if self.modules is not None:
            data += self.modules.addprogram()
        data += f"/>\n</data>"
        rsp = self.xmlsend(data)
        pos = 0
        prog = 0
        # time.sleep(0.01)
        if display:
            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        if rsp[0]:
            bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            old = 0
            fpos = 0
            fsize = len(wfdata)
            while fsize > 0:
                wlen = self.cfg.MaxPayloadSizeToTargetInBytes // self.cfg.SECTOR_SIZE_IN_BYTES \
                       * self.cfg.SECTOR_SIZE_IN_BYTES
                wlen = min(fsize, wlen)
                wdata = wfdata[fpos:fpos + wlen]
                bytesToWrite -= wlen
                fsize -= wlen
                pos += wlen
                fpos += wlen
                if (wlen % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
                    filllen = (wlen // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES) + \
                              self.cfg.SECTOR_SIZE_IN_BYTES
                    wdata += b"\x00" * (filllen - wlen)
                    wlen = len(wdata)
                self.cdc.write(wdata, wlen)
                prog = int(float(pos) / float(total) * float(100))
                if prog > old:
                    if display:
                        print_progress(prog, 100, prefix='Progress:',
                                       suffix='Written (Sector %d)' % (pos // self.cfg.SECTOR_SIZE_IN_BYTES),
                                       bar_length=50)
            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Done', bar_length=50)
            self.cdc.write(b'', self.cfg.MaxPayloadSizeToTargetInBytes)
            # time.sleep(0.2)
            wd = self.wait_for_data()
            info = self.xml.getlog(wd)
            rsp = self.xml.getresponse(wd)
            if "value" in rsp:
                if rsp["value"] != "ACK":
                    self.error(f"Error:")
                    for line in info:
                        self.error(line)
                    return False
        else:
            self.error(f"Error:{rsp}")
            return False
        if display and prog != 100:
            print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        return True

    def cmd_erase(self, physical_partition_number, start_sector, num_partition_sectors, display=True):
        if display:
            self.info(f"\nErasing from physical partition {str(physical_partition_number)}, " +
                      f"sector {str(start_sector)}, sectors {str(num_partition_sectors)}")

        data = f"<?xml version=\"1.0\" ?><data>\n" + \
               f"<program SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\" "
        if self.modules is not None:
            data += self.modules.addprogram()
        data += f"/>\n</data>"

        rsp = self.xmlsend(data, self.skipresponse)
        empty = b"\x00" * self.cfg.MaxPayloadSizeToTargetInBytes
        pos = 0
        prog = 0
        if display:
            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        if rsp[0]:
            bytesToWrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            old = 0
            while bytesToWrite > 0:
                wlen = self.cfg.MaxPayloadSizeToTargetInBytes
                if bytesToWrite < wlen:
                    wlen = bytesToWrite
                self.cdc.write(empty[0:wlen], self.cfg.MaxPayloadSizeToTargetInBytes)
                prog = int(float(pos) / float(total) * float(100))
                if prog > old:
                    if display:
                        print_progress(prog, 100, prefix='Progress:',
                                       suffix='Erased (Sector %d)' % (pos // self.cfg.SECTOR_SIZE_IN_BYTES),
                                       bar_length=50)
                bytesToWrite -= wlen
                pos += wlen
            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Done', bar_length=50)
            self.cdc.write(b'', self.cfg.MaxPayloadSizeToTargetInBytes)
            # time.sleep(0.2)
            res = self.wait_for_data()
            info = self.xml.getlog(res)
            rsp = self.xml.getresponse(res)
            if "value" in rsp:
                if rsp["value"] != "ACK":
                    self.error(f"Error:")
                    for line in info:
                        self.error(line)
                        return False
            else:
                self.error(f"Error:{rsp}")
                return False
        if display and prog != 100:
            print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        return True

    def cmd_read(self, physical_partition_number, start_sector, num_partition_sectors, filename, display=True):
        self.lasterror = b""
        prog = 0
        if display:
            self.info(
                f"\nReading from physical partition {str(physical_partition_number)}, " +
                f"sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)

        with open(filename, "wb") as wr:

            data = f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
                   f" num_partition_sectors=\"{num_partition_sectors}\"" + \
                   f" physical_partition_number=\"{physical_partition_number}\"" + \
                   f" start_sector=\"{start_sector}\"/>\n</data>"

            rsp = self.xmlsend(data, self.skipresponse)
            # time.sleep(0.01)
            if rsp[0]:
                if "value" in rsp[1]:
                    if rsp[1]["value"] == "NAK":
                        if display:
                            self.error(rsp[2].decode('utf-8'))
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
                        if prog > old:
                            print_progress(prog, 100, prefix='Progress:',
                                           suffix='Read (Sector %d)' % (dataread // self.cfg.SECTOR_SIZE_IN_BYTES),
                                           bar_length=50)
                            old = prog
                if display and prog != 100:
                    print_progress(100, 100, prefix='Progress:', suffix='Done', bar_length=50)
                # time.sleep(0.2)
                wd = self.wait_for_data()
                info = self.xml.getlog(wd)
                rsp = self.xml.getresponse(wd)
                if "value" in rsp:
                    if rsp["value"] != "ACK":
                        self.error(f"Error:")
                        for line in info:
                            self.error(line)
                            self.lasterror += bytes(line + "\n", "utf-8")
                        return False
                else:
                    if display:
                        self.error(f"Error:{rsp[2]}")
                        return False
            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            return True

    def cmd_read_buffer(self, physical_partition_number, start_sector, num_partition_sectors, display=True):
        self.lasterror = b""
        prog = 0
        if display:
            self.info(
                f"\nReading from physical partition {str(physical_partition_number)}, " +
                f"sector {str(start_sector)}, sectors {str(num_partition_sectors)}")
            print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)

        data = f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\"/>\n</data>"

        rsp = self.xmlsend(data, self.skipresponse)
        resData = bytearray()
        if rsp[0]:
            if "value" in rsp[1]:
                if rsp[1]["value"] == "NAK":
                    if display:
                        self.error(rsp[2].decode('utf-8'))
                        return -1
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
                if prog > old:
                    if display:
                        print_progress(prog, 100, prefix='Progress:',
                                       suffix='Read (Sector %d)' % (dataread // self.cfg.SECTOR_SIZE_IN_BYTES),
                                       bar_length=50)
                    old = prog
            if display and prog != 100:
                print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)

            wd = self.wait_for_data()
            info = self.xml.getlog(wd)
            rsp = self.xml.getresponse(wd)
            if "value" in rsp:
                if rsp["value"] != "ACK":
                    self.error(f"Error:")
                    for line in info:
                        self.error(line)
                    return resData
            else:
                if len(rsp) > 1:
                    if b"Failed to open the UFS Device" in rsp[2]:
                        self.error(f"Error:{rsp[2]}")
                self.lasterror = rsp[2]
                return resData
        if len(rsp) > 2 and not rsp[0]:
            self.lasterror = rsp[2]
        if display and prog != 100:
            print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        return resData  # Do not remove, needed for oneplus

    def get_gpt(self, lun, gpt_num_part_entries, gpt_part_entry_size, gpt_part_entry_start_lba):
        try:
            data = self.cmd_read_buffer(lun, 0, 2, False)
        except Exception as err:
            self.debug(str(err))
            self.skipresponse = True
            data = self.cmd_read_buffer(lun, 0, 2, False)

        if data == b"" or data == -1:
            return None, None
        magic = unpack("<I", data[0:4])[0]
        if magic == 0x844bdcd1:
            self.info("Nand storage detected. Trying to find partition table")

            if self.nandpart.partitiontblsector is None:
                for sector in range(0, 1024):
                    data = self.cmd_read_buffer(0, sector, 1, False)
                    if data[0:8] != b"\xac\x9f\x56\xfe\x7a\x12\x7f\xcd":
                        continue
                    self.nandpart.partitiontblsector = sector

            if self.nandpart.partitiontblsector is not None:
                data = self.cmd_read_buffer(0, self.nandpart.partitiontblsector + 1, 2, False)
                if self.nandpart.parse(data):
                    return data, self.nandpart
            return None, None
        else:
            guid_gpt = gpt(
                num_part_entries=gpt_num_part_entries,
                part_entry_size=gpt_part_entry_size,
                part_entry_start_lba=gpt_part_entry_start_lba,
                loglevel=self.__logger.level
            )
            try:
                header = guid_gpt.parseheader(data, self.cfg.SECTOR_SIZE_IN_BYTES)
                if "first_usable_lba" in header:
                    sectors = header["first_usable_lba"]
                    if sectors == 0:
                        return None, None
                    if sectors > 34:
                        sectors = 34
                    data = self.cmd_read_buffer(lun, 0, sectors, False)
                    if data == b"":
                        return None, None
                    guid_gpt.parse(data, self.cfg.SECTOR_SIZE_IN_BYTES)
                    return data, guid_gpt
                else:
                    return None, None
            except Exception as err:
                self.debug(str(err))
                return None, None

    def get_backup_gpt(self, lun, gpt_num_part_entries, gpt_part_entry_size, gpt_part_entry_start_lba):
        data = self.cmd_read_buffer(lun, 0, 2, False)
        if data == b"":
            return None
        guid_gpt = gpt(
            num_part_entries=gpt_num_part_entries,
            part_entry_size=gpt_part_entry_size,
            part_entry_start_lba=gpt_part_entry_start_lba,
            loglevel=self.__logger.level
        )
        header = guid_gpt.parseheader(data, self.cfg.SECTOR_SIZE_IN_BYTES)
        if "backup_lba" in header:
            sectors = header["first_usable_lba"] - 1
            data = self.cmd_read_buffer(lun, header["backup_lba"], sectors, False)
            if data == b"":
                return None
            return data
        else:
            return None

    def calc_offset(self, sector, offset):
        sector = sector + (offset // self.cfg.SECTOR_SIZE_IN_BYTES)
        offset = offset % self.cfg.SECTOR_SIZE_IN_BYTES
        return sector, offset

    def getluns(self, argument):
        if argument["--lun"] is not None:
            return [int(argument["--lun"])]

        luns = []
        if self.cfg.MemoryName.lower() == "ufs" or self.cfg.MemoryName.lower() == "spinor":
            for i in range(0, self.cfg.maxlun):
                luns.append(i)
        else:
            luns = [0]
        return luns

    def configure(self, lvl):
        if self.cfg.SECTOR_SIZE_IN_BYTES == 0:
            if self.cfg.MemoryName.lower() == "emmc":
                self.cfg.SECTOR_SIZE_IN_BYTES = 512
            else:
                self.cfg.SECTOR_SIZE_IN_BYTES = 4096

        connectcmd = f"<?xml version =\"1.0\" ?><data>" + \
                     f"<configure MemoryName=\"{self.cfg.MemoryName}\" " + \
                     f"ZLPAwareHost=\"{str(self.cfg.ZLPAwareHost)}\" " + \
                     f"SkipStorageInit=\"{str(int(self.cfg.SkipStorageInit))}\" " + \
                     f"SkipWrite=\"{str(int(self.cfg.SkipWrite))}\" " + \
                     f"MaxPayloadSizeToTargetInBytes=\"{str(self.cfg.MaxPayloadSizeToTargetInBytes)}\"/>" + \
                     "</data>"
        '''
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><response value=\"ACK\" MinVersionSupported=\"1\"" \
        "MemoryName=\"eMMC\" MaxPayloadSizeFromTargetInBytes=\"4096\" MaxPayloadSizeToTargetInBytes=\"1048576\" " \
        "MaxPayloadSizeToTargetInBytesSupported=\"1048576\" MaxXMLSizeInBytes=\"4096\" Version=\"1\" 
        TargetName=\"8953\" />" \
        "</data>"
        '''
        rsp = self.xmlsend(connectcmd)
        if len(rsp) > 1:
            if not rsp[0]:
                if b"Only nop and sig tag can be" in rsp[2]:
                    self.info("Xiaomi EDL Auth detected.")
                    if self.modules.edlauth():
                        rsp = self.xmlsend(connectcmd)
        if len(rsp) > 1:
            if rsp[0] and rsp[1] != {}:  # On Ack
                self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if "MemoryName" not in rsp[1]:
                    # print(rsp[1])
                    rsp[1]["MemoryName"] = "eMMC"
                if "MaxXMLSizeInBytes" not in rsp[1]:
                    rsp[1]["MaxXMLSizeInBytes"] = "4096"
                    self.warning("Couldn't detect MaxPayloadSizeFromTargetinBytes")
                if "MaxPayloadSizeToTargetInBytes" not in rsp[1]:
                    rsp[1]["MaxPayloadSizeToTargetInBytes"] = "1038576"
                if "MaxPayloadSizeToTargetInBytesSupported" not in rsp[1]:
                    rsp[1]["MaxPayloadSizeToTargetInBytesSupported"] = "1038576"
                if rsp[1]["MemoryName"] != self.cfg.MemoryName:
                    self.warning(
                        "Memory type was set as " + self.cfg.MemoryName + " but device reported it is " + rsp[1][
                            "MemoryName"] + " instead.")
                self.cfg.MemoryName = rsp[1]["MemoryName"]
                self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp[1]["MaxPayloadSizeToTargetInBytes"])
                self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(rsp[1]["MaxPayloadSizeToTargetInBytesSupported"])
                self.cfg.MaxXMLSizeInBytes = int(rsp[1]["MaxXMLSizeInBytes"])
                if "MaxPayloadSizeFromTargetInBytes" in rsp[1]:
                    self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp[1]["MaxPayloadSizeFromTargetInBytes"])
                else:
                    self.cfg.MaxPayloadSizeFromTargetInBytes = self.cfg.MaxXMLSizeInBytes
                    self.warning("Couldn't detect MaxPayloadSizeFromTargetinBytes")
                if "TargetName" in rsp[1]:
                    self.cfg.TargetName = rsp[1]["TargetName"]
                    if "MSM" not in self.cfg.TargetName:
                        self.cfg.TargetName = "MSM" + self.cfg.TargetName
                else:
                    self.cfg.TargetName = "Unknown"
                    self.warning("Couldn't detect TargetName")
                if "Version" in rsp[1]:
                    self.cfg.Version = rsp[1]["Version"]
                else:
                    self.cfg.Version = 0
                    self.warning("Couldn't detect Version")
            else:  # on NAK
                if b"ERROR" in rsp[2]:
                    self.error(rsp[2].decode('utf-8'))
                    sys.exit()
                if "MaxPayloadSizeToTargetInBytes" in rsp[1]:
                    try:
                        self.cfg.MemoryName = rsp[1]["MemoryName"]
                        self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp[1]["MaxPayloadSizeToTargetInBytes"])
                        self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(
                            rsp[1]["MaxPayloadSizeToTargetInBytesSupported"])
                        self.cfg.MaxXMLSizeInBytes = int(rsp[1]["MaxXMLSizeInBytes"])
                        self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp[1]["MaxPayloadSizeFromTargetInBytes"])
                        self.cfg.TargetName = rsp[1]["TargetName"]
                        if "MSM" not in self.cfg.TargetName:
                            self.cfg.TargetName = "MSM" + self.cfg.TargetName
                        self.cfg.Version = rsp[1]["Version"]
                        if lvl == 0:
                            return self.configure(lvl + 1)
                        else:
                            self.error(f"Error:{rsp}")
                            sys.exit()
                    except Exception:
                        pass
        self.info(f"TargetName={self.cfg.TargetName}")
        self.info(f"MemoryName={self.cfg.MemoryName}")
        self.info(f"Version={self.cfg.Version}")

        rsp = self.cmd_read_buffer(0, 1, 1, False)
        if rsp == b"" and self.args["--memory"] is None:
            if b"Failed to open the SDCC Device" in self.lasterror:
                self.warning(
                    "Memory type eMMC doesn't seem to match (Failed to init). Trying to use UFS instead.")
                self.cfg.MemoryName = "UFS"
                return self.configure(0)
            if b"ERROR: Failed to initialize (open whole lun) UFS Device slot" in self.lasterror:
                self.warning(
                    "Memory type UFS doesn't seem to match (Failed to init). Trying to use eMMC instead.")
                self.cfg.MemoryName = "eMMC"
                return self.configure(0)
            elif b"Attribute \'SECTOR_SIZE_IN_BYTES\'=4096 must be equal to disk sector size 512" in self.lasterror:
                self.cfg.SECTOR_SIZE_IN_BYTES = 512
            elif b"Attribute \'SECTOR_SIZE_IN_BYTES\'=512 must be equal to disk sector size 4096" in self.lasterror:
                self.cfg.SECTOR_SIZE_IN_BYTES = 4096
        self.luns = self.getluns(self.args)
        return True

    def getlunsize(self, lun):
        if lun not in self.lunsizes:
            try:
                data, guid_gpt = self.get_gpt(lun, int(self.args["--gpt-num-part-entries"]),
                                              int(self.args["--gpt-part-entry-size"]),
                                              int(self.args["--gpt-part-entry-start-lba"]))
                self.lunsizes[lun] = guid_gpt.totalsectors
            except Exception as e:
                self.error(e)
                return -1
        else:
            return self.lunsizes[lun]
        return guid_gpt.totalsectors

    def connect(self):
        v = b'-1'
        if platform.system() == 'Windows':
            self.cdc.timeout = 10
        else:
            self.cdc.timeout = 10
        info = []
        while v != b'':
            try:
                v = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if v == b'':
                    break
                data = self.xml.getlog(v)
                if len(data) > 0:
                    info.append(data[0])
                if not info:
                    break
            except Exception:
                pass
        supfunc = False
        if info == [] or (len(info) > 0 and 'ERROR' in info[0]):
            info = self.cmd_nop()
        if not info:
            self.info("No supported functions detected, configuring qc generic commands")
            self.supported_functions = ['configure', 'program', 'firmwarewrite', 'patch', 'setbootablestoragedrive',
                                        'ufs', 'emmc', 'power', 'benchmark', 'read', 'getstorageinfo',
                                        'getcrc16digest', 'getsha256digest', 'erase', 'peek', 'poke', 'nop', 'xml']
        else:
            self.supported_functions = []
            for line in info:
                if "chip serial num" in line.lower():
                    self.info(line)
                    try:
                        serial = line.split("0x")[1][:-1]
                        self.serial = int(serial, 16)
                    except Exception as e:
                        self.debug(str(e))
                        serial = line.split(": ")[2]
                        self.serial = int(serial.split(" ")[0])
                if supfunc and "end of supported functions" not in line.lower():
                    rs = line.replace("\n", "")
                    if rs != "":
                        rs = rs.replace("INFO: ", "")
                        self.supported_functions.append(rs)
                if "supported functions" in line.lower():
                    supfunc = True

            if len(self.supported_functions) > 1:
                info = "Supported Functions: "
                for line in self.supported_functions:
                    info += line + ","
                self.info(info[:-1])
        try:
            if init_modules is not None:
                self.modules = init_modules(fh=self, serial=self.serial, supported_functions=self.supported_functions,
                                            loglevel=self.__logger.level, devicemodel=self.devicemodel, args=self.args)
            else:
                self.modules = None
        except Exception:
            self.modules = None
        data = self.cdc.read(self.cfg.MaxXMLSizeInBytes)  # logbuf
        try:
            self.info(data.decode('utf-8'))
        except Exception:
            pass

        if not self.supported_functions:
            self.supported_functions = ['configure', 'program', 'firmwarewrite', 'patch', 'setbootablestoragedrive',
                                        'ufs', 'emmc', 'power', 'benchmark', 'read', 'getstorageinfo',
                                        'getcrc16digest', 'getsha256digest', 'erase', 'peek', 'poke', 'nop', 'xml']

        if "getstorageinfo" in self.supported_functions and self.args["--memory"] is None:
            storageinfo = self.cmd_getstorageinfo()
            if storageinfo is not None:
                for info in storageinfo:
                    if "storage_info" in info:
                        try:
                            si = json.loads(info)["storage_info"]
                        except Exception:
                            continue
                        self.info("Storage report:")
                        for sii in si:
                            self.info(f"{sii}:{si[sii]}")
                        if "total_blocks" in si:
                            self.cfg.total_blocks = si["total_blocks"]

                        if "block_size" in si:
                            self.cfg.block_size = si["block_size"]
                        if "page_size" in si:
                            self.cfg.SECTOR_SIZE_IN_BYTES = si["page_size"]
                        if "mem_type" in si:
                            self.cfg.MemoryName = si["mem_type"]
                        if "prod_name" in si:
                            self.cfg.prod_name = si["prod_name"]
                    if "UFS Inquiry Command Output:" in info:
                        self.cfg.prod_name = info.split("Output: ")[1]
                        self.info(info)
                    if "UFS Erase Block Size:" in info:
                        self.cfg.block_size = int(info.split("Size: ")[1], 16)
                        self.info(info)
                    if "UFS Boot" in info:
                        self.cfg.MemoryName = "UFS"
                        self.cfg.SECTOR_SIZE_IN_BYTES = 4096
                    if "UFS Boot Partition Enabled: " in info:
                        self.info(info)
                    if "UFS Total Active LU: " in info:
                        self.cfg.maxlun = int(info.split("LU: ")[1], 16)
        return self.supported_functions

    # OEM Stuff here below --------------------------------------------------

    def cmd_writeimei(self, imei):
        if len(imei) != 16:
            self.info("IMEI must be 16 digits")
            return False
        data = "<?xml version=\"1.0\" ?><data><writeIMEI len=\"16\"/></data>"
        val = self.xmlsend(data)
        if val[0]:
            self.info("writeIMEI succeeded.")
            return True
        else:
            self.error("writeIMEI failed.")
            return False

    def cmd_getstorageinfo(self):
        data = "<?xml version=\"1.0\" ?><data><getstorageinfo /></data>"
        val = self.xmlsend(data)
        if val[0]:
            try:
                data = self.xml.getlog(val[2])
                return data
            except Exception:
                return None
        else:
            self.warning("GetStorageInfo command isn't supported.")
            return None

    def cmd_getstorageinfo_string(self):
        data = "<?xml version=\"1.0\" ?><data><getstorageinfo /></data>"
        val = self.xmlsend(data)
        if val[0]:
            self.info(f"GetStorageInfo:\n--------------------\n")
            data = self.xml.getlog(val[2])
            for line in data:
                self.info(line)
            return True
        else:
            self.warning("GetStorageInfo command isn't supported.")
            return False

    def cmd_poke(self, address, data, filename="", info=False):
        rf = None
        if filename != "":
            rf = open(filename, "rb")
            SizeInBytes = os.stat(filename).st_size
        else:
            SizeInBytes = len(data)
        if info:
            self.info(f"Poke: Address({hex(address)}),Size({hex(SizeInBytes)})")
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
        while lengthtowrite > 0:
            if rf is not None:
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
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" " + \
                        f"size_in_bytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
            else:
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" " + \
                        f"SizeInBytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
            try:
                self.cdc.write(xdata, self.cfg.MaxXMLSizeInBytes)
            except Exception as e:
                self.debug(str(e))
                pass
            addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if b"SizeInBytes" in addrinfo or b"Invalid parameters" in addrinfo:
                tmp = b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" " + \
                        f"SizeInBytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
                self.cdc.write(xdata, self.cfg.MaxXMLSizeInBytes)
                addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                if (b'<response' in addrinfo and 'NAK' in addrinfo) or b"Invalid parameters" in addrinfo:
                    self.error(f"Error:{addrinfo}")
                    return False
            if b"address" in addrinfo and b"can\'t" in addrinfo:
                tmp = b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
                self.error(f"Error:{addrinfo}")
                return False

            addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if b'<response' in addrinfo and b'NAK' in addrinfo:
                print(f"Error:{addrinfo}")
                return False
            pos += maxsize
            datawritten += maxsize
            lengthtowrite -= maxsize
            if info:
                prog = int(float(datawritten) / float(SizeInBytes) * float(100))
                if prog > old:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog
            if info:
                self.info("Done writing.")
        return True

    def cmd_peek(self, address, SizeInBytes, filename="", info=False):
        if info:
            self.info(f"Peek: Address({hex(address)}),Size({hex(SizeInBytes)})")
        wf = None
        if filename != "":
            wf = open(filename, "wb")
        '''
            <?xml version="1.0" ?><data><peek address64="1048576" SizeInBytes="90112" /></data>
            '''
        data = f"<?xml version=\"1.0\" ?><data><peek address64=\"{address}\" " + \
               f"size_in_bytes=\"{SizeInBytes}\" /></data>\n"
        '''
            <?xml version="1.0" encoding="UTF-8" ?><data><log value="Using address 00100000" /></data> 
            <?xml version="1.0" encoding="UTF-8" ?><data><log value="0x22 0x00 0x00 0xEA 0x70 0x00 0x00 0xEA 0x74 0x00 
            0x00 0xEA 0x78 0x00 0x00 0xEA 0x7C 0x00 0x00 0xEA 0x80 0x00 0x00 0xEA 0x84 0x00 0x00 0xEA 0x88 0x00 0x00 
            0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 
            0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 
            0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF 
            0xFF 0xEA 0xFE 0xFF 0xFF 0xEA 0xFE 0xFF " /></data>
            '''
        try:
            self.cdc.write(data, self.cfg.MaxXMLSizeInBytes)
        except Exception as err:
            self.debug(str(err))
            pass
        addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
        if b"SizeInBytes" in addrinfo or b"Invalid parameters" in addrinfo:
            tmp = b""
            while b"NAK" not in tmp and b"ACK" not in tmp:
                tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            data = f"<?xml version=\"1.0\" ?><data><peek address64=\"{hex(address)}\" " + \
                   f"SizeInBytes=\"{hex(SizeInBytes)}\" /></data>"
            self.cdc.write(data, self.cfg.MaxXMLSizeInBytes)
            addrinfo = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if (b'<response' in addrinfo and 'NAK' in addrinfo) or b"Invalid parameters" in addrinfo:
                self.error(f"Error:{addrinfo}")
                return False
        if b"address" in addrinfo and b"can\'t" in addrinfo:
            tmp = b""
            while b"NAK" not in tmp and b"ACK" not in tmp:
                tmp += self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            self.error(f"Error:{addrinfo}")
            return False

        resp = b""
        dataread = 0
        old = 0
        if info:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        while True:
            tmp = self.cdc.read(self.cfg.MaxXMLSizeInBytes)
            if b'<response' in tmp or b"ERROR" in tmp:
                break
            rdata = self.xml.getlog(tmp)[0].replace("0x", "").replace(" ", "")
            tmp2 = b""
            try:
                tmp2 = binascii.unhexlify(rdata)
            except Exception:
                print(rdata)
                exit(0)
            dataread += len(tmp2)
            if wf is not None:
                wf.write(tmp2)
            else:
                resp += tmp2
            if info:
                prog = int(float(dataread) / float(SizeInBytes) * float(100))
                if prog > old:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog

        if wf is not None:
            wf.close()
            if b'<response' in tmp and b'ACK' in tmp:
                if info:
                    self.info(f"Bytes from {hex(address)}, bytes read {hex(dataread)}, written to {filename}.")
                return True
            else:
                self.error(f"Error:{addrinfo}")
                return False
        else:
            return resp

    def cmd_memcpy(self, destaddress, sourceaddress, size):
        data = self.cmd_peek(sourceaddress, size)
        if data != b"" and data:
            if self.cmd_poke(destaddress, data):
                return True
        return False

    def cmd_rawxml(self, data, response=True):
        if response:
            val = self.xmlsend(data)
            if val[0]:
                self.info(f"{data} succeeded.")
                return val[2]
            else:
                self.error(f"{data} failed.")
                self.error(f"{val[2]}")
                return False
        else:
            self.xmlsend(data, False)
            return True
