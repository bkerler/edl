#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import binascii
import json
import os.path
import platform
from binascii import hexlify
from queue import Queue
from threading import Thread

from edlclient.Library.Modules.nothing import nothing
from edlclient.Library.gpt import gpt, AB_FLAG_OFFSET, AB_PARTITION_ATTR_SLOT_ACTIVE
from edlclient.Library.sparse import QCSparse
from edlclient.Library.utils import *
from edlclient.Library.utils import progress

rq = Queue()


def writedata(filename, rq):
    pos = 0
    with open(filename, "wb") as wf:
        while True:
            data = rq.get()
            if data is None:
                break
            pos += len(data)
            wf.write(data)
            rq.task_done()


class response:
    resp = False
    data = b""
    error = ""
    log = None

    def __init__(self, resp=False, data=b"", error: str = "", log: dict = ""):
        self.resp = resp
        self.data = data
        self.error = error
        self.log = log


try:
    from edlclient.Library.Modules.init import modules
except ImportError as e:
    pass


class nand_partition:
    partentries = {}

    def __init__(self, parent, printer=None):
        if printer is None:
            self.printer = print
        else:
            self.printer = printer
        self.partentries = {}
        self.partitiontblsector = None
        self.parent = parent
        self.storage_info = {}
        self.totalsectors = None

    def parse(self, partdata):
        self.partentries = {}

        class partf:
            sector = 0
            sectors = 0
            name = ""
            attr1 = 0
            attr2 = 0
            attr3 = 0
            which_flash = 0

        magic1, magic2, version, numparts = unpack("<IIII", partdata[0:0x10])
        if magic1 == 0x55EE73AA and magic2 == 0xE35EBDDB:
            data = partdata[0x10:]
            for i in range(numparts):
                name, offset, length, attr1, attr2, attr3, which_flash = unpack("16sIIBBBB",
                                                                                data[i * 0x1C:(i * 0x1C) + 0x1C])
                np = partf()
                if name[:2] == b"0:":
                    name = name[2:]
                np.name = name.rstrip(b"\x00").decode('utf-8').lower()
                if self.parent.cfg.block_size == 0:
                    np.sector = offset
                    np.sectors = length
                else:
                    np.sector = offset * self.parent.cfg.block_size // self.parent.cfg.SECTOR_SIZE_IN_BYTES
                    np.sectors = (length & 0xFFFF) * self.parent.cfg.block_size // self.parent.cfg.SECTOR_SIZE_IN_BYTES
                np.attr1 = attr1
                np.attr2 = attr2
                np.attr3 = attr3
                np.which_flash = which_flash
                self.partentries[np.name] = np
            if self.parent.cfg.block_size != 0 and self.parent.cfg.total_blocks != 0:
                self.totalsectors = (self.parent.cfg.block_size // self.parent.cfg.SECTOR_SIZE_IN_BYTES) * \
                                    self.parent.cfg.total_blocks
            else:
                sectors = 0
                for part in self.partentries:
                    if self.partentries[part].sector >= sectors:
                        sectors += self.partentries[part].sectors
                self.totalsectors = sectors
            return True
        return False

    def print(self):
        self.printer("Name                Offset\t\tLength\t\tAttr\t\t\tFlash")
        self.printer("-------------------------------------------------------------")
        for selpart in self.partentries:
            partition = self.partentries[selpart]
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
        self.worker = Thread(target=writefile, args=(wf, self.writequeue, lambda: self.stopthreads,), daemon=True)
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
        num_physical = 0
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
        self.prog = 0
        self.progtime = 0
        self.progpos = 0
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

    def detect_partition(self, arguments, partitionname, send_full=False):
        if arguments is None:
            arguments = {
                "--gpt-num-part-entries": 0,
                "--gpt-part-entry-size": 0,
                "--gpt-part-entry-start-lba": 0
            }
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
                if partitionname in guid_gpt.partentries:
                    return [True, lun, data, guid_gpt] if send_full else [True, lun,
                                                                          guid_gpt.partentries[partitionname]]
            for part in guid_gpt.partentries:
                fpartitions[lunname].append(part)
        return [False, fpartitions]

    def getstatus(self, resp):
        if "value" in resp:
            value = resp["value"]
            if value == "ACK" or value == "true":
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
                        except Exception as err:
                            self.debug(str(err))
                            rdata += hexlify(line).decode('utf-8') + "\n"
                    return rdata
                except Exception as err:  # pylint: disable=broad-except
                    self.debug(str(err))
                    pass
        return data

    def xmlsend(self, data, skipresponse=False) -> response:
        self.cdc.flush()
        self.cdc.xmlread = True
        if isinstance(data, bytes) or isinstance(data, bytearray):
            self.cdc.write(data[:self.cfg.MaxXMLSizeInBytes])
        else:
            self.cdc.write(bytes(data, 'utf-8')[:self.cfg.MaxXMLSizeInBytes])
        rdata = bytearray()
        counter = 0
        timeout = 3
        if not skipresponse:
            while b"<response value" not in rdata:
                try:
                    tmp = self.cdc.read(timeout=None)
                    if tmp == b"" in rdata:
                        counter += 1
                        time.sleep(0.05)
                        if counter > timeout:
                            break
                    rdata += tmp
                except Exception as err:
                    self.error(err)
                    return response(resp=False, error=str(err))
            try:
                if b"raw hex token" in rdata:
                    rdata = rdata
                try:
                    resp = self.xml.getresponse(rdata)
                    status = self.getstatus(resp)
                    if "rawmode" in resp:
                        if resp["rawmode"] == "false":
                            if status:
                                log = self.xml.getlog(rdata)
                                return response(resp=status, data=rdata, log=log)
                            else:
                                error = self.xml.getlog(rdata)
                                return response(resp=status, error=error, data=resp, log=error)
                    else:
                        if status:
                            if b"log value=" in rdata:
                                log = self.xml.getlog(rdata)
                                return response(resp=resp, data=rdata, log=log)
                            return response(resp=status, data=rdata)
                except Exception as e:  # pylint: disable=broad-except
                    rdata = bytes(self.decoder(rdata), 'utf-8')
                    resp = self.xml.getresponse(rdata)
                status = self.getstatus(resp)
                if status:
                    return response(resp=True, data=resp)
                else:
                    error = ""
                    if b"<log value" in rdata:
                        error = self.xml.getlog(rdata)
                    return response(resp=False, error=error, data=resp)
            except Exception as err:
                self.debug(str(err))
                if isinstance(rdata, bytes) or isinstance(rdata, bytearray):
                    try:
                        self.debug("Error on getting xml response:" + rdata.decode('utf-8'))
                    except Exception as err:
                        self.debug("Error on getting xml response:" + hexlify(rdata).decode('utf-8') +
                                   ", Error: " + str(err))
                elif isinstance(rdata, str):
                    self.debug("Error on getting xml response:" + rdata)
                return response(resp=False, error=rdata)
        else:
            return response(resp=True, data=rdata)

    def cmd_reset(self, mode="reset"):
        if mode is None:
            mode = "reset"
        data = f'<?xml version="1.0" ?><data><power value="{mode}"/></data>'
        val = self.xmlsend(data)
        try:
            v = None
            while v != b'':
                v = self.cdc.read(timeout=None)
                if v != b'':
                    resp = self.xml.getlog(v)[0]
                else:
                    break
                print(resp)
        except Exception as err:
            self.error(str(err))
            pass
        if val.resp:
            self.info("Reset succeeded.")
            return True
        else:
            self.error("Reset failed: " + val.error)
            return False

    def cmd_xml(self, filename):
        with open(filename, 'rb') as rf:
            data = rf.read()
            val = self.xmlsend(data)
            if val.resp:
                self.info("Command succeeded." + str(val.data))
                return val.data
            else:
                self.error("Command failed:" + str(val.error))
                return val.error

    def cmd_nop(self):
        data = '<?xml version="1.0" ?><data><nop /></data>'
        resp = self.xmlsend(data, True)
        self.debug(resp.data.hex())
        info = b""
        tmp = None
        while tmp != b"":
            tmp = self.cdc.read(timeout=None)
            if tmp == b"":
                break
            info += tmp
        if info != b"":
            self.info("Nop succeeded.")
            return self.xml.getlog(info)
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
        if val.resp:
            res = self.xml.getlog(val.data)
            for line in res:
                self.info(line)
            if "Digest " in res:
                return res.split("Digest ")[1]
            else:
                return res
        else:
            self.error("GetSha256Digest failed: " + val.error)
            return False

    def cmd_setbootablestoragedrive(self, partition_number):
        data = f"<?xml version=\"1.0\" ?><data>\n<setbootablestoragedrive value=\"{str(partition_number)}\" /></data>"
        val = self.xmlsend(data)
        if val.resp:
            self.info("Setbootablestoragedrive succeeded.")
            return True
        else:
            self.error("Setbootablestoragedrive failed: " + val.error)
            return False

    def cmd_send(self, content, responsexml=True):
        data = f"<?xml version=\"1.0\" ?><data>\n<{content} /></data>"
        if responsexml:
            val = self.xmlsend(data)
            if val.resp:
                return val.data
            else:
                self.error(f"{content} failed.")
                self.error(f"{val.error}")
                return val.error
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
        if rsp.resp:
            if display:
                self.info(f"Patch:\n--------------------\n")
                self.info(rsp.data)
            return True
        else:
            self.error(f"Error:{rsp.error}")
            return False

    def wait_for_data(self):
        tmp = bytearray()
        timeout = 0
        while b'response value' not in tmp:
            res = self.cdc.read(timeout=None)
            if res == b'':
                timeout += 1
                if timeout == 4:
                    break
                time.sleep(0.1)
            tmp += res
        return tmp

    def cmd_program(self, physical_partition_number, start_sector, filename, display=True):
        total = os.stat(filename).st_size
        sparse = QCSparse(filename, self.loglevel)
        sparseformat = False
        if sparse.readheader():
            sparseformat = True
            total = sparse.getsize()
        bytestowrite = total
        progbar = progress(self.cfg.SECTOR_SIZE_IN_BYTES)
        with open(filename, "rb") as rf:
            # Make sure we fill data up to the sector size
            num_partition_sectors = total // self.cfg.SECTOR_SIZE_IN_BYTES
            if (total % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
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
            progbar.show_progress(prefix="Write", pos=0, total=total, display=display)
            if rsp.resp:
                while bytestowrite > 0:
                    wlen = min(bytestowrite, self.cfg.MaxPayloadSizeToTargetInBytes)

                    if sparseformat:
                        wdata = sparse.read(wlen)
                    else:
                        wdata = rf.read(wlen)
                    bytestowrite -= wlen

                    if wlen % self.cfg.SECTOR_SIZE_IN_BYTES != 0:
                        filllen = (wlen // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES) + \
                                  self.cfg.SECTOR_SIZE_IN_BYTES
                        wdata += b"\x00" * (filllen - wlen)

                    self.cdc.write(wdata)
                    progbar.show_progress(prefix="Write", pos=total - bytestowrite, total=total, display=display)
                    self.cdc.write(b'')
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
        return True

    def cmd_program_buffer(self, physical_partition_number, start_sector, wfdata, display=True):
        bytestowrite = len(wfdata)
        total = bytestowrite
        # Make sure we fill data up to the sector size
        num_partition_sectors = bytestowrite // self.cfg.SECTOR_SIZE_IN_BYTES
        if (bytestowrite % self.cfg.SECTOR_SIZE_IN_BYTES) != 0:
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
        progbar = progress(self.cfg.SECTOR_SIZE_IN_BYTES)
        progbar.show_progress(prefix="Write", pos=0, total=total, display=display)
        if rsp.resp:
            pos = 0
            while bytestowrite > 0:
                wlen = min(bytestowrite, self.cfg.MaxPayloadSizeToTargetInBytes)

                wrdata = wfdata[pos:pos + wlen]
                pos += wlen
                bytestowrite -= wlen

                if wlen % self.cfg.SECTOR_SIZE_IN_BYTES != 0:
                    filllen = (wlen // self.cfg.SECTOR_SIZE_IN_BYTES * self.cfg.SECTOR_SIZE_IN_BYTES) + \
                              self.cfg.SECTOR_SIZE_IN_BYTES
                    wrdata += b"\x00" * (filllen - wlen)

                self.cdc.write(wrdata)

                progbar.show_progress(prefix="Write", pos=total - bytestowrite, total=total, display=display)
                self.cdc.write(b'')
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
        else:
            self.error(f"Error:{rsp.error}")
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
        bytestowrite = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
        total = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
        progbar = progress(self.cfg.MaxPayloadSizeToTargetInBytes)
        progbar.show_progress(prefix="Erase", pos=0, total=total, display=display)
        if rsp.resp:
            while bytestowrite > 0:
                wlen = min(bytestowrite, self.cfg.MaxPayloadSizeToTargetInBytes)
                self.cdc.write(empty[:wlen])
                progbar.show_progress(prefix="Erase", pos=total - bytestowrite, total=total, display=display)
                bytestowrite -= wlen
                pos += wlen
                self.cdc.write(b'')

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
        else:
            self.error(f"Error:{rsp.error}")
            return False
        return True

    def cmd_read(self, physical_partition_number, start_sector, num_partition_sectors, filename, display=True):
        global rq
        self.lasterror = b""
        progbar = progress(self.cfg.SECTOR_SIZE_IN_BYTES)
        if display:
            self.info(
                f"\nReading from physical partition {str(physical_partition_number)}, " +
                f"sector {str(start_sector)}, sectors {str(num_partition_sectors)}")

        data = f"<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{self.cfg.SECTOR_SIZE_IN_BYTES}\"" + \
               f" num_partition_sectors=\"{num_partition_sectors}\"" + \
               f" physical_partition_number=\"{physical_partition_number}\"" + \
               f" start_sector=\"{start_sector}\"/>\n</data>"

        rsp = self.xmlsend(data, self.skipresponse)
        self.cdc.xmlread = False
        time.sleep(0.01)
        if not rsp.resp:
            if display:
                self.error(rsp.error)
            return b""
        else:
            bytestoread = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = bytestoread
            show_progress = progbar.show_progress
            usb_read = self.cdc.read
            progbar.show_progress(prefix="Read", pos=0, total=total, display=display)
            worker = Thread(target=writedata, args=(filename, rq), daemon=True)
            worker.start()
            while bytestoread > 0:
                if self.cdc.is_serial:
                    maxsize = self.cfg.MaxPayloadSizeFromTargetInBytes
                else:
                    maxsize = 5 * 1024 * 1024
                size = min(maxsize, bytestoread)
                data = usb_read(size)
                if len(data) > 0:
                    rq.put(data)
                    bytestoread -= len(data)
                    show_progress(prefix="Read", pos=total - bytestoread, total=total, display=display)
            rq.put(None)
            worker.join(60)
            self.cdc.xmlread = True
            wd = self.wait_for_data()
            info = self.xml.getlog(wd)
            rsp = self.xml.getresponse(wd)
            if "value" in rsp:
                if rsp["value"] != "ACK":
                    if bytestoread != 0:
                        self.error(f"Error:")
                        for line in info:
                            self.error(line)
                            self.lasterror += bytes(line + "\n", "utf-8")
                    return False
            else:
                if display:
                    self.error(f"Error:{rsp[2]}")
                    return False
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

        progbar = progress(self.cfg.SECTOR_SIZE_IN_BYTES)
        rsp = self.xmlsend(data, self.skipresponse)
        self.cdc.xmlread = False
        resData = bytearray()
        if not rsp.resp:
            if display:
                self.error(rsp.error)
            return rsp
        else:
            bytestoread = self.cfg.SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = bytestoread
            if display:
                progbar.show_progress(prefix="Read", pos=total - bytestoread, total=total, display=display)
            while bytestoread > 0:
                tmp = self.cdc.read(min(self.cdc.maxsize, bytestoread))
                size = len(tmp)
                bytestoread -= size
                resData.extend(tmp)
                progbar.show_progress(prefix="Read", pos=total - bytestoread, total=total, display=display)
            self.cdc.xmlread = True
            wd = self.wait_for_data()
            info = self.xml.getlog(wd)
            rsp = self.xml.getresponse(wd)
            if "value" in rsp:
                if rsp["value"] != "ACK":
                    self.error(f"Error:")
                    for line in info:
                        self.error(line)
                    return response(resp=False, data=resData, error=info)
                elif "rawmode" in rsp:
                    if rsp["rawmode"] == "false":
                        return response(resp=True, data=resData)
            else:
                if len(rsp) > 1:
                    if b"Failed to open the UFS Device" in rsp[2]:
                        self.error(f"Error:{rsp[2]}")
                    self.lasterror = rsp[2]
                return response(resp=False, data=resData, error=rsp[2])
        if rsp["value"] != "ACK":
            self.lasterror = rsp[2]
        if display and prog != 100:
            progbar.show_progress(prefix="Read", pos=total, total=total, display=display)
        resp = rsp["value"] == "ACK"
        return response(resp=resp, data=resData, error=rsp[2])  # Do not remove, needed for oneplus

    def get_gpt(self, lun, gpt_num_part_entries, gpt_part_entry_size, gpt_part_entry_start_lba, start_sector=1):
        try:
            resp = self.cmd_read_buffer(lun, 0, 1, False)
        except Exception as err:
            self.debug(str(err))
            self.skipresponse = True
            resp = self.cmd_read_buffer(lun, 0, 1, False)

        if not resp.resp:
            for line in resp.error:
                self.error(line)
            return None, None
        data = resp.data
        magic = unpack("<I", data[0:4])[0]
        data += self.cmd_read_buffer(lun, start_sector, 1, False).data
        if magic == 0x844bdcd1:
            self.info("Nand storage detected.")
            self.info("Scanning for partition table ...")
            progbar = progress(1)
            if self.nandpart.partitiontblsector is None:
                sector = 0x280
                progbar.show_progress(prefix="Scanning", pos=sector, total=1024, display=True)
                resp = self.cmd_read_buffer(0, sector, 1, False)
                if resp.resp:
                    if resp.data[0:8] in [b"\xac\x9f\x56\xfe\x7a\x12\x7f\xcd", b"\xAA\x73\xEE\x55\xDB\xBD\x5E\xE3"]:
                        progbar.show_progress(prefix="Scanning", pos=1024, total=1024, display=True)
                        self.nandpart.partitiontblsector = sector
                        self.info(f"Found partition table at sector {sector} :)")
                else:
                    self.error("Error on reading partition table data")
                    return None, None
            if self.nandpart.partitiontblsector is not None:
                resp = self.cmd_read_buffer(0, self.nandpart.partitiontblsector + 1, 2, False)
                if resp.resp:
                    if self.nandpart.parse(resp.data):
                        return resp.data, self.nandpart
            else:
                self.error("Couldn't find partition table, but command \"rs\" might still work !")
                sys.exit(0)
            return None, None
        else:
            data = resp.data
            guid_gpt = gpt(
                num_part_entries=gpt_num_part_entries,
                part_entry_size=gpt_part_entry_size,
                part_entry_start_lba=gpt_part_entry_start_lba,
                loglevel=self.__logger.level
            )
            try:
                sectorsize = self.cfg.SECTOR_SIZE_IN_BYTES
                header = guid_gpt.parseheader(data, sectorsize)
                if header.signature == b"EFI PART":
                    part_table_size = header.num_part_entries * header.part_entry_size
                    sectors = part_table_size // self.cfg.SECTOR_SIZE_IN_BYTES
                    if part_table_size % self.cfg.SECTOR_SIZE_IN_BYTES != 0:
                        sectors += 1
                    if sectors == 0:
                        return None, None
                    if sectors > 64:
                        sectors = 64
                    data += self.cmd_read_buffer(lun, header.part_entry_start_lba, sectors, False).data
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
        resp = self.cmd_read_buffer(lun, 0, 2, False)
        if not resp.resp:
            self.error("Error on reading backup gpt")
            return None
        guid_gpt = gpt(
            num_part_entries=gpt_num_part_entries,
            part_entry_size=gpt_part_entry_size,
            part_entry_start_lba=gpt_part_entry_start_lba,
            loglevel=self.__logger.level
        )
        header = guid_gpt.parseheader(resp.data, self.cfg.SECTOR_SIZE_IN_BYTES)
        if "backup_lba" in header:
            sectors = header.first_usable_lba - 1
            data = self.cmd_read_buffer(lun, header.backup_lba, sectors, False)
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
        if self.cfg.MemoryName.lower() == "ufs":
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

        connectcmd = f"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data>" + \
                     f"<configure MemoryName=\"{self.cfg.MemoryName}\" " + \
                     f"Verbose=\"0\" " + \
                     f"AlwaysValidate=\"0\" " + \
                     f"MaxDigestTableSizeInBytes=\"2048\" " + \
                     f"MaxPayloadSizeToTargetInBytes=\"{str(self.cfg.MaxPayloadSizeToTargetInBytes)}\" " + \
                     f"ZLPAwareHost=\"{str(self.cfg.ZLPAwareHost)}\" " + \
                     f"SkipStorageInit=\"{str(int(self.cfg.SkipStorageInit))}\" " + \
                     f"SkipWrite=\"{str(int(self.cfg.SkipWrite))}\"/>" + \
                     "</data>"
        '''
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><response value=\"ACK\" MinVersionSupported=\"1\"" \
        "MemoryName=\"eMMC\" MaxPayloadSizeFromTargetInBytes=\"4096\" MaxPayloadSizeToTargetInBytes=\"1048576\" " \
        "MaxPayloadSizeToTargetInBytesSupported=\"1048576\" MaxXMLSizeInBytes=\"4096\" Version=\"1\"
        TargetName=\"8953\" />" \
        "</data>"
        '''
        rsp = self.xmlsend(connectcmd)
        if not rsp.resp:
            if rsp.error == "":
                try:
                    if "MemoryName" in rsp.data:
                        self.cfg.MemoryName = rsp.data["MemoryName"]
                except TypeError:
                    self.warning("!DEBUG! rsp.data: '%s'" % (rsp.data,))
                    return self.configure(lvl + 1)
                if "MaxPayloadSizeFromTargetInBytes" in rsp.data:
                    self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp.data["MaxPayloadSizeFromTargetInBytes"])
                if "MaxPayloadSizeToTargetInBytes" in rsp.data:
                    self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp.data["MaxPayloadSizeToTargetInBytes"])
                if "MaxPayloadSizeToTargetInBytesSupported" in rsp.data:
                    self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(
                        rsp.data["MaxPayloadSizeToTargetInBytesSupported"])
                if "TargetName" in rsp.data:
                    self.cfg.TargetName = rsp.data["TargetName"]
                return self.configure(lvl + 1)
            for line in rsp.error:
                if "Not support configure MemoryName eMMC" in line:
                    self.info("eMMC is not supported by the firehose loader. Trying UFS instead.")
                    self.cfg.MemoryName = "UFS"
                    return self.configure(lvl + 1)
                elif "Only nop and sig tag can be" in line:
                    self.info("Xiaomi EDL Auth detected.")
                    try:
                        self.modules = modules(fh=self, serial=self.serial,
                                               supported_functions=self.supported_functions,
                                               loglevel=self.__logger.level,
                                               devicemodel=self.devicemodel, args=self.args)
                    except Exception as err:  # pylint: disable=broad-except
                        self.modules = None
                    if self.modules.edlauth():
                        rsp = self.xmlsend(connectcmd)
                        return rsp.resp
                    else:
                        self.error("Error on EDL Authentification")
                        return False
                elif "MaxPayloadSizeToTargetInBytes" in rsp.data:
                    try:
                        self.cfg.MemoryName = rsp.data["MemoryName"]
                        self.cfg.MaxPayloadSizeToTargetInBytes = int(rsp.data["MaxPayloadSizeToTargetInBytes"])
                        self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(
                            rsp.data["MaxPayloadSizeToTargetInBytesSupported"])
                        if "MaxXMLSizeInBytes" in rsp.data:
                            self.cfg.MaxXMLSizeInBytes = int(rsp.data["MaxXMLSizeInBytes"])
                        else:
                            self.cfg.MaxXMLSizeInBytes = 4096
                        if "MaxPayloadSizeFromTargetInBytes" in rsp.data:
                            self.cfg.MaxPayloadSizeFromTargetInBytes = int(rsp.data["MaxPayloadSizeFromTargetInBytes"])
                        else:
                            self.cfg.MaxPayloadSizeFromTargetInBytes = 4096
                        if "TargetName" in rsp.data:
                            self.cfg.TargetName = rsp.data["TargetName"]
                        else:
                            self.cfg.TargetName = "Unknown"
                        if "MSM" not in self.cfg.TargetName:
                            self.cfg.TargetName = "MSM" + self.cfg.TargetName
                        if "Version" in rsp.data:
                            self.cfg.Version = rsp.data["Version"]
                        else:
                            self.cfg.Version = "Unknown"
                        if lvl == 0:
                            return self.configure(lvl + 1)
                        else:
                            self.error(f"Error:{rsp}")
                            sys.exit()
                    except Exception as e:
                        pass
                elif "ERROR" in line or "WARN" in line:
                    if "ERROR" in line:
                        self.error(line)
                        sys.exit()
                    elif "WARN" in line:
                        self.warning(line)
        else:
            info = self.cdc.read(timeout=1)
            if isinstance(rsp.resp, dict):
                field = rsp.resp
                if "MemoryName" not in field:
                    # print(rsp[1])
                    field["MemoryName"] = "eMMC"
                if "MaxXMLSizeInBytes" not in field:
                    field["MaxXMLSizeInBytes"] = "4096"
                    self.warning("Couldn't detect MaxPayloadSizeFromTargetinBytes")
                if "MaxPayloadSizeToTargetInBytes" not in field:
                    field["MaxPayloadSizeToTargetInBytes"] = "1038576"
                if "MaxPayloadSizeToTargetInBytesSupported" not in field:
                    field["MaxPayloadSizeToTargetInBytesSupported"] = "1038576"
                if field["MemoryName"].lower() != self.cfg.MemoryName.lower():
                    self.warning("Memory type was set as " + self.cfg.MemoryName + " but device reported it is " +
                                 field["MemoryName"] + " instead.")
                self.cfg.MemoryName = field["MemoryName"]
                if "MaxPayloadSizeToTargetInBytes" in field:
                    self.cfg.MaxPayloadSizeToTargetInBytes = int(field["MaxPayloadSizeToTargetInBytes"])
                else:
                    self.cfg.MaxPayloadSizeToTargetInBytes = 1048576
                if "MaxPayloadSizeToTargetInBytesSupported" in field:
                    self.cfg.MaxPayloadSizeToTargetInBytesSupported = int(
                        field["MaxPayloadSizeToTargetInBytesSupported"])
                else:
                    self.cfg.MaxPayloadSizeToTargetInBytesSupported = 1048576
                if "MaxXMLSizeInBytes" in field:
                    self.cfg.MaxXMLSizeInBytes = int(field["MaxXMLSizeInBytes"])
                else:
                    self.cfg.MaxXMLSizeInBytes = 4096
                if "MaxPayloadSizeFromTargetInBytes" in field:
                    self.cfg.MaxPayloadSizeFromTargetInBytes = int(field["MaxPayloadSizeFromTargetInBytes"])
                else:
                    self.cfg.MaxPayloadSizeFromTargetInBytes = self.cfg.MaxXMLSizeInBytes
                    self.warning("Couldn't detect MaxPayloadSizeFromTargetinBytes")
                if "TargetName" in field:
                    self.cfg.TargetName = field["TargetName"]
                    if "MSM" not in self.cfg.TargetName:
                        self.cfg.TargetName = "MSM" + self.cfg.TargetName
                else:
                    self.cfg.TargetName = "Unknown"
                    self.warning("Couldn't detect TargetName")
                if "Version" in field:
                    self.cfg.Version = field["Version"]
                else:
                    self.cfg.Version = 0
                    self.warning("Couldn't detect Version")
            self.info(f"TargetName={self.cfg.TargetName}")
            self.info(f"MemoryName={self.cfg.MemoryName}")
            self.info(f"Version={self.cfg.Version}")
            self.info("Trying to read first storage sector...")
            rsp = self.cmd_read_buffer(0, 1, 1, False)
            self.info("Running configure...")
            if not rsp.resp and self.args["--memory"] is None:
                for line in rsp.error:
                    if "Failed to set the IO options" in line:
                        self.warning(
                            "Memory type eMMC doesn't seem to match (Failed to init). Trying to use NAND instead.")
                        self.cfg.MemoryName = "nand"
                        return self.configure(0)
                    elif "Failed to open the SDCC Device" in line:
                        self.warning(
                            "Memory type eMMC doesn't seem to match (Failed to init). Trying to use UFS instead.")
                        self.cfg.MemoryName = "UFS"
                        return self.configure(0)
                    elif "Failed to initialize (open whole lun) UFS Device slot" in line:
                        self.warning(
                            "Memory type UFS doesn't seem to match (Failed to init). Trying to use eMMC instead.")
                        self.cfg.MemoryName = "eMMC"
                        return self.configure(0)
                    elif "Attribute \'SECTOR_SIZE_IN_BYTES\'=4096 must be equal to disk sector size 512" in line \
                            or "different from device sector size (512)" in line:
                        self.cfg.SECTOR_SIZE_IN_BYTES = 512
                        return self.configure(0)
                    elif "Attribute \'SECTOR_SIZE_IN_BYTES\'=512 must be equal to disk sector size 4096" in line \
                            or "different from device sector size (4096)" in line:
                        self.cfg.SECTOR_SIZE_IN_BYTES = 4096
                        return self.configure(0)
            self.parse_storage()
            for function in self.supported_functions:
                if function == "checkntfeature":
                    if type(self.devicemodel) == list:
                        self.devicemodel = self.devicemodel[0]
                    self.nothing = nothing(fh=self, projid=self.devicemodel, serial=self.serial,
                                           supported_functions=self.supported_functions,
                                           loglevel=self.loglevel)
                    if self.nothing is not None:
                        self.nothing.ntprojectverify()
            self.luns = self.getluns(self.args)
            return True

    def getlunsize(self, lun):
        if lun not in self.lunsizes:
            try:
                data, guid_gpt = self.get_gpt(lun, int(self.args["--gpt-num-part-entries"]),
                                              int(self.args["--gpt-part-entry-size"]),
                                              int(self.args["--gpt-part-entry-start-lba"]))
                self.lunsizes[lun] = guid_gpt.totalsectors
            except Exception as err:
                self.error(err)
                return -1
        else:
            return self.lunsizes[lun]
        return guid_gpt.totalsectors

    def get_supported_functions(self):
        supfunc = False
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
                    except Exception as err:  # pylint: disable=broad-except
                        self.debug(str(err))
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
        data = self.cdc.read(timeout=None)
        try:
            self.info(data.decode('utf-8'))
        except Exception as err:  # pylint: disable=broad-except
            self.debug(str(err))
            pass

        if not self.supported_functions:
            self.supported_functions = ['configure', 'program', 'firmwarewrite', 'patch', 'setbootablestoragedrive',
                                        'ufs', 'emmc', 'power', 'benchmark', 'read', 'getstorageinfo',
                                        'getcrc16digest', 'getsha256digest', 'erase', 'peek', 'poke', 'nop', 'xml']

    def connect(self):
        v = b'-1'
        if platform.system() == 'Windows':
            self.cdc.timeout = 50
        elif platform.system() == 'Darwin':
            # must ensure the timeout is enough to fill the buffer we alloc
            # which is 1MB, othwise some data are dropped in the underlying usb libraries
            self.cdc.timeout = 50
        else:
            self.cdc.timeout = 50
        info = []
        while v != b'':
            try:
                v = self.cdc.read(timeout=None)
                if (b"response" in v and b"</data>" in v) or v == b'':
                    break
                data = self.xml.getlog(v)
                if len(data) > 0:
                    info.append(data[0])
                if not info:
                    break
            except Exception as err:  # pylint: disable=broad-except
                pass

        if info == [] or (len(info) > 0 and 'ERROR' in info[0]):
            if len(info) > 0:
                self.debug(info[0])
        if len(info) > 0:
            supfunc = False
            for line in info:
                self.info(line)
                if "chip serial num" in line.lower():
                    try:
                        serial = line.split("0x")[1][:-1]
                        if ")" in serial:
                            serial = serial[:serial.rfind(")")]
                        self.serial = int(serial, 16)
                    except Exception as err:  # pylint: disable=broad-except
                        self.debug(str(err))
                        serial = line.split(": ")[2]
                        self.serial = int(serial.split(" ")[0])
                if supfunc and "end of supported functions" not in line.lower():
                    rs = line.replace("\n", "")
                    if rs != "":
                        rs = rs.replace("INFO: ", "")
                        self.supported_functions.append(rs)
                if "supported functions" in line.lower():
                    supfunc = True
                    if "program" in line.lower():
                        idx = line.find("Functions: ")
                        if idx != -1:
                            v = line[idx + 11:].split(" ")
                            for val in v:
                                if val != "":
                                    self.supported_functions.append(val)
                            supfunc = False
            try:
                if os.path.exists(self.cfg.programmer):
                    data = open(self.cfg.programmer, "rb").read()
                    for cmd in [b"demacia", b"setprojmodel", b"setswprojmodel", b"setprocstart", b"SetNetType",
                                b"checkntfeature"]:
                        if cmd in data:
                            self.supported_functions.append(cmd.decode('utf-8'))
                state = {
                    "supported_functions": self.supported_functions,
                    "programmer": self.cfg.programmer,
                    "serial": self.serial
                }
                if os.path.exists("edl_config.json"):
                    data = json.loads(open("edl_config.json", "rb").read().decode('utf-8'))
                    if "serial" in data and data["serial"] != state["serial"]:
                        open("edl_config.json", "w").write(json.dumps(state))
                    else:
                        self.supported_functions = data["supported_functions"]
                        self.cfg.programmer = data["programmer"]
                else:
                    open("edl_config.json", "w").write(json.dumps(state))
                if "001920e101cf0000_fa2836525c2aad8a_fhprg.bin" in self.cfg.programmer:
                    self.devicemodel = '20111'
                elif "000b80e100020000_467f3020c4cc788d_fhprg.bin" in self.cfg.programmer:
                    self.devicemodel = '22111'
            except:
                pass

        elif self.serial is None or self.supported_functions is []:
            try:
                if os.path.exists("edl_config.json"):
                    pinfo = json.loads(open("edl_config.json", "rb").read())
                    if not self.supported_functions:
                        if "supported_functions" in pinfo:
                            self.supported_functions = pinfo["supported_functions"]
                    if self.serial is None:
                        if "serial" in pinfo:
                            self.serial = pinfo["serial"]
                else:
                    self.get_supported_functions()
            except:
                self.get_supported_functions()
                pass

        # rsp = self.xmlsend(data, self.skipresponse)

        return self.supported_functions

    def parse_storage(self):
        storageinfo = self.cmd_getstorageinfo()
        if storageinfo is None or storageinfo.resp and len(storageinfo.data) == 0:
            return False
        info = storageinfo.data
        if "UFS Inquiry Command Output" in info:
            self.cfg.prod_name = info["UFS Inquiry Command Output"]
            self.info(info)
        if "UFS Erase Block Size" in info:
            self.cfg.block_size = int(info["UFS Erase Block Size"], 16)
            self.info(info)
            self.cfg.MemoryName = "UFS"
            self.cfg.SECTOR_SIZE_IN_BYTES = 4096
        if "UFS Boot Partition Enabled" in info:
            self.info(info["UFS Boot Partition Enabled"])
        if "UFS Total Active LU" in info:
            self.cfg.maxlun = int(info["UFS Total Active LU"], 16)
        if "SECTOR_SIZE_IN_BYTES" in info:
            self.cfg.SECTOR_SIZE_IN_BYTES = int(info["SECTOR_SIZE_IN_BYTES"])
        if "num_physical_partitions" in info:
            self.cfg.num_physical = int(info["num_physical_partitions"])
        return True

    # OEM Stuff here below --------------------------------------------------

    def cmd_writeimei(self, imei):
        if len(imei) != 16:
            self.info("IMEI must be 16 digits")
            return False
        data = '<?xml version="1.0" ?><data><writeIMEI len="16"/></data>'
        val = self.xmlsend(data)
        if val.resp:
            self.info("writeIMEI succeeded.")
            return True
        else:
            self.error("writeIMEI failed.")
            return False

    def cmd_getstorageinfo(self):
        data = '<?xml version="1.0" ?><data><getstorageinfo physical_partition_number="0"/></data>'
        val = self.xmlsend(data)
        if val.data == '' and val.log == '' and val.resp:
            return None
        if isinstance(val.data, dict):
            if "bNumberLu" in val.data:
                self.cfg.maxlun = int(val.data["bNumberLu"])
        if val.resp:
            if val.log is not None:
                res = {}
                for value in val.log:
                    v = value.split("=")
                    if len(v) > 1:
                        res[v[0]] = v[1]
                    else:
                        if '"storage_info"' in value:
                            try:
                                info = value.replace("INFO:", "")
                                si = json.loads(info)["storage_info"]
                            except Exception as err:  # pylint: disable=broad-except
                                self.debug(str(err))
                                continue
                            self.info("Storage report:")
                            for sii in si:
                                self.info(f"{sii}:{si[sii]}")
                            if "total_blocks" in si:
                                self.cfg.total_blocks = si["total_blocks"]
                            if "num_physical" in si:
                                self.cfg.num_physical = si["num_physical"]
                                self.cfg.maxlun = self.cfg.num_physical
                            if "block_size" in si:
                                self.cfg.block_size = si["block_size"]
                            if "page_size" in si:
                                self.cfg.SECTOR_SIZE_IN_BYTES = si["page_size"]
                            if "mem_type" in si:
                                self.cfg.MemoryName = si["mem_type"]
                            if "prod_name" in si:
                                self.cfg.prod_name = si["prod_name"]
                        else:
                            v = value.split(":")
                            if len(v) > 1:
                                res[v[0]] = v[1].lstrip(" ")
                return response(resp=val.resp, data=res)
            return response(resp=val.resp, data=val.data)
        else:
            if val.error:
                for v in val.error:
                    if "Failed to open the SDCC Device" in v:
                        self.cfg.MemoryName = "ufs"
                        self.configure(0)
                        return self.cmd_getstorageinfo()
            self.warning("GetStorageInfo command isn't supported.")
            return None

    def cmd_setactiveslot(self, slot: str):
        # flags: 0x3a for inactive and 0x6f for active boot partition
        def set_flags(flags, active, is_boot):
            new_flags = flags
            if active:
                if is_boot:
                    #new_flags |= (PART_ATT_PRIORITY_VAL | PART_ATT_ACTIVE_VAL | PART_ATT_MAX_RETRY_COUNT_VAL)
                    #new_flags &= (~PART_ATT_SUCCESSFUL_VAL & ~PART_ATT_UNBOOTABLE_VAL)
                    new_flags = 0x6f << (AB_FLAG_OFFSET * 8)
                else:
                    new_flags |= AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8)
            else:
                if is_boot:
                    #new_flags &= (~PART_ATT_PRIORITY_VAL & ~PART_ATT_ACTIVE_VAL)
                    #new_flags |= ((MAX_PRIORITY-1) << PART_ATT_PRIORITY_BIT)
                    new_flags = 0x3a << (AB_FLAG_OFFSET * 8)
                else:
                    new_flags &= ~(AB_PARTITION_ATTR_SLOT_ACTIVE << (AB_FLAG_OFFSET * 8))
            return new_flags

        def patch_helper(gpt_data_a, gpt_data_b, guid_gpt_a, guid_gpt_b, partition_a, partition_b, slot_a_status,
                         slot_b_status, is_boot):
            part_entry_size = guid_gpt_a.header.part_entry_size

            rf_a = BytesIO(gpt_data_a)
            rf_b = BytesIO(gpt_data_b)

            entryoffset_a = partition_a.entryoffset - (
                        (guid_gpt_a.header.part_entry_start_lba - 2) * guid_gpt_a.sectorsize)
            entryoffset_b = partition_b.entryoffset - (
                        (guid_gpt_b.header.part_entry_start_lba - 2) * guid_gpt_b.sectorsize)
            rf_a.seek(entryoffset_a)
            rf_b.seek(entryoffset_b)

            sdata_a = rf_a.read(part_entry_size)
            sdata_b = rf_b.read(part_entry_size)

            partentry_a = gpt.gpt_partition(sdata_a)
            partentry_b = gpt.gpt_partition(sdata_b)

            partentry_a.flags = set_flags(partentry_a.flags, slot_a_status, is_boot)
            partentry_b.flags = set_flags(partentry_b.flags, slot_b_status, is_boot)
            partentry_a.type, partentry_b.type = partentry_b.type, partentry_a.type

            pdata_a, pdata_b = partentry_a.create(), partentry_b.create()
            return pdata_a, partition_a.entryoffset, pdata_b, partition_b.entryoffset

        def cmd_patch_multiple(lun, start_sector, byte_offset, patch_data):
            offset = 0
            size_each_patch = 8 if len(patch_data) % 8 == 0 else 4
            unpack_fmt = "<I" if size_each_patch == 4 else "<Q"
            write_size = len(patch_data)
            for i in range(0, write_size, size_each_patch):
                pdata_subset = int(unpack(unpack_fmt, patch_data[offset:offset + size_each_patch])[0])
                self.cmd_patch(lun, start_sector, byte_offset + offset, pdata_subset, size_each_patch, False)
                offset += size_each_patch
            return True

        def update_gpt_info(guid_gpt_a, guid_gpt_b, partitionname_a, partitionname_b,
                            gpt_data_a, gpt_data_b, slot_a_status, slot_b_status, lun_a, lun_b
                            ):
            part_a = guid_gpt_a.partentries[partitionname_a]
            part_b = guid_gpt_b.partentries[partitionname_b]

            is_boot = False
            if partitionname_a == "boot_a":
                is_boot = True
            pdata_a, poffset_a, pdata_b, poffset_b = patch_helper(
                gpt_data_a, gpt_data_b,
                guid_gpt_a, guid_gpt_b,
                part_a, part_b,
                slot_a_status, slot_b_status,
                is_boot
            )

            if gpt_data_a and gpt_data_b:
                entryoffset_a = poffset_a - ((guid_gpt_a.header.part_entry_start_lba - 2) * guid_gpt_a.sectorsize)
                gpt_data_a[entryoffset_a: entryoffset_a + len(pdata_a)] = pdata_a
                new_gpt_data_a = guid_gpt_a.fix_gpt_crc(gpt_data_a)

                entryoffset_b = poffset_b - ((guid_gpt_b.header.part_entry_start_lba - 2) * guid_gpt_b.sectorsize)
                gpt_data_b[entryoffset_b: entryoffset_b + len(pdata_b)] = pdata_b
                new_gpt_data_b = guid_gpt_b.fix_gpt_crc(gpt_data_b)

                start_sector_patch_a = poffset_a // self.cfg.SECTOR_SIZE_IN_BYTES
                byte_offset_patch_a = poffset_a % self.cfg.SECTOR_SIZE_IN_BYTES
                cmd_patch_multiple(lun_a, start_sector_patch_a, byte_offset_patch_a, pdata_a)

                if lun_a != lun_b:
                    start_sector_hdr_a = guid_gpt_a.header.current_lba
                    headeroffset_a = guid_gpt_a.sectorsize  # gptData: mbr + gpt header + part array
                    new_hdr_a = new_gpt_data_a[headeroffset_a: headeroffset_a + guid_gpt_a.header.header_size]
                    cmd_patch_multiple(lun_a, start_sector_hdr_a, 0, new_hdr_a)

                start_sector_patch_b = poffset_b // self.cfg.SECTOR_SIZE_IN_BYTES
                byte_offset_patch_b = poffset_b % self.cfg.SECTOR_SIZE_IN_BYTES
                cmd_patch_multiple(lun_b, start_sector_patch_b, byte_offset_patch_b, pdata_b)

                start_sector_hdr_b = guid_gpt_b.header.current_lba
                headeroffset_b = guid_gpt_b.sectorsize
                new_hdr_b = new_gpt_data_b[headeroffset_b: headeroffset_b + guid_gpt_b.header.header_size]
                cmd_patch_multiple(lun_b, start_sector_hdr_b, 0, new_hdr_b)
                return True
            return False

        def ensure_gpt_hdr_consistency(guid_gpt, backup_guid_gpt, gpt_data, backup_gpt_data):
            headeroffset = guid_gpt.sectorsize
            prim_corrupted, backup_corrupted = False, False

            prim_hdr = gpt_data[headeroffset: headeroffset + guid_gpt.header.header_size]
            test_hdr = guid_gpt.fix_gpt_crc(gpt_data)[headeroffset: headeroffset + guid_gpt.header.header_size]
            prim_hdr_crc, test_hdr_crc = prim_hdr[0x10: 0x10 + 4], test_hdr[0x10: 0x10 + 4]
            prim_part_table_crc, test_part_table_crc = prim_hdr[0x58: 0x58 + 4], test_hdr[0x58: 0x58 + 4]
            prim_corrupted = prim_hdr_crc != test_hdr_crc or prim_part_table_crc != test_part_table_crc

            backup_hdr = backup_gpt_data[headeroffset: headeroffset + backup_guid_gpt.header.header_size]
            test_hdr = backup_guid_gpt.fix_gpt_crc(backup_gpt_data)[
                       headeroffset: headeroffset + backup_guid_gpt.header.header_size]
            backup_hdr_crc, test_hdr_crc = backup_hdr[0x10: 0x10 + 4], test_hdr[0x10: 0x10 + 4]
            backup_part_table_crc, test_part_table_crc = backup_hdr[0x58: 0x58 + 4], test_hdr[0x58: 0x58 + 4]
            backup_corrupted = backup_hdr_crc != test_hdr_crc or backup_part_table_crc != test_part_table_crc

            prim_backup_consistent = prim_part_table_crc == backup_part_table_crc
            if prim_corrupted or not prim_backup_consistent:
                if backup_corrupted:
                    self.error("both are gpt headers are corrupted, cannot recover")
                    return False, None, None
                gpt_data[2 * guid_gpt.sectorsize:] = backup_gpt_data[2 * backup_guid_gpt.sectorsize:]
                gpt_data = guid_gpt.fix_gpt_crc(gpt_data)
            elif backup_corrupted or not prim_backup_consistent:
                backup_gpt_data[2 * backup_guid_gpt.sectorsize:] = gpt_data[2 * guid_gpt.sectorsize:]
                backup_gpt_data = backup_guid_gpt.fix_gpt_crc(backup_gpt_data)
            return True, gpt_data, backup_gpt_data

        if slot.lower() not in ["a", "b"]:
            self.error("Only slots a or b are accepted. Aborting.")
            return False
        slot_a_status = None
        if slot == "a":
            slot_a_status = True
        elif slot == "b":
            slot_a_status = False
        slot_b_status = not slot_a_status
        fpartitions = {}
        try:
            for lun_a in self.luns:
                lunname = "Lun" + str(lun_a)
                fpartitions[lunname] = []
                check_gpt_hdr = False
                gpt_data_a, guid_gpt_a = self.get_gpt(lun_a, int(0), int(0), int(0))
                backup_gpt_data_a, backup_guid_gpt_a = self.get_gpt(lun_a, 0, 0, 0, guid_gpt_a.header.backup_lba)
                if guid_gpt_a is None:
                    break
                else:
                    for partitionname_a in guid_gpt_a.partentries:
                        slot = partitionname_a.lower()[-2:]
                        partition_a = backup_guid_gpt_a.partentries[partitionname_a]
                        if slot == "_a":
                            active_a = ((partition_a.flags >> (
                                        AB_FLAG_OFFSET * 8)) & 0xFF) & AB_PARTITION_ATTR_SLOT_ACTIVE == AB_PARTITION_ATTR_SLOT_ACTIVE
                            if (active_a and slot_a_status) or (not active_a and slot_b_status):
                                return True

                            partitionname_b = partitionname_a[:-1] + "b"
                            if partitionname_b in guid_gpt_a.partentries:
                                lun_b = lun_a
                                gpt_data_b = gpt_data_a
                                guid_gpt_b = guid_gpt_a
                                backup_gpt_data_b = backup_gpt_data_a
                                backup_guid_gpt_b = backup_guid_gpt_a
                            else:
                                resp = self.detect_partition(arguments=None,
                                                             partitionname=partitionname_b,
                                                             send_full=True)
                                if not resp[0]:
                                    self.error(f"Cannot find partition {partitionname_b}")
                                    return False
                                _, lun_b, gpt_data_b, guid_gpt_b = resp
                                backup_gpt_data_b, backup_guid_gpt_b = self.get_gpt(lun_b, 0, 0, 0,
                                                                                    guid_gpt_b.header.backup_lba)

                            if not check_gpt_hdr and partitionname_a[
                                                     :3] != "xbl":  # xbl partition don't need check consistency
                                sts, gpt_data_a, backup_gpt_data_a = ensure_gpt_hdr_consistency(guid_gpt_a,
                                                                                                backup_guid_gpt_a,
                                                                                                gpt_data_a,
                                                                                                backup_gpt_data_a)
                                if not sts:
                                    return False
                                if lun_a != lun_b:
                                    sts, gpt_data_b, backup_gpt_data_b = ensure_gpt_hdr_consistency(guid_gpt_b,
                                                                                                    backup_guid_gpt_b,
                                                                                                    gpt_data_b,
                                                                                                    backup_gpt_data_b)
                                    if not sts:
                                        return False
                                check_gpt_hdr = True

                            update_gpt_info(guid_gpt_a, guid_gpt_b,
                                            partitionname_a, partitionname_b,
                                            gpt_data_a, gpt_data_b,
                                            slot_a_status, slot_b_status,
                                            lun_a, lun_b)

                            # TODO: this updates the backup gpt header, but is it needed, since it is updated when xbl loads
                            #update_gpt_info(backup_guid_gpt_a, backup_guid_gpt_b,
                            #                partitionname_a, partitionname_b,
                            #                backup_gpt_data_a, backup_gpt_data_b,
                            #                slot_a_status, slot_b_status,
                            #                lun_a, lun_b)

        except Exception as err:
            self.error(str(err))
            return False
        return True

    def cmd_test(self, cmd):
        token = "1234"
        pk = "1234"
        data = f'<?xml version="1.0" ?>\n<data>\n<{cmd} token="{token}" pk="{pk}" />\n</data>'
        val = self.xmlsend(data)
        if val.resp:
            if b"raw hex token" in val[2]:
                return True
            if b"opcmd is not enabled" in val[2]:
                return True
        return False

    def cmd_getstorageinfo_string(self):
        data = '<?xml version="1.0" ?><data><getstorageinfo /></data>'
        val = self.xmlsend(data)
        if val.resp:
            self.info(f"GetStorageInfo:\n--------------------\n")
            data = self.xml.getlog(val.data)
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
                self.cdc.write(xdata[:self.cfg.MaxXMLSizeInBytes])
            except Exception as err:  # pylint: disable=broad-except
                self.debug(str(err))
                pass
            addrinfo = self.cdc.read(timeout=None)
            if b"SizeInBytes" in addrinfo or b"Invalid parameters" in addrinfo:
                tmp = b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp += self.cdc.read(timeout=None)
                xdata = f"<?xml version=\"1.0\" ?><data><poke address64=\"{str(address + pos)}\" " + \
                        f"SizeInBytes=\"{str(maxsize)}\" value64=\"{content}\" /></data>\n"
                self.cdc.write(xdata[:self.cfg.MaxXMLSizeInBytes])
                addrinfo = self.cdc.read(timeout=None)
                if (b'<response' in addrinfo and 'NAK' in addrinfo) or b"Invalid parameters" in addrinfo:
                    self.error(f"Error:{addrinfo}")
                    return False
            if b"address" in addrinfo and b"can\'t" in addrinfo:
                tmp = b""
                while b"NAK" not in tmp and b"ACK" not in tmp:
                    tmp += self.cdc.read(timeout=None)
                self.error(f"Error:{addrinfo}")
                return False

            addrinfo = self.cdc.read(timeout=None)
            if b'<response' in addrinfo and b'NAK' in addrinfo:
                print(f"Error:{addrinfo}")
                return False
            pos += maxsize
            datawritten += maxsize
            lengthtowrite -= maxsize
            if info:
                prog = round(float(datawritten) / float(SizeInBytes) * float(100), 1)
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
            self.cdc.write(data[:self.cfg.MaxXMLSizeInBytes])
        except Exception as err:  # pylint: disable=broad-except
            self.debug(str(err))
            pass
        addrinfo = self.cdc.read(timeout=None)
        if b"SizeInBytes" in addrinfo or b"Invalid parameters" in addrinfo:
            tmp = b""
            while b"NAK" not in tmp and b"ACK" not in tmp:
                tmp += self.cdc.read(timeout=None)
            data = f"<?xml version=\"1.0\" ?><data><peek address64=\"{hex(address)}\" " + \
                   f"SizeInBytes=\"{hex(SizeInBytes)}\" /></data>"
            self.cdc.write(data[:self.cfg.MaxXMLSizeInBytes])
            addrinfo = self.cdc.read(timeout=None)
            if (b'<response' in addrinfo and 'NAK' in addrinfo) or b"Invalid parameters" in addrinfo:
                self.error(f"Error:{addrinfo}")
                return False
        if b"address" in addrinfo and b"can\'t" in addrinfo:
            tmp = b""
            while b"NAK" not in tmp and b"ACK" not in tmp:
                tmp += self.cdc.read(timeout=None)
            self.error(f"Error:{addrinfo}")
            return False

        resp = b""
        dataread = 0
        old = 0
        if info:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        while True:
            tmp = self.cdc.read(timeout=None)
            if b'<response' in tmp or b"ERROR" in tmp:
                break
            rdata = self.xml.getlog(tmp)[0].replace("0x", "").replace(" ", "")
            tmp2 = b""
            try:
                tmp2 = binascii.unhexlify(rdata)
            except:  # pylint: disable=broad-except
                print(rdata)
                exit(0)
            dataread += len(tmp2)
            if wf is not None:
                wf.write(tmp2)
            else:
                resp += tmp2
            if info:
                prog = round(float(dataread) / float(SizeInBytes) * float(100), 1)
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
            if val.resp:
                self.info(f"{data} succeeded.")
                return val.data
            else:
                self.error(f"{data} failed.")
                self.error(f"{val.error}")
                return False
        else:
            self.xmlsend(data, False)
            return True
