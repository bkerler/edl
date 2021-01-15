from struct import unpack, pack
from Library.utils import *
from Library.hdlc import *
from Library.nand_config import BadFlags, SettingsOpt, nand_ids, nand_manuf_ids, nandregs, NandDevice

class Streaming(metaclass=LogBase):
    def __init__(self, cdc, sahara, loglevel=logging.INFO):
        self.cdc = cdc
        self.hdlc = hdlc(self.cdc)
        self.mode = sahara.mode
        self.sahara=sahara
        self.settings = None
        self.flashinfo = None
        self.bbtbl = {}
        self.nanddevice = None
        self.nandbase = 0
        self.__logger.setLevel(loglevel)
        if loglevel==logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def get_flash_config(self):
        """
        self.regs.NAND_DEV0_CFG0=0x2a0408c0
        self.regs.NAND_DEV0_CFG1=0x804745c
        self.regs.NAND_DEV0_ECC_CFG=0x42040700
        self.regs.NAND_EBI2_ECC_BUF_CFG=0x203
        """

        self.regs.NAND_FLASH_CMD = 0x8000b
        self.regs.NAND_EXEC_CMD = self.nanddevice.NAND_CMD_SOFT_RESET
        self.nandwait()
        dev_cfg0 = self.regs.NAND_DEV0_CFG0
        dev_cfg1 = self.regs.NAND_DEV0_CFG1
        dev_ecc_cfg = self.regs.NAND_DEV0_ECC_CFG

        #dev_ecc1_cfg = self.regs.NAND_DEV1_ECC_CFG
        #dev_cfg1_0 = self.regs.NAND_DEV1_CFG0
        #dev_cfg1_1 = self.regs.NAND_DEV1_CFG1

        """
        self.nand_reset()
        self.set_address(1, 0)
        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ
        self.regs.NAND_EXEC_CMD = 0x1
        self.nandwait()
        tmp = self.memread(self.nanddevice.NAND_FLASH_BUFFER, 512)
        """

        nandid = self.regs.NAND_READ_ID
        cfg0, cfg1, ecc_buf_cfg, ecc_bch_cfg = self.nanddevice.nand_setup(nandid)
        self.regs.NAND_DEV0_CFG0 = cfg0
        self.regs.NAND_DEV0_CFG1 = cfg1
        self.regs.NAND_EBI2_ECC_BUF_CFG = ecc_buf_cfg
        self.regs.NAND_DEV0_ECC_CFG = ecc_bch_cfg

    def nand_post(self):
        self.mempoke(self.nanddevice.NAND_DEV0_ECC_CFG,
                     self.mempeek(self.nanddevice.NAND_DEV0_ECC_CFG) & 0xfffffffe)  # ECC on BCH
        self.mempoke(self.nanddevice.NAND_DEV0_CFG1,
                     self.mempeek(self.nanddevice.NAND_DEV0_CFG1) & 0xfffffffe)  # ECC on R-S

    def nand_onfi(self):
        cmd1 = self.regs.NAND_DEV_CMD1
        vld = self.regs.NAND_DEV_CMD_VLD
        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ
        self.regs.NAND_ADDR0 = 0
        self.regs.NAND_ADDR1 = 0
        self.regs.NAND_DEV0_CFG0 = 0 << self.nanddevice.CW_PER_PAGE | 512 << self.nanddevice.UD_SIZE_BYTES | 5 << self.nanddevice.NUM_ADDR_CYCLES | 0 << self.nanddevice.SPARE_SIZE_BYTES
        self.regs.NAND_DEV1_CFG1 = 7 << self.nanddevice.NAND_RECOVERY_CYCLES | 0 << self.nanddevice.CS_ACTIVE_BSY | 17 << self.nanddevice.BAD_BLOCK_BYTE_NUM | \
                                   1 << self.nanddevice.BAD_BLOCK_IN_SPARE_AREA | 2 << self.nanddevice.WR_RD_BSY_GAP | 0 << self.nanddevice.WIDE_FLASH | \
                                   1 << self.nanddevice.DEV0_CFG1_ECC_DISABLE
        self.regs.NAND_EBI2_ECC_BUF_CFG = 1 << self.nanddevice.ECC_CFG_ECC_DISABLE
        self.regs.NAND_DEV_CMD_VLD = self.regs.NAND_DEV_CMD_VLD & ~(1 << self.nanddevice.READ_START_VLD)
        self.regs.NAND_DEV_CMD1 = (self.regs.NAND_DEV_CMD1 & ~(
                    0xFF << self.nanddevice.READ_ADDR)) | self.nanddevice.NAND_CMD_PARAM << self.nanddevice.READ_ADDR
        self.regs.NAND_EXEC_CMD = 1
        self.regs.NAND_DEV_CMD1_RESTORE = cmd1
        self.regs.DEV_CMD_VLD_RESTORE = vld
        self.regs.NAND_DEV_CMD_VLD = 1
        self.regs.NAND_DEV_CMD1 = 1

        # config_cw_read
        self.regs.NAND_FLASH_CMD = 3
        self.regs.NAND_DEV0_CFG0 = 3
        self.regs.NAND_EBI2_ECC_BUF_CFG = 1
        self.regs.NAND_EXEC_CMD = 1

        tmp = self.memread(self.nanddevice.NAND_FLASH_BUFFER, 512)

        self.regs.NAND_DEV_CMD1_RESTORE = 1
        self.regs.DEV_CMD_VLD_RESTORE = 1

        (bytesperpage, spareperpage,
         bytesperpartialpage, spareperpartialpage,  # obsolete
         pagesperblock, blocksperunit, units,
         addresscycles) = unpack('<IHIHIIBB', tmp[80:102])

        res = dict(vendor=tmp[32:44], model=tmp[44:64], bytesperpage=bytesperpage,
                   spareperpage=spareperpage, bytesperpartialpage=bytesperpartialpage,
                   spareperpartialpage=spareperpartialpage, pagesperblock=pagesperblock,
                   blocksperunit=blocksperunit, units=units, addresscycles=addresscycles,
                   rowaddressbytes=addresscycles & 0x0f, columnaddressbytes=addresscycles >> 4,
                   totalpages=pagesperblock * blocksperunit * units)
        # self.pageaddressbits=bitsforaddress(self.pagesperblock)
        return res

    def nand_init(self, xflag=0):
        self.settings.cwsize = self.settings.sectorsize
        if xflag:
            # increase the codeword size by the OOB chunk size per sector˰
            self.settings.cwsize += self.settings.OOBSIZE // self.settings.sectors_per_page

        # ECC on/off
        self.regs.NAND_DEV0_ECC_CFG = (self.regs.NAND_DEV0_ECC_CFG & 0xfffffffe) | self.settings.args_disable_ecc
        # ECC on/off
        self.regs.NAND_DEV0_CFG1 = (self.regs.NAND_DEV0_CFG1 & 0xfffffffe) | self.settings.args_disable_ecc
        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_SOFT_RESET  # Resetting all controller operations
        self.regs.NAND_EXEC_CMD = 0x1
        self.nandwait()

        # set the command code˰
        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ_ALL  # reading data+ecc+spare

        # clean the sector buffer˰
        for i in range(0, self.settings.cwsize, 4):
            self.mempoke(self.nanddevice.NAND_FLASH_BUFFER + i, 0xffffffff)

    def secure_mode(self):
        resp = self.send(b"\x17\x01", True)
        return 0

    def qclose(self, errmode):
        resp = self.send(b"\x15")
        if not errmode:
            time.sleep(0.5)
            return True
        if len(resp) > 2 and resp[1] == 0x16:
            time.sleep(0.5)
            return True
        logging.error("Error on closing stream")
        return False

    def send_section_header(self, name):
        resp = self.send(b"\x1b\x0e" + name + b"\x00")
        if resp[1] == 0x1c:
            return True
        logger.error("Error on sending section header")
        return False

    def enter_flash_mode(self, ptable=None):
        self.secure_mode()
        self.qclose(0)
        if ptable != None:
            self.send_ptable(ptable, 0)  # 1 for fullflash

    def write_flash(self, partname, filename):
        wbsize = 1024
        filesize = os.stat(filename).st_size
        with open(filename, 'rb') as rf:
            if self.send_section_header(partname):
                adr = 0
                while filesize > 0:
                    subdata = rf.read(wbsize)
                    if len(subdata) < wbsize + 1:
                        subdata += b'\xFF' * ((wbsize + 1) - len(subdata))
                    scmd = b"\x07" + pack("<I", adr) + subdata
                    resp = self.send(scmd)
                    if len(resp) == 0 or resp[1] != 0x8:
                        logger.error("Error on sending data at address %08X" % adr)
                        return False
                    adr += len(subdata)
                    filesize -= len(subdata)
            if not self.qclose(0):
                logger.error("Error on closing data stream")
                return False

    def send_ptable(self, parttable, mode):
        cmdbuf = b"\x19" + pack("<B", mode) + parttable
        resp = self.send(cmdbuf)
        if resp[1] != 0x1a:
            logger.error("Error on sending raw partition table")
            return False
        elif resp[2] == 0x0:
            return True
        logger.error("Partition tables do not match - you need to fully flash the modem")
        return False

    def memread(self, address, length):
        logging.debug("memread %08X:%08X" % (address, length))
        result = b""
        cmdbuf = bytearray(
            [0x11, 0x00, 0x24, 0x30, 0x9f, 0xe5, 0x24, 0x40, 0x9f, 0xe5, 0x12, 0x00, 0xa0, 0xe3, 0x04, 0x00,
             0x81, 0xe4, 0x04, 0x00, 0x83, 0xe0, 0x04, 0x20, 0x93, 0xe4, 0x04, 0x20, 0x81, 0xe4, 0x00, 0x00,
             0x53, 0xe1, 0xfb, 0xff, 0xff, 0x3a, 0x04, 0x40, 0x84, 0xe2, 0x1e, 0xff, 0x2f, 0xe1])
        errcount = 0
        blklen = 1000
        for i in range(0, length, 1000):
            tries = 20
            if (i + 1000) > length:
                blklen = length - i
            iolen = 0
            resp = self.send(cmdbuf + pack("<I", address + i) + pack("<I", blklen), True)
            while tries > 0:
                iolen = len(resp) - 1
                if iolen < (blklen + 4):
                    tries -= 1
                    time.sleep(1)
                    resp += self.hdlc.receive_reply_nocrc()
                else:
                    break
            if tries == 0:
                logging.error(
                    f"Error reading memory at addr {hex(address)}, {str(blklen)} bytes required, {str(iolen)} bytes "
                    f"received.")
                errcount += 1
                result += b"\xeb" * blklen
            else:
                result += resp[5:]

        if errcount > 0:
            return b""
        return result

    def mempeek(self, address):
        res = self.memread(address, 4)
        if res != b"":
            data = unpack("<I", res)[0]
            logging.debug("memread %08X:%08X" % (address, data))
            return data
        return -1

    def memwrite(self, address, data):
        length = len(data)
        cmdbuf = bytearray(
            [0x11, 0x00, 0x38, 0x00, 0x80, 0xe2, 0x24, 0x30, 0x9f, 0xe5, 0x24, 0x40, 0x9f, 0xe5, 0x04, 0x40,
             0x83, 0xe0, 0x04, 0x20, 0x90, 0xe4, 0x04, 0x20, 0x83, 0xe4, 0x04, 0x00, 0x53, 0xe1, 0xfb, 0xff,
             0xff, 0x3a, 0x12, 0x00, 0xa0, 0xe3, 0x00, 0x00, 0xc1, 0xe5, 0x01, 0x40, 0xa0, 0xe3, 0x1e, 0xff,
             0x2f, 0xe1])
        if len(data) > 1000:
            data = data[0:1000]
            length = 1000
        self.send(cmdbuf + pack("<I", address) + pack("<I", length) + data, True)
        return True

    def cmd_memcpy(self, destaddress, sourceaddress, size):
        data = self.memread(sourceaddress, size)
        if data != b"" and data:
            if self.memwrite(destaddress, data):
                return True
        return False

    def mempoke(self, address, value):
        logging.debug("mempoke %08X:%08X" % (address, value))
        data = pack("<I", value & 0xFFFFFFFF)
        return self.memwrite(address, data)

    def reset(self):
        data = self.send(b"\x0B", True)
        return True

    def nandwait(self):
        while True:
            if self.regs.NAND_FLASH_STATUS & 0xF == 0:
                break

    def set_address(self, block, page):
        address = (block * self.settings.num_pages_per_blk) + page
        self.regs.NAND_ADDR0 = address << 16
        self.regs.NAND_ADDR1 = (address >> 16) & 0xFF
        # self.regs.NAND_FLASH_CHIP_SELECT = 0 | 4  # flash0 + undoc bit

    def exec_nand(self, cmd):
        self.regs.NAND_FLASH_CMD = cmd
        self.regs.NAND_EXEC_CMD = 1
        self.nandwait()

    def nand_reset(self):
        self.exec_nand(1)

    def tst_badblock(self):
        badflag = 0
        st = self.regs.NAND_BUFFER_STATUS & 0xFFFF0000
        if self.settings.IsWideFlash == 0:
            if st != 0xFF0000:
                badflag = 1
        elif st != 0xFFFF0000:
            badflag = 1
        return badflag

    def check_block(self, block):
        self.nand_reset()
        self.set_address(block, 0)
        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ_ALL
        self.regs.NAND_FLASH_EXEC = 0x1
        self.nandwait()
        return self.tst_badblock()

    """
    def check_block(self, block):
        cwperpage = (self.settings.pagesize >> 9)
        CFG1_WIDE_FLASH=1<<1
        #if self.settings.bch_mode:
        #    NAND_CFG0_RAW=0xA80420C0
        #else:
        #    NAND_CFG0_RAW=0xA80428C0
        self.nand_reset()
        self.set_address(block, 0)
        self.regs.NAND_FLASH_CMD=self.nanddevice.NAND_CMD_PAGE_READ
        #self.regs.NAND_DEV0_CFG0=NAND_CFG0_RAW & ~(7 << 6)
        self.regs.NAND_EXEC_CMD=0x1
        self.nandwait()
        flashstatus = self.regs.NAND_FLASH_STATUS
        if flashstatus & 0x110:
            return 1
        
        if self.settings.cfg1_enable_bch_ecc and self.settings.ecc_bit == 8:
            val=532 * (cwperpage - 1)
        else:
            val=528 * (cwperpage - 1)
        #val=self.settings.BAD_BLOCK_BYTE_NUM
        ptr = self.nanddevice.NAND_FLASH_BUFFER + (self.settings.pagesize - val)
        flag=self.memread(ptr,2)
        if self.regs.NAND_DEV0_CFG1 & CFG1_WIDE_FLASH:
            if flag[0] != 0xFF or flag[1] != 0xFF:
                return 1
        elif flag[0] != 0xFF:
            return 1
        return 0
    """

    def check_ecc_status(self):
        bs = self.regs.NAND_BUFFER_STATUS
        if (bs & 0x100) != 0 and (self.regs.NAND_FLASH_CMD + 0xec) & 0x40 == 0:
            return -1
        return bs & 0x1f

    def write_badmark(self, block, value):
        udsize = 0x220
        cfg1bak = self.regs.NAND_DEV0_CFG1
        cfgeccbak = self.regs.NAND_DEV0_ECC_CFG
        self.regs.NAND_DEV0_ECC_CFG = self.regs.NAND_DEV0_ECC_CFG | 1
        self.regs.NAND_DEV0_CFG1 = self.regs.NAND_DEV0_CFG1 | 1
        self.hardware_bad_off()
        buf = bytearray([0xeb])
        for i in range(1, udsize):
            buf.append(value)
        self.nand_reset()
        self.nandwait()
        self.set_address(block, 0)
        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PRG_PAGE_ALL
        for i in range(0, self.settings.sectors_per_page):
            self.memwrite(self.nanddevice.NAND_FLASH_BUFFER, buf[:udsize])
            self.regs.NAND_EXEC_CMD = 1
            self.nandwait()
        self.hardware_bad_on()
        self.regs.NAND_DEV0_CFG1 = cfg1bak
        self.regs.NAND_DEV0_ECC_CFG = cfgeccbak

    def mark_bad(self, block):
        if not self.check_block(block):
            self.write_badmark(block, 0)
            return 1
        return 0

    def unmark_bad(self, block):
        if self.check_block(block):
            self.block_erase(block)
            return 1
        return 0

    """
    def tst_badpattern(self, buffer):
        for i in range(0, len(buffer)):
            if buffer[i] != 0xbb:
                return 0
        return 1
    """

    def flash_read(self, block, page, sectors, cwsize=None):
        buffer = bytearray()
        spare = bytearray()
        cursize = 0
        newblock = False
        cfg0 = self.regs.NAND_DEV0_CFG0
        if block not in self.bbtbl:
            newblock = True
        if self.settings.bad_processing_flag == BadFlags.BAD_DISABLE.value:
            self.hardware_bad_off()
        elif self.settings.bad_processing_flag != BadFlags.BAD_IGNORE.value:
            if newblock:
                res = 0
                if block in self.bbtbl:
                    res = self.bbtbl[block]
                else:
                    if self.check_block(block):
                        res = 1
                    self.bbtbl[block] = res
                if res == 1:
                    for i in range(0, self.settings.PAGESIZE):
                        buffer.append(0xbb)
                    return buffer, spare

            self.nand_reset()
            if self.settings.ECC_MODE == 1:
                if cwsize >= self.settings.sectorsize + 4:
                    self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ_ALL
                else:
                    self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ_ECC
            else:
                self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_PAGE_READ_ALL
            self.bch_reset()

        self.set_address(block, page)
        bad_ecc = False
        for sector in range(0, sectors):
            self.regs.NAND_EXEC_CMD = 0x1
            self.nandwait()
            ecc_status = self.check_ecc_status()
            if ecc_status == -1:
                bad_ecc = True
            tmp = self.memread(self.nanddevice.NAND_FLASH_BUFFER, cwsize)
            size = self.settings.UD_SIZE_BYTES
            if cursize + size > self.settings.PAGESIZE:
                size = cursize + size - self.settings.PAGESIZE
                buffer.extend(tmp[:-size])
                spare.extend(tmp[-size:])
            else:
                buffer.extend(tmp)
            cursize += size
        if bad_ecc:
            logger.debug("ECC error at : Block %08X Page %08X" % (block, page))

        if self.settings.bad_processing_flag == BadFlags.BAD_DISABLE.value:
            self.hardware_bad_off()

        self.regs.NAND_DEV0_CFG0 = cfg0
        return buffer, spare

    def hardware_bad_off(self):
        cfg1 = self.regs.NAND_DEV0_CFG1
        cfg1 &= ~(0x3ff << 6)
        self.regs.NAND_DEV0_CFG1 = cfg1

    def hardware_bad_on(self):
        cfg1 = self.regs.NAND_DEV0_CFG1
        cfg1 &= ~(0x7ff << 6)
        cfg1 |= (self.settings.BAD_BLOCK_BYTE_NUM & 0x3FF) << 6
        cfg1 |= self.settings.BAD_BLOCK_IN_SPARE_AREA << 16
        self.regs.NAND_DEV0_CFG1 = cfg1

    def set_badmark_pos(self, pos, place):
        self.settings.BAD_BLOCK_BYTE_NUM = pos
        self.settings.BAD_BLOCK_IN_SPARE_AREA = place & 1
        self.hardware_bad_on()

    def set_udsize(self, size):
        tmpreg = self.regs.NAND_DEV0_CFG0
        tmpreg = (tmpreg & (~(0x3ff << 9))) | (size << 9)
        self.regs.NAND_DEV0_CFG0 = tmpreg
        if ((self.regs.NAND_DEV0_CFG1 >> 27) & 1) != 0:
            tmpreg = self.regs.NAND_DEV0_ECC_CFG
            tmpreg = (tmpreg & (~(0x3ff << 16))) | (size << 16)
            self.regs.NAND_DEV0_ECC_CFG = tmpreg

    def set_sparesize(self, size):
        cfg0 = self.regs.NAND_DEV0_CFG0
        cfg0 = cfg0 & (~(0xf << 23)) | (size << 23)
        self.regs.NAND_DEV0_CFG0 = cfg0

    def set_eccsize(self, size):
        cfg1 = self.regs.NAND_DEV0_CFG1
        if ((cfg1 >> 27) & 1) != 0:
            self.settings.cfg1_enable_bch_ecc = 1
        if self.settings.cfg1_enable_bch_ecc == 1:
            ecccfg = self.regs.NAND_DEV0_ECC_CFG
            ecccfg = (ecccfg & (~(0x1f << 8)) | (size << 8))
            self.regs.NAND_DEV0_ECC_CFG = ecccfg
        else:
            cfg0 = self.regs.NAND_DEV0_CFG0
            cfg0 = cfg0 & (~(0xf << 19)) | (size << 19)
            self.regs.NAND_DEV0_CFG0 = cfg0

    def bch_reset(self):
        if not self.settings.cfg1_enable_bch_ecc:
            return
        cfgecc_temp = self.regs.NAND_DEV0_ECC_CFG
        self.regs.NAND_DEV0_ECC_CFG = cfgecc_temp | 2
        self.regs.NAND_DEV0_ECC_CFG = cfgecc_temp

    def set_blocksize(self, udsize, ss, eccs):
        self.set_udsize(udsize)
        self.set_sparesize(ss)
        self.set_eccsize(eccs)

    def get_udsize(self):
        return (self.regs.NAND_DEV0_CFG0 & (0x3ff << 9)) >> 9

    def block_erase(self, block):
        self.nand_reset()
        self.regs.NAND_ADDR0 = block * self.settings.num_pages_per_blk
        self.regs.NAND_ADDR1 = 0
        oldcfg = self.regs.NAND_DEV0_CFG0
        self.regs.NAND_DEV0_CFG0 = oldcfg & ~0x1c0

        self.regs.NAND_FLASH_CMD = self.nanddevice.NAND_CMD_BLOCK_ERASE
        self.regs.NAND_EXEC_CMD = 1
        self.nandwait()
        self.regs.NAND_DEV0_CFG0 = oldcfg

    def disable_bam(self):
        nandcstate = {}
        for i in range(0, 0xec, 4):
            value=self.mempeek(self.nanddevice.NAND_FLASH_CMD + i)
            nandcstate[i]=value
        self.mempoke(self.settings.bcraddr, 1)
        self.mempoke(self.settings.bcraddr, 0)
        for i in nandcstate:
            addr = self.nanddevice.NAND_FLASH_CMD + i
            value = nandcstate[i]
            self.mempoke(addr, value)
        self.regs.NAND_EXEC_CMD = 1

    def read_partition_table(self):
        cwsize = self.settings.sectorsize
        if self.settings.ECC_MODE == 1:
            cwsize = self.settings.UD_SIZE_BYTES
        for block in range(0, 12):
            buffer, spare = self.flash_read(block, 0, 1, cwsize)
            if buffer[0:8] != b"\xac\x9f\x56\xfe\x7a\x12\x7f\xcd":
                continue

            buffer, spare = self.flash_read(block, 1, 2, cwsize)
            magic1, magic2, version, numparts = unpack("<IIII", buffer[0:0x10])
            if magic1 == 0x55EE73AA or magic2 == 0xE35EBDDB:
                return buffer
        return -1

    def get_partitions(self):
        partitions = {}
        partdata = self.read_partition_table()
        if partdata != -1:
            data = partdata[0x10:]
            for i in range(0, len(data) // 0x1C):
                name, offset, length, attr1, attr2, attr3, which_flash = unpack("16sIIBBBB",
                                                                                data[i * 0x1C:(i * 0x1C) + 0x1C])
                if name[1] != 0x3A:
                    break
                partitions[name[2:].rstrip(b"\x00").decode('utf-8').lower()] = dict(offset=offset,
                                                                                    length=length & 0xFFFF,
                                                                                    attr1=attr1, attr2=attr2,
                                                                                    attr3=attr3,
                                                                                    which_flash=which_flash)
            return partitions
        return {}

    def tst_loader(self):
        i = self.identify_chipset()
        if i <= 0:
            self.settings.bad_loader = 1
            return 0
        return 1

    def setupregs(self):
        self.regs = nandregs(self)
        self.regs.register_mapping = {
            "NAND_FLASH_CMD": self.nanddevice.NAND_FLASH_CMD,
            "NAND_ADDR0": self.nanddevice.NAND_ADDR0,
            "NAND_ADDR1": self.nanddevice.NAND_ADDR1,
            "NAND_FLASH_CHIP_SELECT": self.nanddevice.NAND_FLASH_CHIP_SELECT,
            "NAND_EXEC_CMD": self.nanddevice.NAND_EXEC_CMD,
            "NAND_FLASH_STATUS": self.nanddevice.NAND_FLASH_STATUS,
            "NAND_BUFFER_STATUS": self.nanddevice.NAND_BUFFER_STATUS,
            "NAND_DEV0_CFG0": self.nanddevice.NAND_DEV0_CFG0,
            "NAND_DEV0_CFG1": self.nanddevice.NAND_DEV0_CFG1,
            "NAND_DEV0_ECC_CFG": self.nanddevice.NAND_DEV0_ECC_CFG,
            "NAND_DEV1_ECC_CFG": self.nanddevice.NAND_DEV1_ECC_CFG,
            "NAND_DEV1_CFG0": self.nanddevice.NAND_DEV1_CFG0,
            "NAND_DEV1_CFG1": self.nanddevice.NAND_DEV1_CFG1,
            "NAND_READ_ID": self.nanddevice.NAND_READ_ID,
            "NAND_READ_STATUS": self.nanddevice.NAND_READ_STATUS,
            "NAND_DEV_CMD0": self.nanddevice.NAND_DEV_CMD0,
            "NAND_DEV_CMD1": self.nanddevice.NAND_DEV_CMD1,
            "NAND_DEV_CMD2": self.nanddevice.NAND_DEV_CMD2,
            "NAND_DEV_CMD_VLD": self.nanddevice.NAND_DEV_CMD_VLD,
            "SFLASHC_BURST_CFG": self.nanddevice.SFLASHC_BURST_CFG,
            "NAND_EBI2_ECC_BUF_CFG": self.nanddevice.NAND_EBI2_ECC_BUF_CFG,
            "NAND_FLASH_BUFFER": self.nanddevice.NAND_FLASH_BUFFER
        }

    def connect(self, mode=1):
        time.sleep(0.200)
        if mode == 0:
            cmdbuf = bytearray(
                [0x11, 0x00, 0x12, 0x00, 0xa0, 0xe3, 0x00, 0x00, 0xc1, 0xe5, 0x01, 0x40, 0xa0, 0xe3, 0x1e, 0xff, 0x2f,
                 0xe1])
            resp = self.send(cmdbuf, True)
            i = resp[1]
            if i == 0x12:
                # if not self.tst_loader():
                #    print("Unlocked bootloader being used, cannot continue")
                #    exit(2)
                chipset = self.identify_chipset()
                self.settings = SettingsOpt(self, chipset)
                self.nanddevice = NandDevice(self.settings)
                self.setupregs()
                self.get_flash_config()
                return True

        info = b"\x01QCOM fast download protocol host\x03\x23\x23\x23\x20"
        resp = self.send(info, True)
        if b"Unrecognized flash device" in resp:
            logging.error("Unrecognized flash device, patch loader !")
            self.reset()
            return False
        resp = bytearray(resp)
        if resp[1] != 2:
            resp = self.send(info, True)
        if len(resp) > 0x2c:
            logging.info("Successfully uploaded programmer :)")
            infolen = resp[0x2c]

            if mode == 2:
                logging.info("Detected flash memory: %s" % resp[0x2d:0x2d + infolen].decode('utf-8'))
                return True

            chipset = self.identify_chipset()
            self.settings = SettingsOpt(self, chipset)
            if self.settings.bad_loader:
                logging.error("Loader id doesn't match device, please fix config and patch loader. Rebooting.")
                self.reset()
                return False
            self.nanddevice = NandDevice(self.settings)
            self.setupregs()

            if self.cdc.pid == 0x900e or self.cdc.pid==0x0076:
                print("Boot to 0x9008")
                self.mempoke(0x193d100, 1)
                # dload-mode-addr, TCSR_BOOT_MISC_DETECT, iomap.h
                # msm8916,8939,8953 0x193d100
                # msm8996 0x7b3000
                self.mempeek(0x7980000)
                self.cdc.close()
                sys.exit(0)

            if self.settings.bam:
                self.disable_bam()  # only for sahara
            self.get_flash_config()
            cfg0 = self.mempeek(self.nanddevice.NAND_DEV0_CFG0)
            sectorsize = (cfg0 & (0x3ff << 9)) >> 9
            sparebytes = (cfg0 >> 23) & 0xf
            logging.info("HELLO protocol version: %i" % resp[0x22])
            logging.info("Chipset: %s" % self.settings.chipname)
            logging.info("Base address of the NAND controller: %08x" % self.settings.nandbase)
            val = resp[0x2d:0x2d + infolen].decode('utf-8') if resp[0x2d] != 0x65 else ""
            logging.info("Flash memory: %s %s, %s" % (self.settings.flash_mfr, val, self.settings.flash_descr))
            # logging.info("Maximum packet size: %i byte",*((unsigned int*)&rbuf[0x24]))
            logging.info("Sector size: %d bytes" % sectorsize)
            logging.info("Page size: %d bytes (%d sectors)" % (self.settings.PAGESIZE, self.settings.sectors_per_page))
            logging.info("The number of pages in the block: %d" % self.settings.num_pages_per_blk)
            logging.info("OOB size: %d bytes" % self.settings.OOBSIZE)
            ecctype = "BCH" if self.settings.cfg1_enable_bch_ecc else "R-S"
            logging.info("ECC: %s, %i bit" % (ecctype, self.settings.ecc_bit))
            logging.info("ЕСС size: %d bytes" % self.settings.ecc_size)
            logging.info("Spare bytes: %d bytes" % sparebytes)
            markerpos = "spare" if self.nanddevice.BAD_BLOCK_IN_SPARE_AREA else "user"
            logging.info("Defective block marker position: %s+%x" % (markerpos, self.nanddevice.BAD_BLOCK_BYTE_NUM))
            logging.info("The total size of the flash memory = %u blocks (%i MB)" % (self.settings.MAXBLOCK,
                                                                                     self.settings.MAXBLOCK * self.settings.num_pages_per_blk / 1024 * self.settings.PAGESIZE / 1024))
            return True
        else:
            logging.error("Uploaded programmer doesn't respond :(")
            return False

    def load_block(self, block, cwsize):
        buffer = bytearray()
        for page in range(0, self.settings.num_pages_per_blk):
            tmp, spare = self.flash_read(block, page, self.settings.sectors_per_page, cwsize)
            buffer.extend(tmp)
        return buffer

    def read_blocks(self, fw, block, length, cwsize, savespare=False, info=True):
        badblocks = 0
        old = 0
        pos = 0
        totallength = length * self.settings.num_pages_per_blk * self.settings.PAGESIZE
        if info:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        startoffset = block * self.settings.num_pages_per_blk * self.settings.PAGESIZE
        endoffset = startoffset + totallength

        for offset in range(startoffset, endoffset, self.settings.PAGESIZE):
            pages = int(offset / self.settings.PAGESIZE)
            curblock = int(pages / self.settings.num_pages_per_blk)
            curpage = int(pages - curblock * self.settings.num_pages_per_blk)
            data, spare = self.flash_read(curblock, curpage, self.settings.sectors_per_page, cwsize)
            if self.bbtbl[curblock] != 1 or (self.settings.bad_processing_flag != BadFlags.BAD_SKIP.value):
                fw.write(data)
                if savespare:
                    fw.write(spare)
            else:
                logger.debug("Bad block at block %d" % curblock)
                badblocks += 1
            pos += self.settings.PAGESIZE
            if info:
                prog = int(float(pos) / float(totallength) * float(100))
                if prog > old:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old = prog
        return badblocks

    """
    def read_blocks_ext(self, fw, block, length, yaffsmode, info=True):
        buffer = bytearray()
        badblocks = 0
        pos = 0
        old = 0
        totallength = length * self.settings.num_pages_per_blk * self.settings.PAGESIZE
        if info:
            print_progress(0, 100, prefix='Progress:', suffix='Complete', bar_length=50)
        for curblock in range(block, block + length):
            for page in range(0, self.settings.num_pages_per_blk):
                tmp, spare = self.flash_read(block, page, self.settings.sectors_per_page, self.settings.sectorsize + 4)
                buffer.extend(tmp)
                if info:
                    prog = int(float(pos) / float(totallength) * float(100))
                    if prog > old:
                        print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                        old = prog

            if self.bbtbl[block] == 1 and (self.settings.bad_processing_flag != BadFlags.BAD_SKIP.value):
                print("Bad block at block %d" % curblock)
                badblocks += 1
            else:
                for page in range(0, self.settings.num_pages_per_blk):
                    pgoffset = page * self.settings.sectors_per_page * (self.settings.sectorsize + 4)
                    for sec in range(0, self.settings.sectors_per_page):
                        udoffset = pgoffset + sec * (self.settings.sectorsize + 4)
                        if sec != (self.settings.sectors_per_page - 1):
                            fw.write(buffer[udoffset:udoffset + self.settings.sectorsize - 4])
                        else:
                            fw.write(buffer[udoffset:udoffset + self.settings.sectorsize - 4 * (
                                    self.settings.sectors_per_page - 1)])

                    if yaffsmode == 1:
                        extbuf = bytearray()
                        soff = pgoffset + (self.settings.sectorsize + 4) * (self.settings.sectors_per_page - 1) + (
                                self.settings.sectorsize - 4 * (self.settings.sectors_per_page - 1))
                        extbuf.extend(buffer[soff])
                        for i in range(0, self.settings.OOBSIZE):
                            extbuf.append(0xff)
                        fw.write(extbuf)
        return badblocks
    """

    def read_raw(self, start, length, cwsize, filename):
        with open(filename, 'wb') as fw:
            if self.settings.rflag == 0:  # normal
                self.read_blocks(fw, start, length, cwsize)
            """
            elif self.settings.rflag == 1:  # linux
                self.read_blocks_ext(fw, start, length, 0)  # Fixme
            elif self.settings.rflag == 2:  # yaffs
                self.read_blocks_ext(fw, start, length, 1)  # Fixme
            """

    def send(self, cmd, nocrc=False):
        if self.hdlc is not None:
            return self.hdlc.send_cmd_np(cmd, nocrc)
        return False

    def identify_chipset(self):
        cmd = bytearray([0x11, 0x00, 0x04, 0x10, 0x2d, 0xe5, 0x0e, 0x00, 0xa0, 0xe1, 0x03, 0x00, 0xc0, 0xe3, 0xff, 0x30,
                         0x80, 0xe2, 0x34, 0x10, 0x9f, 0xe5, 0x04, 0x20, 0x90, 0xe4, 0x01, 0x00, 0x52, 0xe1, 0x03, 0x00,
                         0x00, 0x0a, 0x03, 0x00, 0x50, 0xe1, 0xfa, 0xff, 0xff, 0x3a, 0x00, 0x00, 0xa0, 0xe3, 0x00, 0x00,
                         0x00, 0xea, 0x00, 0x00, 0x90, 0xe5, 0x04, 0x10, 0x9d, 0xe4, 0x01, 0x00, 0xc1, 0xe5, 0xaa, 0x00,
                         0xa0, 0xe3, 0x00, 0x00, 0xc1, 0xe5, 0x02, 0x40, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1, 0xef, 0xbe,
                         0xad, 0xde])
        resp = self.send(cmd, True)
        if resp[1] != 0xaa:
            resp = self.send(cmd, True)
            if resp[1] != 0xaa:
                return -1
        return resp[2]  # 08


def test_nand_config():
    class sahara:
        mode = None
    qs = Streaming(None, sahara(),logging.INFO)
    qs.settings = SettingsOpt(qs, 8)
    qs.nanddevice = NandDevice(qs.settings)
    testconfig = [
        # nandid, buswidth, density, pagesize, blocksize, oobsize, bchecc, cfg0, cfg1, eccbufcfg, bccbchcfg, badblockbyte
        [0x1590aaad, 8, 256, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        # ZTE MF920V, MDM9x07
        [0x1590ac01, 8, 256, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        # ZTE OSH-150
        [0x1590acad, 8, 256, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x1590aac8, 8, 256, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x1590acc8, 8, 512, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x1d00f101, 8, 128, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x1d80f101, 8, 128, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],

        #Sierra 9x15
        [0x1900aaec, 8, 256, 2048, 131072, 64, 8, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        #[0x1590aa98, 8, 256, 2048, 131072, 64, 8, 0xa8d408c0, 0x0004745c, 0x00000203, 0x42040d10, 0x000001d1],
        [0x1590aa98, 8, 256, 2048, 131072, 64, 8, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x2690ac2c, 8, 512, 4096, 262144, 224, 8, 0x290409c0, 0x08045d5c, 0x00000203, 0x42040d10, 0x00000175],
        #End
        [0x2690dc98, 8, 512, 4096, 262144, 128, 4, 0x2a0409c0, 0x0804645c, 0x00000203, 0x42040700, 0x00000191],
        # Sierra Wireless EM7455, MDM9x35, Quectel EC25, Toshiba KSLCMBL2VA2M2A
        [0x2690ac98, 8, 512, 4096, 262144, 256, 8, 0x290409c0, 0x08045d5c, 0x00000203, 0x42040d10, 0x00000175],
        [0x9590daef, 8, 256, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x9580f1c2, 8, 128, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x9580f1c2, 8, 128, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x9590dac2, 8, 256, 2048, 131072, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        [0x1590ac01, 8, 512, 2048, 128, 64, 4, 0x2a0408c0, 0x0804745c, 0x00000203, 0x42040700, 0x000001d1],
        # Netgear MR5100
        [0x26d0a32c, 8, 1024, 4096, 262144, 256, 8, 0x290409c0, 0x08045d5c, 0x00000203, 0x42040d10, 0x00000175],
    ]
    errorids = []
    for test in testconfig:
        nandid, buswidth, density, pagesize, blocksize, oobsize, bchecc, cfg0, cfg1, eccbufcfg, bccbchcfg, badblockbyte = test
        res_cfg0, res_cfg1, res_ecc_buf_cfg, res_ecc_bch_cfg = qs.nanddevice.nand_setup(nandid)
        if cfg0 != res_cfg0 or cfg1 != res_cfg1 or eccbufcfg != res_ecc_buf_cfg or res_ecc_bch_cfg != bccbchcfg:
            errorids.append([nandid,res_cfg0,res_cfg1,res_ecc_buf_cfg,res_ecc_bch_cfg])
            res_cfg0, res_cfg1, res_ecc_buf_cfg, res_ecc_bch_cfg = qs.nanddevice.nand_setup(nandid)

    if len(errorids) > 0:
        st = ""
        for id in errorids:
            st += hex(id[0]) + f" {hex(id[1]),hex(id[2]),hex(id[3]),hex(id[4])},"
        st = st[:-1]
        print("Error at: "+st)
        assert ("Error at : " + st)
    else:
        print("Yay, all nand_config tests are ok !!!!")


if __name__ == "__main__":
    print("Running nand config tests...")
    test_nand_config()
