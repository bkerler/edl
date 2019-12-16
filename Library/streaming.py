import xml.etree.ElementTree as ET
import binascii
import time
import os
from Library.utils import *
from Library.hdlc import *
logger = logging.getLogger(__name__)

nand_ids=[
            ("NAND 16MiB 1,8V 8-bit", 0x33, 16),
            ("NAND 16MiB 3,3V 8-bit", 0x73, 16),
            ("NAND 16MiB 1,8V 16-bit", 0x43, 16),
            ("NAND 16MiB 3,3V 16-bit", 0x53, 16),

            ("NAND 32MiB 1,8V 8-bit", 0x35, 32),
            ("NAND 32MiB 3,3V 8-bit", 0x75, 32),
            ("NAND 32MiB 1,8V 16-bit", 0x45, 32),
            ("NAND 32MiB 3,3V 16-bit", 0x55, 32),

            ("NAND 64MiB 1,8V 8-bit", 0x36, 64),
            ("NAND 64MiB 3,3V 8-bit", 0x76, 64),
            ("NAND 64MiB 1,8V 16-bit", 0x46, 64),
            ("NAND 64MiB 3,3V 16-bit", 0x56, 64),

            ("NAND 128MiB 1,8V 8-bit", 0x78, 128),
            ("NAND 128MiB 1,8V 8-bit", 0x39, 128),
            ("NAND 128MiB 3,3V 8-bit", 0x79, 128),
            ("NAND 128MiB 1,8V 16-bit", 0x72, 128),
            ("NAND 128MiB 1,8V 16-bit", 0x49, 128),
            ("NAND 128MiB 3,3V 16-bit", 0x74, 128),
            ("NAND 128MiB 3,3V 16-bit", 0x59, 128),
            ("NAND 256MiB 3,3V 8-bit", 0x71, 256),

            # 512 Megabit
            ("NAND 64MiB 1,8V 8-bit", 0xA2, 64),
            ("NAND 64MiB 1,8V 8-bit", 0xA0, 64),
            ("NAND 64MiB 3,3V 8-bit", 0xF2, 64),
            ("NAND 64MiB 3,3V 8-bit", 0xD0, 64),
            ("NAND 64MiB 1,8V 16-bit", 0xB2, 64),
            ("NAND 64MiB 1,8V 16-bit", 0xB0, 64),
            ("NAND 64MiB 3,3V 16-bit", 0xC2, 64),
            ("NAND 64MiB 3,3V 16-bit", 0xC0, 64),

           # 1 Gigabit
            ("NAND 128MiB 1,8V 8-bit", 0xA1, 128),
            ("NAND 128MiB 3,3V 8-bit", 0xF1, 128),
            ("NAND 128MiB 3,3V 8-bit", 0xD1, 128),
            ("NAND 128MiB 1,8V 16-bit", 0xB1, 128),
            ("NAND 128MiB 3,3V 16-bit", 0xC1, 128),
            ("NAND 128MiB 1,8V 16-bit", 0xAD, 128),

            # 2 Gigabit
            ("NAND 256MiB 1.8V 8-bit", 0xAA, 256),
            ("NAND 256MiB 3.3V 8-bit", 0xDA, 256),
            ("NAND 256MiB 1.8V 16-bit", 0xBA, 256),
            ("NAND 256MiB 3.3V 16-bit", 0xCA, 256),

            # 4 Gigabit
            ("NAND 512MiB 1.8V 8-bit", 0xAC, 512),
            ("NAND 512MiB 3.3V 8-bit", 0xDC, 512),
            ("NAND 512MiB 1.8V 16-bit", 0xBC, 512),
            ("NAND 512MiB 3.3V 16-bit", 0xCC, 512),

            # 8 Gigabit
            ("NAND 1GiB 1.8V 8-bit", 0xA3, 1024),
            ("NAND 1GiB 3.3V 8-bit", 0xD3, 1024),
            ("NAND 1GiB 1.8V 16-bit", 0xB3, 1024),
            ("NAND 1GiB 3.3V 16-bit", 0xC3, 1024),

            # 16 Gigabit
            ("NAND 2GiB 1.8V 8-bit", 0xA5, 2048),
            ("NAND 2GiB 3.3V 8-bit", 0xD5, 2048),
            ("NAND 2GiB 1.8V 16-bit", 0xB5, 2048),
            ("NAND 2GiB 3.3V 16-bit", 0xC5, 2048),

            # 32 Gigabit
            ("NAND 4GiB 1.8V 8-bit", 0xA7, 4096),
            ("NAND 4GiB 3.3V 8-bit", 0xD7, 4096),
            ("NAND 4GiB 1.8V 16-bit", 0xB7, 4096),
            ("NAND 4GiB 3.3V 16-bit", 0xC7, 4096),

            # 64 Gigabit
            ("NAND 8GiB 1.8V 8-bit", 0xAE, 8192),
            ("NAND 8GiB 3.3V 8-bit", 0xDE, 8192),
            ("NAND 8GiB 1.8V 16-bit", 0xBE, 8192),
            ("NAND 8GiB 3.3V 16-bit", 0xCE, 8192),

            # 128 Gigabit
            ("NAND 16GiB 1.8V 8-bit", 0x1A, 16384),
            ("NAND 16GiB 3.3V 8-bit", 0x3A, 16384),
            ("NAND 16GiB 1.8V 16-bit", 0x2A, 16384),
            ("NAND 16GiB 3.3V 16-bit", 0x4A, 16384),

            # 256 Gigabit
            ("NAND 32GiB 1.8V 8-bit", 0x1C, 32768),
            ("NAND 32GiB 3.3V 8-bit", 0x3C, 32768),
            ("NAND 32GiB 1.8V 16-bit", 0x2C, 32768),
            ("NAND 32GiB 3.3V 16-bit", 0x4C, 32768),

            # 512 Gigabit
            ("NAND 64GiB 1.8V 8-bit", 0x1E, 65536),
            ("NAND 64GiB 3.3V 8-bit", 0x3E, 65536),
            ("NAND 64GiB 1.8V 16-bit", 0x2E, 65536),
            ("NAND 64GiB 3.3V 16-bit", 0x4E, 65536),
            (0, 0, 0),
]

nand_manuf_ids=[
    (0x98, "Toshiba"),
    (0xec, "Samsung"),
    (0x04, "Fujitsu"),
    (0x8f, "National"),
    (0x07, "Renesas"),
    (0x20, "ST Micro"),
    (0xad, "Hynix"),
    (0x2c, "Micron"),
    (0xc8, "Elite Semiconductor"),
    (0x01, "Spansion/AMD"),
    (0xef, "Winbond"),
    (0x0, "")
]

class settingsopt:
    def __init__(self,parent,chipset, verbose):
        self.parent=parent
        logger.setLevel(verbose)
        self.bad_loader=0
        self.spp=0
        self.pagesize=0
        self.sectorsize=512
        self.maxblock=0
        self.flash_mfr=""
        self.flash_descr=""
        self.oobsize=0
        self.flash16bit=0
        self.badsector=0
        self.badflag=0
        self.badposition=0
        self.badplace=0
        self.bch_mode=0
        self.ecc_size=0
        self.ecc_bit=0
        self.ppb=64
        self.udflag=0

        if chipset<=0:
            self.bad_loader=1
        if chipset==3:
            self.name="MDM9x25"
            self.loader="NPRG9x25p.bin"
            self.eloader="ENPRG9x25p.bin"
            self.msmid=[0x07f1]
            self.ctrl_type=0
            self.udflag=1
            self.nandbase=0xf9af0000
            self.bcraddr=0xfc401a40
        elif chipset==8:
            self.name="MDM9x3X"
            self.loader="NPRG9x35p.bin"
            self.eloader="ENPRG9x35p.bin"
            self.msmid=[0x0922]
            self.ctrl_type=0
            self.udflag=1
            self.nandbase=0xf9af0000
            self.bcraddr=0xfc401a40
        elif chipset==10:
            self.name = "MDM9x4X"
            self.loader = "NPRG9x45p.bin"
            self.eloader = "ENPRG9x45p.bin"
            self.msmid = [0x0950,0x0951]
            self.ctrl_type = 0
            self.udflag = 1
            self.nandbase=0x079b0000
            self.bcraddr=0x0183f000

        if self.ctrl_type==0:
            self.nandcmd_stop=0x01
            self.nandcmd_read=0x32
            self.nandcmd_readall=0x34
            self.nandcmd_program=0x34
            self.nandcmd_programall=0x39
            self.nandcmd_erase=0x3A
            self.nandcmd_identify=0x0B
            self.nandreg_cmd=0
            self.nandreg_adr0=4
            self.nandreg_adr1=8
            self.nandreg_cs=0xc
            self.nandreg_exec=0x10
            self.nandreg_buf_st=0x18
            self.nandreg_fl_st=0x14
            self.nandreg_cfg0=0x20
            self.nandreg_cfg1=0x24
            self.nandreg_ecc=0x28
            self.nandreg_id=0x40
            self.nandreg_sbuf=0x100
        elif self.ctrl_type==1:
            self.nandcmd_stop = 0x07
            self.nandcmd_read = 0x01
            self.nandcmd_readall = 0xffff
            self.nandcmd_program = 0x03
            self.nandcmd_programall = 0xffff
            self.nandcmd_erase = 0x04
            self.nandcmd_identify = 0x05
            self.nandreg_cmd=0x304
            self.nandreg_adr0=0x300
            self.nandreg_adr1=0xffff
            self.nandreg_cs=0x30c
            self.nandreg_exec=0xffff
            self.nandreg_buf_st=0xffff
            self.nandreg_fl_st=0x308
            self.nandreg_cfg0=0xffff
            self.nandreg_cfg1=0x328
            self.nandreg_ecc=0xffff
            self.nandreg_id=0x320
            self.nandreg_sbuf=0x0

        self.nandreg_cmd=self.nandbase+self.nandreg_cmd
        self.nandreg_adr0=self.nandbase+self.nandreg_adr0
        self.nandreg_adr1=self.nandbase+self.nandreg_adr1
        self.nandreg_cs=self.nandbase+self.nandreg_cs
        self.nandreg_exec=self.nandbase+self.nandreg_exec
        self.nandreg_buf_st=self.nandbase+self.nandreg_buf_st
        self.nandreg_fl_st=self.nandbase+self.nandreg_fl_st
        self.nandreg_cfg0=self.nandbase+self.nandreg_cfg0
        self.nandreg_cfg1=self.nandbase+self.nandreg_cfg1
        self.nandreg_ecc=self.nandbase+self.nandreg_ecc
        self.nandreg_id=self.nandbase+self.nandreg_id
        self.nandreg_sbuf=self.nandbase+self.nandreg_sbuf

    def get_flash_config(self):
        self.parent.mempoke(self.nandreg_cmd,0x8000b)
        self.parent.mempoke(self.nandreg_exec,1)
        self.parent.nandwait()
        nandid=self.parent.mempeek(self.nandreg_id)
        fid = (nandid >> 8) & 0xff
        pid = nandid & 0xff

        self.flash_mfr=""
        for info in nand_manuf_ids:
            if info[0]==pid:
                self.flash_mfr=info[1]

        chipsize=0
        for info in nand_ids:
            if info[1]==fid:
                chipsize=info[2]
                self.flash_descr=info[0]

        cfg0 = self.parent.mempeek(self.nandreg_cfg0)
        cfg1 = self.parent.mempeek(self.nandreg_cfg1)
        ecccfg = self.parent.mempeek(self.nandreg_ecc)
        self.sectorsize = 512

        devcfg = (nandid>>24) & 0xff
        self.pagesize = 1024 << (devcfg & 0x3)
        self.blocksize = 64 << ((devcfg >> 4) & 0x3)
        self.spp = self.pagesize//self.sectorsize

        if ((((cfg0 >> 6) & 7) | ((cfg0 >> 2) & 8)) == 0):
            if self.bad_loader==0:
                self.parent.mempoke(self.nandreg_cfg0, (cfg0 | 0x40000 | (((spp-1) & 8) << 2) | (((spp-1) & 7) << 6)))

        self.bch_mode=0
        if (((cfg1 >> 27) & 1) != 0):
            self.bch_mode=1
        if self.bch_mode:
            self.ecc_size=(ecccfg>>8)&0x1F
            self.ecc_bit=(((ecccfg>>4)&3)+1)*4 if ((ecccfg>>4)&4) else 4
        else:
            self.ecc_size=(cfg0>>19)&0xF
            self.ecc_bit=4

        self.badposition = (cfg1 >> 6) & 0x3ff
        self.badplace = (cfg1 >> 16) & 1

        linuxcwsize = 528
        if (self.bch_mode and (self.ecc_bit == 8)):
            linuxcwsize=532

        c_badmark_pos = (self.pagesize - (linuxcwsize * (self.spp - 1)) + 1)
        if self.badposition == 0:
            logging.info("The marker position of defective blocks is autodetected.")
            self.badplace=0
            self.badposition=c_badmark_pos
        if (self.badposition!=c_badmark_pos):
            logging.warning("The marker position of defective blocks mismatches with calculated one.")

        if ((cfg1 & 2) != 0):
            self.flash16bit=1

        if (chipsize != 0):
            self.maxblock=chipsize*1024//self.blocksize
        else:
            self.maxblock=0x800

        if self.oobsize==0:
            if ((nandid == 0x2690ac2c) or (nandid == 0x2690ac98)):
                self.oobsize = 256
            else:
                self.oobsize = (8 << ((devcfg >> 2) & 0x1)) * (self.pagesize >> 9)

class qualcomm_streaming:
    def __init__(self,cdc,sahara):
        self.cdc=cdc
        self.hdlc = hdlc(self.cdc)
        self.mode=sahara.mode
        self.settings=None

    def memread(self,address,length):
        result=b""
        cmdbuf=bytearray([0x11,0x00,0x24,0x30,0x9f,0xe5,0x24,0x40,0x9f,0xe5,0x12,0x00,0xa0,0xe3,0x04,0x00,
                          0x81,0xe4,0x04,0x00,0x83,0xe0,0x04,0x20,0x93,0xe4,0x04,0x20,0x81,0xe4,0x00,0x00,
                          0x53,0xe1,0xfb,0xff,0xff,0x3a,0x04,0x40,0x84,0xe2,0x1e,0xff,0x2f,0xe1])
        errcount=0
        blklen=1000
        for i in range(0,length,1000):
            tries=20
            if (i+1000)>length:
                blklen=length-i
            resp=b""
            while (tries>0):
                resp=self.send(cmdbuf+struct.pack("<I", blklen)+struct.pack("<I",address+i))
                iolen=len(resp)-1
                if iolen<(blklen+4):
                    tries-=1
                    time.sleep(1)
                else:
                    break
            if tries==0:
                logging.error(f"Error reading memory at addr {hex(address)}, {str(blklen)} bytes required, {str(iolen)} bytes received.")
                errcount+=1
                result+=b"\xeb"*blklen
            else:
                result+=resp[1:]
        return [errcount==0,result]

    def mempeek(self,address):
        res=self.memread(address,4)
        if res[0]==True:
            return struct.unpack("<I",res[1][:4])
        return -1

    def memwrite(self,address,data,length):
        cmdbuf=bytearray([0x11,0x00,0x38,0x00,0x80,0xe2,0x24,0x30,0x9f,0xe5,0x24,0x40,0x9f,0xe5,0x04,0x40,
                          0x83,0xe0,0x04,0x20,0x90,0xe4,0x04,0x20,0x83,0xe4,0x04,0x00,0x53,0xe1,0xfb,0xff,
                          0xff,0x3a,0x12,0x00,0xa0,0xe3,0x00,0x00,0xc1,0xe5,0x01,0x40,0xa0,0xe3,0x1e,0xff,
                          0x2f,0xe1])
        if len(data)>1000:
            data=data[0:1000]
            length=1000
        self.send(cmdbuf+struct.pack("<I",address)+struct.pack("<I",length)+data)
        return True

    def mempoke(self,address,value):
        data=struct.pack("<I",value)
        return self.memwrite(address,data,4)

    def nandwait(self):
        if self.settings.ctrl_type==0:
            while(True):
                if (self.mempeek(self.settings.nandreg_fl_st)&0xF)==0:
                    break
        else:
            while (True):
                if (self.mempeek(self.settings.nandreg_fl_st)&0x3)==0:
                    break

    def setaddr(self,block,page):
        address=(block*self.settings.ppb)+page
        if self.settings.ctrl_type == 0: #MDM
            self.mempoke(self.settings.nandreg_adr0,address<<16)
            self.mempoke(self.settings.nandreg_adr0,(address>>16)&0xFF)
        else: #MSM
            self.mempoke(self.settings.nandreg_adr0,address<<8)

    def exec_nand(self,cmd):
        if self.settings.ctrl_type == 0: #MDM
            self.mempoke(self.settings.nandreg_cmd,cmd)
            self.mempoke(self.settings.nandreg_exec,1)
            self.nandwait()
        else: #MSM
            self.mempoke(self.settings.nandreg_cmd,cmd)
            self.nandwait()

    def nand_reset(self):
        self.exec_nand(1)

    def test_badblock(self):
        badflag=0
        st=self.mempeek(self.settings.nandreg_buf_st)&0xFFFF0000
        if self.settings.flash16bit==0:
            if st!=0xFF0000:
                badflag=1
        elif st!=0xFFFF0000:
            badflag=1
        return badflag

    def check_block(self,block):
        self.nand_reset()
        self.setaddr(block,0)
        self.mempoke(self.settings.nandreg_cmd,0x34)
        self.mempoke(self.settings.nandreg_exec, 0x1)
        self.nandwait()
        return self.test_badblock()

    def check_ecc_status(self):
        bs=self.mempeek(self.settings.nandreg_buf_st)
        if ((bs&0x100)!=0) and ((self.mempeek(self.settings.nandreg_cmd+0xec)&0x40)==0):
            return -1
        return bs&0x1f

    def write_badmark(self,block,value):
        udsize=0x220
        cfg1bak=self.mempeek(self.settings.nandreg_cfg1)
        cfgeccback=self.mempeek(self.settings.nandreg_ecc)
        self.mempoke(self.settings.nandreg_ecc,self.mempeek(self.settings.nandreg_ecc)|1)
        self.mempoke(self.settings.nandreg_cfg1, self.mempeek(self.settings.nandreg_cfg1) | 1)
        self.hardware_bad_off()
        buf=bytearray([0xeb])
        for i in range(1,udsize):
            buf.append(value)
        self.nand_reset()
        self.nandwait()
        self.setaddr(block,0)
        self.mempoke(self.settings.nandreg_cmd,0x39)
        for i in range(0,self.settings.spp):
            self.memwrite(self.settings.nandreg_sbuf,buf,udsize)
            self.mempoke(self.settings.nandreg_exec,1)
            self.nandwait()
        self.hardware_bad_on()
        self.mempoke(self.settings.nandreg_cfg1,cfg1bak)
        self.mempoke(self.settings.nandreg_ecc,cfgeccbak)

    def mark_bad(self,block):
        if not self.check_block(block):
            self.write_badmark(block,0)
            return 1
        return 0

    def unmark_bad(self,block):
        if self.check_block(block):
            self.block_erase(block)
            return 1
        return 0

    def test_badpattern(self,buffer):
        for i in range(0,len(buffer)):
            if buffer[i]!=0xbb:
                return 0
        return 1

    def flash_read(self,block,page,sector):
        self.nand_reset()
        self.setaddr(block,page)
        if self.settings.ctrl_type == 0:
            self.mempoke(self.settings.nandreg_cmd,0x34)
            for i in range(0,sector+1):
                self.mempoke(self.settings.nandreg_exec,0x1)
                self.nandwait()
        else:
            for i in range(0,sector+1):
                self.mempoke(self.settings.nandreg_cmd,0x34)
                self.nandwait()
        if self.test_badblock()==0:
            return 0
        return 1

    def hardware_bad_off(self):
        cfg1=self.mempeek(self.settings.nandreg_cfg1)
        cfg1 &= ~(0x3ff<<6)
        self.mempoke(self.settings.nandreg_cfg1,cfg1)

    def hardware_bad_on(self):
        cfg1=self.mempeek(self.settings.nandreg_cfg1)
        cfg1 &= ~(0x7ff<<6)
        cfg1 |=(self.settings.badposition & 0x3FF)<<6
        cfg1 |= self.settings.badplace<<16
        self.mempoke(self.settings.nandreg_cfg1,cfg1)

    def set_badmark_pos(self,pos,place):
        self.settings.badposition=pos
        self.settings.badplace=place&1
        self.hardware_bad_on()

    def set_udsize(self,size):
        tmpreg=self.mempeek(self.settings.nandreg_cfg0)
        tmpreg=(tmpreg&(~(0x3ff<<9)))|(size<<9)
        self.mempoke(self.settings.nandreg_cfg0,tmpreg)
        if (((self.mempeek(self.settings.nandreg_cfg1)>>27)&1)!=0):
            tmpreg = self.mempeek(self.settings.nandreg_ecc)
            tmpreg = (tmpreg & (~(0x3ff << 16))) | (size << 16)
            self.mempoke(self.settings.nandreg_ecc, tmpreg)

    def set_sparesize(self,size):
        cfg0=self.mempeek(self.settings.nandreg_cfg0)
        cfg0=cfg0&(~(0xf<<23))|(size<<23)
        self.mempoke(self.settings.nandreg_cfg0,cfg0)

    def set_eccsize(self,size):
        cfg1 = self.mempeek(self.settings.nandreg_cfg1)
        if ((cfg1>>27)&1)!=0:
            self.settings.bch_mode=1
        if self.settings.bch_mode==1:
            ecccfg = self.mempeek(self.settings.nandreg_ecc)
            ecccfg = (ecccfg&(~(0x1f<<8))|(size<<8))
            self.mempoke(self.settings.nandreg_ecc,ecccfg)
        else:
            cfg0 = self.mempeek(self.settings.nandreg_cfg0)
            cfg0=cfg0&(~(0xf<<19))|(size<<19)
            self.mempoke(self.settings.nandreg_cfg0,cfg0)

    def bch_reset(self):
        if not self.settings.bch_mode:
            return
        cfgecctemp=self.mempeek(self.settings.nandreg_ecc)
        self.mempoke(self.settings.nandreg_ecc,cfgecctemp|2)
        self.mempoke(self.settings.nandreg_ecc, cfgecctemp)

    def set_blocksize(self,udsize,ss,eccs):
        self.set_udsize(udsize)
        self.set_sparesize(ss)
        self.set_eccsize(eccs)


    def get_udsize(self):
        return (self.mempeek(self.settings.nandreg_cfg0) & (0x3ff<<9))>>9

    def block_erase(self,block):
        self.nand_reset()
        self.mempoke(self.settings.nandreg_adr0,block*self.settings.ppb)
        self.mempoke(self.settings.nandreg_adr1,0)
        oldcfg=self.mempeek(self.settings.nandreg_cfg0)
        self.mempoke(self.settings.nandreg_cf0, oldcfg&~(0x1c0))

        self.mempoke(self.settings.nandreg_cmd,0x3a)
        self.mempoke(self.settings.nandreg_exec,1)
        self.nandwait()
        self.mempoke(self.settings.nandreg_cfg0,oldcfg)

    def disable_bam(self):
        nandcstate=[]
        for i in range(0,0xec,4):
            nandcstate.append(self.mempeek(self.settings.nandreg_cmd+i))
        self.mempoke(self.settings.bcraddr,1)
        self.mempoke(self.settings.bcraddr,0)
        for i in range(0,0xec,4):
            self.mempoke(self.settings.nandreg_cmd+i, nandcstate[i])
        self.mempoke(self.settings.nandreg_exec,1)

    def load_ptable_flash(self):
        udsize=512
        if self.settings.udflag:
            udsize=516
        partitions=[]
        for block in range(0,12):
            self.flash_read(block,0,0)
            buffer=self.memread(self.settings.nandreg_sbuf,udsize)
            if buffer[0:8]!=b"\xac\x9f\x56\xfe\x7a\x12\x7f\xcd":
                continue
            self.flash_read(block,1,0)
            buffer=self.memread(self.settings.nandreg_sbuf,udsize)
            self.mempoke(self.settings.nandreg_exec,1)
            self.nandwait()
            buffer+=self.memread(self.settings.nandreg_sbuf,udsize)
            magic1,magic2,version,numparts=struct.unpack("<IIII",buffer[0:0x10])[0]
            if magic1==0xAA7D1B9A and magic2==0x1F7D48BC:
                data=buffer[0x10:]
                for i in range(0,len(data),0x1c):
                    name,offset,length,attr1,attr2,attr3,which_flash=struct.unpack("16sIIBBBB",data[i:i+0x1C])
                    partitions.append(dict(name=name,offset=offset,length=length,attr1=attr1,attr2=attr2,attr3=attr3,which_flash=which_flash))
                return partitions
            return []

    def connect(self,mode=1):
        time.sleep(0.200)
        if mode==0:
            cmdbuf=bytearray([0x11,0x00,0x12,0x00,0xa0,0xe3,0x00,0x00,0xc1,0xe5,0x01,0x40,0xa0,0xe3,0x1e,0xff,0x2f,0xe1])
            resp=self.send(cmdbuf)
            i=resp[1]
            if i==0x12:
                if not self.test_loader():
                    print("Unlocked bootloader being used, cannot continue")
                    exit(2)
                # self.get_flash_config()
                chipset=self.identify_chipset()
                self.settings=settingsopt(self,chipset)

        info=self.send(b"\x01QCOM fast download protocol host\x03\x23\x23\x23\x20")
        resp=self.send(info)
        if resp[1]!=2:
            resp = self.send(info)
        infolen=resp[0x2c]

        if mode==2:
            logging.info("Detected flash memory: %s" % resp[0x2d:0x2d+infolen].decode('utf-8'))
            return

        chipset=self.identify_chipset()
        self.settings=settingsopt(self,chipset)
        self.disable_bam() #only for sahara
        self.settings.get_flash_config()
        cfg0=self.mempeek(self.settings.nandreg_cfg0)

        logging.info("HELLO protocol version: %i",resp[0x22])
        logging.info("Chipset: %s",self.settings.name)
        logging.info("Base address of the NAND controller: %08x",self.settings.nandbase)
        val=resp[0x2d:0x2d+infolen].decode('utf-8') if resp[0x2d] != 0x65 else ""
        logging.info("Flash memory: %s %s, %s",self.settings.flash_mfr,val,self.settings.flash_descr)
        #logging.info("Maximum packet size: %i byte",*((unsigned int*)&rbuf[0x24]))
        logging.info("Sector size: %u bytes",(cfg0&(0x3ff<<9))>>9)
        logging.info("Page size: %u bytes (%u sectors)",self.settings.pagesize,self.settings.spp)
        logging.info("The number of pages in the block: %u",self.settings.ppb)
        logging.info("The size OOB: %u bytes",self.settings.oobsize)
        ecctype="BCH" if self.settings.bch_mode else "R-S"
        logging.info("Type of ECC: %s, %i bit",ecctype,self.settings.ecc_bit)
        logging.info("The size ЕСС: %u bytes",self.settings.ecc_size)
        logging.info("Spare bytes: %u bytes",(cfg0>>23)&0xf)
        markerpos="spare" if self.settings.badplace else "user"
        logging.info("Defective block marker position: %s+%x",markerpos,self.settings.badposition)
        logging.info("The total size of the flash memory = %u blocks (%i MB)",self.settings.maxblock,self.settings.maxblock*self.settings.ppb/1024*self.settings.pagesize/1024)

    def lock_block(self,block,cwsize):
        errcount=0
        blockbuf=bytearray()
        if self.bad_processing_flag==BAD_DISABLE:
            self.hardware_bad_off()
        elif self.bad_processing_flag!=BAD_IGNORE:
            if self.check_block(block):
                for i in range(0,cwsize*self.settings.spp*self.settings.ppb):
                    blockbuf.append(0xbb)
                return [0,blockbuf]
        cfg0=self.mempeek(self.settings.nandreg_cfg0)
        self.nand_reset()
        if (cwsize>(self.settings.sectorsize+4)):
            self.mempoke(self.settings.nandreg_cmd,0x34)
        else:
            self.mempoke(self.settings.nandreg_cmd,0x33)
        self.bch_reset()
        for page in range(0,self.settings.ppb):
            self.setaddr(block,page)
            for sec in range(0,self.settings.spp):
                self.mempoke(self.settings.nandreg_exec,1)
                self.nandwait()
                status=self.check_ecc_status()
                if status!=0:
                    print("blk %x  pg %i  sec  %i err %i---",block,page,sec,status)
                    errcount+=1
                blockbuf.extend(self.memread(self.settings.nandreg_sbuf,cwsize)) #blockbuf+(pg*spp+sec)*cwsize
        if self.bad_processing_flag==BAD_DISABLE:
            self.hardware_bad_on()
        self.mempoke(self.settings.nandreg_cfg0,cfg0)

    def read_block(self,block,cwsize,filename):
        with open(filename,'wb') as fw:
            [okflag,blockbuf]=self.load_block(block,cwsize)
            if okflag or (self.settings.bad_processing_flag != BAD_SKIP):
                fw.write(blockbuf[:cwsize*self.settings.spp*self.settings.ppb])

    def read_block_ext(self,block,filename,yaffsmode):
        with open(filename,'wb') as fw:
            [okflag,blockbuf]=self.load_block(block,self.settings.sectorsize+4)
            if not okflag and (self.settings.bad_processing_flag==BAD_SKIP):
                return 1
            for page in range(0,self.settings.ppb):
                pgoffset=page*self.settings.spp*(self.settings.sectorsize+4)
                for sec in range(0,self.settings.spp):
                    udoffset=pgoffset+sec*(self.settings.sectorsize+4)
                    if sec!=(spp-1):
                        fw.write(blockbuf[udoffset:udoffset+self.settings.sectorsize-4])
                    else:
                        fw.write(blockbuf[udoffset:udoffset+self.settings.sectorsize-4*(self.settings.spp-1)])
            if yaffsmode==1:
                extbuf=bytearray()
                soff=pgoffset+(self.settings.sectorsize+4)*(self.settings.spp-1)+(self.settings.sectorsize-4*(self.settings.spp-1))
                extbuf.extend(blockbuf[soff])
                for i in range(0,self.settings.oobsize):
                    extbuf.append(0xff)
                fw.write(extbuf)

    def read_partition_table(self):
        self.connect(0)
        cwsize=self.settings.sectorsize
        #if readfullsector:
        #    cwsize+=self.settings.oobsize//self.settings.spp
        self.mempoke(self.settings.nandreg_ecc,self.mempeek(self.settings.nandreg_ecc)&0xfffffffe|eccflag)
        self.mempoke(self.settings.nandreg_cfg1,self.mempeek(self.settings.nandreg_cfg1) & 0xfffffffe | eccflag)
        self.mempoke(self.settings.nandreg_cmd,1)
        self.mempoke(self.settings.nandreg_cmd,1)
        self.nandwait()
        self.mempoke(self.settings.nandreg_cmd,0x34)
        for i in range(0,cwsize,4):
            self.mempoke(self.settings.nandreg_sbuf+i,0xffffffff)

    def read_raw(self,start,len,cwsize,filename,rflag):
        for block in range(start,start+len):
            if rflag==0: #normal
                badflag=self.read_block(block,cwsize,filename)
            elif rflag==1: #linux
                badflag=self.read_block_ext(block, filename, 0)
            elif rflag==2: #yaffs
                badflag=self.read_block_ext(block, filename, 1)

    def send(self, cmd):
        if self.hdlc != None:
           return self.hdlc.send_cmd_np(cmd)

    def identify_chipset(self):
        cmd=bytearray([0x11,0x00,0x04,0x10,0x2d,0xe5,0x0e,0x00,0xa0,0xe1,0x03,0x00,0xc0,0xe3,0xff,0x30,
                       0x80,0xe2,0x34,0x10,0x9f,0xe5,0x04,0x20,0x90,0xe4,0x01,0x00,0x52,0xe1,0x03,0x00,
                       0x00,0x0a,0x03,0x00,0x50,0xe1,0xfa,0xff,0xff,0x3a,0x00,0x00,0xa0,0xe3,0x00,0x00,
                       0x00,0xea,0x00,0x00,0x90,0xe5,0x04,0x10,0x9d,0xe4,0x01,0x00,0xc1,0xe5,0xaa,0x00,
                       0xa0,0xe3,0x00,0x00,0xc1,0xe5,0x02,0x40,0xa0,0xe3,0x1e,0xff,0x2f,0xe1,0xef,0xbe,
                       0xad,0xde])
        resp=self.send(cmd)
        if resp[1]!=0xaa:
            return -1
        return resp[2] #08

