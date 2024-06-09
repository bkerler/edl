#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import inspect
import logging
import os
import sys
from queue import Queue
from struct import unpack

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
from edlclient.Library.utils import LogBase, print_progress

MAX_STORE_SIZE = 1024 * 1024 * 1024 * 2  # 2 GBs


class QCSparse(metaclass=LogBase):
    def __init__(self, filename, loglevel):
        self.rf = open(filename, 'rb')
        self.data = Queue()
        self.__logger = self.__logger
        self.offset = 0
        self.tmpdata = bytearray()
        self.__logger.setLevel(loglevel)

        self.major_version = None
        self.minor_version = None
        self.file_hdr_sz = None
        self.chunk_hdr_sz = None
        self.blk_sz = None
        self.total_blks = None
        self.total_chunks = None
        self.image_checksum = None

        self.tmp_offset = 0

        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning

        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def readheader(self):
        buf = self.rf.read(0x1C)
        if len(buf) != 28:
            return False
        header = unpack("<I4H4I", buf)
        magic = header[0]
        self.major_version = header[1]
        self.minor_version = header[2]
        self.file_hdr_sz = header[3]
        self.chunk_hdr_sz = header[4]
        self.blk_sz = header[5]
        self.total_blks = header[6]
        self.total_chunks = header[7]
        self.image_checksum = header[8]
        if magic != 0xED26FF3A:
            return False
        if self.file_hdr_sz != 28:
            self.error("The file header size was expected to be 28, but is %u." % self.file_hdr_sz)
            return False
        if self.chunk_hdr_sz != 12:
            self.error("The chunk header size was expected to be 12, but is %u." % self.chunk_hdr_sz)
            return False
        self.info("Sparse Format detected. Using unpacked image.")
        return True

    def get_chunk_size(self):
        if self.total_blks < self.offset:
            self.error(
                "The header said we should have %u output blocks, but we saw %u" % (self.total_blks, self.offset))
            return -1
        header = unpack("<2H2I", self.rf.read(self.chunk_hdr_sz))
        chunk_type = header[0]
        chunk_sz = header[2]
        total_sz = header[3]
        data_sz = total_sz - 12

        if chunk_type == 0xCAC1:
            if data_sz != (chunk_sz * self.blk_sz):
                self.error(
                    "Raw chunk input size (%u) does not match output size (%u)" % (data_sz, chunk_sz * self.blk_sz))
                return -1
            else:
                self.rf.seek(self.rf.tell() + data_sz)
                return chunk_sz * self.blk_sz
        elif chunk_type == 0xCAC2:
            if data_sz != 4:
                self.error("Fill chunk should have 4 bytes of fill, but this has %u" % data_sz)
                return -1
            else:
                self.rf.seek(self.rf.tell() + data_sz)
                return chunk_sz * self.blk_sz
        elif chunk_type == 0xCAC3:
            return chunk_sz * self.blk_sz
        elif chunk_type == 0xCAC4:
            if data_sz != 4:
                self.error("CRC32 chunk should have 4 bytes of CRC, but this has %u" % data_sz)
                return -1
            else:
                self.rf.seek(self.rf.tell() + data_sz)
                return 0
        else:
            self.debug("Unknown chunk type 0x%04X" % chunk_type)
            return -1

    def unsparse(self):
        if self.total_blks < self.offset:
            self.error(
                "The header said we should have %u output blocks, but we saw %u" % (self.total_blks, self.offset))
            return -1
        header = unpack("<2H2I", self.rf.read(self.chunk_hdr_sz))
        chunk_type = header[0]
        chunk_sz = header[2]
        total_sz = header[3]
        data_sz = total_sz - 12
        if chunk_type == 0xCAC1:
            if data_sz != (chunk_sz * self.blk_sz):
                self.error(
                    "Raw chunk input size (%u) does not match output size (%u)" % (data_sz, chunk_sz * self.blk_sz))
                return -1
            else:
                self.debug("Raw data")
                data = self.rf.read(chunk_sz * self.blk_sz)
                self.offset += chunk_sz
                return data
        elif chunk_type == 0xCAC2:
            if data_sz != 4:
                self.error("Fill chunk should have 4 bytes of fill, but this has %u" % data_sz)
                return -1
            else:
                fill_bin = self.rf.read(4)
                fill = unpack("<I", fill_bin)
                self.debug(format("Fill with 0x%08X" % fill))
                data = fill_bin * (chunk_sz * self.blk_sz // 4)
                self.offset += chunk_sz
                return data
        elif chunk_type == 0xCAC3:
            data = b'\x00' * chunk_sz * self.blk_sz
            self.offset += chunk_sz
            return data
        elif chunk_type == 0xCAC4:
            if data_sz != 4:
                self.error("CRC32 chunk should have 4 bytes of CRC, but this has %u" % data_sz)
                return -1
            else:
                crc_bin = self.rf.read(4)
                crc = unpack("<I", crc_bin)
                self.debug(format("Unverified CRC32 0x%08X" % crc))
                return b""
        else:
            self.debug("Unknown chunk type 0x%04X" % chunk_type)
            return -1

    def getsize(self):
        self.rf.seek(0x1C)
        length = 0
        chunk = 0
        while chunk < self.total_chunks:
            tlen = self.get_chunk_size()
            if tlen == -1:
                break
            length += tlen
            chunk += 1
        self.rf.seek(0x1C)
        return length

    def read(self, length=None):
        if self.tmp_offset >= MAX_STORE_SIZE:
            self.tmpdata = self.tmpdata[self.tmp_offset:]
            self.tmp_offset = 0
        if length is None:
            return self.unsparse()
        if (self.tmp_offset + length) <= len(self.tmpdata):
            tdata = self.tmpdata[self.tmp_offset: self.tmp_offset + length]
            self.tmp_offset += length
            return tdata
        while (self.tmp_offset + length) > len(self.tmpdata):
            self.tmpdata.extend(self.unsparse())
            if (self.tmp_offset + length) <= len(self.tmpdata):
                tdata = self.tmpdata[self.tmp_offset: self.tmp_offset + length]
                self.tmp_offset += length
                return tdata


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("./sparse.py <sparse_partition.img> <outfile>")
        sys.exit()
    sp = QCSparse(sys.argv[1], logging.INFO)
    if sp.readheader():
        print("Extracting sectors to " + sys.argv[2])
        with open(sys.argv[2], "wb") as wf:
            """
            old=0
            while sp.offset<sp.total_blks:
                prog=int(sp.offset / sp.total_blks * 100)
                if prog>old:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete', bar_length=50)
                    old=prog
                data=sp.read()
                if data==b"" or data==-1:
                    break
                wf.write(data)
            if len(sp.tmpdata)>0:
                wf.write(sp.tmpdata)
                sp.tmpdata=bytearray()
            print_progress(100, 100, prefix='Progress:', suffix='Complete', bar_length=50)
            """

            fsize = sp.getsize()
            SECTOR_SIZE_IN_BYTES = 4096
            num_partition_sectors = 5469709
            MaxPayloadSizeToTargetInBytes = 0x200000
            bytesToWrite = SECTOR_SIZE_IN_BYTES * num_partition_sectors
            total = SECTOR_SIZE_IN_BYTES * num_partition_sectors
            old = 0
            pos = 0
            while fsize > 0:
                wlen = MaxPayloadSizeToTargetInBytes // SECTOR_SIZE_IN_BYTES * SECTOR_SIZE_IN_BYTES
                if fsize < wlen:
                    wlen = fsize
                wdata = sp.read(wlen)
                bytesToWrite -= wlen
                fsize -= wlen
                pos += wlen
                pv = wlen % SECTOR_SIZE_IN_BYTES
                if pv != 0:
                    filllen = (wlen // SECTOR_SIZE_IN_BYTES * SECTOR_SIZE_IN_BYTES) + \
                              SECTOR_SIZE_IN_BYTES
                    wdata += b"\x00" * (filllen - wlen)
                    wlen = len(wdata)

                wf.write(wdata)

                prog = round(float(pos) / float(total) * float(100), 1)
                if prog > old:
                    print_progress(prog, 100, prefix='Progress:', suffix='Complete (Sector %d)'
                                                                         % (pos // SECTOR_SIZE_IN_BYTES),
                                   bar_length=50)

        print("Done.")
