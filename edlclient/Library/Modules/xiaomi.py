#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import logging
from edlclient.Library.utils import LogBase


class xiaomi(metaclass=LogBase):
    def __init__(self, fh, projid="18825", serial=123456, ATOBuild=0, Flash_Mode=0, cf=0, supported_functions=None,
                 loglevel=logging.INFO):
        self.fh = fh
        self.xiaomi_authdata = b"\x93\x6E\x3A\x8E\x57\x3C\xAD\x07\xC1\x67\x64\x4B\x61\x21\x78\x35\xD8\x5A\xD4\xFD" + \
                               b"\xDB\x7D\x84\x0A\x2B\x72\x25\x43\x2F\xCD\xA1\x3A\x7C\x19\x2C\xFA\x97\x9E\xD1\x65" + \
                               b"\x17\xE6\x97\x0B\x1B\x07\xDF\x6C\x51\x6F\xEC\x81\xF6\x96\x8F\xCF\x7F\xFD\xDB\xC3" + \
                               b"\x97\xA1\x62\xC2\xCA\x3E\x5D\x76\x12\x4A\xA1\x76\x9F\x1B\x21\x64\xB3\x9B\x76\x93" + \
                               b"\x0B\x4C\xC6\x75\x19\xF7\xF3\x39\x87\x76\x77\xF4\xE8\xAF\x25\x82\x86\x82\xBC\xBF" + \
                               b"\x4E\x59\x3A\x57\xE7\xE3\x05\x32\x69\x92\x53\xE0\xB1\xCC\x5D\x9D\x0D\x55\x4A\xF2" + \
                               b"\xBD\x46\xD5\x6F\x18\xD6\xE5\x29\x0B\xA4\xA0\xCA\xC2\x43\x1F\x9F\x19\xC4\xC1\xA3" + \
                               b"\x9D\x76\x64\xFF\xAB\x48\xA9\xE1\x1A\x55\x93\x86\x81\x98\x35\xB8\x4D\xF5\x67\x5E" + \
                               b"\x70\xD2\x5F\xDB\x51\x23\xE7\xB0\x40\xFE\x21\x10\x8F\x0A\xE6\xD7\xD9\xD2\x67\xF2" + \
                               b"\xC9\xC6\x1A\xD0\x54\xC6\x84\x93\xDC\x4D\x33\xF7\x4D\x0C\xF2\xD4\xAA\xDC\xD4\x30" + \
                               b"\x15\x2D\xB6\x7C\x22\xA1\x81\xAD\x6D\x77\x61\x63\x7F\x70\xCB\xDA\x88\x4C\xDC\x11" + \
                               b"\x33\x72\x03\x83\x77\x90\xE6\x84\x5C\xA5\xA8\x76\x79\x30\xB9\xC2\x6F\xDA\x71\x27" + \
                               b"\x25\x64\xCA\x34\x76\x3D\x35\x2F\x5F\xE4\x2A\xB7\x38\xFB\x38\xA5"
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def edl_auth(self):
        """
        Redmi A1, Poco F1, Redmi 5 Pro, 6 Pro, 7 Pro, 7A, 8, 8A, 8A Dual, 8A Pro, Y2, S2
        """
        authcmd = b"<?xml version=\"1.0\" ?><data> <sig TargetName=\"sig\" size_in_bytes=\"256\" verbose=\"1\"/></data>"
        rsp = self.fh.xmlsend(authcmd)
        if rsp.resp:
            rsp = self.fh.xmlsend(self.xiaomi_authdata)
            if rsp.resp:
                if "value" in rsp.resp:
                    if rsp.resp["value"] == "ACK":
                        if 'authenticated' in rsp.log[0].lower() and 'true' in rsp.log[0].lower():
                            return True
        return False
