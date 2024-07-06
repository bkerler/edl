#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import base64
import logging
from edlclient.Library.utils import LogBase


class xiaomi(metaclass=LogBase):
    def __init__(self, fh, projid="18825", serial=123456, ATOBuild=0, Flash_Mode=0, cf=0, supported_functions=None,
                 loglevel=logging.INFO):
        self.fh = fh
        self.xiaomi_authdata = [
            # "QlJORVVnSXVRSTJscjhrU1dDQ3E1dWM3ZnpoRw=="
            "k246jlc8rQfBZ2RLYSF4Ndha1P3bfYQKK3IlQy/NoTp8GSz6l57RZRfmlwsbB99sUW/sgfaWj89//dvDl6Fiwso"
            "+XXYSSqF2nxshZLObdpMLTMZ1GffzOYd2d/ToryWChoK8v05ZOlfn4wUyaZJT4LHMXZ0NVUryvUbVbxjW5SkLpKDKwkMfnxnEwaOddmT"
            "/q0ip4RpVk4aBmDW4TfVnXnDSX9tRI+ewQP4hEI8K5tfZ0mfyycYa0FTGhJPcTTP3TQzy1Krc1DAVLbZ8IqGBrW13YWN"
            "/cMvaiEzcETNyA4N3kOaEXKWodnkwucJv2nEnJWTKNHY9NS9f5Cq3OPs4pQ=="
        ]
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
        for authdata in self.xiaomi_authdata:
            rsp = self.fh.xmlsend(authcmd)
            if not rsp.resp:
                continue

            rsp = self.fh.xmlsend(base64.b64decode(authdata))
            if not rsp.resp:
                continue

            if 'authenticated' in rsp.log[0].lower():
                return True

        return False
