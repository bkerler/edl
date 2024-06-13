#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import hashlib
import logging
import random

from edlclient.Library.utils import LogBase


class nothing(metaclass=LogBase):
    def __init__(self, fh, projid="22111", serial=123456, ATOBuild=0, Flash_Mode=0, cf=0, supported_functions=None,
                 loglevel=logging.INFO):
        self.fh = fh
        self.projid = projid
        # self.projid == "22111":
        self.hashverify = "16386b4035411a770b12507b2e30297c0c5471230b213e6a1e1e701c6a425150"
        self.serial = serial
        self.supported_functions = supported_functions
        self.__logger.setLevel(loglevel)
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def generatetoken(self, token1: str = None):
        if token1 is None:
            token1 = random.randbytes(32).hex()
        authresp = token1 + self.projid + ("%x" % self.serial) + self.hashverify
        token2 = hashlib.sha256(bytes(authresp, 'utf-8')).hexdigest()[:64]
        token3 = self.hashverify
        return bytes(
            f"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data>\n    <ntprojectverify  token1=\"{token1}\" token2=\"{token2}\" token3=\"{token3}\"/>\n</data>\n",
            'utf-8')

    def ntprojectverify(self):
        """
        Nothing Phone 2
        """
        authcmd = b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data>\n  <checkntfeature />\n</data>\n"
        rsp = self.fh.xmlsend(authcmd)
        if rsp.resp:
            authresp = self.generatetoken()
            rsp = self.fh.xmlsend(authresp)
            if rsp.resp:
                if b"ACK" in rsp.data:
                    return True
                if "value" in rsp.resp:
                    if rsp.resp["value"] == "ACK":
                        if 'authenticated' in rsp.log[0].lower() and 'true' in rsp.log[0].lower():
                            return True
        return False


if __name__ == "__main__":
    nt = nothing(fh=None, projid="22111", serial=1729931115)
    res = nt.generatetoken(token1="512034500a07154561661e0f371f4a712a0b76074605724c640e301d632b3671")
    org = b"<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data>\n    <ntprojectverify  token1=\"512034500a07154561661e0f371f4a712a0b76074605724c640e301d632b3671\" token2=\"1ecd222465436eb8acc0cfc41e90d1e677165c184ea7d9631615014dac88c669\" token3=\"16386b4035411a770b12507b2e30297c0c5471230b213e6a1e1e701c6a425150\"/>\n</data>\n"
    if res != org:
        print("Error !")
    print(res)
    print(nt.generatetoken())
