#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from edlclient.edl import main as Edl

EDL_ARGS = {
    "--debugmode": False,
    "--devicemodel": None,
    "--genxml": False,
    "--gpt-num-part-entries": "0",
    "--gpt-part-entry-size": "0",
    "--gpt-part-entry-start-lba": "0",
    "--loader": "None",
    "--lun": None,
    "--maxpayload": "0x100000",
    "--memory": None,
    "--partitionfilename": None,
    "--partitions": None,
    "--pid": "-1",
    "--portname": None,
    "--resetmode": None,
    "--sectorsize": None,
    "--serial": False,
    "--serial_number": None,
    "--skip": None,
    "--skipresponse": False,
    "--skipstorageinit": False,
    "--skipwrite": False,
    "--tcpport": "1340",
    "--vid": "-1",

    "<command>": None,
    "<data>": None,
    "<directory>": None,
    "<filename>": None,
    "<imagedir>": None,
    "<length>": None,
    "<lun>": None,
    "<offset>": None,
    "<options>": None,
    "<partitionname>": None,
    "<patch>": None,
    "<rawprogram>": None,
    "<sectors>": None,
    "<size>": None,
    "<slot>": None,
    "<start_sector>": None,
    "<xmlfile>": None,
    "<xmlstring>": None,
}

class edl_api():
    def __init__(self, args: dict = EDL_ARGS):
        self.edl = None
        self.status = 0
        self.args = {**args}
        return

    def init(self) -> int:
        self.edl = Edl(self.args)
        self.status = self.edl.run()
        return self.status

    def deinit(self) -> int:
        if (self.edl != None):
            self.status = self.edl.exit()
            self.edl = None
        return self.status

    def reinit(self) -> int:
        if (self.deinit() == 1):
            return self.status
        return self.init()

    def set_arg(self, key: str, value, reset: bool = False):
        if (not key in self.args):
            return "Invalid key!"

        if (reset):
            value = EDL_ARGS[key]

        self.args[key] = value
        if (self.edl != None):
            self.edl.args = self.args
        return self.args

    def reset_arg(self, key: str):
        return self.set_arg(key, None, True)

    def __del__(self) -> int:
        return self.deinit()

    # ----- Actual API -----

    def server(self):
        return self.edl.fh.handle_firehose("server", self.edl.args)

    def memorydump(self):
        return self.edl.fh.handle_firehose("memorydump", self.edl.args)

    def printgpt(self):
        return self.edl.fh.handle_firehose("printgpt", self.edl.args)

    def gpt(self, directory: str):
        self.set_arg("<directory>", directory)
        self.edl.fh.handle_firehose("printgpt", self.edl.args)
        return self.edl.fh.handle_firehose("gpt", self.edl.args)

    def r(self, partitionname: str, filename: str):
        self.set_arg("<partitionname>", partitionname)
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose('r', self.edl.args)

    def rl(self, directory: str):
        self.set_arg("<directory>", directory)
        return self.edl.fh.handle_firehose("rl", self.edl.args)

    def rf(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("rf", self.edl.args)

    def rs(self, start_sector: str, sectors: str, filename: str):
        self.set_arg("<start_sector>", start_sector)
        self.set_arg("<sectors>", sectors)
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("rs", self.edl.args)

    def w(self, partitionname: str, filename: str):
        self.set_arg("<partitionname>", partitionname)
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose('w', self.edl.args)

    def wl(self, directory: str):
        self.set_arg("<directory>", directory)
        return self.edl.fh.handle_firehose("wl", self.edl.args)

    def wf(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("wf", self.edl.args)

    def ws(self, start_sector: str, filename: str):
        self.set_arg("<start_sector>", start_sector)
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("ws", self.edl.args)

    def e(self, partitionname: str):
        self.set_arg("<partitionname>", partitionname)
        return self.edl.fh.handle_firehose('e', self.edl.args)

    def es(self, start_sector: str, sectors: str):
        self.set_arg("<start_sector>", start_sector)
        self.set_arg("<sectors>", sectors)
        return self.edl.fh.handle_firehose("es", self.edl.args)

    def ep(self, partitionname: str, sectors: str):
        self.set_arg("<partitionname>", partitionname)
        self.set_arg("<sectors>", sectors)
        return self.edl.fh.handle_firehose("ep", self.edl.args)

    def footer(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("footer", self.edl.args)

    def peek(self, offset: int, length: int, filename: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<length>", length)
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("peek", self.edl.args)

    def peekhex(self, offset: int, length: int):
        self.set_arg("<offset>", offset)
        self.set_arg("<length>", length)
        return self.edl.fh.handle_firehose("peekhex", self.edl.args)

    def peekdword(self, offset: int):
        self.set_arg("<offset>", offset)
        return self.edl.fh.handle_firehose("peekdword", self.edl.args)

    def peekqword(self, offset: int):
        self.set_arg("<offset>", offset)
        return self.edl.fh.handle_firehose("peekqword", self.edl.args)

    def memtbl(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("memtbl", self.edl.args)

    def poke(self, offset: int, filename: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("poke", self.edl.args)

    def pokehex(self, offset: int, data: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<data>", data)
        return self.edl.fh.handle_firehose("pokehex", self.edl.args)

    def pokedword(self, offset: int, data: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<data>", data)
        return self.edl.fh.handle_firehose("pokedword", self.edl.args)

    def pokeqword(self, offset: int, data: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<data>", data)
        return self.edl.fh.handle_firehose("pokeqword", self.edl.args)

    def memcpy(self, offset: int, size: int):
        self.set_arg("<offset>", offset)
        self.set_arg("<size>", size)
        return self.edl.fh.handle_firehose("memcpy", self.edl.args)

    def secureboot(self):
        return self.edl.fh.handle_firehose("server", self.edl.args)

    def pbl(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("pbl", self.edl.args)

    def qfp(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.edl.fh.handle_firehose("qfp", self.edl.args)

    def getstorageinfo(self):
        return self.edl.fh.handle_firehose("getstorageinfo", self.edl.args)

    def setbootablestoragedrive(self, lun: str):
        self.set_arg("<lun>", lun)
        return self.edl.fh.handle_firehose("setbootablestoragedrive", self.edl.args)

    def getactiveslot(self):
        return self.edl.fh.handle_firehose("getactiveslot", self.edl.args)

    def setactiveslot(self, slot: str):
        self.set_arg("<slot>", slot)
        return self.edl.fh.handle_firehose("setactiveslot", self.edl.args)

    def send(self, command: str):
        self.set_arg("<command>", command)
        return self.edl.fh.handle_firehose("send", self.edl.args)

    def xml(self, xmlfile: str):
        self.set_arg("<xmlfile>", xmlfile)
        return self.edl.fh.handle_firehose("xml", self.edl.args)

    def rawxml(self, xmlstring: str):
        self.set_arg("<xmlstring>", xmlstring)
        return self.edl.fh.handle_firehose("rawxml", self.edl.args)

    def reset(self):
        return self.edl.fh.handle_firehose("reset", self.edl.args)

    def nop(self):
        return self.edl.fh.handle_firehose("nop", self.edl.args)

    def modules(self, command: str, options: str):
        self.set_arg("<command>", command)
        self.set_arg("<options>", options)
        return self.edl.fh.handle_firehose("modules", self.edl.args)

    def provision(self, xmlfile: str):
        self.set_arg("<xmlfile>", xmlfile)
        return self.edl.fh.handle_firehose("provision", self.edl.args)

    def qfil(self, rawprogram: str, patch: str, imagedir: str):
        self.set_arg("<rawprogram>", rawprogram)
        self.set_arg("<patch>", patch)
        self.set_arg("<imagedir>", imagedir)
        return self.edl.fh.handle_firehose("qfil", self.edl.args)
