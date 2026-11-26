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
    "--vip-table-path": None,
    "--create-digests": None,

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
        self.status: int | None = 0
        self.args = {**args}
        return

    def fh(self):
        """Return the connected firehose client or fail with a clear message."""
        if self.edl is None or self.edl.fh is None:
            raise RuntimeError("EDL isn't connected, call init() first")
        return self.edl.fh

    def init(self) -> int:
        self.edl = Edl(self.args)
        self.status = self.edl.run()
        return self.status if self.status is not None else 0

    def deinit(self) -> int:
        if self.edl is not None:
            self.status = self.edl.exit()
            self.edl = None
        return self.status if self.status is not None else 0

    def reinit(self) -> int:
        if (self.deinit() == 1):
            return self.status if self.status is not None else 0
        return self.init()

    def set_arg(self, key: str, value, reset: bool = False):
        if (not key in self.args):
            return "Invalid key!"

        if (reset):
            value = EDL_ARGS[key]

        self.args[key] = value
        if self.edl is not None:
            self.edl.args = self.args
        return self.args

    def reset_arg(self, key: str):
        return self.set_arg(key, None, True)

    def __del__(self) -> int:
        return self.deinit()

    # ----- Actual API -----

    def server(self):
        return self.fh().handle_firehose("server", self.args)

    def memorydump(self):
        return self.fh().handle_firehose("memorydump", self.args)

    def printgpt(self):
        return self.fh().handle_firehose("printgpt", self.args)

    def gpt(self, directory: str):
        self.set_arg("<directory>", directory)
        self.fh().handle_firehose("printgpt", self.args)
        return self.fh().handle_firehose("gpt", self.args)

    def r(self, partitionname: str, filename: str):
        self.set_arg("<partitionname>", partitionname)
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose('r', self.args)

    def rl(self, directory: str):
        self.set_arg("<directory>", directory)
        return self.fh().handle_firehose("rl", self.args)

    def rf(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("rf", self.args)

    def rs(self, start_sector: str, sectors: str, filename: str):
        self.set_arg("<start_sector>", start_sector)
        self.set_arg("<sectors>", sectors)
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("rs", self.args)

    def w(self, partitionname: str, filename: str):
        self.set_arg("<partitionname>", partitionname)
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose('w', self.args)

    def wl(self, directory: str):
        self.set_arg("<directory>", directory)
        return self.fh().handle_firehose("wl", self.args)

    def wf(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("wf", self.args)

    def ws(self, start_sector: str, filename: str):
        self.set_arg("<start_sector>", start_sector)
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("ws", self.args)

    def e(self, partitionname: str):
        self.set_arg("<partitionname>", partitionname)
        return self.fh().handle_firehose('e', self.args)

    def es(self, start_sector: str, sectors: str):
        self.set_arg("<start_sector>", start_sector)
        self.set_arg("<sectors>", sectors)
        return self.fh().handle_firehose("es", self.args)

    def ep(self, partitionname: str, sectors: str):
        self.set_arg("<partitionname>", partitionname)
        self.set_arg("<sectors>", sectors)
        return self.fh().handle_firehose("ep", self.args)

    def footer(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("footer", self.args)

    def peek(self, offset: int, length: int, filename: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<length>", length)
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("peek", self.args)

    def peekhex(self, offset: int, length: int):
        self.set_arg("<offset>", offset)
        self.set_arg("<length>", length)
        return self.fh().handle_firehose("peekhex", self.args)

    def peekdword(self, offset: int):
        self.set_arg("<offset>", offset)
        return self.fh().handle_firehose("peekdword", self.args)

    def peekqword(self, offset: int):
        self.set_arg("<offset>", offset)
        return self.fh().handle_firehose("peekqword", self.args)

    def memtbl(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("memtbl", self.args)

    def poke(self, offset: int, filename: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("poke", self.args)

    def pokehex(self, offset: int, data: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<data>", data)
        return self.fh().handle_firehose("pokehex", self.args)

    def pokedword(self, offset: int, data: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<data>", data)
        return self.fh().handle_firehose("pokedword", self.args)

    def pokeqword(self, offset: int, data: str):
        self.set_arg("<offset>", offset)
        self.set_arg("<data>", data)
        return self.fh().handle_firehose("pokeqword", self.args)

    def memcpy(self, offset: int, size: int):
        self.set_arg("<offset>", offset)
        self.set_arg("<size>", size)
        return self.fh().handle_firehose("memcpy", self.args)

    def secureboot(self):
        return self.fh().handle_firehose("server", self.args)

    def pbl(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("pbl", self.args)

    def qfp(self, filename: str):
        self.set_arg("<filename>", filename)
        return self.fh().handle_firehose("qfp", self.args)

    def getstorageinfo(self):
        return self.fh().handle_firehose("getstorageinfo", self.args)

    def setbootablestoragedrive(self, lun: str):
        self.set_arg("<lun>", lun)
        return self.fh().handle_firehose("setbootablestoragedrive", self.args)

    def getactiveslot(self):
        return self.fh().handle_firehose("getactiveslot", self.args)

    def setactiveslot(self, slot: str):
        self.set_arg("<slot>", slot)
        return self.fh().handle_firehose("setactiveslot", self.args)

    def send(self, command: str):
        self.set_arg("<command>", command)
        return self.fh().handle_firehose("send", self.args)

    def xml(self, xmlfile: str):
        self.set_arg("<xmlfile>", xmlfile)
        return self.fh().handle_firehose("xml", self.args)

    def rawxml(self, xmlstring: str):
        self.set_arg("<xmlstring>", xmlstring)
        return self.fh().handle_firehose("rawxml", self.args)

    def reset(self):
        return self.fh().handle_firehose("reset", self.args)

    def nop(self):
        return self.fh().handle_firehose("nop", self.args)

    def modules(self, command: str, options: str):
        self.set_arg("<command>", command)
        self.set_arg("<options>", options)
        return self.fh().handle_firehose("modules", self.args)

    def provision(self, xmlfile: str):
        self.set_arg("<xmlfile>", xmlfile)
        return self.fh().handle_firehose("provision", self.args)

    def qfil(self, rawprogram: str, patch: str, imagedir: str):
        self.set_arg("<rawprogram>", rawprogram)
        self.set_arg("<patch>", patch)
        self.set_arg("<imagedir>", imagedir)
        return self.fh().handle_firehose("qfil", self.args)
