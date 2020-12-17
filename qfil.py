#!/usr/bin/env python3

"""QFIL tools for qualcomm IC based on https://github.com/bkerler/edl
   by LyuOnLine
QFIL tools for qualcomm ICs.
- Detail logs for sahara and firehose communications.
- Support config xml file samed as qualcomm tools.

Args:
- firehose： firehose images, such as prog_firehose_ddr.elf.
- rawprogram : rawprogram config xml, such as rawprogram_unsparse.xml or rawprogram*.xml.
- patch : patch config xml, such as patch0.xml or patch*.xml.
- imagedir : directory name of images resides.
"""
from Library.utils import *
from Library.usblib import usb_class
from Library.sahara import qualcomm_sahara
from Library.firehose import qualcomm_firehose
from Library.xmlparser import xmlparser
import argparse
import logging
import logging.config
import time
import colorama
import copy
import os
try:
    import xml.etree.cElementTree as ET
    from xml.etree import cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ET
    from xml.etree import ElementTree


class ColorFormatter(logging.Formatter):
    LOG_COLORS = {
        logging.ERROR: colorama.Fore.RED,
        logging.WARNING: colorama.Fore.YELLOW,
    }

    def format(self, record, *args, **kwargs):
        # if the corresponding logger has children, they may receive modified
        # record, so we want to keep it intact
        new_record = copy.copy(record)
        if new_record.levelno in self.LOG_COLORS:
            pad = ""
            if new_record.name != "root":
                print(new_record.name)
                pad = "[LIB]: "
            # we want levelname to be in different color, so let's modify it
            new_record.msg = "{pad}{color_begin}{msg}{color_end}".format(
                pad=pad,
                msg=new_record.msg,
                color_begin=self.LOG_COLORS[new_record.levelno],
                color_end=colorama.Style.RESET_ALL,
            )
        # now we can let standart formatting take care of the rest
        return super(ColorFormatter, self).format(new_record, *args, **kwargs)

def getluns(memory):
    luns = []
    if not memory == "emmc":
        for i in range(0, 99):
            luns.append(i)
    else:
        luns = [0]
    return luns


if __name__ == '__main__':
    global log
    parser = argparse.ArgumentParser(description="Qualcomm QFIL tools")
    parser.add_argument("--vid", "-V", type=lambda x: int(x, 16),
                        default=0x05c6, help="usb vendor id, default is 0x05c6.")
    parser.add_argument("--pid", "-P", type=lambda x: int(x, 16),
                        default=0x9008, help="usb product id, default is 0x9008.")
    parser.add_argument("--firehose", "-f", type=str,
                        required=True, help="EDL firehose image.")
    parser.add_argument("--rawprogram", "-x", type=str, required=True, nargs="+",
                        help="rawprogram.xml file. If multiple filed needed, using rawprogram*.xml.")
    parser.add_argument("--patch", "-p", type=str, required=True, nargs="+",
                        help="patch.xml file. If multiple filed needed, using patch*.xml")
    parser.add_argument("--imagedir", "-D", type=str,
                        required=True, help="Directory name of images resides")
    parser.add_argument("--log_level", "-l", choices=[
                        "warn", "info", "debug"], required=False, default="info", help="log level")
    parser.add_argument("--skipresponse", "-s", type=bool, help="Skip read/write final response from mobile")
    parser.add_argument("--memory", "-m", choices=["emmc", "ufs"], default="emmc", help="memory type")
    args = parser.parse_args()
    log_level = {"warn": logging.WARN, "info": logging.INFO,
                 "debug": logging.DEBUG}[args.log_level]

    filename="log.txt"
    log = log_class(log_level, filename)

    log.info("[INFO] firehose image: %s" % args.firehose)
    log.info("[INFO] rawprogram files: %s" % str(args.rawprogram))
    log.info("[INFO] patch files: %s" % str(args.patch))
    log.info("[INFO] USB device 0x%04x:0x%04x" % (args.vid, args.pid))
    cdc = usb_class(vid=args.vid, pid=args.pid, log=log)
    cdc.timeout = 100
    sahara = qualcomm_sahara(cdc)

    log.info("[USB] waiting for device connecting...")
    while True:
        if cdc.connect():
            break
        else:
            time.sleep(1)

    log.info("[SAHARA] reading firehose images.")
    fl = open(args.firehose, "rb")
    sahara.programmer = fl.read()
    fl.close()

    log.info("[SAHARA] connecting...")
    sahara.connect()

    log.info("[SAHARA] reading sahara info, hwid, sn, sbl version...")
    sahara.info()

    log.info("[SAHARA] entering image tx mode...")
    sahara.connect()

    log.info("[SAHARA] upload firehose image...")
    m = sahara.upload_loader()
    if not m:
        log.error("[ERROR] update firehose image failed!")
        sys.exit(1)

    log.info("[FIREHOSE] waiting connecting...")
    cfg = qualcomm_firehose.cfg()
    cfg.MemoryName = args.memory
    cfg.ZLPAwareHost = 1
    cfg.SkipStorageInit = False
    cfg.SkipWrite = False
    cfg.MaxPayloadSizeToTargetInBytes = 1048576
    cfg.SECTOR_SIZE_IN_BYTES = 512
    cfg.bit64 = True
    fh = qualcomm_firehose(cdc, xmlparser(), cfg,
                           log, None, sahara.serial,args.skipresponse, getluns(args.memory))
    supported_functions = fh.connect(0)
    log.info("[FIREHOSE] connected ok. supported functions: %s" %
                 supported_functions)

    log.info("[FIREHOSE] raw programming...")
    for xml in args.rawprogram:
        log.info("[FIREHOSE] programming %s" % xml)
        fl = open(xml, "r")
        for evt, elem in ET.iterparse(fl, events=["end"]):
            if elem.tag == "program":
                if elem.get("filename", ""):
                    filename = os.path.join(
                        args.imagedir, elem.get("filename"))
                    if not os.path.isfile(filename):
                        log.error("[ERROR] %s not existed!" % filename)
                        sys.exit(1)
                    partition_number = elem.get("physical_partition_number")
                    start_sector = elem.get("start_sector")
                    log.info("[FIREHOSE] programming {filename} to partition({partition})@sector({start_sector})...".format(
                        filename=filename, partition=partition_number, start_sector=start_sector))
                    fh.cmd_program(partition_number, start_sector, filename)
    log.info("[FIREHOSE] raw programming ok.")

    log.info("[FIREHOSE] patching...")
    for xml in args.patch:
        log.info("[FIREHOSE] patching with %s" % xml)
        fl = open(xml, "r")
        for evt, elem in ET.iterparse(fl, events=["end"]):
            if elem.tag == "patch":
                filename = elem.get("filename")
                start_sector = elem.get("start_sector")
                size_in_bytes = elem.get("size_in_bytes")
                log.info("[FIREHOSE] patching {filename} sector({start_sector}), size={size_in_bytes}".format(
                    filename=filename, start_sector=start_sector, size_in_bytes=size_in_bytes))
                content = ElementTree.tostring(elem).decode("utf-8")
                cmd = "<?xml version=\"1.0\" ?><data>\n<{content} /></data>".format(
                    content=content)
                print(cmd)
                fh.xmlsend(content)

    log.info("[FIREHOSE] patching ok")

    log.info("[INFO] reset target...")
    fh.cmd_reset()
    log.info("[INFO] QFIL ok!")
