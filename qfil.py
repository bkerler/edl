#!/usr/bin/env python3
"""
QFIL tools for qualcomm IC based on https://github.com/bkerler/edl by LyuOnLine

QFIL tools for qualcomm ICs.
- Detail logs for sahara and firehose communications.
- Support config xml file samed as qualcomm tools.

Args:
- firehose： firehose images, such as prog_firehose_ddr.elf.
- rawprogram : rawprogram config xml, such as rawprogram_unsparse.xml or rawprogram*.xml.
- patch : patch config xml, such as patch0.xml or patch*.xml.
- imagedir : directory name of images resides.
"""
import argparse
import logging.config
import time
import copy
import os
import sys
import colorama
from Library.usblib import usb_class
from Library.sahara import qualcomm_sahara
from Library.firehose import qualcomm_firehose
from Library.xmlparser import xmlparser
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



if __name__ == '__main__':
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
    parser.add_argument("--lun", "-lun", default="0", help="lun")
    parser.add_argument("--devicemodel", "-dev", default="", help="Device prjid")
    args = parser.parse_args()
    log_level = {"warn": logging.WARN, "info": logging.INFO,
                 "debug": logging.DEBUG}[args.log_level]


    def getluns(memory):
        luns = []
        if not memory == "emmc":
            for i in range(0, 99):
                luns.append(i)
        else:
            luns = [0]
        return luns


    def find_bootable_partition(rawprogram):
        part = -1
        for xml in rawprogram:
            fl = open(xml, "r")
            for evt, elem in ET.iterparse(fl, events=["end"]):
                if elem.tag == "program":
                    label = elem.get("label")
                    if label in ['xbl', 'xbl_a', 'sbl1']:
                        if part != -1:
                            logging.error("[FIREHOSE] multiple bootloader found!")
                            return -1
                        part = elem.get("physical_partition_number")

        return part

    LOG_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "root": {
                "()": ColorFormatter,
                "format": "%(message)s",
            }
        },
        "handlers": {
            "root": {
                "level": log_level,
                "formatter": "root",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {
            "": {
                "handlers": ["root"],
                "level": log_level,
                "propagate": False
            }
        },
    }
    logging.config.dictConfig(LOG_CONFIG)

    logging.info("[INFO] firehose image: %s" % args.firehose)
    logging.info("[INFO] rawprogram files: %s" % str(args.rawprogram))
    logging.info("[INFO] patch files: %s" % str(args.patch))
    logging.info("[INFO] USB device 0x%04x:0x%04x" % (args.vid, args.pid))
    cdc = usb_class(vidpid=[args.vid, args.pid])
    cdc.timeout = 100
    sahara = qualcomm_sahara(cdc)

    logging.info("[USB] waiting for device connecting...")
    while True:
        if cdc.connect():
            break
        time.sleep(1)

    logging.info("[SAHARA] reading firehose images.")
    fl = open(args.firehose, "rb")
    sahara.programmer = fl.read()
    fl.close()

    logging.info("[SAHARA] connecting...")
    sahara.connect()

    logging.info("[SAHARA] reading sahara info, hwid, sn, sbl version...")
    sahara.info()

    logging.info("[SAHARA] entering image tx mode...")
    sahara.connect()

    logging.info("[SAHARA] upload firehose image...")
    m = sahara.upload_loader()
    if not m:
        logging.error("[ERROR] update firehose image failed!")
        sys.exit(1)

    logging.info("[FIREHOSE] waiting connecting...")
    cfg = qualcomm_firehose.cfg()
    cfg.MemoryName = args.memory
    cfg.ZLPAwareHost = 1
    cfg.SkipStorageInit = False
    cfg.SkipWrite = False
    cfg.MaxPayloadSizeToTargetInBytes = 1048576
    cfg.SECTOR_SIZE_IN_BYTES = 512
    cfg.bit64 = True
    fh = qualcomm_firehose(cdc, xmlparser(), cfg, log_level, args.devicemodel, sahara.serial,args.skipresponse,
                           getluns(args.memory))
    supported_functions = fh.connect(0)
    logging.info("[FIREHOSE] connected ok. supported functions: %s" %
                 supported_functions)

    logging.info("[FIREHOSE] raw programming...")
    for xml in args.rawprogram:
        logging.info("[FIREHOSE] programming %s" % xml)
        fl = open(xml, "r")
        for evt, elem in ET.iterparse(fl, events=["end"]):
            if elem.tag == "program":
                if elem.get("filename", ""):
                    filename = os.path.join(
                        args.imagedir, elem.get("filename"))
                    if not os.path.isfile(filename):
                        logging.error("[ERROR] %s not existed!" % filename)
                        sys.exit(1)
                    partition_number = elem.get("physical_partition_number")
                    start_sector = elem.get("start_sector")
                    logging.info("[FIREHOSE] programming {filename} to partition({partition})@sector({start_sector})...".format(
                        filename=filename, partition=partition_number, start_sector=start_sector))
                    fh.cmd_program(partition_number, start_sector, filename)
    logging.info("[FIREHOSE] raw programming ok.")

    logging.info("[FIREHOSE] patching...")
    for xml in args.patch:
        logging.info("[FIREHOSE] patching with %s" % xml)
        fl = open(xml, "r")
        for evt, elem in ET.iterparse(fl, events=["end"]):
            if elem.tag == "patch":
                filename = elem.get("filename")
                if filename != "DISK":
                    continue
                start_sector = elem.get("start_sector")
                size_in_bytes = elem.get("size_in_bytes")
                logging.info("[FIREHOSE] patching {filename} sector({start_sector}), size={size_in_bytes}".format(
                    filename=filename, start_sector=start_sector, size_in_bytes=size_in_bytes))
                content = ElementTree.tostring(elem).decode("utf-8")
                CMD = "<?xml version=\"1.0\" ?><data>\n<{content} /></data>".format(
                    content=content)
                print(CMD)
                fh.xmlsend(CMD)

    logging.info("[FIREHOSE] patching ok")
    bootable = find_bootable_partition(args.rawprogram)
    if bootable != -1:
        if fh.cmd_setbootablestoragedrive(bootable):
            logging.info("[FIREHOSE] partition({partition}) is now bootable\n".format(partition=bootable));
        else:
            logging.info("[FIREHOSE] set partition({partition}) as bootable failed\n".format(partition=bootable));

    logging.info("[INFO] reset target...")
    fh.cmd_reset()
    logging.info("[INFO] QFIL ok!")
