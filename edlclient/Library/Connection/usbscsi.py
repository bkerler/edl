#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
import argparse
from edlclient.Library.Connection.usblib import *


def main():
    info = 'MassStorageBackdoor (c) B.Kerler 2019.'
    parser = argparse.ArgumentParser(description=info)
    print("\n" + info + "\n\n")
    parser.add_argument('-vid', metavar="<vid>", help='[Option] Specify vid, default=0x2e04)', default="0x2e04")
    parser.add_argument('-pid', metavar="<pid>", help='[Option] Specify pid, default=0xc025)', default="0xc025")
    parser.add_argument('-interface', metavar="<pid>", help='[Option] Specify interface number)', default="")
    parser.add_argument('-nokia', help='[Option] Enable Nokia adb backdoor', action='store_true')
    parser.add_argument('-alcatel', help='[Option] Enable alcatel adb backdoor', action='store_true')
    parser.add_argument('-zte', help='[Option] Enable zte adb backdoor', action='store_true')
    parser.add_argument('-htc', help='[Option] Enable htc adb backdoor', action='store_true')
    parser.add_argument('-htcums', help='[Option] Enable htc ums adb backdoor', action='store_true')
    args = parser.parse_args()
    vid = None
    pid = None
    if args.vid != "":
        vid = int(args.vid, 16)
    if args.pid != "":
        pid = int(args.pid, 16)
    if args.interface != "":
        interface = int(args.interface, 16)
    else:
        interface = -1

    usbscsi = Scsi(vid, pid, interface)
    if usbscsi.connect():
        if args.nokia:
            usbscsi.send_fih_adbenable()
            usbscsi.send_fih_root()
        elif args.zte:
            usbscsi.send_zte_adbenable()
        elif args.htc:
            usbscsi.send_htc_adbenable()
        elif args.htcums:
            usbscsi.send_htc_ums_adbenable()
        elif args.alcatel:
            usbscsi.send_alcatel_adbenable()
        else:
            print("A command is required. Use -h to see options.")
            exit(0)
        usbscsi.close()


if __name__ == '__main__':
    main()
