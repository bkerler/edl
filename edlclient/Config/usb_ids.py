#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

default_ids = [
    [0x05c6, 0x9008, -1],
    [0x0fce, 0x9dde, -1],
    [0x0fce, 0xade5, -1],
    [0x05c6, 0x900e, -1],
    [0x05c6, 0x9025, -1],
    [0x1199, 0x9062, -1],
    [0x1199, 0x9070, -1],
    [0x1199, 0x9090, -1],
    [0x0846, 0x68e0, -1],
    [0x19d2, 0x0076, -1]
]

default_diag_vid_pid = [
    [0x2c7c, 0x0125, -1],  # Quectel EC25
    [0x1199, 0x9071, -1],  # Sierra Wireless
    [0x1199, 0x9091, -1],  # Sierra Wireless
    [0x0846, 0x68e2,  2],  # Netgear
    [0x05C6, 0x9008, -1],  # QC EDL
    [0x0fce, 0x9dde, -1],  # SONY EDL
    [0x0fce, 0xade5, -1],  # SONY EDL
    [0x05C6, 0x676C, 0],   # QC Handset
    [0x05c6, 0x901d, 0],   # QC Android "setprop sys.usb.config diag,adb"
    [0x19d2, 0x0016, -1],  # ZTE Diag
    [0x19d2, 0x0076, -1],  # ZTE Download
    [0x19d2, 0x0500, -1],  # ZTE Android
    [0x19d2, 0x1404, 2],  # ZTE ADB Modem
    [0x12d1, 0x1506, -1],
    [0x413c, 0x81d7, 5],  # Telit LN940/T77W968
    [0x1bc7, 0x1040, 0],  # Telit LM960A18 USBCFG 1 QMI
    [0x1bc7, 0x1041, 0],  # Telit LM960A18 USBCFG 2 MBIM
    [0x1bc7, 0x1201, 0],  # Telit LE910C4-NF
    [0x05c6, 0x9091, 0],
    [0x05c6, 0x9092, 0]
]
