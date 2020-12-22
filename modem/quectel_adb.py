#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2020 under MIT license
# If you use my code, make sure you refer to my name
# If you want to use in a commercial product, ask me before integrating it

import crypt
import sys
import serial
if len(sys.argv)<2:
    print("Usage: ./quectel_adb.py [enable,disable]")
    sys.exit()
ser = serial.Serial('/dev/ttyUSB2')
ser.baudrate=115200
if sys.argv[1]=="enable":
    print("Sending download mode command to /dev/ttyUSB2")
    ser.write(b"AT+QADBKEY?\r")
    salt=ser.readline()
    salt+=ser.readline()
    if not b"ERROR" in salt:
    	salt=sys.argv[1]
    	code=crypt.crypt("SH_adb_quectel","$1$"+salt)
    	code=code[12:]
    	ser.write(b"AT+QADBKEY=\"%s\"\n" % code)
    	ser.write(b"AT+QCFG=\"usbcfg\",0x2C7C,0x125,1,1,1,1,1,1,0\n\n")
else:
    print("In order to disable adb:")
    ser.write("AT+QCFG=\"usbcfg\",0x2C7C,0x125,1,1,1,1,1,0,0\n")
    print(ser.readline())
