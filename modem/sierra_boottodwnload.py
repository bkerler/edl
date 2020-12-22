#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2019 under MIT license
# If you use my code, make sure you refer to my name
# If you want to use in a commercial product, ask me before integrating it

import serial
print("Sending download mode command to /dev/ttyUSB2")
ser = serial.Serial('/dev/ttyUSB2')
ser.baudrate=115200
ser.write(b'AT!BOOTHOLD\r')
print(ser.readline())
ser.write(b'AT!QPSTDLOAD\r')
print(ser.readline())
#ser.write(b'AT!QPSTDLOAD\r')
#print(ser.readline())
print("Done switching to download mode")
ser.close()    
