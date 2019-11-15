# Qualcomm Sahara / Firehose Attack Client / Diag Tools
(c) B. Kerler 2018-2019

Why
===
- Because we'd like to flexible dump smartphones
- Because attacking firehose is kewl
- Because memory dumping helps to find issues :)
  
Installation
=============
- Get python >= 3.7 64-Bit

- Add "blacklist qcserial" as last line to /etc/modprobe.d/blacklist.conf
- Copy Drivers/51-edl.rules to /etc/udev/rules.d
- Copy Drivers/50-android.rules to /etc/udev/rules.d
- sudo apt install adb
- sudo apt install fastboot

Linux/Windows: 
- "python -m pip install pyusb pyserial"

Windows:
- Use Filter Installer to install libusb filter driver 
  on Qualcomm 9008 port otherwise we won't detect the device

Run EDL
=======
- "./edl.py -h" -> to see help with all options
- "./edl.py -printgpt 0 -memory ufs" -> to print gpt on lun 0 on device with ufs
- "./edl.py -printgpt 0 -memory emmc" -> to print gpt on device with emmc
- "./edl.py -rf 0 flash.bin -memory emmc" -> to dump whole flash on lun 0 for device with emmc
- "./edl.py -footer 0 footer.bin -memory emmc" -> to dump the crypto footer on lun 0 for Androids
- "./edl.py -w 0 boot boot.img -memory emmc" -> to write boot.img to the "boot" partition on lun 0 on the device with emmc flash
- "./edl.py -memory emmc -server" -> Run TCP/IP server, see tcpclient.py for an example client

Install EDL loaders
===============
- "mkdir examples"
- Copy all your loaders into the examples directory
- "./fhloaderparse.py examples" -> will autodetect and rename loader structure and copy them to the "Loaders" directory

Run Diag
========
Allows to send commands to the qc diag port
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -info" -> Send cmd "00" and return info
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -spc 303030303030" -> Send spc "303030303030"
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -cmd 00" -> Send cmd "00" (hexstring)
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -nvread 0x55" -> Display nvitem 0x55
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -nvbackup backup.json" -> Backup all nvitems to a json structured file
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -efsread efs.bin" -> Dump the EFS Modem partition to file efs.bin
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -efslistdir /" -> Display / directory listing of EFS


Issues
======
- Secure loader with SDM660 on Xiaomi not yet supported
- EFS directory write and file read has to be added

Tested with
===========
- Oneplus 3T, Oneplus 6T, BQ X, BQ X5, BQ X2, Gigaset ME Pure, ZTE MF210

Published under MIT license
Additional license limitations: No use in commercial products without prior permit.

Enjoy !
