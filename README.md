# Qualcomm Sahara / Firehose Attack Client / Diag Tools
(c) B. Kerler 2018-2020

## Why

- Because we'd like to flexible dump smartphones
- Because attacking firehose is kewl
- Because memory dumping helps to find issues :)
  
## Installation

- Get python >= 3.7 64-Bit
- Add "blacklist qcserial" as last line to /etc/modprobe.d/blacklist.conf
- Copy Drivers/51-edl.rules to /etc/udev/rules.d
- Copy Drivers/50-android.rules to /etc/udev/rules.d
- sudo apt install adb
- sudo apt install fastboot
- sudo sudo apt install liblzma-dev

Linux/Windows: 
- "python -m pip install -r requirements.txt" (use python3 instead of python if you use python2 and python3)

Windows:
- Boot device into 9008 mode, install Qualcomm_Diag_QD_Loader_2016_driver.exe from Drivers\Windows,
  then install libusb-win32-devel-filter-1.2.6.0.exe.
  Run Filter Wizard, "Install a device filter",  select "Qualcomm HS-USB QDLoader 9008"
  and press "Install" to install libusb filter driver otherwise we won't detect the device.
  Then use the edl tool.
or
- Use Zadig 2.4 or higher, list all devices, select QUSB_BULK device and replace
  driver with libusb 1.2.6 one (will replace original driver)

## Convert EDL loaders for automatic usage

- Make a subdirectory "newstuff", copy your edl loaders to this subdirectory
- "./fhloaderparse.py newstuff Loaders"

## Run EDL (examples)

### Generic

- "./edl.py -h" -> to see help with all options
- "./edl.py server --memory=ufs --tcpport=1340" -> Run TCP/IP server on port 1340, see tcpclient.py for an example client
- "./edl.py xml run.xml" -> To send a xml file run.xml via firehose
- "./edl.py reset" -> To reboot the phone
- "./edl.py rawxml <xmlstring>' -> To send own xml string, example : 
   '''bash
   ./edl.py rawxml "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><response value=\"ACK\" /></data>"
   '''
- "./edl.py [anycommand] --debugmode" -> enables Verbose. Only do that is REALLY needed as it will print out everything happening !

### For EMMC Flash

- "./edl.py printgpt" -> to print gpt on device with emmc
- "./edl.py rf flash.bin" -> to dump whole flash for device with emmc
- "./edl.py rl dumps --skip=userdata --genxml" -> to dump all partitions to directory dumps for device with emmc and skipping userdata partition, write rawprogram0.xml
- "./edl.py rs 0 15 data.bin" -> to dump 15 sectors from starting sector 0 to file data.bin for device with emmc
- "./edl.py rs 0 15 data.bin --skipresponse" -> to dump 15 sectors from starting sector 0 to file data.bin for device with emmc, ignores missing ACK from phones
- "./edl.py r boot_a boot.img" -> to dump the partition "boot_a" to the filename boot.img for device with emmc
- "./edl.py r boot_a,boot_b boot_a.img,boot_b.img" -> to dump multiple partitions to multiple filenames
- "./edl.py footer footer.bin" -> to dump the crypto footer for Androids with emmc flash
- "./edl.py w boot_a boot.img" -> to write boot.img to the "boot" partition on lun 0 on the device with emmc flash
- "./edl.py wl dumps" -> to write all files from "dumps" folder to according partitions to flash
- "./edl.py wf dump.bin" -> to write the rawimage dump.bin to flash
- "./edl.py e misc" -> to erase the partition misc on emmc flash
- "./edl.py gpt . --genxml" -> dump gpt_main0.bin/gpt_backup0.bin and write rawpartition0.xml to current directory (".")


### For UFS Flash

- "./edl.py printgpt --memory=ufs --lun=0" -> to print gpt on lun 0
- "./edl.py printgpt --memory=ufs" -> to print gpt of all lun
- "./edl.py rf lun0.bin --memory=ufs --lun=0" -> to dump whole lun 0
- "./edl.py rf flash.bin --memory=ufs" -> to dump all luns as lun0_flash.bin, lun1_flash.bin, ...
- "./edl.py rl dumps --memory=ufs --lun=0 --skip=userdata,vendor_a" -> to dump all partitions from lun0 to directory dumps for device with ufs and skip userdata and vendor_a partition
- "./edl.py rl dumps --memory=ufs --genxml" -> to dump all partitions from all lun to directory dumps and write rawprogram[lun].xml
- "./edl.py rs 0 15 data.bin --memory=ufs --lun=0" -> to dump 15 sectors from starting sector 0 from lun 0 to file data.bin
- "./edl.py r boot_a boot.img --memory=ufs --lun=4" -> to dump the partition "boot_a" from lun 4 to the filename boot.img
- "./edl.py r boot_a boot.img --memory=ufs" -> to dump the partition "boot_a" to the filename boot.img using lun autodetection
- "./edl.py r boot_a,boot_b boot_a.img,boot_b.img --memory=ufs" -> to dump multiple partitions to multiple filenames
- "./edl.py footer footer.bin --memory=ufs" -> to dump the crypto footer
- "./edl.py w boot boot.img --memory=ufs --lun=4" -> to write boot.img to the "boot" partition on lun 4 on the device with ufs flash
- "./edl.py wl dumps --memory=ufs --lun=0" -> to write all files from "dumps" folder to according partitions to flash lun 0
- "./edl.py wl dumps --memory=ufs" -> to write all files from "dumps" folder to according partitions to flash and try to autodetect lun
- "./edl.py wf dump.bin --memory=ufs --lun=0" -> to write the rawimage dump.bin to flash lun 0
- "./edl.py e misc --memory=ufs --lun=0" -> to erase the partition misc on lun 0
- "./edl.py gpt . --genxml --memory=ufs" -> dump gpt_main[lun].bin/gpt_backup[lun].bin and write rawpartition[lun].xml to current directory (".")

### For devices with peek/poke command

- "./edl.py peek 0x200000 0x10 mem.bin" -> To dump 0x10 bytes from offset 0x200000 to file mem.bin from memory
- "./edl.py peekhex 0x200000 0x10" -> To dump 0x10 bytes from offset 0x200000 as hex string from memory
- "./edl.py peekqword 0x200000" -> To display a qword (8-bytes) at offset 0x200000 from memory
- "./edl.py pokeqword 0x200000 0x400000" -> To write the q-word value 0x400000 to offset 0x200000 in memory
- "./edl.py poke 0x200000 mem.bin" -> To write the binary file mem.bin to offset 0x200000 in memory
- "./edl.py secureboot" -> To display secureboot fuses (only on EL3 loaders)
- "./edl.py pbl pbl.bin" -> To dump pbl (only on EL3 loaders)
- "./edl.py qfp qfp.bin" -> To dump qfprom fuses (only on EL3 loaders)

### For generic unlocking
- "./edl.py modules oemunlock" -> Unlocks OEM if partition "config" exists, fastboot oem unlock is still needed afterwards

### QFIL in linux console (credits to LyuOnLine):

- For flashing full image:
   ```
   ./qfil.py --log_level info --firehose prog_firehose_lite.elf --rawprogram rawprogram0.xml --patch patch0.xml --imagedir image_dir
   ```

## Install EDL loaders

- "mkdir examples"
- Copy all your loaders into the examples directory
- "./fhloaderparse.py examples" -> will autodetect and rename loader structure and copy them to the "Loaders" directory
- Or rename Loaders manually as msmid_pkhash[8 bytes].bin

## Run Diag port tools (examples)

For Oneplus 6T, enter *#801#* on dialpad, set Engineer Mode and Serial to on and try :

- "./diag.py -vid 0x05c6 -pid 0x676c -interface 0 -info"

### Usage

- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -info" -> Send cmd "00" and return info
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -spc 303030303030" -> Send spc "303030303030"
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -cmd 00" -> Send cmd "00" (hexstring)
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -nvread 0x55" -> Display nvitem 0x55
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -nvbackup backup.json" -> Backup all nvitems to a json structured file
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -efsread efs.bin" -> Dump the EFS Modem partition to file efs.bin
- "./diag.py -vid 0x1234 -pid 0x5678 -interface 0 -efslistdir /" -> Display / directory listing of EFS


## Issues

- Secure loader with SDM660 on Xiaomi not yet supported
- EFS directory write and file read has to be added

## Tested with

- Oneplus 3T/5/6T/7T, BQ X, BQ X5, BQ X2, Gigaset ME Pure, ZTE MF210

## Contributions
- We need an implementation of the VIP Programming, functions addprogram and addpatch should be used (as a Module in Modules)

## Report issues 
- Please run using the option --debugmode and then commit an issue and attach the "log.txt" file

Published under MIT license
Additional license limitations: No use in commercial products without prior permit.

Enjoy !
