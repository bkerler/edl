# Qualcomm Sahara / Firehose Client V1.0
(c) B. Kerler 2018

Why
===
- Because we'd like to flexible dump smartphones
- Because attacking firehose is kewl
  
Installation
=============
- Get python 3.7 64-Bit
- Install capstone + keystone engine:

```
cd ~
git clone https://github.com/keystone-engine/keystone --recursive
cd keystone && mkdir -p build && cd build && cmake .. 
../make-lib.sh
sudo make install 
cd ../bindings/python
sudo python3 setup.py build install
```
```
cd ~
git clone https://github.com/aquynh/capstone --recursive
cd capstone
./make.sh
sudo ./make.sh install
cd ../bindings/python
sudo python3 setup.py build install
```


Linux/Windows: 
- Add "blacklist qcserial" as last line to /etc/modprobe.d/blacklist.conf
- Copy 51-edl.rules to /etc/udev/rules.d
- Copy 50-android.rules to /etc/udev/rules.d
- sudo apt install adb
- sudo apt install fastboot
- "python3 -m pip install pyusb pyserial"

Windows:
- "python -m pip install pyusb pyserial"
- Use Filter Installer to install libusb filter driver 
  on Qualcomm 9008 port otherwise we won't detect the device

Run
===
Replace python with python3 on Linux :)

- "python edl.py -h" -> to see help with all other exciting options and features
- "python edl.py -loader firehoseloader.elf -printgpt -memory emmc" -> if you use your own Loader
- "python edl.py -printgpt -memory ufs -lun 0" -> to print gpt on first lun on device with ufs
- "python edl.py -printgpt -memory emmc" -> to print gpt on device with emmc
- "python edl.py -rf flash.bin -memory emmc" -> to dump whole flash on device with emmc
- "python edl.py -r recovery recovery.bin -memory emmc" -> to dump recovery partition as recovery.bin
- "python edl.py -rs 0 12 dump.bin -memory emmc" -> to dump sector 0 with size of 12 sectors as dump.bin
- "python edl.py -w recovery recovery.bin -memory emmc" -> write recovery.bin to recovery partition
- "python edl.py -ws 16 data.bin -memory emmc" -> write data.bin to starting sector 16
- "python edl.py -peek 0x200000 0x10000 -memory emmc" -> peek memory, offset 0x200000, length 0x10000 (if supported by loader)
- "python edl.py -rpbl -memory emmc" -> dump pbl (boot rom), if supported by loader
etc.

Remarks
=======
Put your loaders into the Loader directory for autodetection. See PutYourLoadersInHere.txt on
how to store the loaders correctly to make the autodetection work :)

Issues
======
- Tested with : Oneplus One, Oneplus X, Oneplus 3T, BQ X, BQ X5, Xiaomi Mi A1, Xiaomi Mi A2, Gigaset ME Pure, etc.
- Secure loader with SDM660 on Xiaomi not yet supported, but regular SDM660/845 is supported

ToDo
====
- Implement Poke (Write memory)
 
Published under MIT license
Additional license limitations: No use in commercial products without prior permit.

Enjoy !
