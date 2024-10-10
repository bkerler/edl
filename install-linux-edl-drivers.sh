#!bin/bash

cd ./Drivers

sudo cp ./50-android.rules /etc/udev/rules.d/50-android.rules
sudo cp ./51-edl.rules /etc/udev/rules.d/51-edl.rules
sudo cp ./69-libmtp.rules /etc/udev/rules.d/69-libmtp.rules
sudo cp ./blacklist-qcserial /etc/modprobe.d/blacklist-qcserial

sudo udevadm control --reload-rules
sudo udevadm trigger

echo "Now rebuild your initramfs and reboot."
