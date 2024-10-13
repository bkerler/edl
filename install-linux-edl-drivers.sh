#!bin/bash

cd ./Drivers

sudo cp ./50-android.rules /etc/udev/rules.d/50-android.rules
sudo cp ./51-edl.rules /etc/udev/rules.d/51-edl.rules
sudo cp ./69-libmtp.rules /etc/udev/rules.d/69-libmtp.rules

sudo udevadm control --reload-rules
sudo udevadm trigger

echo "You may want to move Drivers/blackist-qcserial.cofn into the /etc/modprobe.d and then rebuild initramfs however serial mode may be broken."
