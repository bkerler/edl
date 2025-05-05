#!/usr/bin/env sh

PATH_DRIVERS=$(dirname "${0}")/Drivers

[ "$(id -u)" != 0 ] && { printf "You must run this script as root!\n" && exit 1; }
! [ -d "${PATH_DRIVERS}" ] && { printf "Missing \"Drivers\" directory!\n" && exit 1; }

cp "${PATH_DRIVERS}"/*.rules /etc/udev/rules.d/
cp "${PATH_DRIVERS}"/blacklist*.conf /etc/modprobe.d/

udevadm control --reload-rules
udevadm trigger

printf "Now rebuild your initramfs and reboot\n"
