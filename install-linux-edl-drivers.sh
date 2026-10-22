#!/usr/bin/env sh

set -eu

PATH_SCRIPT=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
PATH_DRIVERS="${PATH_SCRIPT}/Drivers"

[ "$(uname -s)" = Linux ] || { printf "This script configures Linux USB permissions only.\n"; exit 1; }

[ "$(id -u)" != 0 ] && { printf "You must run this script as root!\n" && exit 1; }
! [ -d "${PATH_DRIVERS}" ] && { printf "Missing \"Drivers\" directory!\n" && exit 1; }

command -v udevadm >/dev/null || { printf "udevadm is required.\n"; exit 1; }

install -m 644 "${PATH_DRIVERS}"/*.rules /etc/udev/rules.d/
install -m 644 "${PATH_DRIVERS}"/blacklist*.conf /etc/modprobe.d/

udevadm control --reload-rules
udevadm trigger

printf "Now rebuild your initramfs and reboot\n"
