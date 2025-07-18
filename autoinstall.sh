#!/usr/bin/env sh

PATH_SCRIPT=$(dirname "${0}")

[ "$(id -u)" != 0 ] && { printf "\nYou must run this script as root!\n" && exit 1; }

if [ "$(uname -s)" = "Linux" ]; then
	if ! "${PATH_SCRIPT}/install-linux-edl-drivers.sh"; then
		printf "\nFailed to install the needed drivers!\n" && exit 1
	fi
fi

if ! pip3 install -r "${PATH_SCRIPT}/requirements.txt" --break-system-packages; then
	printf "\nFailed to install the dependencies!\n" && exit 1
fi

# The CFLAGS below is needed if your GCC version is >= 14
if ! CFLAGS="-Wno-int-conversion" pip3 install -U "${PATH_SCRIPT}" --break-system-packages; then
	printf "\nFailed to install this program!\n" && exit 1
fi

printf "\nInstallation complete! Now rebuild your initramfs and reboot\n"
