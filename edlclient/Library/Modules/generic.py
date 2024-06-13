#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!

import logging
from edlclient.Library.utils import LogBase


class generic(metaclass=LogBase):
    def __init__(self, fh, serial, args, loglevel):
        self.fh = fh
        self.serial = serial
        self.args = args
        self.__logger.setLevel(loglevel)
        self.error = self.__logger.error
        if loglevel == logging.DEBUG:
            logfilename = "log.txt"
            fh = logging.FileHandler(logfilename)
            self.__logger.addHandler(fh)

    def oem_unlock(self, enable):
        res = self.fh.detect_partition(self.args, "config")
        if res[0]:
            lun = res[1]
            rpartition = res[2]
            if rpartition.sectors <= (0x8000 // self.fh.cfg.SECTOR_SIZE_IN_BYTES):
                offsettopatch = 0x7FFF
                sector, offset = self.fh.calc_offset(rpartition.sector, offsettopatch)
            else:
                offsettopatch = 0x7FFFF
                sector, offset = self.fh.calc_offset(rpartition.sector, offsettopatch)
            if enable:
                value = 0x1
            else:
                value = 0x0
            size_in_bytes = 1
            if self.fh.cmd_patch(lun, sector, offset, value, size_in_bytes, True):
                print(f"Patched sector {str(rpartition.sector)}, offset {str(offset)} with value {value}, " +
                      f"size in bytes {size_in_bytes}.")
            else:
                print(f"Error on writing sector {str(rpartition.sector)}, offset {str(offset)} with value {value}, " +
                      f"size in bytes {size_in_bytes}.")
        else:
            """
            #define DEVICE_MAGIC "ANDROID-BOOT!"
            #define DEVICE_MAGIC_SIZE 13
            #define MAX_PANEL_ID_LEN 64
            #define MAX_VERSION_LEN  64
            #if VBOOT_MOTA
            struct device_info
            {
                unsigned char magic[DEVICE_MAGIC_SIZE];
                bool is_unlocked;
                bool is_tampered;
                bool is_verified;
                bool charger_screen_enabled;
                char display_panel[MAX_PANEL_ID_LEN];
                char bootloader_version[MAX_VERSION_LEN];
                char radio_version[MAX_VERSION_LEN];
                bool is_unlock_critical;
            };
            #else
            struct device_info
            {
                unsigned char magic[DEVICE_MAGIC_SIZE];
                bool is_unlocked; #0x10
                bool is_tampered; #0x14
                bool charger_screen_enabled; #0x18
                char display_panel[MAX_PANEL_ID_LEN];
                char bootloader_version[MAX_VERSION_LEN];
                char radio_version[MAX_VERSION_LEN];
                bool verity_mode; // 1 = enforcing, 0 = logging
                bool is_unlock_critical;
            };
            #endif
            """
            res = self.fh.detect_partition(self.args, "devinfo")
            if res[0]:
                lun = res[1]
                rpartition = res[2]
                offsettopatch1 = 0x10  # is_unlocked
                offsettopatch2 = 0x18  # is_critical_unlocked
                offsettopatch3 = 0x7FFE10  # zte
                offsettopatch4 = 0x7FFE18  # zte
                sector1, offset1 = self.fh.calc_offset(rpartition.sector, offsettopatch1)
                sector2, offset2 = self.fh.calc_offset(rpartition.sector, offsettopatch2)
                sector3, offset3 = self.fh.calc_offset(rpartition.sector, offsettopatch3)
                sector4, offset4 = self.fh.calc_offset(rpartition.sector, offsettopatch4)
                value = 0x1
                size_in_bytes = 1
                if self.fh.cmd_patch(lun, sector1, offset1, 0x1, size_in_bytes, True):
                    if self.fh.cmd_patch(lun, sector2, offset2, 0x1, size_in_bytes, True):
                        print(
                            f"Patched sector {str(rpartition.sector)}, offset {str(offset1)} with value {value}, " +
                            f"size in bytes {size_in_bytes}.")
                        data = self.fh.cmd_read_buffer(lun, rpartition.sector, rpartition.sectors)
                        if (len(data) > 0x7FFE20) and data[0x7FFE00:0x7FFE10] == b"ANDROID-BOOT!\x00\x00\x00":
                            if self.fh.cmd_patch(lun, sector3, offset3, value, size_in_bytes, True):
                                if self.fh.cmd_patch(lun, sector4, offset4, value, size_in_bytes, True):
                                    print(
                                        f"Patched sector {str(rpartition.sector)}, offset {str(offset1)} with " +
                                        f"value {value}, size in bytes {size_in_bytes}.")
                        return True
                print(
                    f"Error on writing sector {str(rpartition.sector)}, offset {str(offset1)} with value {value}, " +
                    f"size in bytes {size_in_bytes}.")
                return False
            else:
                fpartitions = res[1]
                self.error(f"Error: Couldn't detect partition: \"devinfo\"\nAvailable partitions:")
                for lun in fpartitions:
                    for rpartition in fpartitions[lun]:
                        if self.args["--memory"].lower() == "emmc":
                            self.error("\t" + rpartition)
                        else:
                            self.error(lun + ":\t" + rpartition)
