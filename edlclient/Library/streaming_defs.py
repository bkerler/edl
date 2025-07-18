#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2024 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
class open_mode_type:
    OPEN_MODE_NONE = 0x00  # Not opened yet
    OPEN_BOOTLOADER = 0x01  # Bootloader Image
    OPEN_BOOTABLE = 0x02  # Bootable Image
    OPEN_CEFS = 0x03  # CEFS Image
    OPEN_MODE_FACTORY = 0x04  # Factory Image


class open_multi_mode_type:
    OPEN_MULTI_MODE_NONE = 0x00  # Not opened yet
    OPEN_MULTI_MODE_PBL = 0x01  # Primary Boot Loader
    OPEN_MULTI_MODE_QCSBLHDCFG = 0x02  # QC 2ndary Boot Loader Header and  Config Data
    OPEN_MULTI_MODE_QCSBL = 0x03  # QC 2ndary Boot Loader
    OPEN_MULTI_MODE_OEMSBL = 0x04  # OEM 2ndary Boot Loader
    OPEN_MULTI_MODE_AMSS = 0x05  # AMSS modem executable
    OPEN_MULTI_MODE_APPS = 0x06  # APPS executable
    OPEN_MULTI_MODE_OBL = 0x07  # OTP Boot Loader
    OPEN_MULTI_MODE_FOTAUI = 0x08  # FOTA UI binarh
    OPEN_MULTI_MODE_CEFS = 0x09  # Modem CEFS image
    OPEN_MULTI_MODE_APPSBL = 0x0A  # APPS Boot Loader
    OPEN_MULTI_MODE_APPS_CEFS = 0x0B  # APPS CEFS image
    OPEN_MULTI_MODE_FLASH_BIN = 0x0C  # Flash.bin image for Windows mobile
    OPEN_MULTI_MODE_DSP1 = 0x0D  # DSP1 runtime image
    OPEN_MULTI_MODE_CUSTOM = 0x0E  # Image for user defined partition
    OPEN_MULTI_MODE_DBL = 0x0F  # DBL Image for SB Architecture 2.0
    OPEN_MULTI_MODE_OSBL = 0x10  # OSBL Image for SB Architecture 2.0
    OPEN_MULTI_MODE_FSBL = 0x11  # FSBL Image for SB Architecture 2.0
    OPEN_MULTI_MODE_DSP2 = 0x12  # DSP2 executable
    OPEN_MULTI_MODE_RAW = 0x13  # APPS EFS2 RAW image
    OPEN_MULTI_MODE_EMMC_USER = 0x21  # EMMC USER partition
    OPEN_MULTI_MODE_EMMC_BOOT0 = 0x22  # EMMC BOOT partition 0
    OPEN_MULTI_MODE_EMMC_BOOT1 = 0x23  # EMMC BOOT partition 1
    OPEN_MULTI_MODE_EMMC_RPMB = 0x24  # EMMC BOOT partition 1
    OPEN_MULTI_MODE_EMMC_GPP1 = 0x25  # EMMC GPP partition 1
    OPEN_MULTI_MODE_EMMC_GPP2 = 0x26  # EMMC GPP partition 2
    OPEN_MULTI_MODE_EMMC_GPP3 = 0x27  # EMMC GPP partition 3
    OPEN_MULTI_MODE_EMMC_GPP4 = 0x28  # EMMC GPP partition 4


class response_code_type:
    ACK = 0x00  # Successful
    RESERVED_1 = 0x01  # Reserved
    NAK_INVALID_DEST = 0x02  # Failure: destination address is invalid.
    NAK_INVALID_LEN = 0x03  # Failure: operation length is invalid.
    NAK_EARLY_END = 0x04  # Failure: packet was too short for this cmd.
    NAK_INVALID_CMD = 0x05  # Failure: invalid command
    RESERVED_6 = 0x06  # Reserved
    NAK_FAILED = 0x07  # Failure: operation did not succeed.
    NAK_WRONG_IID = 0x08  # Failure: intelligent ID code was wrong.
    NAK_BAD_VPP = 0x09  # Failure: programming voltage out of spec
    NAK_VERIFY_FAILED = 0x0A  # Failure: readback verify did not match
    RESERVED_0xB = 0x0B  # Reserved
    NAK_INVALID_SEC_CODE = 0x0C  # Failure: Incorrect security code
    NAK_CANT_POWER_DOWN = 0x0D  # Failure: Cannot power down phone
    NAK_NAND_NOT_SUPP = 0x0E  # Failure: Download to NAND not supported
    NAK_CMD_OUT_SEQ = 0x0F  # Failure: Command out of sequence
    NAK_CLOSE_FAILED = 0x10  # Failure: Close command failed
    NAK_BAD_FEATURE_BITS = 0x11  # Failure: Incompatible Feature Bits
    NAK_NO_SPACE = 0x12  # Failure: Out of space
    NAK_INVALID_SEC_MODE = 0x13  # Failure: Multi-Image invalid security mode
    NAK_MIBOOT_NOT_SUPP = 0x14  # Failure: Multi-Image boot not supported
    NAK_PWROFF_NOT_SUPP = 0x15  # Failure: Power off not supported
