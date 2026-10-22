# Qualcomm Sahara / Firehose Attack Client / Diag Tools
(c) B. Kerler 2018-2026
Licensed under GPLv3 license.

# Be aware that if you use anything from this repository in any (including) compiled form, you need to opensource your code as well !
# Violating against the GPLv3 license will enforce me to stop developing these opensource tools.

## Why

- Because we'd like to flexible dump smartphones
- Because attacking firehose is kewl
- Because memory dumping helps to find issues :)

## QC Sahara V3 Support (Fixed in this fork)

This fork fixes the issue where Sahara V3 protocol cannot read chip information (MSM_ID, OEM_ID, MODEL_ID) on newer Qualcomm devices.

### Problem
As mentioned in the original README:
> For newer QC phones, loader autodetection doesn't work anymore as the Sahara loader doesn't offer a way to read the pkhash anymore

**Root Cause**: Sahara V3 devices no longer respond to `cmd=0x03` (OEM_PK_HASH_READ) and `cmd=0x02` (MSM_HW_ID_READ).

### Solution
Use `cmd=0x0A` (CHIP_ID_V3_READ) to read extended chip information for V3 devices.

#### V3 Extended Info Data Structure
| Offset | Size | Description |
|--------|------|-------------|
| 0-3 | 4 bytes | Chip Identifier V3 |
| 36-39 | 4 bytes | MSM_ID |
| 40-41 | 2 bytes | OEM_ID |
| 42-43 | 2 bytes | MODEL_ID |
| 44-45 | 2 bytes | Alternative OEM_ID (if offset 40 is 0) |

### Changes
- Added `SAHARA_EXEC_CMD_READ_CHIP_ID_V3` (0x0A) command constant in `sahara_defs.py`
- Added `cmdexec_get_chip_id_v3()` method to read and parse V3 extended info
- Modified `cmd_info()` to use V3 extended info when version >= 3
- **Try to read PK_HASH on V3 devices** (may still work on some devices)
- Enabled loader autodetection for V3 devices via HWID/MSM_ID/PKHash matching
- Construct V1/V2 compatible HWID format for loader database lookup
- Improved V3 output format for better readability

#### V3 Output Example
```
Reading Chip Info : OK
- Sahara version  : 3
- Chip Serial Number : 4971f38f
- Chip Identifier V3 : 5a040000
- MSM HWID : 0x28c0e1 | model_id:0xa012 | oem_id:0051 OPPO
- OEM PKHASH : 3cceb55b6d88a0bea0e24d9641500fa239738b42575031188d3aaf92349b3b14
- HW_ID : 0028c0e10051a012
```

### Testing
- Tested on OnePlus/OPPO devices with SM8350, SM8450, SM8550
- Tested on Xiaomi devices (various Snapdragon platforms)
- Backward compatible with V1/V2 devices

### Files Changed
- `edlclient/Library/sahara_defs.py` - Added V3 command constant
- `edlclient/Library/sahara.py` - Added V3 chip info reading and improved output format

> **Note**: If autodetection still fails, you can use `--loader` option to specify a loader manually.
  
### Use LiveDVD (everything ready to go, based on Ubuntu):
User: user, Password:user (based on Ubuntu 22.04 LTS)

[Live DVD V4](https://www.androidfilehost.com/?fid=15664248565197184488)

[Live DVD V4 Mirror](https://drive.google.com/file/d/10OEw1d-Ul_96MuT3WxQ3iAHoPC4NhM_X/view?usp=sharing)

## Installation

### Install in the current directory

Use a normal user terminal in an empty directory. You can download just the
installer there; it obtains the source directly into the **current directory**.
It stages downloads separately and preserves the running installer when the
repository contains a file with the same name. Other existing files are never
overwritten. An existing EDL checkout is reused.

On Windows (PowerShell 5.1 or newer):
```powershell
mkdir edl-client
cd edl-client
curl.exe -fL -o install_edl_win10_win11.ps1 https://raw.githubusercontent.com/bkerler/edl/master/install_edl_win10_win11.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install_edl_win10_win11.ps1
.\edl.bat --help
```

On Linux/macOS:
```sh
mkdir edl-client
cd edl-client
curl -fL -o autoinstall.sh https://raw.githubusercontent.com/bkerler/edl/master/autoinstall.sh
sh ./autoinstall.sh
./edl --help
```

Git is used when available; otherwise the official GitHub source archive is
downloaded. Loaders are fetched automatically unless `-SkipLoaders` (Windows) or
`--skip-loaders` (Unix) is specified. Alternatively, get the source yourself:
```sh
git clone https://github.com/bkerler/edl
cd edl
git submodule update --init --recursive
```

The installer detects Python 3.10+ with `venv` and `ensurepip`, then creates or
reuses an isolated `.venv` in the current directory. EDL and its dependencies are
installed there. The local `edl.bat` / `edl` launcher uses that environment, so
activation and changes to the machine PATH are unnecessary. Other CLI commands
are in `.venv\Scripts` on Windows or `.venv/bin` on Unix.

After updating the source, rerun the installer to update the environment. Existing
directories that are not isolated virtual environments are refused.

### Python dependencies

Inside an activated virtual environment, install with `python -m pip install .`
to get the dependencies needed by all declared CLI commands, including modem tools
and OnePlus encryption support.

Additional features are available as extras:

| Extra | Install from a checkout | Features |
| --- | --- | --- |
| `asm` | `python -m pip install ".[asm]"` | Assembly and disassembly with Capstone and Keystone |
| `qrcode` | `python -m pip install ".[qrcode]"` | OnePlus factory QR codes saved as PNG images |

Install both with `python -m pip install ".[asm,qrcode]"`.
`python -m pip install -r requirements.txt` installs the base dependencies and both
extras for users running scripts from a checkout; it does not install the package.

`pyproject.toml` is the source of truth for dependencies. `requirements.txt` is a
generated compatibility file for source-only workflows. After changing
dependencies, run `python .github/scripts/update_requirements.py` and `uv lock`. The generator
uses `tomli` on Python 3.10 (also installed by the `build` development tool).
CI checks the generated file with `python .github/scripts/update_requirements.py --check`.

### Linux (Debian/Ubuntu/Mint/etc):
From the directory where you want EDL installed:
```sh
sh ./autoinstall.sh
./edl --help

# An existing interpreter and optional features
sh ./autoinstall.sh --python /path/to/python3 --extras asm,qrcode
```

If no compatible Python is found, the `[y/N/path]` prompt accepts an existing
executable path, cancels on `N`/Enter, or installs **system/global Python outside
the project** on `y`. Linux uses apt, dnf or pacman; this system package step may
need `sudo`. Python Install Manager is Windows-only. On Debian/Ubuntu, a manual
Python setup needs the `python3-venv` package as well as `python3`.

For a manual install, use `python3 -m venv .venv` followed by
`.venv/bin/python -m pip install .`. To use the CLI names in the current shell,
run `. .venv/bin/activate`.

#### Linux USB detection and permissions

The installer checks libusb and compares the udev rules/blacklist with `Drivers/`.
If anything is missing, it asks before installing system packages or running the
driver configuration with `sudo`. Already configured systems need no elevation.
Use `--skip-drivers` for serial-only operation or to manage USB setup yourself:

```sh
sudo sh ./install-linux-edl-drivers.sh
```

This installs the udev rules and qcserial blacklist from `Drivers/`. Follow its
instructions to rebuild your distribution's initramfs and reboot. If ModemManager
claims the device, stop that service before using EDL.

### macOS:
```bash
# From the installation directory, as your normal user:
sh ./autoinstall.sh
./edl --help
```

Missing Python or libusb can be installed with Homebrew after confirmation.

### Windows:

#### Install with PowerShell (Windows 10 and later)

Open a normal PowerShell window in the installation directory. The installer
searches the local `.venv`, active environment, PATH, registered Python/Store
installations and Python launcher runtimes.

```powershell
.\install_edl_win10_win11.ps1
.\edl.bat --help

# An existing interpreter and optional features
.\install_edl_win10_win11.ps1 -Python C:\Python310\python.exe -Extras 'asm,qrcode'
```

If local script execution is disabled, run
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install_edl_win10_win11.ps1`.
If no compatible Python is found, the `[y/N/path]` prompt means:

- `N` or Enter cancels without installing Python.
- A path selects an existing Python 3.10+ executable, including one in a virtual environment.
- `y` installs the official [Python Install Manager](https://docs.python.org/3.14/using/windows.html)
  and Python 3.14. This is a **current-user global Python installation outside
  the project `.venv`**, not an all-users installation. It changes the user-wide
  Python environment. WinGet uses the official Store package; without WinGet,
  the official python.org AppInstaller feed is used.

Detection disables implicit Python Manager runtime installation. Python and EDL
setup stay in the original user process. WinGet and Zadig request administrator
privileges only when their installation or driver configuration needs them.

For unattended/serial-only setup with an existing Python:
```powershell
.\install_edl_win10_win11.ps1 -Python C:\Python310\python.exe -SkipDrivers -SkipLoaders -NoInput
```

Unix has equivalent `--python`, `--skip-drivers`, `--skip-loaders` and `--no-input`
options. Unattended mode fails when a required prerequisite is missing; it never
confirms a global Python or driver installation automatically.

For a manual installation:
```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\edl.exe --help
```

#### Windows USB driver setup

The installer checks whether Zadig is available and, if needed, asks permission
to install it with `winget install --id akeo.ie.Zadig --exact --source winget`.
WinGet and Zadig handle any required elevation; the EDL/Python installation stays
in the original user process. Declining continues setup for serial mode.
Use `-SkipDrivers` if your device driver is already configured or you manage it yourself.

After installation, connect the device in EDL mode and open Zadig. Enable
**Options > List All Devices**, select your **EDL/QHSUSB_BULK device**, then
install **WinUSB** for that device. Having Zadig installed does not prove that
the device driver is ready. See the [official Zadig guide](https://github.com/pbatard/libwdi/wiki/Zadig).

For manual driver setup:
```powershell
.\install_edl_win10_win11.ps1 -DriversOnly
```

`Drivers\Windows\Install_Windows.bat` retains the upstream OnePlus 9008
driver entry. Use the separate `-DriversOnly` command above for Zadig setup.

- Install normal QC 9008 Serial Port driver (or use default Windows COM Port one, make sure no exclamation is seen)
- Get usbdk installer (.msi) from [here](https://github.com/daynix/UsbDk/releases/) and install it
- Test on device connect using "UsbDkController -n" if you see a device with pid 0x9008
- Works fine under Windows 10 and 11 :D

#### Using serial port instead of usb
With Port autodetection
```bash
edl --serial
```

or Port name
```bash
edl --portname \\.\COM1
```

------------------------------------------------------------------------------------------------------------------------------------
## Get Loaders
You should get these automatically if you do a ``` git submodule update --init --recursive ```
or from [here](https://github.com/bkerler/Loaders)

## Convert own EDL loaders for automatic usage

- Make a subdirectory "newstuff", copy your edl loaders to this subdirectory
- ```fhloaderparse newstuff Loaders```

- or sniff existing edl tools using Totalphase Beagle 480, set filter to ```filter({'inputs': False, 'usb3': False, 'chirps': False, 'dev': 26, 'usb2resets': False, 'sofs': False, 'ep': 1})```, export to binary file as "sniffeddata.bin" and then use ```beagle_to_loader sniffeddata.bin```


## Install EDL loaders

- ```mkdir examples```
- Copy all your loaders into the examples directory
- ```fhloaderparse examples Loaders``` -> will autodetect and rename loader structure and copy them to the "Loaders" directory
- Or rename Loaders manually as "msmid_pkhash[8 bytes].bin" and put them into the Loaders directory

------------------------------------------------------------------------------------------------------------------------------------

## Run EDL (examples)

Your device needs to have a usb pid of 0x9008 in order to make the edl tool work.
If your device is semi bricked and entered the usb pid 0x900E, there are several options
to get back the 0x9008 mode :

1. Use a edl cable (Short D+ with GND) and force reboot the phone (either vol up + power pressing for more than 20 seconds or disconnect battery), works with emmc + ufs flash (this will only work if XBL/SBL isn't broken)

2. If emmc flash is used, remove battery, short DAT0 with gnd, connect battery, then remove short.

3. If a ufs flash is used, things are very much more complicated. You will need to open the ufs die and short the clk line on boot, some boards have special test points for that.

4. Some devices have boot config resistors, if you find the right ones you may enforce booting to sdcard instead of flash.


### Generic

- ```edl -h``` -> to see help with all options
- ```edl server --memory=ufs --tcpport=1340``` -> Run TCP/IP server on port 1340, see tcpclient.py for an example client
- ```edl xml run.xml``` -> To send a xml file run.xml via firehose
- ```edl reset``` -> To reboot the phone
- ```edl rawxml <xmlstring>``` -> To send own xml string, example :
   ```edl rawxml "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data><response value=\"ACK\" /></data>```
- ```edl [anycommand] --debugmode``` -> enables Verbose. Do that only when REALLY needed as it will print out everything happening!

### For EMMC Flash

- ```edl printgpt``` -> to print gpt on device with emmc
- ```edl rf flash.bin``` -> to dump whole flash for device with emmc
- ```edl rl dumps --skip=userdata --genxml``` -> to dump all partitions to directory dumps for device with emmc and skipping userdata partition, write rawprogram0.xml
- ```edl rs 0 15 data.bin``` -> to dump 15 sectors from starting sector 0 to file data.bin for device with emmc
- ```edl rs 0 15 data.bin --skipresponse``` -> to dump 15 sectors from starting sector 0 to file data.bin for device with emmc, ignores missing ACK from phones
- ```edl r boot_a boot.img``` -> to dump the partition "boot_a" to the filename boot.img for device with emmc
- ```edl r boot_a,boot_b boot_a.img,boot_b.img``` -> to dump multiple partitions to multiple filenames
- ```edl footer footer.bin``` -> to dump the crypto footer for Androids with emmc flash
- ```edl w boot_a boot.img``` -> to write boot.img to the "boot" partition on lun 0 on the device with emmc flash
- ```edl w gpt gpt.img``` -> to write gpt partition table from gpt.img to the first sector on the device with emmc flash
- ```edl wl dumps``` -> to write all files from "dumps" folder to according partitions to flash
- ```edl wf dump.bin``` -> to write the rawimage dump.bin to flash
- ```edl e misc``` -> to erase the partition misc on emmc flash
- ```edl gpt . --genxml``` -> dump gpt_main0.bin/gpt_backup0.bin and write rawprogram0.xml to current directory (".")


### For UFS Flash

- ```edl printgpt --memory=ufs --lun=0``` -> to print gpt on lun 0
- ```edl printgpt --memory=ufs``` -> to print gpt of all lun
- ```edl rf lun0.bin --memory=ufs --lun=0``` -> to dump whole lun 0
- ```edl rf flash.bin --memory=ufs``` -> to dump all luns as lun0_flash.bin, lun1_flash.bin, ...
- ```edl rl dumps --memory=ufs --lun=0 --skip=userdata,vendor_a``` -> to dump all partitions from lun0 to directory dumps for device with ufs and skip userdata and vendor_a partition
- ```edl rl dumps --memory=ufs --genxml``` -> to dump all partitions from all lun to directory dumps and write rawprogram[lun].xml
- ```edl rs 0 15 data.bin --memory=ufs --lun=0``` -> to dump 15 sectors from starting sector 0 from lun 0 to file data.bin
- ```edl r boot_a boot.img --memory=ufs --lun=4``` -> to dump the partition "boot_a" from lun 4 to the filename boot.img
- ```edl r boot_a boot.img --memory=ufs``` -> to dump the partition "boot_a" to the filename boot.img using lun autodetection
- ```edl r boot_a,boot_b boot_a.img,boot_b.img --memory=ufs``` -> to dump multiple partitions to multiple filenames
- ```edl footer footer.bin --memory=ufs``` -> to dump the crypto footer
- ```edl w boot boot.img --memory=ufs --lun=4``` -> to write boot.img to the "boot" partition on lun 4 on the device with ufs flash
- ```edl w gpt gpt.img --memory=ufs --lun=4``` -> to write gpt partition table from gpt.img to the lun 4 on the device with ufs flash
- ```edl wl dumps --memory=ufs --lun=0``` -> to write all files from "dumps" folder to according partitions to flash lun 0
- ```edl wl dumps --memory=ufs``` -> to write all files from "dumps" folder to according partitions to flash and try to autodetect lun
- ```edl wf dump.bin --memory=ufs --lun=0``` -> to write the rawimage dump.bin to flash lun 0
- ```edl e misc --memory=ufs --lun=0``` -> to erase the partition misc on lun 0
- ```edl gpt . --genxml --memory=ufs``` -> dump gpt_main[lun].bin/gpt_backup[lun].bin and write rawprogram[lun].xml to current directory (".")

### QFIL emulation (credits to LyuOnLine):

- For flashing full image:
   ```
   edl qfil rawprogram0.xml patch0.xml image_dir
   ```
------------------------------------------------------------------------------------------------------------------------------------

### For devices with peek/poke command

- ```edl peek 0x200000 0x10 mem.bin``` -> To dump 0x10 bytes from offset 0x200000 to file mem.bin from memory
- ```edl peekhex 0x200000 0x10``` -> To dump 0x10 bytes from offset 0x200000 as hex string from memory
- ```edl peekqword 0x200000``` -> To display a qword (8-bytes) at offset 0x200000 from memory
- ```edl pokeqword 0x200000 0x400000``` -> To write the q-word value 0x400000 to offset 0x200000 in memory
- ```edl poke 0x200000 mem.bin``` -> To write the binary file mem.bin to offset 0x200000 in memory
- ```edl secureboot``` -> To display secureboot fuses (only on EL3 loaders)
- ```edl pbl pbl.bin``` -> To dump pbl (only on EL3 loaders)
- ```edl qfp qfp.bin``` -> To dump qfprom fuses (only on EL3 loaders)

------------------------------------------------------------------------------------------------------------------------------------

### For generic unlocking
- ```edl modules oemunlock enable``` -> Unlocks OEM if partition "config" exists, fastboot oem unlock is still needed afterwards

#### Dump memory (0x900E mode)
- ```edl memorydump```
- 
------------------------------------------------------------------------------------------------------------------------------------
### Streaming mode (credits to forth32)

#### Enter streaming mode

##### Sierra Wireless Modem
- Send AT!BOOTHOLD and AT!QPSTDLOAD to modem port or use ```modem/boottodwnload.py``` script
- Send AT!ENTERCND="A710" and then AT!EROPTION=0 for memory dump
- ```edl --vid 1199 --pid 9070 --loader=loaders/NPRG9x35p.bin printgpt``` -> To show the partition table

##### Netgear MR1100
- run ```boottodownload```, device will enter download mode (0x900E pid)
- ```edl printgpt --loader=Loaders/qualcomm/patched/mdm9x5x/NPRG9x55p.bin```, device will reboot to 0x9008
- now use edl regulary such as ```edl printgpt``` (do not use loader option)

##### ZTE MF920V, Quectel, Telit, etc.. Modem
- run ```enableadb```, or send to at port "AT+ZCDRUN=E", or send via ```qc_diag -sahara```
- ```adb reboot edl```
- ```edl printgpt``` -> To show the partition table


## Run Diag port tools (examples)

For Oneplus 6T, enter *#801#* on dialpad, set Engineer Mode and Serial to on and try :

- ```qc_diag -vid 0x05c6 -pid 0x676c -interface 0 -info```

### Usage

- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -info``` -> Send cmd "00" and return info
- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -spc 303030303030``` -> Send spc "303030303030"
- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -cmd 00``` -> Send cmd "00" (hexstring)
- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -nvread 0x55``` -> Display nvitem 0x55
- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -nvbackup backup.json``` -> Backup all nvitems to a json structured file
- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -efsread efs.bin``` -> Dump the EFS Modem partition to file efs.bin
- ```qc_diag -vid 0x1234 -pid 0x5678 -interface 0 -efslistdir /``` -> Display / directory listing of EFS


## Issues

- Secure loader with SDM660 on Xiaomi not yet supported (EDL authentification)
- VIP Programming not supported (Contributions are welcome !)
- EFS directory write and file read has to be added (Contributions are welcome !)


## Tested with

- Oneplus 3T/5/6T/7T/8/8t/9/Nord CE/N10/N100 (Read-Only), BQ X, BQ X5, BQ X2, Gigaset ME Pure, ZTE MF210, ZTE MF920V, Sierra Wireless EM7455, Netgear MR1100-10EUS, Netgear MR5100
- SIMCOM SIM8905E

Published under GPLv3 license
Additional license limitations: No use in commercial products without prior permit.

Enjoy !
