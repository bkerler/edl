#!/usr/bin/env sh

set -eu

PATH_SCRIPT=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
SELF="$PATH_SCRIPT/$(basename "$0")"
TARGET=$(pwd -P)
REPOSITORY=https://github.com/bkerler/edl.git
PYTHON=${PYTHON:-}
EXTRAS=
SKIP_DRIVERS=0
SKIP_LOADERS=0
NO_INPUT=0
STAGE=

die() { printf '%s\n' "$*" >&2; exit 1; }
need_value() { [ "$2" -ge 2 ] || die "Missing value for $1"; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --python) need_value "$1" "$#"; PYTHON=$2; shift 2 ;;
        --extras) need_value "$1" "$#"; EXTRAS=$2; shift 2 ;;
        --repository) need_value "$1" "$#"; REPOSITORY=$2; shift 2 ;;
        --skip-drivers) SKIP_DRIVERS=1; shift ;;
        --skip-loaders) SKIP_LOADERS=1; shift ;;
        --no-input) NO_INPUT=1; shift ;;
        -h|--help)
            printf 'Install EDL into the CURRENT directory, using .venv.\n'
            printf 'Options: --python <exe> --extras asm,qrcode --skip-drivers --skip-loaders --no-input --repository <git-url>\n'
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$EXTRAS" in ''|asm|qrcode|asm,qrcode|qrcode,asm) ;; *) die 'Choose asm, qrcode, or asm,qrcode' ;; esac

cleanup_stage() {
    [ -n "$STAGE" ] || return 0
    case "$STAGE" in "$TARGET"/.edl-stage.*) rm -rf "$STAGE" ;; *) die 'Unexpected staging directory' ;; esac
    STAGE=
}
trap cleanup_stage 0
trap 'exit 1' HUP INT TERM

fetch_file() {
    if command -v curl >/dev/null 2>&1; then curl -fL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
    else die 'Install Git, curl or wget to download the source.'; fi
}

get_checkout() {
    if [ -f "$TARGET/pyproject.toml" ] && [ -d "$TARGET/edlclient" ]; then return; fi
    for entry in "$TARGET"/* "$TARGET"/.[!.]* "$TARGET"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        [ "$entry" = "$SELF" ] || die 'The current directory contains other files. Choose an empty directory or an EDL checkout.'
    done
    STAGE=$(mktemp -d "$TARGET/.edl-stage.XXXXXX")
    if command -v git >/dev/null 2>&1; then
        git clone --quiet --no-hardlinks -- "$REPOSITORY" "$STAGE/source"
        checkout="$STAGE/source"
    else
        [ "$REPOSITORY" = https://github.com/bkerler/edl.git ] || die 'Git is required for a custom repository.'
        fetch_file https://github.com/bkerler/edl/archive/refs/heads/master.tar.gz "$STAGE/source.tar.gz"
        tar -xzf "$STAGE/source.tar.gz" -C "$STAGE"
        checkout="$STAGE/edl-master"
    fi
    for entry in "$checkout"/* "$checkout"/.[!.]* "$checkout"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        destination="$TARGET/$(basename "$entry")"
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            [ "$destination" = "$SELF" ] || die "Refusing to overwrite $destination"
        fi
    done
    for entry in "$checkout"/* "$checkout"/.[!.]* "$checkout"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        destination="$TARGET/$(basename "$entry")"
        [ "$destination" = "$SELF" ] || mv "$entry" "$destination"
    done
    cleanup_stage
}

get_loaders() {
    if [ -d "$TARGET/.git" ] && command -v git >/dev/null 2>&1; then
        git -C "$TARGET" submodule update --init --recursive --quiet
    elif [ ! -d "$TARGET/Loaders" ] || [ -z "$(ls -A "$TARGET/Loaders")" ]; then
        STAGE=$(mktemp -d "$TARGET/.edl-stage.XXXXXX")
        fetch_file https://github.com/bkerler/Loaders/archive/refs/heads/main.tar.gz "$STAGE/loaders.tar.gz"
        tar -xzf "$STAGE/loaders.tar.gz" -C "$STAGE"
        mkdir -p "$TARGET/Loaders"
        cp -R "$STAGE/Loaders-main/." "$TARGET/Loaders/"
        cleanup_stage
    fi
}

probe_python() {
    "$1" -I -c 'import sys, venv, ensurepip; assert sys.version_info >= (3,10); print(sys.executable)' 2>/dev/null
}

run_root() {
    if [ "$(id -u)" = 0 ]; then "$@"
    elif command -v sudo >/dev/null 2>&1; then sudo "$@"
    else die 'Administrator privileges are needed for this system package or driver step; install it manually.'; fi
}

install_system_python() {
    if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1; then brew install python
    elif command -v apt-get >/dev/null 2>&1; then
        run_root apt-get update
        run_root apt-get install -y python3 python3-venv
    elif command -v dnf >/dev/null 2>&1; then run_root dnf install -y python3 python3-pip
    elif command -v pacman >/dev/null 2>&1; then run_root pacman -S --needed --noconfirm python python-pip
    else die 'Install Python 3.10+ and its venv support with your distribution tools, then rerun with --python <path>.'; fi
}

select_python() {
    if [ -n "$PYTHON" ]; then
        if found=$(probe_python "$PYTHON"); then PYTHON=$found; return; fi
    else
        if [ -x "$TARGET/.venv/bin/python" ] && found=$(probe_python "$TARGET/.venv/bin/python"); then
            PYTHON=$found; return
        fi
        for candidate in python3 python python3.14 python3.13 python3.12 python3.11 python3.10; do
            if found=$(probe_python "$candidate"); then PYTHON=$found; return; fi
        done
    fi
    [ "$NO_INPUT" = 0 ] || die 'Python 3.10+ with venv is unavailable. Supply --python <executable>.'
    while :; do
        printf 'Python 3.10+ with venv is missing. y installs GLOBAL/system Python outside this project, using your OS package manager (administrator privileges may be needed).\n'
        printf 'Install global Python, cancel, or enter an executable path [y/N/path]: '
        IFS= read -r answer || die 'Installation cancelled.'
        case "$answer" in
            y|Y)
                install_system_python
                PYTHON=
                for candidate in python3 python; do
                    if found=$(probe_python "$candidate"); then PYTHON=$found; return; fi
                done
                die 'The installed Python still lacks Python 3.10+, venv or ensurepip.' ;;
            ''|n|N) die 'Installation cancelled; no global Python was installed.' ;;
            *) if found=$(probe_python "$answer"); then PYTHON=$found; return; fi
               printf 'That path does not provide Python 3.10+, venv and ensurepip.\n' ;;
        esac
    done
}

ensure_usb() {
    library=$("$PYTHON" -I -c 'from ctypes.util import find_library; print(bool(find_library("usb-1.0")))' 2>/dev/null) || library=False
    case "$(uname -s)" in
        Linux)
            rules=ok
            for file in "$TARGET"/Drivers/*.rules "$TARGET"/Drivers/blacklist*.conf; do
                case "$file" in *.rules) installed="/etc/udev/rules.d/$(basename "$file")" ;;
                                *) installed="/etc/modprobe.d/$(basename "$file")" ;; esac
                cmp -s "$file" "$installed" || rules=missing
            done
            if [ "$library" = True ] && [ "$rules" = ok ] && command -v udevadm >/dev/null 2>&1; then
                printf 'USB library and device rules are already installed.\n'; return
            fi
            [ "$NO_INPUT" = 0 ] || die 'USB support is missing. Run interactively or use --skip-drivers for serial mode.'
            printf 'Install missing libusb/udev support and device rules? Only these system changes need administrator privileges [y/N]: '
            IFS= read -r answer || answer=n
            case "$answer" in y|Y) ;; *) printf 'USB setup skipped; serial mode remains usable.\n'; return ;; esac
            if [ "$library" != True ] || ! command -v udevadm >/dev/null 2>&1; then
                if command -v apt-get >/dev/null 2>&1; then
                    run_root apt-get update
                    run_root apt-get install -y libusb-1.0-0 udev
                elif command -v dnf >/dev/null 2>&1; then run_root dnf install -y libusb1 systemd-udev
                elif command -v pacman >/dev/null 2>&1; then run_root pacman -S --needed --noconfirm libusb systemd
                else die 'Install libusb and udev with your distribution tools, then rerun.'; fi
            fi
            run_root sh "$TARGET/install-linux-edl-drivers.sh"
            ;;
        Darwin)
            [ "$library" = True ] && return
            [ "$NO_INPUT" = 0 ] || die 'libusb is missing. Install it with Homebrew or use --skip-drivers.'
            printf 'Install the missing libusb package with Homebrew [y/N]: '
            IFS= read -r answer || answer=n
            case "$answer" in y|Y) brew install libusb ;; *) printf 'USB setup skipped.\n' ;; esac
            ;;
    esac
}

printf 'Installing EDL in %s\n' "$TARGET"
get_checkout
[ -f "$TARGET/install.py" ] || die 'This checkout is outdated: update it to include install.py.'
if [ -e "$TARGET/.venv" ]; then
    [ -f "$TARGET/.venv/pyvenv.cfg" ] || die 'The existing .venv is not an isolated virtual environment. Move it aside first.'
    grep -Eq '^[[:space:]]*include-system-site-packages[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$TARGET/.venv/pyvenv.cfg" || die 'The existing .venv shares system packages. Move it aside first.'
fi
select_python
printf 'Using Python: %s\n' "$PYTHON"
[ "$SKIP_DRIVERS" = 1 ] || ensure_usb
[ "$SKIP_LOADERS" = 1 ] || get_loaders
set -- --venv "$TARGET/.venv"
[ -z "$EXTRAS" ] || set -- "$@" --extras "$EXTRAS"
"$PYTHON" -I "$TARGET/install.py" "$@"
printf 'Ready. Run ./edl --help (or .venv/bin/edl --help).\n'
