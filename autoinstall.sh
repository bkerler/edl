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
CHECKOUT_STATE="$TARGET/.edl-checkout-state"
CHECKOUT_ACTIVE=0
CHECKOUT_PREPARED=0

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
finish_checkout() {
    [ "$CHECKOUT_ACTIVE" = 1 ] || return 0
    if [ "$CHECKOUT_PREPARED" = 1 ]; then restore_interrupted_checkout
    else remove_checkout_state; fi
    CHECKOUT_ACTIVE=0
}
trap 'finish_checkout; cleanup_stage' 0
trap 'exit 1' HUP INT TERM

remove_checkout_state() {
    [ -d "$CHECKOUT_STATE" ] && [ ! -L "$CHECKOUT_STATE" ] || die 'Unexpected checkout state directory.'
    for entry in "$CHECKOUT_STATE"/* "$CHECKOUT_STATE"/.[!.]* "$CHECKOUT_STATE"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "$entry" in "$CHECKOUT_STATE/owner"|"$CHECKOUT_STATE/committed") continue ;; esac
        rm -rf "$entry"
    done
    rm -f "$CHECKOUT_STATE/owner" "$CHECKOUT_STATE/committed"
    rmdir "$CHECKOUT_STATE"
}

restore_interrupted_checkout() {
    [ -e "$CHECKOUT_STATE" ] || [ -L "$CHECKOUT_STATE" ] || return 0
    [ -d "$CHECKOUT_STATE" ] && [ ! -L "$CHECKOUT_STATE" ] || die 'Unexpected checkout state directory.'
    if [ -z "$(ls -A "$CHECKOUT_STATE")" ]; then remove_checkout_state; return; fi
    committed=0
    if [ -f "$CHECKOUT_STATE/committed" ] && [ "$(cat "$CHECKOUT_STATE/committed")" = edl-checkout-v1 ]; then committed=1; fi
    if [ "$committed" = 0 ]; then
        [ -f "$CHECKOUT_STATE/owner" ] && [ "$(cat "$CHECKOUT_STATE/owner")" = edl-checkout-v1 ] || die 'Unrecognized .edl-checkout-state directory; move it aside before installing.'
        if [ -f "$CHECKOUT_STATE/plan" ]; then
            while IFS= read -r name; do
                case "$name" in ''|.|..|*/*|.edl-checkout-state) die 'Invalid checkout recovery entry.' ;; esac
                [ "$TARGET/$name" != "$SELF" ] || die 'The recovery plan includes the running installer.'
            done < "$CHECKOUT_STATE/plan"
            while IFS= read -r name; do
                if [ -e "$TARGET/$name" ] || [ -L "$TARGET/$name" ]; then
                    if [ -e "$CHECKOUT_STATE/source/$name" ] || [ -L "$CHECKOUT_STATE/source/$name" ]; then
                        die "Checkout recovery would overwrite staged data: $name. Both copies were retained."
                    fi
                    mv "$TARGET/$name" "$CHECKOUT_STATE/source/$name"
                fi
            done < "$CHECKOUT_STATE/plan"
            printf 'Rolled back an interrupted source checkout.\n'
        fi
    fi
    remove_checkout_state
}

fetch_file() {
    if command -v curl >/dev/null 2>&1; then curl -fL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then wget -q "$1" -O "$2"
    else die 'Install Git, curl or wget to download the source.'; fi
}

is_edl_checkout() {
    [ -f "$1/pyproject.toml" ] && [ -d "$1/edlclient" ] || return 1
    awk -v quote="'" '
        /^[[:space:]]*\[/ {
            project = ($0 ~ /^[[:space:]]*\[[[:space:]]*project[[:space:]]*\][[:space:]]*(#.*)?$/)
            if (project) tables++
        }
        project && /^[[:space:]]*name[[:space:]]*=/ {
            names++
            value = $0
            sub(/^[^=]*=[[:space:]]*/, "", value)
            sub(/[[:space:]]*#.*$/, "", value)
            sub(/[[:space:]]*$/, "", value)
            if (value == "\"edlclient\"" || value == quote "edlclient" quote) valid++
        }
        END { exit !(tables == 1 && names == 1 && valid == 1) }
    ' "$1/pyproject.toml"
}

check_target() {
    if is_edl_checkout "$TARGET"; then return; fi
    for entry in "$TARGET"/* "$TARGET"/.[!.]* "$TARGET"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        [ "$entry" = "$SELF" ] || die 'The current directory contains other files. Choose an empty directory or an EDL checkout.'
    done
}

get_checkout() {
    restore_interrupted_checkout
    check_target
    if is_edl_checkout "$TARGET"; then return; fi
    mkdir "$CHECKOUT_STATE"
    CHECKOUT_ACTIVE=1
    printf 'edl-checkout-v1\n' > "$CHECKOUT_STATE/owner"
    checkout="$CHECKOUT_STATE/source"
    if command -v git >/dev/null 2>&1; then
        git clone --quiet --no-hardlinks -- "$REPOSITORY" "$checkout"
    else
        [ "$REPOSITORY" = https://github.com/bkerler/edl.git ] || die 'Git is required for a custom repository.'
        fetch_file https://github.com/bkerler/edl/archive/refs/heads/master.tar.gz "$CHECKOUT_STATE/source.tar.gz"
        tar -xzf "$CHECKOUT_STATE/source.tar.gz" -C "$CHECKOUT_STATE"
        mv "$CHECKOUT_STATE/edl-master" "$checkout"
    fi
    is_edl_checkout "$checkout" || die 'The downloaded source is not an edlclient project.'
    : > "$CHECKOUT_STATE/plan.tmp"
    for entry in "$checkout"/* "$checkout"/.[!.]* "$checkout"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        destination="$TARGET/$(basename "$entry")"
        name=$(basename "$entry")
        case "$name" in .edl-checkout-state|*'
'*) die 'The downloaded source contains a reserved or unsupported installer path.' ;; esac
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            [ "$destination" = "$SELF" ] || die "Refusing to overwrite $destination"
        fi
        [ "$destination" = "$SELF" ] || printf '%s\n' "$name" >> "$CHECKOUT_STATE/plan.tmp"
    done
    mv "$CHECKOUT_STATE/plan.tmp" "$CHECKOUT_STATE/plan"
    CHECKOUT_PREPARED=1
    while IFS= read -r name; do
        destination="$TARGET/$name"
        if [ -e "$destination" ] || [ -L "$destination" ]; then die "Refusing to overwrite $destination"; fi
        mv "$checkout/$name" "$destination"
    done < "$CHECKOUT_STATE/plan"
    printf 'edl-checkout-v1\n' > "$CHECKOUT_STATE/committed"
    finish_checkout
}

get_loaders() {
    if [ -e "$TARGET/.git" ] && command -v git >/dev/null 2>&1; then
        git -C "$TARGET" submodule update --init --recursive --quiet
    else
        marker="$TARGET/Loaders/.edl-download-complete"
        if [ -f "$marker" ] && [ "$(cat "$marker")" = edl-loaders-main-v1 ]; then return; fi
        STAGE=$(mktemp -d "$TARGET/.edl-stage.XXXXXX")
        fetch_file https://github.com/bkerler/Loaders/archive/refs/heads/main.tar.gz "$STAGE/loaders.tar.gz"
        tar -xzf "$STAGE/loaders.tar.gz" -C "$STAGE"
        [ -d "$STAGE/Loaders-main" ] && [ -n "$(ls -A "$STAGE/Loaders-main")" ] || die 'The Loader archive is empty.'
        mkdir -p "$TARGET/Loaders"
        cp -R "$STAGE/Loaders-main/." "$TARGET/Loaders/"
        # Retry interrupted downloads/extraction/copies; keep files absent from the archive.
        printf 'edl-loaders-main-v1\n' > "$STAGE/complete"
        mv -f "$STAGE/complete" "$marker"
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
restore_interrupted_checkout
check_target
if [ -e "$TARGET/.venv" ]; then
    [ -f "$TARGET/.venv/pyvenv.cfg" ] || die 'The existing .venv is not an isolated virtual environment. Move it aside first.'
    grep -Eq '^[[:space:]]*include-system-site-packages[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$TARGET/.venv/pyvenv.cfg" || die 'The existing .venv shares system packages. Move it aside first.'
fi
select_python
printf 'Using Python: %s\n' "$PYTHON"
get_checkout
[ -f "$TARGET/install.py" ] || die 'This checkout is outdated: update it to include install.py.'
[ "$SKIP_DRIVERS" = 1 ] || ensure_usb
[ "$SKIP_LOADERS" = 1 ] || get_loaders
set -- --venv "$TARGET/.venv"
[ -z "$EXTRAS" ] || set -- "$@" --extras "$EXTRAS"
"$PYTHON" -I "$TARGET/install.py" "$@"
printf 'Ready. Run ./edl --help (or .venv/bin/edl --help).\n'
