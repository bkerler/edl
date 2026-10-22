#!/usr/bin/env python3
"""Install this checkout into a private virtual environment (Python 3.10+)."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import venv


ROOT = Path(__file__).resolve().parent


def extras(value):
    if not value:
        return ""
    names = value.split(",")
    if any(name not in ("asm", "qrcode") for name in names):
        raise argparse.ArgumentTypeError("Choose asm, qrcode, or asm,qrcode")
    return ",".join(dict.fromkeys(names))


def install(destination, features):
    # Ignore settings that could redirect pip outside the selected environment.
    env = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "PIP_USER", "PIP_TARGET",
                 "PIP_PREFIX", "PIP_ROOT", "PIP_PYTHON", "PIP_BREAK_SYSTEM_PACKAGES"):
        env.pop(name, None)
    env["PIP_CONFIG_FILE"] = os.devnull

    config = destination / "pyvenv.cfg"
    if destination.exists() and not config.is_file():
        raise ValueError(f"{destination} already exists and is not a virtual environment; choose --venv elsewhere")
    if not config.exists():
        print(f"Creating virtual environment: {destination}", flush=True)
        venv.EnvBuilder(with_pip=True).create(destination)

    settings = {}
    for line in config.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            settings[key.strip().lower()] = value.strip().lower()
    if settings.get("include-system-site-packages") != "false":
        raise ValueError("The environment must disable system site-packages; choose a new --venv directory")

    scripts = destination / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    details = json.loads(subprocess.check_output([
        str(python), "-I", "-c",
        "import json, sys; print(json.dumps([sys.prefix, sys.base_prefix, list(sys.version_info[:2])]))",
    ], env=env, text=True))
    prefix, base, version = details
    if Path(prefix).resolve() != destination or prefix == base or tuple(version) < (3, 10):
        raise ValueError("The selected environment must use an isolated Python 3.10+ interpreter")

    package = str(ROOT) + (f"[{features}]" if features else "")
    subprocess.run([str(python), "-I", "-m", "pip", "install", "--no-user", "--upgrade", package],
                   env=env, check=True)
    subprocess.run([str(python), "-I", "-m", "pip", "check"], env=env, check=True)
    launcher = ROOT / "edl"
    if os.name != "nt" and launcher.is_file():
        launcher.chmod(launcher.stat().st_mode | 0o111)
    command = scripts / ("edl.exe" if os.name == "nt" else "edl")
    print(f'Installed EDL in {destination}\nRun: "{command}" --help')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venv", type=Path, default=ROOT / ".venv", help="Virtual environment directory")
    parser.add_argument("--extras", type=extras, default="", help="Optional features: asm,qrcode")
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.exit(1, "Python 3.10 or newer is required.\n")
    try:
        install(args.venv.expanduser().resolve(), args.extras)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
