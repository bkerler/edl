"""Dependency resolution checks, independent of CLI packaging fixes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import venv


ROOT = Path(__file__).resolve().parents[2]


def run(*command, cwd):
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env["PYTHONIOENCODING"] = "utf-8"
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=180,
    )
    if result.returncode:
        raise AssertionError(
            f"Command failed ({result.returncode}): {command}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout


class DependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.wheels = []
        for name, flags in (("direct", ["--wheel"]), ("sdist", [])):
            output = cls.work / name
            run(sys.executable, "-m", "build", "--no-isolation", *flags,
                "--outdir", str(output), cwd=ROOT)
            cls.wheels.append(next(output.glob("*.whl")))

    @classmethod
    def environment(cls, name):
        root = cls.work / name
        venv.EnvBuilder(with_pip=True).create(root)
        scripts = root / ("Scripts" if os.name == "nt" else "bin")
        return scripts / ("python.exe" if os.name == "nt" else "python")

    def test_default_dependency_install(self):
        for wheel in self.wheels:
            with self.subTest(wheel=wheel.parent.name):
                python = self.environment(wheel.parent.name + "-installed")
                run(str(python), "-m", "pip", "install", str(wheel), cwd=self.work)
                run(str(python), "-m", "pip", "check", cwd=self.work)
                run(str(python), "-c", "\n".join((
                    "import importlib.util, pathlib, sys",
                    "for name in ('capstone', 'keystone', 'qrcode'):",
                    "    assert importlib.util.find_spec(name) is None, name",
                    "from edlclient.Library import cryptutils",
                    "from edlclient.Library.Modules import oneplus, oneplus_param",
                    "module = pathlib.Path(cryptutils.__file__).resolve()",
                    "assert pathlib.Path(sys.prefix).resolve() in module.parents, module",
                )), cwd=self.work)

    def test_optional_dependency_install(self):
        for extra, missing, check in (
            ("asm", "qrcode", "\n".join((
                "from edlclient.Library import asmtools",
                "code = bytes(asmtools.asm('nop', 'arm', 'arm', False))",
                "disassembler = asmtools.Cs(asmtools.CS_ARCH_ARM, asmtools.CS_MODE_ARM)",
                "instructions = list(disassembler.disasm(code, 0x1000))",
                "assert len(instructions) == 1 and instructions[0].mnemonic == 'nop'",
            ))),
            ("qrcode", "capstone", "\n".join((
                "from pathlib import Path",
                "import qrcode",
                "target = Path('optional-qr.png')",
                "qrcode.make('op_eng://dependency-test').save(str(target))",
                "assert target.read_bytes().startswith(bytes.fromhex('89504e470d0a1a0a'))",
            ))),
        ):
            with self.subTest(extra=extra):
                python = self.environment("extra-" + extra)
                run(str(python), "-m", "pip", "install",
                    str(self.wheels[0]) + "[" + extra + "]", cwd=self.work)
                run(str(python), "-m", "pip", "check", cwd=self.work)
                run(str(python), "-c",
                    f"import importlib.util; assert importlib.util.find_spec('{missing}') is None",
                    cwd=self.work)
                run(str(python), "-c", check, cwd=self.work)

    def test_legacy_requirements(self):
        python = self.environment("legacy-source")
        run(str(python), "-m", "pip", "install", "-r",
            str(ROOT / "requirements.txt"), cwd=self.work)
        run(str(python), "-m", "pip", "check", cwd=self.work)
        run(str(python), "-c", "\n".join((
            "import importlib.util",
            "assert importlib.util.find_spec('edlclient') is None",
            "from Cryptodome.Cipher import AES",
            "from Exscript.protocols.telnetlib import Telnet",
            "from passlib.hash import md5_crypt",
            "import requests, serial, usb.core, capstone, keystone, qrcode",
            "from PIL import Image",
        )), cwd=self.work)

    def test_generated_requirements(self):
        run(sys.executable, str(ROOT / ".github/scripts/update_requirements.py"),
            "--check", cwd=self.work)


if __name__ == "__main__":
    unittest.main()
