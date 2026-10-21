"""Packaging regression checks; install build, setuptools and wheel first.

Run with: python -m unittest discover -s tests -v
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CLI_ARGS = {
    "edl": ["--help"],
    "qc_diag": ["--help"],
    "sierrakeygen": ["--help"],
    "boottodwnload": ["--help"],
    "enableadb": ["--help"],
    "fhloaderparse": [],
    "beagle_to_loader": [],
}


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


class PackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.wheels = []
        # Exercise both a direct wheel and the default sdist -> wheel release build.
        for name, flags in (("direct", ["--wheel"]), ("sdist", [])):
            output = cls.work / name
            run(sys.executable, "-m", "build", "--no-isolation", *flags,
                "--outdir", str(output), cwd=ROOT)
            cls.wheels.append(next(output.glob("*.whl")))
        cls.environment = cls.work / "environment"
        venv.EnvBuilder(with_pip=True).create(cls.environment)
        cls.scripts = cls.environment / ("Scripts" if os.name == "nt" else "bin")
        cls.python = cls.scripts / ("python.exe" if os.name == "nt" else "python")
        # Use the existing requirements file to exercise package structure
        # independently of dependency metadata.
        run(str(cls.python), "-m", "pip", "install", "-r",
            str(ROOT / "requirements.txt"), cwd=cls.work)

    def test_wheel_contents(self):
        for wheel in self.wheels:
            with self.subTest(wheel=wheel.parent.name), zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
                for required in (
                    "edlclient/edl.py", "edlclient/Config/nvitems.xml",
                    "edlclient/Windows/libusb-1.0.dll",
                    "edlclient/Windows/libusb32-1.0.dll",
                ):
                    self.assertIn(required, names)
                for name in names:
                    if name.endswith(".py"):
                        self.assertTrue(name.startswith("edlclient/"), name)
                        self.assertNotIn("edlclient/Tools/Library/", name)
                        self.assertNotIn("edlclient/Tools/Config/", name)
                        compile(archive.read(name), name, "exec")

    def test_installed_entry_points(self):
        for wheel in self.wheels:
            with self.subTest(wheel=wheel.parent.name):
                python, scripts = self.python, self.scripts
                run(str(python), "-m", "pip", "install", "--no-deps", "--no-index",
                    "--force-reinstall", str(wheel), cwd=self.work)
                output = run(str(python), "-c", "\n".join((
                    "import importlib.metadata, inspect, pathlib, sys",
                    "sys.argv = ['entry-point-test', '--invalid-import-argument']",
                    "dist = importlib.metadata.distribution('edlclient')",
                    "for entry in dist.entry_points:",
                    "    if entry.group == 'console_scripts':",
                    "        function = entry.load()",
                    "        inspect.signature(function).bind()",
                    "        module = pathlib.Path(inspect.getfile(function)).resolve()",
                    "        assert pathlib.Path(sys.prefix).resolve() in module.parents, module",
                    "        print(entry.name)",
                )), cwd=self.work)
                self.assertEqual(set(output.splitlines()) & CLI_ARGS.keys(), CLI_ARGS.keys())
                for command, args in CLI_ARGS.items():
                    with self.subTest(command=command):
                        executable = scripts / (command + (".exe" if os.name == "nt" else ""))
                        output = run(str(executable), *args, cwd=self.work)
                        self.assertIn("usage:", output.lower())
                self.assertIn("3", run(str(scripts / ("edl.exe" if os.name == "nt" else "edl")),
                                       "--version", cwd=self.work))

    def test_source_launchers(self):
        for script in ("edl.py", "qc_diag.py", "boottodwnload.py", "enableadb.py", "fhloaderparse.py"):
            with self.subTest(script=script):
                output = run(str(self.python), str(ROOT / script),
                             *CLI_ARGS[Path(script).stem], cwd=self.work)
                self.assertIn("usage:", output.lower())
        # These tools used to depend on the Tools/Library and Tools/Config links.
        for command, args in CLI_ARGS.items():
            script = ROOT / "edlclient" / "Tools" / (command + ".py")
            if script.exists():
                with self.subTest(script=str(script)):
                    output = run(str(self.python), str(script), *args, cwd=self.work)
                    self.assertIn("usage:", output.lower())


if __name__ == "__main__":
    unittest.main()
