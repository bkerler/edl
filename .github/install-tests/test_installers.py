"""Real checkout/venv tests plus isolated interactive bootstrap checks."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = os.name == "nt"


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="edl-bootstrap-tests-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        cls.repository = cls.work / "source repository"
        cls.repository.mkdir()
        files = subprocess.check_output(["git", "-C", str(ROOT), "ls-files", "-z"], text=True).split("\0")
        files += ["install.py", "edl", ".gitattributes", "install_edl_win10_win11.ps1"]
        for name in set(files):
            source = ROOT / name
            if not name or not source.is_file():
                continue
            target = cls.repository / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        for name in ("edl", "autoinstall.sh", "install-linux-edl-drivers.sh"):
            target = cls.repository / name
            target.write_bytes(target.read_bytes().replace(b"\r\n", b"\n"))
            target.chmod(0o755)
        for args in (
            ["init", "-q", str(cls.repository)],
            ["-C", str(cls.repository), "config", "core.autocrlf", "false"],
            ["-C", str(cls.repository), "add", "--all"],
            ["-C", str(cls.repository), "-c", "user.name=Installer Tests", "-c",
             "user.email=tests@example.invalid", "-c", "commit.gpgsign=false",
             "-c", "core.hooksPath=" + str(cls.work / "no-hooks"), "commit", "-qm", "fixture"],
        ):
            subprocess.run(["git", *args], check=True, capture_output=True)

    def run_command(self, *command, cwd=None, success=True, overrides=None, input=None):
        env = os.environ.copy()
        env.pop("PYTHONHOME", None)
        env.pop("PYTHONPATH", None)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        env.update(overrides or {})
        result = subprocess.run(command, cwd=cwd or self.work, env=env, input=input,
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=240)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("Installed EDL in", result.stdout)
        return result

    def bootstrap(self, target, extras=None, python=sys.executable, unattended=True, **kwargs):
        if WINDOWS:
            command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                       str(target / "install_edl_win10_win11.ps1"), "-SkipDrivers", "-SkipLoaders",
                       "-Repository", str(self.repository)]
            if python:
                command += ["-Python", python]
            if unattended:
                command += ["-NoInput"]
            if extras:
                command += ["-Extras", extras]
        else:
            command = ["sh", str(target / "autoinstall.sh"), "--skip-drivers", "--skip-loaders",
                       "--repository", str(self.repository)]
            if python:
                command += ["--python", python]
            if unattended:
                command += ["--no-input"]
            if extras:
                command += ["--extras", extras]
        return self.run_command(*command, cwd=target, **kwargs)

    def downloaded_installer(self, name):
        target = self.work / name
        target.mkdir()
        filename = "install_edl_win10_win11.ps1" if WINDOWS else "autoinstall.sh"
        script = target / filename
        shutil.copy2(ROOT / filename, script)
        script.write_bytes(script.read_bytes().replace(b"\r\n", b"\n") + b"\n# downloaded bootstrap sentinel\n")
        return target, script

    def test_current_directory_clone_install_and_update(self):
        baseline = self.run_command(sys.executable, "-I", "-m", "pip", "list", "--format=json").stdout
        target, script = self.downloaded_installer("installed here with spaces")
        original = script.read_bytes()
        trap = self.work / "outside install target"
        config = self.work / "pip.ini"
        config.write_text(f"[install]\ntarget = {trap}\nuser = true\n", encoding="utf-8")
        result = self.bootstrap(target, overrides={"PIP_TARGET": str(trap), "PIP_USER": "1",
                                "PIP_PREFIX": str(trap), "PIP_ROOT": str(trap), "PIP_CONFIG_FILE": str(config)})
        self.assertIn("Installed EDL in", result.stdout)
        self.assertEqual(script.read_bytes(), original)
        self.assertTrue((target / "edlclient").is_dir())
        self.assertTrue((target / ".git").is_dir())
        self.assertFalse(trap.exists())
        self.assertEqual(list(target.glob(".edl-stage-*")), [])
        scripts = target / ".venv" / ("Scripts" if WINDOWS else "bin")
        python = scripts / ("python.exe" if WINDOWS else "python")
        probe = "\n".join((
            "import importlib.util, json, sys, edlclient",
            "print(json.dumps([sys.prefix, sys.base_prefix, edlclient.__file__,",
            " [importlib.util.find_spec(n) is not None for n in ('capstone','keystone','qrcode')]]))",
        ))
        prefix, base, module, optional = json.loads(self.run_command(str(python), "-I", "-c", probe).stdout)
        self.assertEqual(Path(prefix).resolve(), (target / ".venv").resolve())
        self.assertNotEqual(prefix, base)
        self.assertIn((target / ".venv").resolve(), Path(module).resolve().parents)
        self.assertEqual(optional, [False, False, False])
        for name, args in (("edl", ["--help"]), ("qc_diag", ["--help"]),
                           ("sierrakeygen", ["--help"]), ("boottodwnload", ["--help"]),
                           ("enableadb", ["--help"]), ("fhloaderparse", []), ("beagle_to_loader", [])):
            with self.subTest(command=name):
                command = scripts / (name + (".exe" if WINDOWS else ""))
                self.assertIn("usage:", self.run_command(str(command), *args).stdout.lower())
        if WINDOWS:
            harness = self.work / "launch-batch.ps1"
            harness.write_text("param($Launcher)\n& $Launcher --help\nexit $LASTEXITCODE\n", encoding="utf-8")
            output = self.run_command("powershell.exe", "-NoProfile", "-File", str(harness),
                                      str(target / "edl.bat")).stdout
        else:
            output = self.run_command(str(target / "edl"), "--help").stdout
        self.assertIn("usage:", output.lower())
        marker = target / ".venv" / "keep.txt"
        marker.write_text("preserved", encoding="utf-8")
        if not WINDOWS:
            (target / "edl").chmod(0o644)  # Source archives may lose executable permissions.
        updated = self.bootstrap(target, extras="asm,qrcode", python=None)
        self.assertIn(str(python), updated.stdout)
        if not WINDOWS:
            self.assertIn("usage:", self.run_command(str(target / "edl"), "--help").stdout.lower())
        optional = json.loads(self.run_command(str(python), "-I", "-c", probe).stdout)[3]
        self.assertEqual(optional, [True, True, True])
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserved")
        after = self.run_command(sys.executable, "-I", "-m", "pip", "list", "--format=json").stdout
        self.assertEqual(json.loads(baseline), json.loads(after))

    def test_refuse_other_files_before_clone(self):
        target, script = self.downloaded_installer("existing files")
        marker = target / "keep.txt"
        marker.write_text("preserved", encoding="utf-8")
        result = self.bootstrap(target, success=False)
        self.assertIn("contains other files", result.stdout + result.stderr)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserved")
        self.assertFalse((target / ".git").exists())

    def test_refuse_a_different_project_despite_matching_directory(self):
        target, _ = self.downloaded_installer("different project")
        (target / "edlclient").mkdir()
        metadata = '[project]\nname = "another-project"\n[tool.fixture]\nname = "edlclient"\n'
        (target / "pyproject.toml").write_text(metadata, encoding="utf-8")
        (target / "install.py").write_text("raise RuntimeError('Other project executed')\n", encoding="utf-8")
        result = self.bootstrap(target, success=False)
        self.assertIn("contains other files", result.stdout + result.stderr)
        self.assertNotIn("Other project executed", result.stdout + result.stderr)
        self.assertFalse((target / ".venv").exists())
        self.assertEqual((target / "pyproject.toml").read_text(encoding="utf-8"), metadata)

    def test_helper_refuses_unsafe_environments(self):
        for name, shared in (("unrelated directory", False), ("system site packages", True)):
            with self.subTest(name=name):
                target = self.work / name
                if shared:
                    venv.EnvBuilder(system_site_packages=True, with_pip=False).create(target)
                else:
                    target.mkdir()
                marker = target / "keep.txt"
                marker.write_text("preserved", encoding="utf-8")
                self.run_command(sys.executable, "-I", str(ROOT / "install.py"),
                                 "--venv", str(target), success=False)
                self.assertEqual(marker.read_text(encoding="utf-8"), "preserved")

    def test_invalid_extras_before_clone(self):
        target, _ = self.downloaded_installer("invalid extras")
        result = self.bootstrap(target, extras="unknown-feature", success=False)
        self.assertIn("Choose asm, qrcode", result.stdout + result.stderr)
        self.assertFalse((target / ".git").exists())

    def test_pip_failure(self):
        target = self.work / "failed installation"
        empty = self.work / "empty index"
        empty.mkdir()
        shutil.copytree(self.repository, target, ignore=shutil.ignore_patterns(".git"))
        self.bootstrap(target, success=False, overrides={
            "PIP_NO_INDEX": "1", "PIP_FIND_LINKS": str(empty), "PIP_CACHE_DIR": str(empty),
        })


if __name__ == "__main__":
    unittest.main()
