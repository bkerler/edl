"""Interactive Unix decisions with fake system package tools."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import shutil
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipIf(os.name == "nt", "Unix bootstrap controls")
class UnixControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="edl-unix-controls-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        (self.work / "edlclient").mkdir()
        (self.work / "pyproject.toml").write_text("# existing test checkout\n", encoding="utf-8")
        (self.work / "install.py").write_text(
            "import json, sys\nfrom pathlib import Path\n"
            "Path(__file__).with_suffix('.result').write_text(json.dumps(sys.executable))\n", encoding="utf-8")

    def invoke(self, answer, no_input=False, overrides=None):
        command = ["sh", str(ROOT / "autoinstall.sh"), "--python", str(self.work / "missing-python"),
                   "--skip-drivers", "--skip-loaders"]
        if no_input:
            command += ["--no-input"]
        env = os.environ.copy()
        env.update(overrides or {})
        return subprocess.run(command, cwd=self.work, input=answer, env=env,
                              capture_output=True, text=True, timeout=30)

    def test_n_cancels_and_path_uses_existing_python(self):
        result = self.invoke("n\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GLOBAL/system Python", result.stdout)
        self.assertFalse((self.work / "install.result").exists())
        result = self.invoke(sys.executable + "\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads((self.work / "install.result").read_text()), sys.executable)

    def test_no_input_never_installs_python(self):
        result = self.invoke("y\n", no_input=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Supply --python", result.stderr)
        self.assertFalse((self.work / "install.result").exists())

    def test_y_runs_only_the_mocked_system_package_steps(self):
        tools = self.work / "fake system tools"
        tools.mkdir()
        log = self.work / "package-commands.log"
        scripts = {
            "uname": "printf 'Linux\\n'\n",
            "id": "printf '1000\\n'\n",
            "python3": "exec " + shlex.quote(sys.executable) + ' "$@"\n',
            "sudo": 'printf "sudo %s\\n" "$*" >> ' + shlex.quote(str(log)) + '\nexec "$@"\n',
            "apt-get": 'printf "apt-get %s\\n" "$*" >> ' + shlex.quote(str(log)) + "\n",
        }
        for name, body in scripts.items():
            tool = tools / name
            tool.write_text("#!/bin/sh\n" + body, encoding="utf-8")
            tool.chmod(0o755)
        result = self.invoke("y\n", overrides={"PATH": str(tools) + os.pathsep + os.environ["PATH"]})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = log.read_text()
        self.assertIn("sudo apt-get update", commands)
        self.assertIn("apt-get install -y python3 python3-venv", commands)
        self.assertTrue((self.work / "install.result").exists())

    def test_archive_without_git_preserves_downloaded_script(self):
        target = self.work / "archive install"
        target.mkdir()
        script = target / "autoinstall.sh"
        script.write_bytes((ROOT / "autoinstall.sh").read_bytes().replace(b"\r\n", b"\n")
                           + b"\n# downloaded installer\n")
        original = script.read_bytes()
        source = self.work / "edl-master"
        source.mkdir()
        (source / "edlclient").mkdir()
        (source / "pyproject.toml").write_text("# fixture\n", encoding="utf-8")
        shutil.copy2(self.work / "install.py", source / "install.py")
        (source / "autoinstall.sh").write_text("# archive copy\n", encoding="utf-8")
        archive = self.work / "source.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(source, arcname="edl-master")
        tools = self.work / "archive tools"
        tools.mkdir()
        for name in ("dirname", "basename", "mktemp", "tar", "gzip", "mv", "rm"):
            (tools / name).symlink_to(shutil.which(name))
        curl = tools / "curl"
        curl.write_text("#!/bin/sh\nexec " + shlex.quote(shutil.which("cp")) + " "
                        + shlex.quote(str(archive)) + ' "$4"\n', encoding="utf-8")
        curl.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(tools)
        result = subprocess.run(["/bin/sh", str(script), "--python", sys.executable,
                                 "--skip-drivers", "--skip-loaders", "--no-input"],
                                cwd=target, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(script.read_bytes(), original)
        self.assertTrue((target / "install.result").exists())
        self.assertEqual(list(target.glob(".edl-stage.*")), [])
