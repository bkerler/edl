"""Real competing installer processes, including an orphaned native writer."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class InstallerConcurrencyTests(unittest.TestCase):
    def exercise_lock(self, perl_only=False):
        with tempfile.TemporaryDirectory(prefix="edl-concurrency-") as directory:
            work = Path(directory)
            env = os.environ.copy()
            if perl_only:
                tools = work / "perl locking tools"
                tools.mkdir()
                for name in ("dirname", "basename", "awk", "ls", "rm", "mkdir", "rmdir", "cat", "perl"):
                    (tools / name).symlink_to(shutil.which(name))
                env["PATH"] = str(tools)
            for ending in ("normal", "killed"):
                with self.subTest(ending=ending, perl_only=perl_only):
                    target = work / ending
                    target.mkdir()
                    (target / "edlclient").mkdir()
                    (target / "pyproject.toml").write_text('[project]\nname = "edlclient"\n', encoding="utf-8")
                    (target / "install.py").write_text(
                        "import os, time\nfrom pathlib import Path\n"
                        "root = Path(__file__).parent\n"
                        "if not (root / 'release').exists():\n"
                        "    state = root / '.edl-checkout-state'\n"
                        "    state.mkdir()\n"
                        "    (state / 'owner').write_text('edl-checkout-v1\\n')\n"
                        "    (state / 'payload').write_text('active writer ' + str(os.getpid()))\n"
                        "    (root / 'ready').write_text(str(os.getpid()))\n"
                        "    while not (root / 'release').exists():\n"
                        "        time.sleep(0.02)\n", encoding="utf-8")
                    if os.name == "nt":
                        command = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                   str(ROOT / "install_edl_win10_win11.ps1"), "-Python", sys.executable,
                                   "-SkipDrivers", "-SkipLoaders", "-NoInput"]
                    else:
                        command = ["/bin/sh", str(ROOT / "autoinstall.sh"), "--python", sys.executable,
                                   "--skip-drivers", "--skip-loaders", "--no-input"]
                    holder = subprocess.Popen(command, cwd=target, env=env, stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True)
                    state = target / ".edl-checkout-state"
                    lock_path = target / ".edl-install.lock"
                    def attempt():
                        return subprocess.run(command, cwd=target, env=env, capture_output=True,
                                              text=True, timeout=10)
                    def assert_blocked():
                        result = attempt()
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn("lock", (result.stdout + result.stderr).lower())
                        self.assertEqual((state / "payload").read_text(), active_payload)
                    try:
                        deadline = time.monotonic() + 10
                        while not (target / "ready").exists() and holder.poll() is None and time.monotonic() < deadline:
                            time.sleep(0.02)
                        if not (target / "ready").exists():
                            holder.kill()
                            stdout, stderr = holder.communicate(timeout=10)
                            self.fail("Installer did not reach the writer: " + stdout + stderr)
                        self.assertTrue(lock_path.is_file())
                        inode = lock_path.stat().st_ino
                        active_payload = (state / "payload").read_text()
                        assert_blocked()
                        if ending == "killed":
                            holder.kill()
                            holder.wait(timeout=10)
                            # The native Python child is still writing: it must retain the lock.
                            assert_blocked()
                        (target / "release").touch()
                        stdout, stderr = holder.communicate(timeout=10)
                        if ending == "normal":
                            self.assertEqual(holder.returncode, 0, stdout + stderr)
                        result = attempt()
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertFalse(state.exists(), "Retry did not recover pending state")
                        if os.name == "nt":
                            self.assertFalse(lock_path.exists(), "DeleteOnClose did not clean the lock")
                        else:
                            self.assertEqual(lock_path.stat().st_ino, inode, "Lock inode was replaced")
                    finally:
                        (target / "release").touch()
                        if holder.poll() is None:
                            holder.kill()
                        holder.communicate(timeout=10)

    def test_same_target_serializes_recovery_and_native_writers(self):
        self.exercise_lock()

    @unittest.skipIf(os.name == "nt" or not shutil.which("perl"), "Unix native Perl flock fallback")
    def test_perl_fallback_retains_the_kernel_lock(self):
        self.exercise_lock(perl_only=True)
