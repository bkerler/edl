import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from edlclient.Library.Modules import oneplus_param as op


class ParamWriteTests(unittest.TestCase):
    def test_failed_decryption_does_not_mutate_input(self):
        tool = op.paramtools(0, 0)
        data = bytearray(0x50000)
        before = bytes(data)
        with patch.object(tool, "decryptsid", return_value=(None,) * 4):
            with patch.object(tool, "encryptsid") as encrypt:
                with self.assertRaisesRegex(ValueError, "SID 0x13c"):
                    tool.setparamvalue(data, 0x13C, 0x80, 1)
                encrypt.assert_not_called()
        self.assertEqual(bytes(data), before)

    def test_valid_encrypted_record_still_updates(self):
        tool = op.paramtools(0, 0)
        base = 0x12C * 0x400
        data = bytearray(base + 0x1000)
        data[base:] = tool.encryptsid(bytes(0xB80), 1, 1, 0)
        before = bytes(data)
        result = tool.setparamvalue(data, 0x12C, 0x80, 7)
        item, hv, cv, counter = tool.decryptsid(result[base:])
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item[:4], b"\x07\x00\x00\x00")
        self.assertEqual(item[4:], bytes(0xB80 - 4))
        self.assertEqual((hv, cv, counter), (1, 1, 2))
        self.assertEqual(result[:base], before[:base])
        self.assertEqual(len(result), len(before))
        self.assertEqual(bytes(data), before)

    def test_cli_failure_preserves_output_state(self):
        for existing in (False, True):
            with self.subTest(existing=existing):
                with tempfile.TemporaryDirectory() as folder:
                    source = Path(folder) / "param.bin"
                    source.write_bytes(bytes(0x50000))
                    output = Path(str(source) + ".patched")
                    if existing:
                        output.write_bytes(b"keep this file")
                    args = [
                        "oneplus_param.py",
                        "setparam",
                        str(source),
                        "0x13C",
                        "0x80",
                        "1",
                    ]
                    with patch("sys.argv", args):
                        with patch.object(
                            op.paramtools,
                            "decryptsid",
                            return_value=(None,) * 4,
                        ):
                            with self.assertRaises(ValueError):
                                op.main()
                    self.assertEqual(source.read_bytes(), bytes(0x50000))
                    if existing:
                        self.assertEqual(output.read_bytes(), b"keep this file")
                    else:
                        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
