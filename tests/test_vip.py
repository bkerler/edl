"""Tests for the VIP (Validated Image Programming) table handling.

The file layout is a compatibility contract with qdl, so these tests pin the
exact sizes and hash chaining derived from qdl's src/vip.c.
"""
import hashlib
import os
import shutil
import tempfile

import pytest

from edlclient.Library.vip import (
    CHAINED_TABLE_FILE_PREF,
    DIGEST_FULL_TABLE_FILE,
    DIGEST_TABLE_TO_SIGN_FILE,
    DIGEST_TABLE_TO_SIGN_FILE_MBN,
    MAX_DIGESTS_PER_CHAINED_TABLE,
    MAX_DIGESTS_PER_SIGNED_TABLE,
    VIP_INIT,
    Vip,
    VipDigestGenerator,
    VipTransfer,
)

DIGEST_LEN = 32


def packet(i):
    return f"packet-{i}".encode()


def generate(tmpdir, count):
    """Generate digest tables for `count` synthetic packets, returning their hashes."""
    gen = VipDigestGenerator(tmpdir, printer=lambda *_: None)
    digests = []
    for i in range(count):
        data = packet(i)
        digests.append(hashlib.sha256(data).digest())
        gen.chunk_init()
        gen.chunk_update(data)
        gen.chunk_store()
    assert gen.finalize()
    return digests


def read(tmpdir, name):
    with open(os.path.join(tmpdir, name), "rb") as rf:
        return rf.read()


def test_signed_table_only(tmpdir=None):
    path = tempfile.mkdtemp()
    try:
        digests = generate(path, 3)
        assert read(path, DIGEST_FULL_TABLE_FILE) == b"".join(digests)
        # fewer than 53 packets: no chained hash is appended
        assert read(path, DIGEST_TABLE_TO_SIGN_FILE) == b"".join(digests)
        assert not os.path.exists(os.path.join(path, f"{CHAINED_TABLE_FILE_PREF}0.bin"))
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_signed_table_exact_fit():
    path = tempfile.mkdtemp()
    try:
        digests = generate(path, MAX_DIGESTS_PER_SIGNED_TABLE)
        assert read(path, DIGEST_TABLE_TO_SIGN_FILE) == b"".join(digests)
        assert not os.path.exists(os.path.join(path, f"{CHAINED_TABLE_FILE_PREF}0.bin"))
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_one_chained_table():
    path = tempfile.mkdtemp()
    try:
        digests = generate(path, MAX_DIGESTS_PER_SIGNED_TABLE + 1)
        chained = read(path, f"{CHAINED_TABLE_FILE_PREF}0.bin")
        # one digest plus the trailing zero byte
        assert chained == digests[-1] + b"\x00"

        signed = read(path, DIGEST_TABLE_TO_SIGN_FILE)
        expected = b"".join(digests[:MAX_DIGESTS_PER_SIGNED_TABLE]) + hashlib.sha256(chained).digest()
        assert signed == expected
        assert len(signed) == 54 * DIGEST_LEN
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_two_chained_tables_chain_hash():
    path = tempfile.mkdtemp()
    try:
        count = MAX_DIGESTS_PER_SIGNED_TABLE + MAX_DIGESTS_PER_CHAINED_TABLE + 1
        digests = generate(path, count)
        last = read(path, f"{CHAINED_TABLE_FILE_PREF}1.bin")
        first = read(path, f"{CHAINED_TABLE_FILE_PREF}0.bin")

        # final table: remaining digest + trailing zero
        assert last == digests[-1] + b"\x00"
        # first table: 255 digests + hash of the final table
        expected_first = b"".join(
            digests[MAX_DIGESTS_PER_SIGNED_TABLE:MAX_DIGESTS_PER_SIGNED_TABLE + MAX_DIGESTS_PER_CHAINED_TABLE]
        ) + hashlib.sha256(last).digest()
        assert first == expected_first
        # signed table ends with the hash of the first chained table
        signed = read(path, DIGEST_TABLE_TO_SIGN_FILE)
        assert signed[-DIGEST_LEN:] == hashlib.sha256(first).digest()
        assert len(signed) == 54 * DIGEST_LEN
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_full_chained_table_no_trailing_zero():
    path = tempfile.mkdtemp()
    try:
        # exactly one full chained table: it is final, so it gets the zero byte
        count = MAX_DIGESTS_PER_SIGNED_TABLE + MAX_DIGESTS_PER_CHAINED_TABLE
        generate(path, count)
        assert len(read(path, f"{CHAINED_TABLE_FILE_PREF}0.bin")) == (MAX_DIGESTS_PER_CHAINED_TABLE * DIGEST_LEN) + 1
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_transfer_table_scheduling():
    path = tempfile.mkdtemp()
    try:
        count = MAX_DIGESTS_PER_SIGNED_TABLE + 2
        generate(path, count)
        # the signed table is loaded as an MBN
        shutil.copy(os.path.join(path, DIGEST_TABLE_TO_SIGN_FILE),
                    os.path.join(path, DIGEST_TABLE_TO_SIGN_FILE_MBN))

        sent = []
        transfer = VipTransfer(path, send_raw=lambda d: sent.append(len(d)) or True,
                             recv_response=lambda: True)
        assert transfer.load()

        packets = 0
        # first packet triggers the signed table
        assert transfer.send_pending_tables()
        assert len(sent) == 1
        transfer.count_packet()
        packets += 1
        # ... then the signed table covers 53 packets in total
        for _ in range(MAX_DIGESTS_PER_SIGNED_TABLE - 1):
            transfer.send_pending_tables()
            transfer.count_packet()
            packets += 1
        assert len(sent) == 1, "no chained table needed yet"
        # the 54th packet is preceded by the first chained table
        assert transfer.send_pending_tables()
        assert len(sent) == 2
        assert transfer._chained_cur == 1
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_transfer_rejects_missing_tables():
    path = tempfile.mkdtemp()
    try:
        transfer = VipTransfer(path, send_raw=lambda d: True, recv_response=lambda: True)
        assert not transfer.load()
        # the programmer asked for VIP but nothing was provided
        assert transfer.state == 0
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_marker_detection():
    transfer = VipTransfer(tempfile.gettempdir(), send_raw=lambda d: True, recv_response=lambda: True)
    assert not transfer.programmer_requires_vip
    transfer.check_programmer_marker("INFO: VIP is enabled, receiving the signed table of size 8192")
    assert transfer.programmer_requires_vip


def test_modes_are_exclusive():
    base = tempfile.mkdtemp()
    try:
        with pytest.raises(ValueError):
            Vip(table_path=os.path.join(base, "tables"), digest_path=os.path.join(base, "digests"))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_facade_loads_tables_on_construction():
    base = tempfile.mkdtemp()
    try:
        tables = os.path.join(base, "tables")
        os.makedirs(tables)
        with open(os.path.join(tables, DIGEST_TABLE_TO_SIGN_FILE_MBN), "wb") as wf:
            wf.write(b"signed-table")
        vip = Vip(table_path=tables, send_raw=lambda d: True, recv_response=lambda: True)
        assert vip.transfer is not None
        assert vip.transfer.state == VIP_INIT

        # a directory without tables must not silently look like an enabled session
        empty = os.path.join(base, "empty")
        os.makedirs(empty)
        assert Vip(table_path=empty, send_raw=lambda d: True, recv_response=lambda: True).transfer is None
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_facade_sends_chained_table_after_budget():
    base = tempfile.mkdtemp()
    try:
        digests_dir = os.path.join(base, "digests")
        tables = os.path.join(base, "tables")
        generate(digests_dir, MAX_DIGESTS_PER_SIGNED_TABLE + 2)
        os.makedirs(tables)
        # the signed table is provided as an MBN, the chained tables as they were written
        shutil.copy(os.path.join(digests_dir, DIGEST_TABLE_TO_SIGN_FILE),
                    os.path.join(tables, DIGEST_TABLE_TO_SIGN_FILE_MBN))
        for name in os.listdir(digests_dir):
            if name.startswith(CHAINED_TABLE_FILE_PREF):
                shutil.copy(os.path.join(digests_dir, name), os.path.join(tables, name))

        sent = []
        vip = Vip(table_path=tables, send_raw=lambda d: sent.append(len(d)) or True,
                  recv_response=lambda: True)
        for _ in range(MAX_DIGESTS_PER_SIGNED_TABLE + 1):
            assert vip.begin_packet(b"x")
            vip.end_packet()
        # signed table + chained table 0
        assert len(sent) == 2
    finally:
        shutil.rmtree(base, ignore_errors=True)
