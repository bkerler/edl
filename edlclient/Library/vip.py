#!/usr/bin/env python3
# (c) B.Kerler 2018-2025 under GPLv3 license
# If you use my code, make sure you refer to my name
#
# !!!!! If you use this code in commercial products, your product is automatically
# GPLv3 and has to be open sourced under GPLv3 as well. !!!!!
"""Validated Image Programming (VIP).

When secure boot is enabled the firehose programmer announces

    VIP is enabled, receiving the signed table of size <n>

and afterwards validates every packet it receives against a pre-loaded table of
SHA256 digests: packets matching the next entry are accepted, anything else is
rejected and the target halts.

The file layout matches qdl (Qualcomm's reference implementation), so tables are
interchangeable between the two tools:

  DIGEST_TABLE.bin              SHA256 of every packet in send order (intermediate,
                                only used to build the two file sets below)
  DigestsToSign.bin             first 53 digests + SHA256 of ChainedTableOfDigests0.bin
  ChainedTableOfDigests<n>.bin  up to 255 digests plus the SHA256 of the next table,
                                the last one ends with a single zero byte
                                (so its size can't be a multiple of the sector size)

DigestsToSign.bin has to be wrapped into an MBN and signed with sectools:

    sectools mbn-tool generate --data DigestsToSign.bin --mbn-version 6 \\
        --outfile DigestsToSign.bin.mbn
    sectools secure-image --sign DigestsToSign.bin.mbn --image-id=VIP
"""
import hashlib
import logging
import os

MAX_DIGESTS_PER_SIGNED_FILE = 54
MAX_DIGESTS_PER_CHAINED_FILE = 256
MAX_CHAINED_FILES = 32

# The last slot of every file is reserved for the chained hash
MAX_DIGESTS_PER_SIGNED_TABLE = MAX_DIGESTS_PER_SIGNED_FILE - 1
MAX_DIGESTS_PER_CHAINED_TABLE = MAX_DIGESTS_PER_CHAINED_FILE - 1

DIGEST_FULL_TABLE_FILE = "DIGEST_TABLE.bin"
DIGEST_TABLE_TO_SIGN_FILE = "DigestsToSign.bin"
DIGEST_TABLE_TO_SIGN_FILE_MBN = DIGEST_TABLE_TO_SIGN_FILE + ".mbn"
CHAINED_TABLE_FILE_PREF = "ChainedTableOfDigests"

# Marker the programmer prints when it expects a signed table
VIP_PROGRAMMER_MARKER = "VIP is enabled, receiving the signed table"

VIP_DISABLED = 0
VIP_INIT = 1
VIP_SEND_NEXT_TABLE = 2
VIP_SEND_DATA = 3


class VipDigestGenerator:
    """Collects the SHA256 of every packet and turns them into the qdl table files."""

    def __init__(self, path, loglevel=logging.INFO, printer=None):
        self.path = path
        self.__logger = logging.getLogger("vip")
        self.__logger.setLevel(loglevel)
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.debug = self.__logger.debug
        self.printer = printer if printer is not None else print
        self._hash = None
        self._digests = 0
        self._table = os.path.join(path, DIGEST_FULL_TABLE_FILE)
        self._fh = None
        try:
            os.makedirs(path, exist_ok=True)
            # Held for the whole session, closed by close()/finalize()
            self._fh = open(self._table, "wb")  # noqa: SIM115
        except OSError as err:
            self.error(f"Couldn't create {self._table}: {err}")
            self._fh = None

    def chunk_init(self):
        self._hash = hashlib.sha256()

    def chunk_update(self, data):
        if self._hash is not None and data:
            self._hash.update(bytes(data))

    def chunk_store(self):
        if self._hash is None:
            return
        digest = self._hash.digest()
        self._hash = None
        if self._fh is None:
            return
        try:
            self._fh.write(digest)
        except OSError as err:
            self.error(f"Couldn't write to {self._table}: {err}")
            self.close()
            return
        self.debug(f"packet {self._digests}: {digest.hex()}")
        self._digests += 1

    def close(self):
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    def finalize(self):
        """Close the table and write DigestsToSign.bin and the chained tables."""
        self.close()
        self.info(f"VIP: {self._digests} packet digests written to {self._table}")
        if self._digests == 0:
            self.error("VIP: no packets were hashed, no digest tables written")
            return False
        return self._create_chained_tables()

    def _write_digests(self, dest, start, count):
        """Copy count digests starting at index start, returning their hash context."""
        ctx = hashlib.sha256()
        path = os.path.join(self.path, dest)
        try:
            with open(self._table, "rb") as rf, open(path, "wb") as wf:
                rf.seek(start * 32)
                remaining = count * 32
                while remaining > 0:
                    chunk = rf.read(min(remaining, 16 * 32))
                    if not chunk:
                        self.error(f"Short read on {self._table}")
                        return None
                    wf.write(chunk)
                    ctx.update(chunk)
                    remaining -= len(chunk)
        except OSError as err:
            self.error(f"Couldn't write {path}: {err}")
            return None
        return ctx

    def _append(self, name, data):
        path = os.path.join(self.path, name)
        try:
            with open(path, "ab") as wf:
                wf.write(data)
        except OSError as err:
            self.error(f"Couldn't append to {path}: {err}")
            return False
        return True

    def _create_chained_tables(self):
        total = self._digests
        signed_count = min(total, MAX_DIGESTS_PER_SIGNED_TABLE)
        signed_ctx = self._write_digests(DIGEST_TABLE_TO_SIGN_FILE, 0, signed_count)
        if signed_ctx is None:
            return False

        chained = 0
        if total > MAX_DIGESTS_PER_SIGNED_TABLE:
            chained = (total - MAX_DIGESTS_PER_SIGNED_TABLE + MAX_DIGESTS_PER_CHAINED_TABLE - 1) \
                // MAX_DIGESTS_PER_CHAINED_TABLE

        # Step 2: split the remaining digests over the chained tables, hashing each
        # payload as we go so the chained hashes don't need a second read pass.
        contexts = []
        remaining = total - signed_count
        idx = 0
        while remaining > 0:
            count = min(remaining, MAX_DIGESTS_PER_CHAINED_TABLE)
            name = f"{CHAINED_TABLE_FILE_PREF}{idx}.bin"
            ctx = self._write_digests(name, total - remaining, count)
            if ctx is None:
                return False
            remaining -= count
            if remaining == 0:
                # A single zero byte, so the table size can't be a sector multiple
                if not self._append(name, b"\x00"):
                    return False
                ctx.update(b"\x00")
            contexts.append(ctx)
            idx += 1

        # Step 3: append the hash of table n+1 to table n, and the hash of table 0
        # to DigestsToSign.bin, walking backwards.
        chained_hash = b""
        for i in range(len(contexts) - 1, -1, -1):
            ctx = contexts[i]
            if i < len(contexts) - 1:
                ctx.update(chained_hash)
            chained_hash = ctx.digest()
            if i == 0:
                if not self._append(DIGEST_TABLE_TO_SIGN_FILE, chained_hash):
                    return False
            else:
                if not self._append(f"{CHAINED_TABLE_FILE_PREF}{i - 1}.bin", chained_hash):
                    return False

        self.info(f"VIP: wrote {DIGEST_TABLE_TO_SIGN_FILE} "
                  f"({signed_count} digests) and {chained} chained table(s) to {self.path}")
        return True


class VipTransfer:
    """Sends the signed digest tables and keeps the per-table packet budget.

    send_raw(data) writes raw bytes to the transport, recv_response() reads one
    firehose response (used to confirm each table transfer).
    """

    def __init__(self, path, send_raw, recv_response, loglevel=logging.INFO):
        self.path = path
        self.send_raw = send_raw
        self.recv_response = recv_response
        self.__logger = logging.getLogger("vip")
        self.__logger.setLevel(loglevel)
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.debug = self.__logger.debug
        self.state = VIP_DISABLED
        self.programmer_requires_vip = False
        self._signed = None
        self._chained = []
        self._chained_cur = 0
        self._frames_sent = 0
        self._frames_left = 0
        self._sending_table = False

    def load(self):
        signed = os.path.join(self.path, DIGEST_TABLE_TO_SIGN_FILE_MBN)
        try:
            with open(signed, "rb") as rf:
                self._signed = rf.read()
        except OSError as err:
            self.error(f"Couldn't read the signed VIP table {signed}: {err}")
            return False

        for i in range(MAX_CHAINED_FILES):
            name = os.path.join(self.path, f"{CHAINED_TABLE_FILE_PREF}{i}.bin")
            if not os.path.exists(name):
                break
            try:
                with open(name, "rb") as rf:
                    self._chained.append(rf.read())
            except OSError as err:
                self.error(f"Couldn't read {name}: {err}")
                return False

        self.state = VIP_INIT
        self.info(f"VIP enabled, {len(self._chained)} chained table(s) loaded "
                  f"({len(self._signed)} bytes signed table)")
        return True

    def check_programmer_marker(self, line):
        """Track whether the programmer announced VIP support."""
        if not self.programmer_requires_vip and isinstance(line, str) and VIP_PROGRAMMER_MARKER in line:
            self.programmer_requires_vip = True
            self.info("Programmer requires VIP")

    @property
    def active(self):
        return self.state != VIP_DISABLED

    @property
    def sending_table(self):
        return self._sending_table

    def send_pending_tables(self):
        """Send the signed table or the next chained table if the budget ran out."""
        if self.state == VIP_INIT:
            if not self._send_table(self._signed, "signed table"):
                return False
            self.state = VIP_SEND_DATA
            self._frames_sent = 0
            self._frames_left = MAX_DIGESTS_PER_SIGNED_TABLE
        elif self.state == VIP_SEND_NEXT_TABLE:
            if self._chained_cur >= len(self._chained):
                self.error("VIP: the required quantity of chained tables is missing")
                return False
            if not self._send_table(self._chained[self._chained_cur], f"chained table {self._chained_cur}"):
                return False
            self.state = VIP_SEND_DATA
            self._frames_sent = 0
            self._frames_left = MAX_DIGESTS_PER_CHAINED_TABLE
            self._chained_cur += 1
        else:
            return True

        # The programmer confirms every table transfer
        if not self.recv_response():
            self.error("VIP: sending of the digest table failed")
            return False
        self.info("VIP: digest table sent successfully")
        return True

    def count_packet(self):
        """Account for one packet after its table has been sent."""
        if self.state != VIP_SEND_DATA:
            return
        self._frames_sent += 1
        if self._frames_sent >= self._frames_left:
            self.state = VIP_SEND_NEXT_TABLE

    def _send_table(self, data, name):
        if data is None:
            self.error(f"VIP: no {name} loaded")
            return False
        self._sending_table = True
        try:
            ok = self.send_raw(data)
        finally:
            self._sending_table = False
        if not ok:
            self.error(f"VIP: failed to send the {name}")
            return False
        self.debug(f"VIP: sent the {name} ({len(data)} bytes)")
        return True


class Vip:
    """Facade wiring digest generation and table transfer into a firehose session.

    Only one of the two modes can be active, matching qdl's
    --create-digests / --vip-table-path mutual exclusion.
    """

    def __init__(self, table_path=None, digest_path=None, send_raw=None,
                 recv_response=None, loglevel=logging.INFO, printer=None):
        self.generator = None
        self.transfer = None
        if table_path and digest_path:
            raise ValueError("VIP table generation and VIP transfer can't be enabled together")
        if digest_path:
            self.generator = VipDigestGenerator(digest_path, loglevel=loglevel, printer=printer)
        elif table_path:
            self.transfer = VipTransfer(table_path, send_raw, recv_response, loglevel=loglevel)
            if not self.transfer.load():
                # Without tables the device would reject every packet, so disable the mode
                self.transfer = None

    @property
    def enabled(self):
        return self.generator is not None or self.transfer is not None

    def begin_packet(self, data):
        """Prepare the digest for one outgoing packet and send pending tables."""
        if self.transfer is not None and not self.transfer.send_pending_tables():
            return False
        if self.generator is not None:
            self.generator.chunk_init()
            self.generator.chunk_update(data)
        return True

    def end_packet(self):
        if self.generator is not None:
            self.generator.chunk_store()
        if self.transfer is not None:
            self.transfer.count_packet()

    def check_log(self, line):
        if self.transfer is not None:
            self.transfer.check_programmer_marker(line)

    def finalize(self):
        if self.generator is not None:
            return self.generator.finalize()
        return True

    def close(self):
        if self.generator is not None:
            self.generator.close()
