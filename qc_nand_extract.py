#!/usr/bin/env python3
"""Extract Qualcomm MIBIB partitions and UBI volumes from a NAND dump.

The older Qualcomm NAND layout used by MDM9x07 stores the MIBIB partition
table in 128 KiB erase-block units.  This tool handles the data-only dumps
produced by Qualcomm tools and can also read conventional page+OOB dumps.

Examples::

    ./qc_nand_extract.py flash.bin -o flash-extracted
    ./qc_nand_extract.py flash.bin --list
    ./qc_nand_extract.py raw-nand.bin --oob-size 64 -o extracted

Raw partition files are always copied exactly as logical NAND data.  When a
partition contains UBI, the tool additionally writes logical UBI volume data
with UBI headers removed.  A volume is named ``*.ubifs`` only when its data
starts with the UBIFS superblock magic; otherwise it is named ``*.volume``.
"""

from __future__ import annotations

import argparse
import json
import mmap
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple


MIB_MAGIC = b"\xaa\x73\xee\x55\xdb\xbd\x5e\xe3"
UBI_EC_MAGIC = b"UBI#"
UBI_VID_MAGIC = b"UBI!"
UBIFS_MAGIC = b"UBIFS#"
UBI_LAYOUT_IDS = {0x7FFFEFFF, 0x7FFFFFFF, 0x7FFFFFFE}  # Qualcomm and upstream UBI values
VTBL_RECORD_SIZE = 172
VTBL_MAX_VOLUMES = 128


@dataclass
class Partition:
    name: str
    start_block: int
    block_count: int
    attr1: int
    attr2: int
    attr3: int
    which_flash: int
    table_offset: int = 0

    @property
    def start(self) -> int:
        return self.start_block * self._eraseblock_size

    @property
    def end(self) -> int:
        return (self.start_block + self.block_count) * self._eraseblock_size

    # Set by parse_partitions; keeping the table fields in eraseblock units
    # avoids silently treating them as byte offsets.
    _eraseblock_size: int = field(default=0, repr=False, compare=False)


@dataclass
class VTBLRecord:
    volume_id: int
    name: str
    reserved_pebs: int
    alignment: int
    data_pad: int
    vol_type: int
    upd_marker: int
    flags: int


@dataclass
class UBIPEB:
    offset: int
    erase_counter: int
    vid_offset: int
    data_offset: int
    vol_id: int
    lnum: int
    data_size: int
    used_ebs: int
    data_pad: int
    sqnum: int


class ImageReader:
    """Map logical NAND data onto either a data-only or page+OOB image."""

    def __init__(self, path: Path, mode: str, page_size: int, oob_size: int):
        self.path = path
        self.mode = mode
        self.page_size = page_size
        self.oob_size = oob_size
        self.page_stride = page_size + oob_size
        self.handle = path.open("rb")
        self.mm = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)
        self.file_size = len(self.mm)

    @property
    def logical_size(self) -> int:
        if self.mode == "data":
            return self.file_size
        pages = self.file_size // self.page_stride
        return pages * self.page_size

    def close(self) -> None:
        self.mm.close()
        self.handle.close()

    def physical_to_logical(self, physical: int) -> Optional[int]:
        if self.mode == "data":
            return physical
        page, within = divmod(physical, self.page_stride)
        if within >= self.page_size:
            return None
        return page * self.page_size + within

    def read_logical(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.logical_size:
            raise ValueError(
                f"logical read outside image: offset=0x{offset:x}, size=0x{size:x}"
            )
        if self.mode == "data":
            return self.mm[offset : offset + size]

        result = bytearray()
        while size:
            page, within = divmod(offset, self.page_size)
            take = min(size, self.page_size - within)
            physical = page * self.page_stride + within
            result.extend(self.mm[physical : physical + take])
            offset += take
            size -= take
        return bytes(result)

    def iter_logical(self, offset: int, size: int, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        while size:
            take = min(size, chunk_size)
            yield self.read_logical(offset, take)
            offset += take
            size -= take


def _safe_name(name: str) -> str:
    name = name.strip().replace("/", "_").replace("\\", "_")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    return name or "unnamed"


def _decode_name(raw: bytes) -> Optional[str]:
    raw = raw.split(b"\0", 1)[0]
    if len(raw) < 2 or raw[:2] != b"0:":
        return None
    try:
        name = raw[2:].decode("ascii")
    except UnicodeDecodeError:
        return None
    return name if name else None


def parse_mib_at(reader: ImageReader, offset: int, eraseblock_size: int) -> Optional[Tuple[List[Partition], int]]:
    """Parse and validate one candidate MIBIB table at a logical offset."""
    try:
        header = reader.read_logical(offset, 16)
        magic1, magic2, version, count = struct.unpack("<IIII", header)
    except (ValueError, struct.error):
        return None
    if (magic1, magic2) != (0x55EE73AA, 0xE35EBDDB):
        return None
    if not 1 <= count <= 128 or version > 0x100:
        return None
    try:
        table = reader.read_logical(offset + 16, count * 0x1C)
    except ValueError:
        return None

    parts: List[Partition] = []
    previous_end = 0
    for index in range(count):
        entry = table[index * 0x1C : (index + 1) * 0x1C]
        try:
            raw_name, start, length, attr1, attr2, attr3, which_flash = struct.unpack(
                "<16sIIBBBB", entry
            )
        except struct.error:
            return None
        name = _decode_name(raw_name)
        if name is None or length == 0:
            return None
        # Qualcomm MIBIB tables normally describe a contiguous device.  Do
        # not require contiguity, but reject implausible overlapping entries.
        if start < previous_end:
            return None
        previous_end = start + length
        parts.append(
            Partition(name, start, length, attr1, attr2, attr3, which_flash, offset, eraseblock_size)
        )
    if previous_end * eraseblock_size > reader.logical_size:
        return None
    return parts, version


def find_mib(reader: ImageReader, eraseblock_size: int, requested_offset: Optional[int] = None) -> Tuple[int, List[Partition], int]:
    if requested_offset is not None:
        parsed = parse_mib_at(reader, requested_offset, eraseblock_size)
        if parsed is None:
            raise ValueError(f"no valid MIBIB table at 0x{requested_offset:x}")
        parts, version = parsed
        return requested_offset, parts, version

    position = 0
    while True:
        position = reader.mm.find(MIB_MAGIC, position)
        if position < 0:
            break
        logical = reader.physical_to_logical(position)
        if logical is not None:
            parsed = parse_mib_at(reader, logical, eraseblock_size)
            if parsed is not None:
                parts, version = parsed
                return logical, parts, version
        position += 1
    raise ValueError("could not find a valid Qualcomm MIBIB table")


def layout_candidates(args: argparse.Namespace) -> Iterable[Tuple[str, int, int]]:
    if args.layout == "data":
        yield "data", args.page_size, 0
        return
    if args.oob_size is not None:
        yield "raw", args.page_size, args.oob_size
        return
    if args.layout == "raw":
        raise ValueError("--layout raw requires --oob-size")

    # Data-only is the common Qualcomm EDL output.  The remaining candidates
    # cover common 2 KiB/4 KiB NAND OOB layouts for conventional raw dumps.
    yield "data", args.page_size, 0
    for page_size in (args.page_size, 4096 if args.page_size == 2048 else 2048):
        for oob_size in (64, 128, 224, 256):
            yield "raw", page_size, oob_size


def open_and_find(args: argparse.Namespace) -> Tuple[ImageReader, int, List[Partition], int]:
    errors = []
    seen = set()
    for mode, page_size, oob_size in layout_candidates(args):
        key = (mode, page_size, oob_size)
        if key in seen:
            continue
        seen.add(key)
        reader = ImageReader(args.input, mode, page_size, oob_size)
        try:
            found = find_mib(reader, args.eraseblock_size, args.mib_offset)
            return reader, found[0], found[1], found[2]
        except ValueError as exc:
            errors.append(f"{mode}/page={page_size}/oob={oob_size}: {exc}")
            reader.close()
    raise ValueError("; ".join(errors))


def parse_ec(reader: ImageReader, offset: int, eraseblock_size: int) -> Optional[Tuple[int, int, int, int, int, int]]:
    try:
        header = reader.read_logical(offset, 64)
        if header[:4] != UBI_EC_MAGIC or header[4] not in (1,):
            return None
        ec, vid_offset, data_offset, image_seq = struct.unpack_from(">QIII", header, 8)
    except (ValueError, struct.error):
        return None
    if not (reader.page_size <= vid_offset < data_offset < eraseblock_size):
        return None
    if data_offset + 64 > eraseblock_size:
        return None
    return ec, vid_offset, data_offset, image_seq, header[5], struct.unpack_from(">I", header, 60)[0]


def parse_vid(
    reader: ImageReader,
    peb_offset: int,
    ec_info: Tuple[int, int, int, int, int, int],
    eraseblock_size: int,
) -> Optional[UBIPEB]:
    ec, vid_offset, data_offset, _image_seq, _compat, _ec_crc = ec_info
    try:
        header = reader.read_logical(peb_offset + vid_offset, 64)
        if header[:4] != UBI_VID_MAGIC or header[4] != 1:
            return None
        vol_id, lnum, data_size, used_ebs, data_pad = struct.unpack_from(">IIIII", header, 8)
        sqnum = struct.unpack_from(">Q", header, 32)[0]
    except (ValueError, struct.error):
        return None
    if vol_id == 0xFFFFFFFF or lnum == 0xFFFFFFFF:
        return None
    leb_size = eraseblock_size - data_offset
    if data_size > leb_size or data_pad > leb_size:
        return None
    return UBIPEB(peb_offset, ec, vid_offset, data_offset, vol_id, lnum, data_size, used_ebs, data_pad, sqnum)


def scan_ubi(reader: ImageReader, partition: Partition) -> List[UBIPEB]:
    pebs: List[UBIPEB] = []
    for offset in range(partition.start, partition.end, partition._eraseblock_size):
        ec = parse_ec(reader, offset, partition._eraseblock_size)
        if ec is None:
            continue
        peb = parse_vid(reader, offset, ec, partition._eraseblock_size)
        if peb is not None:
            pebs.append(peb)
    return pebs


def parse_vtbl(reader: ImageReader, pebs: List[UBIPEB]) -> Dict[int, VTBLRecord]:
    layout = [peb for peb in pebs if peb.vol_id in UBI_LAYOUT_IDS]
    for peb in sorted(layout, key=lambda item: (item.lnum, -item.sqnum)):
        try:
            data = reader.read_logical(
                peb.offset + peb.data_offset, VTBL_RECORD_SIZE * VTBL_MAX_VOLUMES
            )
        except ValueError:
            continue
        records: Dict[int, VTBLRecord] = {}
        for volume_id in range(VTBL_MAX_VOLUMES):
            record = data[volume_id * VTBL_RECORD_SIZE : (volume_id + 1) * VTBL_RECORD_SIZE]
            reserved, alignment, data_pad, vol_type, marker, name_len = struct.unpack_from(
                ">IIIBBH", record, 0
            )
            if name_len == 0 or name_len > 127:
                continue
            raw_name = record[16 : 16 + name_len]
            try:
                name = raw_name.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not name or any(ord(char) < 0x20 for char in name):
                continue
            flags = struct.unpack_from(">I", record, 144)[0]
            records[volume_id] = VTBLRecord(
                volume_id, name, reserved, alignment, data_pad, vol_type, marker, flags
            )
        if records:
            return records
    return {}


def group_volumes(pebs: List[UBIPEB]) -> Dict[int, List[UBIPEB]]:
    grouped: Dict[int, Dict[int, UBIPEB]] = {}
    for peb in pebs:
        if peb.vol_id in UBI_LAYOUT_IDS:
            continue
        by_lnum = grouped.setdefault(peb.vol_id, {})
        old = by_lnum.get(peb.lnum)
        if old is None or peb.sqnum >= old.sqnum:
            by_lnum[peb.lnum] = peb
    return {vol_id: sorted(rows.values(), key=lambda item: item.lnum) for vol_id, rows in grouped.items()}


def write_partition(reader: ImageReader, partition: Partition, destination: Path) -> None:
    with destination.open("wb") as output:
        for chunk in reader.iter_logical(partition.start, partition.block_count * partition._eraseblock_size):
            output.write(chunk)


def write_volume(
    reader: ImageReader,
    pebs: List[UBIPEB],
    record: Optional[VTBLRecord],
    destination: Path,
    eraseblock_size: int,
) -> Dict[str, object]:
    if not pebs:
        raise ValueError("empty UBI volume")
    data_offset = pebs[0].data_offset
    leb_size = eraseblock_size - data_offset
    volume_pebs = record.reserved_pebs if record and record.reserved_pebs else max(p.lnum for p in pebs) + 1
    volume_pebs = max(volume_pebs, max(p.lnum for p in pebs) + 1)
    blank = b"\xff" * min(1024 * 1024, leb_size)
    by_lnum = {peb.lnum: peb for peb in pebs}
    with destination.open("wb") as output:
        for lnum in range(volume_pebs):
            peb = by_lnum.get(lnum)
            if peb is None:
                remaining = leb_size
                while remaining:
                    chunk = blank[: min(remaining, len(blank))]
                    output.write(chunk)
                    remaining -= len(chunk)
                continue
            remaining = leb_size
            source = peb.offset + peb.data_offset
            while remaining:
                take = min(remaining, 1024 * 1024)
                output.write(reader.read_logical(source, take))
                source += take
                remaining -= take
    try:
        magic = reader.read_logical(pebs[0].offset + data_offset, 6)
    except ValueError:
        magic = b""
    return {
        "volume_id": pebs[0].vol_id,
        "name": record.name if record else f"vol-{pebs[0].vol_id}",
        "pebs_present": len(pebs),
        "pebs_output": volume_pebs,
        "leb_size": leb_size,
        "data_offset": data_offset,
        "ubifs": magic == UBIFS_MAGIC,
    }


def ubi_metadata(reader: ImageReader, partition: Partition, pebs: List[UBIPEB], records: Dict[int, VTBLRecord]) -> Dict[str, object]:
    volumes = group_volumes(pebs)
    return {
        "partition": partition.name,
        "start": partition.start,
        "end": partition.end,
        "eraseblock_size": partition._eraseblock_size,
        "pebs": len(pebs),
        "volumes": [
            {
                "volume_id": volume_id,
                "name": records[volume_id].name if volume_id in records else f"vol-{volume_id}",
                "pebs_present": len(items),
                "lnum_min": min(item.lnum for item in items),
                "lnum_max": max(item.lnum for item in items),
            }
            for volume_id, items in sorted(volumes.items())
        ],
    }


def print_listing(reader: ImageReader, table_offset: int, version: int, partitions: List[Partition]) -> None:
    print(f"Input: {reader.path} ({reader.file_size} bytes)")
    layout = "data-only" if reader.mode == "data" else f"page+OOB (page={reader.page_size}, oob={reader.oob_size})"
    print(f"Layout: {layout}; logical size={reader.logical_size}; eraseblock={partitions[0]._eraseblock_size}")
    print(f"MIBIB: offset=0x{table_offset:x}, version={version}, partitions={len(partitions)}")
    print("NAME                 START       SIZE        BLOCKS")
    for partition in partitions:
        print(f"{partition.name:<20} 0x{partition.start:08x} 0x{partition.end - partition.start:08x} {partition.block_count}")
    for partition in partitions:
        pebs = scan_ubi(reader, partition)
        if not pebs:
            continue
        records = parse_vtbl(reader, pebs)
        volumes = group_volumes(pebs)
        print(f"UBI {partition.name}: {len(pebs)} VID headers")
        for volume_id, items in sorted(volumes.items()):
            name = records[volume_id].name if volume_id in records else f"vol-{volume_id}"
            print(f"  {name} (id={volume_id}, PEBs={len(items)}, LEBs={min(x.lnum for x in items)}..{max(x.lnum for x in items)})")


def extract(args: argparse.Namespace) -> int:
    reader, table_offset, partitions, version = open_and_find(args)
    try:
        for partition in partitions:
            if args.partitions and partition.name.lower() not in args.partitions:
                continue
            if args.list:
                continue
        if args.list:
            print_listing(reader, table_offset, version, partitions)
            return 0

        output = args.output
        output.mkdir(parents=True, exist_ok=True)
        selected = [p for p in partitions if not args.partitions or p.name.lower() in args.partitions]
        table_json = {
            "input": str(args.input),
            "layout": reader.mode,
            "page_size": reader.page_size,
            "oob_size": reader.oob_size,
            "logical_size": reader.logical_size,
            "eraseblock_size": args.eraseblock_size,
            "mibib_offset": table_offset,
            "version": version,
            "partitions": [
                {
                    "name": p.name,
                    "start_block": p.start_block,
                    "block_count": p.block_count,
                    "start": p.start,
                    "size": p.end - p.start,
                    "attr1": p.attr1,
                    "attr2": p.attr2,
                    "attr3": p.attr3,
                    "which_flash": p.which_flash,
                }
                for p in partitions
            ],
        }
        (output / "mibib.json").write_text(json.dumps(table_json, indent=2) + "\n", encoding="utf-8")

        for partition in selected:
            filename = output / f"{_safe_name(partition.name)}.bin"
            write_partition(reader, partition, filename)
            print(f"{partition.name}: {filename} ({partition.end - partition.start} bytes)")
            if args.no_ubi:
                continue
            pebs = scan_ubi(reader, partition)
            if not pebs:
                continue
            records = parse_vtbl(reader, pebs)
            volumes = group_volumes(pebs)
            ubi_dir = output / "ubi" / _safe_name(partition.name)
            ubi_dir.mkdir(parents=True, exist_ok=True)
            metadata = ubi_metadata(reader, partition, pebs, records)
            volume_metadata = []
            for volume_id, items in sorted(volumes.items()):
                record = records.get(volume_id)
                name = record.name if record else f"vol-{volume_id}"
                # The extension is corrected after inspecting the first LEB.
                temporary = ubi_dir / f"{_safe_name(name)}.volume"
                info = write_volume(reader, items, record, temporary, partition._eraseblock_size)
                if info["ubifs"]:
                    final = temporary.with_suffix(".ubifs")
                    temporary.replace(final)
                    info["file"] = str(final.relative_to(output))
                else:
                    info["file"] = str(temporary.relative_to(output))
                volume_metadata.append(info)
                print(f"  UBI volume {name}: {info['file']} ({info['pebs_present']} PEBs)")
            metadata["volumes"] = volume_metadata
            (ubi_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote extraction metadata: {output / 'mibib.json'}")
        return 0
    finally:
        reader.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, nargs="?", default=Path("flash.bin"), help="NAND dump (default: flash.bin)")
    parser.add_argument("-o", "--output", type=Path, default=Path("flash-extracted"), help="output directory")
    parser.add_argument("--list", action="store_true", help="list MIBIB partitions and detected UBI volumes without writing files")
    parser.add_argument("-p", "--partitions", help="comma-separated partition names to extract")
    parser.add_argument("--no-ubi", action="store_true", help="do not scan UBI or write logical UBI volumes")
    parser.add_argument("--layout", choices=("auto", "data", "raw"), default="auto", help="input layout (default: auto)")
    parser.add_argument("--page-size", type=int, default=2048, help="NAND page size for raw layouts (default: 2048)")
    parser.add_argument("--oob-size", type=int, help="OOB bytes per page; selects page+OOB input")
    parser.add_argument("--eraseblock-size", type=int, default=128 * 1024, help="logical eraseblock size (default: 131072)")
    parser.add_argument("--mib-offset", type=lambda value: int(value, 0), help="logical MIBIB table offset, e.g. 0x140800")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    if args.eraseblock_size <= 0 or args.page_size <= 0 or (args.oob_size is not None and args.oob_size < 0):
        parser.error("page, OOB, and eraseblock sizes must be non-negative, with page/eraseblock sizes non-zero")
    args.partitions = {item.strip().lower() for item in args.partitions.split(",")} if args.partitions else None
    try:
        return extract(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
