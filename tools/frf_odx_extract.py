#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Unwrap VAG FRF containers and extract ODX FLASHDATA payload bytes.

This is a read-only container-layer tool. It does not apply ODX encryption or
compression methods. Use ``fpke_datax.py`` for supported Skoda FPK_E/Data_X
decoding; ODX AA decoding requires the same separately supplied inner AES key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from typing import Any


MAX_FRF_BYTES = 512 * 1024 * 1024
MAX_ODX_BYTES = 1024 * 1024 * 1024
MAX_FLASHDATA_BYTES = 512 * 1024 * 1024
MAX_TOTAL_FLASHDATA_BYTES = 1024 * 1024 * 1024
MAX_FLASHDATA_RECORDS = 4096
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decrypt_frf(key_material: bytes, encrypted: bytes) -> bytes:
    """Apply the BSD-2-Clause VW_Flash FRF rolling-XOR algorithm."""
    if not key_material:
        raise ValueError("FRF outer key material is empty")
    output = bytearray(len(encrypted))
    key_index = 0
    first_seed = 0
    second_seed = 1
    for index, byte in enumerate(encrypted):
        key_byte = key_material[key_index]
        first_seed = ((first_seed + key_byte) * 3) & 0xFF
        output[index] = byte ^ (first_seed ^ 0xFF ^ second_seed ^ key_byte)
        second_seed = ((second_seed + 1) * first_seed) & 0xFF
        key_index = (key_index + 1) % len(key_material)
    return bytes(output)


def _read_bounded_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo,
                         limit: int) -> bytes:
    if info.file_size < 0 or info.file_size > limit:
        raise ValueError(f"ZIP member exceeds configured limit: {info.filename!r}")
    if info.flag_bits & 0x1:
        raise ValueError(f"encrypted ZIP members are not supported: {info.filename!r}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        raise ValueError(f"ZIP symlink member is not accepted: {info.filename!r}")
    path = info.filename.replace("\\", "/")
    rel = PurePosixPath(path)
    if not path or rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise ValueError(f"unsafe ZIP member path: {info.filename!r}")
    chunks: list[bytes] = []
    total = 0
    with archive.open(info, "r") as stream:
        while True:
            chunk = stream.read(min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"ZIP member exceeds configured limit: {info.filename!r}")
            chunks.append(chunk)
    if total != info.file_size:
        raise ValueError(f"ZIP member size mismatch: {info.filename!r}")
    return b"".join(chunks)


def unwrap_frf(source: Path, output: Path, key_file: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    key_file = key_file.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"output already exists; choose a new path: {output}")
    if not source.is_file() or source.stat().st_size > MAX_FRF_BYTES:
        raise ValueError("FRF source is not a regular file or exceeds the configured limit")
    key = key_file.read_bytes()
    encrypted = source.read_bytes()
    decrypted = decrypt_frf(key, encrypted)
    if not zipfile.is_zipfile(BytesIO(decrypted)):
        raise ValueError("FRF outer decryption did not produce a ZIP archive")
    with zipfile.ZipFile(BytesIO(decrypted), "r") as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        odx_members = [info for info in members if PurePosixPath(info.filename).suffix.casefold() == ".odx"]
        if len(odx_members) != 1:
            raise ValueError(f"FRF must contain exactly one ODX member; found {len(odx_members)}")
        odx = _read_bounded_member(archive, odx_members[0], MAX_ODX_BYTES)
    output.mkdir(parents=True)
    (output / "unwrapped.odx").write_bytes(odx)
    manifest = {
        "format": "vag-frf-outer-unwrapped-v1",
        "source": {"name": source.name, "bytes": len(encrypted), "sha256": sha256(encrypted)},
        "frf_key": {"required": True, "provided": True, "material": "not included"},
        "decrypted_zip_sha256": sha256(decrypted),
        "selected_member": odx_members[0].filename,
        "odx": {"file": "unwrapped.odx", "bytes": len(odx), "sha256": sha256(odx)},
        "scope": "FRF outer wrapper only; ODX FLASHDATA methods not decoded",
        "upstream_algorithm": "bri3d/VW_Flash frf/decryptfrf.py at 293f46d782bae2ced930497889b71eb782f122cb; BSD-2-Clause",
    }
    (output / "frf_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(element: ET.Element, name: str, default: str = "") -> str:
    for child in element:
        if _local_name(child.tag) == name:
            return (child.text or "").strip()
    return default


def _decode_odx_aa(flashdata: list[dict[str, Any]], data_dir: Path,
                   output: Path, key: bytes, allow_three_byte_terminator: bool) -> dict[str, Any]:
    import fpke_datax

    decoded_root = output / "decoded"
    decoded_root.mkdir()
    decoded_records: list[dict[str, Any]] = []
    seen_partitions: set[int] = set()
    allowed_terminators = (3, 12, 16) if allow_three_byte_terminator else (12, 16)
    for row in flashdata:
        if row["encrypt_compress_method"].casefold() != "aa":
            continue
        segments = [segment for datablock in row["datablocks"] for segment in datablock["segments"]]
        if len(segments) != 1:
            raise ValueError(f"AA record {row['id']!r} must map to exactly one segment")
        try:
            partition_id = int(segments[0]["source_start_address"], 16)
            logical_size = int(segments[0]["uncompressed_size"], 10)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"AA record {row['id']!r} has invalid address/size metadata") from exc
        if not 0 <= partition_id <= 0xFF:
            raise ValueError(f"AA record {row['id']!r} partition id is outside 0..255")
        if partition_id in seen_partitions:
            raise ValueError(f"multiple AA records map to partition {partition_id:#x}")
        seen_partitions.add(partition_id)
        raw_path = data_dir / f"{row['id']}.bin"
        payload = raw_path.read_bytes()
        if len(payload) != row["raw_payload_bytes"] or sha256(payload) != row["raw_payload_sha256"]:
            raise ValueError(f"ODX payload size/hash changed before decode: {row['id']}")
        result = fpke_datax.decode_aa_payload(
            payload, key, expected_partition=partition_id, expected_span=logical_size,
            allowed_terminator_sizes=allowed_terminators,
        )
        partition_dir = decoded_root / f"Partition{partition_id}"
        partition_dir.mkdir()
        stream_path = partition_dir / "decoded_subblock_stream.bin"
        stream_path.write_bytes(result["stream"])
        segments_dir = partition_dir / "segments"
        segments_dir.mkdir()
        record_summaries = []
        for record in result["records"]:
            summary = {name: value for name, value in record.items() if name != "payload"}
            if record["tag"] == fpke_datax.TAG_DATA:
                name = f"record-{record['index']:06d}-offset-{record['relative_offset']:08x}.bin"
                (segments_dir / name).write_bytes(record["payload"])
                summary["segment_file"] = f"segments/{name}"
            record_summaries.append(summary)
        record_manifest = {
            "format": "odx-aa-fpke-sparse-decode-v1",
            "source_record_id": row["id"],
            "source_payload_sha256": row["raw_payload_sha256"],
            "partition_id": partition_id,
            "logical_size": logical_size,
            "stream": {"file": stream_path.name, "bytes": len(result["stream"]),
                       "sha256": result["stream_sha256"], "pad_count": result["pad_count"]},
            "iv_sha256": result["iv_sha256"],
            "terminal_sizes_allowed": list(allowed_terminators),
            "signature_verification": "not performed",
            "records": record_summaries,
        }
        (partition_dir / "manifest.json").write_text(
            json.dumps(record_manifest, indent=2) + "\n", encoding="utf-8"
        )
        decoded_records.append({"partition_id": partition_id,
                                "manifest": f"Partition{partition_id}/manifest.json",
                                "stream_sha256": result["stream_sha256"],
                                "segment_count": sum(r["tag"] == fpke_datax.TAG_DATA for r in result["records"])})
    if not decoded_records:
        raise ValueError("ODX has no method-AA records to decode")
    return {"format": "odx-aa-decode-index-v1", "key": {"required": True, "provided": True,
            "material": "not included"}, "decoder": "fpke_datax.decode_aa_payload",
            "iv": "00..0f (observed direct ODX path)",
            "records": decoded_records}


def extract_odx(source: Path, output: Path, *, decode_aa: bool = False,
                key: bytes | None = None, allow_three_byte_terminator: bool = False) -> dict[str, Any]:
    source = source.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"output already exists; choose a new path: {output}")
    if not source.is_file() or source.stat().st_size > MAX_ODX_BYTES:
        raise ValueError("ODX source is not a regular file or exceeds the configured limit")
    output.mkdir(parents=True)
    data_dir = output / "flashdata"
    data_dir.mkdir()
    flashdata: list[dict[str, Any]] = []
    datablocks: dict[str, list[dict[str, Any]]] = {}
    root_attributes: dict[str, str] = {}
    total_payload_bytes = 0
    try:
        for event, element in ET.iterparse(source, events=("start", "end")):
            tag = _local_name(element.tag)
            if event == "start":
                if tag == "ODX" and not root_attributes:
                    root_attributes = dict(element.attrib)
                continue
            if tag == "FLASHDATA":
                identifier = element.get("ID", "")
                if (len(identifier) > 128 or not SAFE_ID.fullmatch(identifier)
                        or any(row["id"] == identifier for row in flashdata)):
                    raise ValueError(f"unsafe, missing, or duplicate FLASHDATA ID: {identifier!r}")
                if len(flashdata) >= MAX_FLASHDATA_RECORDS:
                    raise ValueError("ODX FLASHDATA record count exceeds configured limit")
                hex_text = _child_text(element, "DATA")
                if len(hex_text) > 2 * MAX_FLASHDATA_BYTES:
                    raise ValueError(f"FLASHDATA {identifier!r} exceeds configured size limit")
                payload = bytes.fromhex(hex_text)
                if len(payload) > MAX_FLASHDATA_BYTES:
                    raise ValueError(f"FLASHDATA {identifier!r} exceeds configured size limit")
                if total_payload_bytes + len(payload) > MAX_TOTAL_FLASHDATA_BYTES:
                    raise ValueError("total ODX FLASHDATA bytes exceed configured output limit")
                total_payload_bytes += len(payload)
                destination = data_dir / f"{identifier}.bin"
                with destination.open("xb") as writer:
                    writer.write(payload)
                flashdata.append({
                    "id": identifier,
                    "short_name": _child_text(element, "SHORT-NAME"),
                    "encrypt_compress_method": _child_text(element, "ENCRYPT-COMPRESS-METHOD"),
                    "raw_payload_file": f"flashdata/{identifier}.bin",
                    "raw_payload_bytes": len(payload),
                    "raw_payload_sha256": sha256(payload),
                })
                element.clear()
            elif tag == "DATABLOCK":
                reference = next((node for node in element.iter() if _local_name(node.tag) == "FLASHDATA-REF"), None)
                flashdata_ref = reference.get("ID-REF", "") if reference is not None else ""
                segments = []
                for node in element.iter():
                    if _local_name(node.tag) == "SEGMENT":
                        values = {_local_name(child.tag): (child.text or "").strip() for child in node}
                        segments.append({"source_start_address": values.get("SOURCE-START-ADDRESS", ""),
                                         "uncompressed_size": values.get("UNCOMPRESSED-SIZE", "")})
                if flashdata_ref:
                    datablocks.setdefault(flashdata_ref, []).append({
                        "id": element.get("ID", ""), "short_name": _child_text(element, "SHORT-NAME"),
                        "segments": segments,
                    })
                element.clear()
        if not flashdata:
            raise ValueError("ODX contains no FLASHDATA records")
        for row in flashdata:
            row["datablocks"] = datablocks.get(row["id"], [])
        aa_manifest = None
        if decode_aa:
            if key is None:
                raise ValueError("ODX AA decoding requires a user-supplied 16-byte AES key")
            aa_manifest = _decode_odx_aa(flashdata, data_dir, output, key, allow_three_byte_terminator)
        manifest = {
            "format": "vag-odx-raw-flashdata-v1",
            "scope": "ODX DATA hex decoded to bytes; encryption/compression method not applied",
            "source": {"name": source.name, "bytes": source.stat().st_size, "sha256": sha256_file(source)},
            "odx_root_attributes": root_attributes,
            "flashdata_count": len(flashdata),
            "flashdata": flashdata,
        }
        if aa_manifest is not None:
            manifest["aa_decode"] = aa_manifest
        (output / "odx_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest
    except Exception as exc:
        (output / "FREEZE_LEDGER.md").write_text(
            "# Frozen partial ODX extraction\n\n"
            f"Source: `{source.name}`\n\nFailure: `{type(exc).__name__}: {exc}`\n\n"
            "Partial output is retained; choose a new output path for another run.\n",
            encoding="utf-8",
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    frf = sub.add_parser("frf", help="decrypt the FRF outer wrapper and retain its single ODX member")
    frf.add_argument("--source", required=True, type=Path)
    frf.add_argument("--output", required=True, type=Path)
    frf.add_argument("--frf-key-file", required=True, type=Path,
                      help="VW_Flash-compatible FRF outer key material (separate from the inner AES key)")
    odx = sub.add_parser("odx", help="extract ODX FLASHDATA bytes, optionally decoding supported AA records")
    odx.add_argument("--source", required=True, type=Path)
    odx.add_argument("--output", required=True, type=Path)
    odx.add_argument("--decode-aa", action="store_true",
                     help="also decode supported AA records using the required inner AES-128 key")
    key_group = odx.add_mutually_exclusive_group()
    key_group.add_argument("--key-file", type=Path, help="raw 16-byte or 32-hex-digit AES key file")
    key_group.add_argument("--key-env", help="environment variable containing exactly 32 AES key hex digits")
    odx.add_argument("--allow-three-byte-ff-terminator", action="store_true",
                     help="also accept the observed three-FF ODX terminal variant")
    args = parser.parse_args()
    try:
        if args.command == "frf":
            result = unwrap_frf(args.source, args.output, args.frf_key_file)
        else:
            if args.decode_aa:
                import fpke_datax
                key = fpke_datax.load_aes128_key(key_file=args.key_file, key_env=args.key_env)
            elif args.key_file is not None or args.key_env is not None:
                raise ValueError("--key-file/--key-env require --decode-aa")
            else:
                key = None
            if args.allow_three_byte_ff_terminator and not args.decode_aa:
                raise ValueError("--allow-three-byte-ff-terminator requires --decode-aa")
            result = extract_odx(args.source, args.output, decode_aa=args.decode_aa, key=key,
                                 allow_three_byte_terminator=args.allow_three_byte_ff_terminator)
        print(json.dumps({"status": "PASS", "output": str(args.output.resolve()),
                          "flashdata_count": result.get("flashdata_count")}, indent=2))
        return 0
    except Exception as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
