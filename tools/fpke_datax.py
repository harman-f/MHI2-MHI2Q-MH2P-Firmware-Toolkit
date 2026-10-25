#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only FPKE version-3 container unpacker.

This tool decrypts the observed AA/1A payload streams and writes decoded stream
bytes plus a manifest and individual tag-09 sparse payloads. It does not verify
signatures, construct a flash image, encrypt, sign, or rebuild containers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import zlib


MAGIC = b"ZZZZ"
TRAILER = bytes.fromhex("a5a5a5a500000001")
HEADER_END = 0x180
PREFIX_OFFSET = 0x180
PREFIX_LENGTH = 16
PAYLOAD_OFFSET = 0x190
DESCRIPTOR_OFFSETS = (0x20, 0xD0)
DESCRIPTOR_FIELDS_SIZE = 0x30
SIGNATURE_SIZE = 0x80
PREFIX_ID = 0xF0000000
AA = 0xAA
METHOD_1A = 0x1A
TAG_DATA = 0x09
TAG_END = 0xFF
DATA_MAGIC = 0xF11EF11E
DEFAULT_MAX_SOURCE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_DECODED_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_RECORDS = 100_000
HEX_AES128_KEY = re.compile(r"^[0-9A-Fa-f]{32}$")
DEFAULT_AA_IV = bytes(range(16))
DEFAULT_TERMINATOR_SIZES = (12, 16)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def crc32_fpke(data: bytes, init: int = 0) -> int:
    """Reflected CRC-32 with the observed zero initial state and xorout."""
    if not 0 <= init <= 0xFFFFFFFF:
        raise ValueError("CRC initial value must be an unsigned 32-bit integer")
    return (zlib.crc32(data, init ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _be32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def _descriptor(raw: bytes, offset: int, expected_index: int) -> dict:
    if offset + DESCRIPTOR_FIELDS_SIZE > HEADER_END:
        raise ValueError("Descriptor fields exceed the fixed header")
    if raw[offset:offset + 4] != MAGIC:
        raise ValueError(f"Descriptor {expected_index} has invalid marker")

    index = _be32(raw, offset + 4)
    object_id = _be32(raw, offset + 8)
    version = _be32(raw, offset + 12)
    version_bytes = raw[offset + 12:offset + 16]
    try:
        version_ascii = version_bytes.decode("ascii")
    except UnicodeDecodeError:
        version_ascii = None
    if (version_ascii is not None
            and (len(version_ascii) != 4 or not version_ascii.isdecimal())):
        version_ascii = None
    method = _be32(raw, offset + 16)
    logical_size = _be32(raw, offset + 20)
    stored_size = _be32(raw, offset + 24)
    reserved = _be32(raw, offset + 28)
    stored_offset = _be32(raw, offset + 32)
    stored_length = _be32(raw, offset + 36)
    crc_field = _be32(raw, offset + 40)
    signature_length = _be32(raw, offset + 44)

    if index != expected_index:
        raise ValueError(f"Descriptor sequence mismatch at {offset:#x}")
    if stored_size != stored_length:
        raise ValueError(f"Descriptor {index} stored size/length disagree")
    if signature_length != SIGNATURE_SIZE:
        raise ValueError(f"Descriptor {index} has unsupported signature-area size")
    descriptor_end = offset + DESCRIPTOR_FIELDS_SIZE + signature_length
    if descriptor_end > HEADER_END:
        raise ValueError(f"Descriptor {index} exceeds the header boundary")
    signature = raw[offset + DESCRIPTOR_FIELDS_SIZE:descriptor_end]

    return {
        "index": index,
        "id": object_id,
        "version_field": version,
        "version_ascii": version_ascii,
        "method": method,
        "logical_size": logical_size,
        "stored_size": stored_size,
        "reserved": reserved,
        "stored_offset": stored_offset,
        "stored_length": stored_length,
        "crc_field": crc_field,
        "signature_area_size": signature_length,
        "signature_area_sha256": _sha256(signature),
        "descriptor_offset": offset,
    }


def parse_container(raw: bytes, max_source: int = DEFAULT_MAX_SOURCE_BYTES) -> dict:
    """Validate a canonical version-3 container and return its stored objects."""
    if not isinstance(raw, bytes):
        raise ValueError("Container input must be bytes")
    if len(raw) > max_source:
        raise ValueError(f"Container exceeds source limit ({max_source} bytes)")
    if len(raw) < HEADER_END + PREFIX_LENGTH + len(TRAILER):
        raise ValueError("Container is too short")
    if raw[:4] != MAGIC:
        raise ValueError("Invalid global marker")
    if _be32(raw, 4) != HEADER_END:
        raise ValueError("Unsupported header boundary")
    if _be32(raw, 8) != 3:
        raise ValueError("Only canonical version-3 containers are supported")
    if _be32(raw, 12) != 2:
        raise ValueError("Expected exactly two descriptors")

    descriptors = [
        _descriptor(raw, offset, index)
        for index, offset in enumerate(DESCRIPTOR_OFFSETS)
    ]
    prefix_desc, payload_desc = descriptors
    if prefix_desc["id"] != PREFIX_ID or prefix_desc["method"] != 0:
        raise ValueError("Descriptor 0 is not the expected method-0 prefix object")
    if (prefix_desc["logical_size"] != PREFIX_LENGTH
            or prefix_desc["stored_size"] != PREFIX_LENGTH
            or prefix_desc["stored_offset"] != PREFIX_OFFSET
            or prefix_desc["stored_length"] != PREFIX_LENGTH):
        raise ValueError("Descriptor 0 prefix dimensions disagree")
    expected_payload_version = "1055" if payload_desc["id"] == 0 else "1703"
    if (payload_desc["id"] > 0xFF
            or payload_desc["method"] not in (AA, METHOD_1A)
            or payload_desc["version_ascii"] != expected_payload_version
            or payload_desc["logical_size"] == 0):
        raise ValueError("Descriptor 1 has unsupported id, method, or logical size")
    if payload_desc["stored_offset"] != PAYLOAD_OFFSET:
        raise ValueError("Descriptor 1 payload pointer is not the canonical 0x190")
    if payload_desc["stored_size"] == 0 or payload_desc["stored_size"] % 16:
        raise ValueError("AES-CBC payload length must be nonzero and 16-byte aligned")

    trailer_start = len(raw) - len(TRAILER)
    ranges = []
    for desc in descriptors:
        start = desc["stored_offset"]
        end = start + desc["stored_length"]
        if start < HEADER_END or end < start or end > trailer_start:
            raise ValueError(f"Descriptor {desc['index']} object is out of bounds")
        ranges.append((start, end, desc["index"]))
    ranges.sort()
    if ranges[0][0] != HEADER_END or ranges[0][1] != PAYLOAD_OFFSET:
        raise ValueError("Prefix object does not immediately follow the header")
    if ranges[1][0] != PAYLOAD_OFFSET or ranges[1][1] != trailer_start:
        raise ValueError("Payload object does not end at the fixed trailer")
    if ranges[0][1] > ranges[1][0]:
        raise ValueError("Stored object ranges overlap")
    if raw[-len(TRAILER):] != TRAILER:
        raise ValueError("Invalid container trailer")

    prefix = raw[PREFIX_OFFSET:PAYLOAD_OFFSET]
    payload = raw[PAYLOAD_OFFSET:trailer_start]
    if len(prefix) != prefix_desc["stored_length"]:
        raise ValueError("Prefix length disagrees with descriptor")
    if len(payload) != payload_desc["stored_length"]:
        raise ValueError("Payload length disagrees with descriptor")
    prefix_crc = crc32_fpke(prefix)
    if prefix_crc != prefix_desc["crc_field"]:
        raise ValueError("Prefix CRC-32 does not match descriptor 0")

    partition_id = payload_desc["id"]
    if raw[0x10:0x14] != struct.pack(">I", 0x10000581):
        raise ValueError("Unexpected global project identifier")

    return {
        "source_size": len(raw),
        "source_sha256": _sha256(raw),
        "format_version": 3,
        "header_end": HEADER_END,
        "global_project_id": _be32(raw, 0x10),
        "partition_id": partition_id,
        "version_ascii": payload_desc["version_ascii"],
        "method": payload_desc["method"],
        "logical_size": payload_desc["logical_size"],
        "stored_size": payload_desc["stored_size"],
        "prefix": prefix,
        "prefix_sha256": _sha256(prefix),
        "prefix_crc32_fpke": prefix_crc,
        "payload": payload,
        "payload_sha256": _sha256(payload),
        "trailer": raw[-len(TRAILER):],
        "descriptors": descriptors,
    }


def decompress_lzss(src: bytes, max_output: int = DEFAULT_MAX_DECODED_BYTES) -> bytes:
    """Decode the observed AA LZSS stream with a strict output bound."""
    if not isinstance(src, bytes):
        raise ValueError("LZSS input must be bytes")
    if max_output < 0:
        raise ValueError("LZSS output limit must be nonnegative")
    window = bytearray(4096)
    write_pos = 0xFEE
    out = bytearray()
    pos = 0

    while pos < len(src):
        flags = src[pos]
        pos += 1
        if pos >= len(src):
            raise ValueError("LZSS flags byte has no tokens")
        for bit in range(8):
            if pos >= len(src):
                break
            if (flags >> bit) & 1:
                if len(out) >= max_output:
                    raise ValueError("LZSS decoded output exceeds configured limit")
                value = src[pos]
                pos += 1
                out.append(value)
                window[write_pos] = value
                write_pos = (write_pos + 1) & 0xFFF
            else:
                if len(src) - pos < 2:
                    raise ValueError("Truncated LZSS back-reference")
                b0, b1 = src[pos], src[pos + 1]
                pos += 2
                ref_pos = ((b1 & 0xF0) << 4) | b0
                length = (b1 & 0x0F) + 3
                if len(out) + length > max_output:
                    raise ValueError("LZSS decoded output exceeds configured limit")
                for k in range(length):
                    value = window[(ref_pos + k) & 0xFFF]
                    out.append(value)
                    window[write_pos] = value
                    write_pos = (write_pos + 1) & 0xFFF
    return bytes(out)


def _decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 16:
        raise ValueError("AES key must be exactly 16 bytes")
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("AES IV must be exactly 16 bytes")
    if not ciphertext or len(ciphertext) % 16:
        raise ValueError("AES-CBC ciphertext must be nonempty and 16-byte aligned")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise RuntimeError("The cryptography package is required for AES-CBC") from exc
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decode_container(
    raw: bytes,
    key: bytes,
    max_output: int = DEFAULT_MAX_DECODED_BYTES,
    max_source: int = DEFAULT_MAX_SOURCE_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
) -> dict:
    """Decrypt a version-3 AA or 1A payload and return the decoded stream."""
    if max_output < 0:
        raise ValueError("Decoded output limit must be nonnegative")
    parsed = parse_container(raw, max_source=max_source)
    plaintext = _decrypt_cbc(parsed["payload"], key, parsed["prefix"])
    if parsed["method"] == AA:
        aa_result = _decode_aa_plaintext(
            plaintext,
            parsed["partition_id"],
            parsed["logical_size"],
            max_output=max_output,
            max_records=max_records,
            allowed_terminator_sizes=DEFAULT_TERMINATOR_SIZES,
        )
        stream = aa_result["stream"]
        pad_prefix_size = aa_result["pad_count"] + 1
    elif parsed["method"] == METHOD_1A:
        if len(plaintext) > max_output:
            raise ValueError("1A decoded output exceeds configured limit")
        stream = plaintext
        pad_prefix_size = 0
    else:  # parse_container already constrains this, retain a defensive gate.
        raise ValueError(f"Unsupported method {parsed['method']:#x}")

    result = dict(parsed)
    result.update({
        "stream": stream,
        "stream_size": len(stream),
        "stream_sha256": _sha256(stream),
        "decrypted_plaintext_size": len(plaintext),
        "aa_padding_prefix_size": pad_prefix_size,
    })
    if parsed["method"] == AA:
        result["records"] = aa_result["records"]
    return result


def _decode_aa_plaintext(
    plaintext: bytes,
    partition_id: int,
    logical_size: int,
    *,
    max_output: int,
    max_records: int,
    allowed_terminator_sizes: tuple[int, ...],
) -> dict:
    """Decode and validate one already AES-decrypted AA payload."""
    if not plaintext:
        raise ValueError("AA plaintext is empty")
    pad_count = plaintext[0]
    if pad_count > 15:
        raise ValueError("AA prefix pad count is outside 0..15")
    pad_end = 1 + pad_count
    if pad_end > len(plaintext) or plaintext[1:pad_end] != bytes(pad_count):
        raise ValueError("AA prefix padding is truncated or nonzero")
    stream = decompress_lzss(plaintext[pad_end:], max_output=max_output)
    records = parse_subblocks(
        stream,
        partition_id,
        logical_size,
        max_records=max_records,
        allowed_terminator_sizes=allowed_terminator_sizes,
    )
    return {
        "stream": stream,
        "stream_size": len(stream),
        "stream_sha256": _sha256(stream),
        "pad_count": pad_count,
        "records": records,
    }


def decode_aa_payload(
    ciphertext: bytes,
    key: bytes,
    expected_partition: int | None = None,
    expected_span: int | None = None,
    *,
    iv: bytes = DEFAULT_AA_IV,
    max_output: int = DEFAULT_MAX_DECODED_BYTES,
    max_source: int = DEFAULT_MAX_SOURCE_BYTES,
    max_records: int = DEFAULT_MAX_RECORDS,
    allowed_terminator_sizes: tuple[int, ...] = DEFAULT_TERMINATOR_SIZES,
) -> dict:
    """Decode direct ODX AA ciphertext without an FPK_E Data_X wrapper.

    The default IV 00..0f is the observed value for the supported direct ODX
    sample path. Supply a separately established 16-byte IV for other data.
    When the caller supplies partition/span metadata, both are validated
    against every sparse record. If omitted, the partition id and minimum span
    are inferred from the validated stream and returned in the result.
    """
    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise ValueError("AA ciphertext must be nonempty bytes")
    if max_source <= 0 or max_output < 0 or max_records <= 0:
        raise ValueError("AA source/output/record limits must be positive (output may be zero)")
    if len(ciphertext) > max_source:
        raise ValueError("AA ciphertext exceeds configured source limit")
    plaintext = _decrypt_cbc(ciphertext, key, iv)
    if not plaintext:
        raise ValueError("AA plaintext is empty")
    pad_count = plaintext[0]
    if pad_count > 15:
        raise ValueError("AA prefix pad count is outside 0..15")
    pad_end = 1 + pad_count
    if pad_end > len(plaintext) or plaintext[1:pad_end] != bytes(pad_count):
        raise ValueError("AA prefix padding is truncated or nonzero")
    stream = decompress_lzss(plaintext[pad_end:], max_output=max_output)

    if expected_partition is None:
        if len(stream) < 2 or stream[0] != TAG_DATA:
            raise ValueError("Cannot infer partition id from first AA subblock")
        partition_id = stream[1]
    else:
        if not isinstance(expected_partition, int) or isinstance(expected_partition, bool):
            raise ValueError("Expected partition id must be an integer")
        partition_id = expected_partition
    if not 0 <= partition_id <= 0xFF:
        raise ValueError("Expected partition id must fit an unsigned byte")

    if expected_span is None:
        records = parse_subblocks(
            stream,
            partition_id,
            0xFFFFFFFF,
            max_records=max_records,
            allowed_terminator_sizes=allowed_terminator_sizes,
        )
        endpoints = [
            record["relative_offset"] + record["payload_size"]
            for record in records if record["tag"] == TAG_DATA
        ]
        if not endpoints:
            raise ValueError("AA stream contains no sparse data records")
        logical_size = max(endpoints)
    else:
        if not isinstance(expected_span, int) or isinstance(expected_span, bool):
            raise ValueError("Expected partition span must be an integer")
        logical_size = expected_span
        records = parse_subblocks(
            stream,
            partition_id,
            logical_size,
            max_records=max_records,
            allowed_terminator_sizes=allowed_terminator_sizes,
        )

    return {
        "stream": stream,
        "stream_size": len(stream),
        "stream_sha256": _sha256(stream),
        "pad_count": pad_count,
        "partition_id": partition_id,
        "logical_size": logical_size,
        "logical_size_source": "caller" if expected_span is not None else "minimum_sparse_extent_inferred",
        "iv_sha256": _sha256(iv),
        "records": records,
    }


def make_subblock(tag: int, part_id: int, rel_offset: int, payload: bytes) -> bytes:
    """Build one observed sparse-record encoding (not a container/repacker)."""
    if tag not in (TAG_DATA, TAG_END):
        raise ValueError("Only observed tag 09 and FF records are supported")
    if not 0 <= part_id <= 0xFF or not 0 <= rel_offset <= 0xFFFFFFFF:
        raise ValueError("Subblock id or offset is out of range")
    if not isinstance(payload, bytes) or len(payload) > 0xFFFFFFFF:
        raise ValueError("Subblock payload must fit an unsigned 32-bit length")
    if tag == TAG_END:
        if rel_offset != 0 or len(payload) not in (12, 16) or payload != bytes([0xFF]) * len(payload):
            raise ValueError("FF terminator requires offset 0 and 12 or 16 FF bytes")
        magic = 0
    else:
        magic = DATA_MAGIC
    header_without_checksum = struct.pack(
        "<BBHIII", tag, part_id, 0, rel_offset, magic, len(payload)
    )
    words = struct.unpack("<8H", header_without_checksum)
    checksum = (-sum(words)) & 0xFFFF
    header = struct.pack(
        "<BBHIII", tag, part_id, checksum, rel_offset, magic, len(payload)
    )
    return header + payload


def parse_subblocks(
    stream: bytes,
    partition_id: int,
    logical_size: int,
    max_records: int = DEFAULT_MAX_RECORDS,
    allowed_terminator_sizes: tuple[int, ...] = (12, 16),
) -> list[dict]:
    """Validate sparse records while retaining original stream offsets/payloads."""
    if not isinstance(stream, bytes):
        raise ValueError("Subblock stream must be bytes")
    if not 0 <= partition_id <= 0xFF:
        raise ValueError("Partition id must fit the subblock's one-byte field")
    if not 0 < logical_size <= 0xFFFFFFFF:
        raise ValueError("Logical size must be a nonzero unsigned 32-bit value")
    if max_records <= 0:
        raise ValueError("Record limit must be positive")

    records = []
    pos = 0
    saw_terminator = False
    while pos < len(stream):
        if saw_terminator:
            raise ValueError("Bytes follow the FF terminator")
        if len(records) >= max_records:
            raise ValueError("Subblock count exceeds configured limit")
        if len(stream) - pos < 16:
            raise ValueError("Truncated subblock header")
        tag, part_id, checksum, rel_offset, magic, payload_size = struct.unpack_from(
            "<BBHIII", stream, pos
        )
        header = stream[pos:pos + 16]
        if (sum(struct.unpack("<8H", header)) & 0xFFFF) != 0:
            raise ValueError(f"Subblock {len(records)} checksum is not additive-zero")
        if part_id != partition_id:
            raise ValueError(f"Subblock {len(records)} partition id mismatch")
        payload_start = pos + 16
        payload_end = payload_start + payload_size
        if payload_end < payload_start or payload_end > len(stream):
            raise ValueError(f"Subblock {len(records)} payload is truncated")
        payload = stream[payload_start:payload_end]

        if tag == TAG_DATA:
            if magic != DATA_MAGIC:
                raise ValueError(f"Subblock {len(records)} tag-09 magic mismatch")
            if rel_offset + payload_size > logical_size:
                raise ValueError(f"Subblock {len(records)} exceeds logical partition size")
            terminator = False
        elif tag == TAG_END:
            if magic != 0 or rel_offset != 0:
                raise ValueError("FF terminator reserved fields are invalid")
            if (payload_size not in allowed_terminator_sizes
                    or payload != bytes([0xFF]) * payload_size):
                sizes = ", ".join(str(size) for size in allowed_terminator_sizes)
                raise ValueError(f"FF terminator payload must be one of ({sizes}) FF bytes")
            terminator = True
        else:
            raise ValueError(f"Unsupported subblock tag {tag:#04x}")

        record = {
            "index": len(records),
            "tag": tag,
            "partition_id": part_id,
            "checksum": checksum,
            "relative_offset": rel_offset,
            "magic": magic,
            "payload_size": payload_size,
            "payload_sha256": _sha256(payload),
            "stream_offset": pos,
            "terminator": terminator,
        }
        if terminator:
            record["terminator_payload_size"] = payload_size
        if tag == TAG_DATA:
            record["payload"] = payload
        records.append(record)
        pos = payload_end
        saw_terminator = terminator

    if not saw_terminator:
        raise ValueError("Sparse stream is missing its final FF terminator")
    return records


def assemble_analysis_image(
    records: list[dict],
    logical_size: int,
    fill_byte: int,
    max_image_size: int = DEFAULT_MAX_DECODED_BYTES,
) -> dict:
    """Assemble an explicitly filled analysis image, never a physical image."""
    if not 0 < logical_size <= 0xFFFFFFFF:
        raise ValueError("Logical size must be a nonzero unsigned 32-bit value")
    if logical_size > max_image_size:
        raise ValueError("Analysis image exceeds configured output limit")
    if not 0 <= fill_byte <= 0xFF:
        raise ValueError("Analysis fill byte must be in 0..255")

    intervals = []
    for record in records:
        if record.get("tag") != TAG_DATA:
            continue
        offset = record.get("relative_offset")
        payload = record.get("payload")
        if not isinstance(offset, int) or not isinstance(payload, bytes):
            raise ValueError("Analysis image requires tag-09 records with payload bytes")
        end = offset + len(payload)
        if offset < 0 or end > logical_size:
            raise ValueError("Analysis record exceeds declared logical size")
        if end == offset:
            continue
        intervals.append((offset, end, payload))

    intervals.sort(key=lambda item: (item[0], item[1]))
    covered_bytes = 0
    previous_end = 0
    gaps = []
    image = bytearray([fill_byte]) * logical_size
    for offset, end, payload in intervals:
        if offset < previous_end:
            raise ValueError("Overlapping tag-09 records cannot be assembled safely")
        if offset > previous_end:
            gaps.append([previous_end, offset - previous_end])
        image[offset:end] = payload
        covered_bytes += end - offset
        previous_end = end
    if previous_end < logical_size:
        gaps.append([previous_end, logical_size - previous_end])
    return {
        "image": bytes(image),
        "unknown_gaps": gaps,
        "covered_bytes": covered_bytes,
        "coverage_percent": (covered_bytes * 100.0 / logical_size),
        "fill_byte": fill_byte,
    }


def load_aes128_key(
    *, key_file: Path | None = None, key_env: str | None = None
) -> bytes:
    """Load a caller-supplied AES-128 key without printing or persisting it.

    Exactly one source is required. Key files may contain 16 raw bytes or 32
    ASCII hexadecimal characters with one optional final line ending.
    Environment variables must contain exactly 32 ASCII hexadecimal characters.
    """
    if (key_file is None) == (key_env is None):
        raise ValueError("Provide exactly one key source: key_file or key_env")
    if key_file is not None:
        if key_file.is_symlink() or not key_file.is_file():
            raise ValueError("Key file must be a regular, non-symlink file")
        key_data = key_file.read_bytes()
        if len(key_data) == 16:
            return key_data
        try:
            key_text = key_data.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Key file must contain 16 raw bytes or 32 ASCII hex characters") from exc
        if key_text.endswith("\r\n"):
            key_text = key_text[:-2]
        elif key_text.endswith(("\r", "\n")):
            key_text = key_text[:-1]
    else:
        key_text = os.environ.get(key_env, "")
    if not key_text:
        raise ValueError("Provided AES-128 key source is empty")
    if not HEX_AES128_KEY.fullmatch(key_text):
        raise ValueError("AES-128 key must be exactly 32 hexadecimal characters (no spaces or 0x prefix)")
    return bytes.fromhex(key_text)


def _parse_key(args: argparse.Namespace) -> bytes:
    if args.key_file is not None:
        return load_aes128_key(key_file=args.key_file)
    return load_aes128_key(key_env=args.key_env)


def _source_files(source: Path) -> tuple[list[Path], bool]:
    if source.is_file():
        if source.is_symlink():
            raise ValueError("Symbolic-link input files are not supported")
        if not source.name.startswith("Data_") or source.suffix.lower() != ".bin":
            raise ValueError("A file source must be named Data_*.bin")
        return [source], False
    if source.is_dir():
        candidates = sorted(source.rglob("Data_*.bin"))
        if any(path.is_symlink() for path in candidates):
            raise ValueError("Symbolic-link Data_*.bin inputs are not supported")
        files = [path for path in candidates if path.is_file()]
        if not files:
            raise ValueError("Source directory contains no Data_*.bin files")
        return files, True
    raise ValueError(f"Source does not exist: {source}")


def _check_no_overlap(source: Path, output: Path, is_directory: bool) -> None:
    source = source.resolve()
    output = output.resolve()
    if is_directory:
        if source == output or source in output.parents or output in source.parents:
            raise ValueError("Source and output directories must not overlap")
    elif source == output or source in output.parents:
        raise ValueError("Output must not contain or replace the source file")


def _output_relative(source: Path, source_root: Path, is_directory: bool) -> Path:
    relative = source.relative_to(source_root) if is_directory else Path(source.name)
    return relative.with_name(relative.name + ".decoded.bin")


def _run_one(
    source_path: Path,
    relative_base: Path,
    staging: Path,
    key: bytes,
    source_label: str,
    max_source: int,
    max_output: int,
    max_records: int,
    analysis_fill: int | None,
) -> dict:
    source_size = source_path.stat().st_size
    if source_size > max_source:
        raise ValueError(f"Source exceeds {max_source}-byte limit: {source_path}")
    raw = source_path.read_bytes()
    decoded = decode_container(
        raw, key, max_output=max_output, max_source=max_source,
        max_records=max_records,
    )
    records = decoded.get("records")
    if records is None:
        records = parse_subblocks(
            decoded["stream"], decoded["partition_id"], decoded["logical_size"],
            max_records=max_records,
        )

    stream_path = staging / relative_base
    stream_path.parent.mkdir(parents=True, exist_ok=True)
    stream_path.write_bytes(decoded["stream"])
    segments_dir = stream_path.with_name(stream_path.name + ".segments")
    segments_dir.mkdir(parents=True, exist_ok=True)

    manifest_records = []
    sparse_payload_bytes = 0
    for record in records:
        item = {k: v for k, v in record.items() if k != "payload"}
        item["payload_sha256"] = record["payload_sha256"]
        if record["tag"] == TAG_DATA:
            payload = record["payload"]
            segment_name = (
                f"record-{record['index']:06d}-offset-{record['relative_offset']:08x}.bin"
            )
            segment_path = segments_dir / segment_name
            segment_path.write_bytes(payload)
            item["segment_path"] = segment_path.relative_to(staging).as_posix()
            sparse_payload_bytes += len(payload)
        else:
            item["payload_retained_in_decoded_stream"] = True
        manifest_records.append(item)

    analysis_image_info = None
    if analysis_fill is not None:
        assembled = assemble_analysis_image(
            records,
            decoded["logical_size"],
            analysis_fill,
            max_image_size=max_output,
        )
        image_name = f"{relative_base.name}.analysis-fill-{analysis_fill:02x}.img"
        image_path = stream_path.with_name(image_name)
        image_path.write_bytes(assembled["image"])
        analysis_image_info = {
            "path": image_path.relative_to(staging).as_posix(),
            "bytes": len(assembled["image"]),
            "sha256": _sha256(assembled["image"]),
            "fill_byte": f"{analysis_fill:02x}",
            "unknown_gaps": assembled["unknown_gaps"],
            "covered_bytes": assembled["covered_bytes"],
            "coverage_percent": assembled["coverage_percent"],
            "semantics": "analysis_only_unknown_gaps_not_original_flash_content",
            "physical_address": "unknown",
            "terminator_applied": False,
        }

    return {
        "source_path": source_label,
        "source_size": decoded["source_size"],
        "source_sha256": decoded["source_sha256"],
        "partition_id": decoded["partition_id"],
        "method": f"{decoded['method']:02x}",
        "logical_size_declared": decoded["logical_size"],
        "stored_size": decoded["stored_size"],
        "decoded_stream_path": stream_path.relative_to(staging).as_posix(),
        "decoded_stream_size": decoded["stream_size"],
        "decoded_stream_sha256": decoded["stream_sha256"],
        "sparse_mapped_payload_bytes": sparse_payload_bytes,
        "record_count": len(records),
        "signature_verification": "not performed",
        "analysis_image": analysis_image_info,
        "records": manifest_records,
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="One Data_*.bin file or a directory to scan recursively")
    parser.add_argument("--output", required=True, type=Path, help="New, nonexistent output directory")
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key-env", default="FPKE_AES_KEY",
                           help="Environment variable holding exactly 32 hex characters (no key default)")
    key_group.add_argument("--key-file", type=Path,
                           help="File containing 16 raw key bytes or exactly 32 ASCII hex characters")
    parser.add_argument("--max-source-mib", type=int, default=256, help="Maximum source file size in MiB")
    parser.add_argument("--max-decoded-mib", type=int, default=512, help="Maximum decoded stream size in MiB")
    parser.add_argument("--max-records", type=int, default=DEFAULT_MAX_RECORDS, help="Maximum subblocks per source")
    parser.add_argument("--analysis-fill", choices=("00", "ff"),
                        help="Also write an analysis-only logical image, explicitly filling unknown gaps")
    args = parser.parse_args()

    try:
        if args.source.is_symlink():
            raise ValueError("Symbolic-link source paths are not supported")
        if args.output.is_symlink():
            raise ValueError("Symbolic-link output paths are not supported")
        source = args.source.resolve()
        output = args.output.resolve()
        files, is_directory = _source_files(source)
        _check_no_overlap(source, output, is_directory)
        if output.exists():
            raise ValueError(f"Output already exists: {output}")
        if not output.parent.is_dir():
            raise ValueError("Output parent directory must already exist")
        if args.max_source_mib <= 0 or args.max_decoded_mib <= 0 or args.max_records <= 0:
            raise ValueError("Configured limits must be positive")
        max_source = args.max_source_mib * 1024 * 1024
        max_output = args.max_decoded_mib * 1024 * 1024
        key = _parse_key(args)

        output.mkdir()
        ledger_path = output / "FREEZE_LEDGER.md"
        completed_sources = []
        current_source = None
        try:
            ledger_path.write_text(
                "# FPKE unpack run preservation ledger\n\n"
                "Status: RUNNING\n\n"
                "This output directory was created by fpke_datax.py. On failure, "
                "all produced files are preserved for inspection.\n",
                encoding="utf-8",
            )
            entries = []
            for source_path in files:
                current_source = (
                    source_path.relative_to(source).as_posix()
                    if is_directory else source_path.name
                )
                relative = _output_relative(source_path, source, is_directory)
                entries.append(_run_one(
                    source_path, relative, output, key, current_source,
                    max_source=max_source,
                    max_output=max_output,
                    max_records=args.max_records,
                    analysis_fill=(int(args.analysis_fill, 16)
                                   if args.analysis_fill is not None else None),
                ))
                completed_sources.append(current_source)
            manifest = {
                "tool": "fpke_datax.py",
                "format_version_supported": 3,
                "read_only_scope": "decoded streams and sparse tag-09 payloads; optional explicit-fill analysis image",
                "signature_verification": "not performed",
                "logical_size_semantics": "declared destination span; not decoded stream length",
                "source_count": len(entries),
                "sources": entries,
            }
            (output / "manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            ledger_path.write_text(
                "# FPKE unpack run preservation ledger\n\n"
                "Status: COMPLETE\n\n"
                f"Processed sources: {len(entries)}\n"
                "The finalized manifest is `manifest.json`.\n",
                encoding="utf-8",
            )
        except Exception as exc:
            try:
                produced = sorted(
                    path.relative_to(output).as_posix()
                    for path in output.rglob("*") if path.is_file()
                )
                ledger_path.write_text(
                    "# FPKE unpack run preservation ledger\n\n"
                    "Status: FAILED; output preserved for inspection\n\n"
                    f"Completed sources: {json.dumps(completed_sources)}\n\n"
                    f"Source in progress: {current_source or 'none'}\n\n"
                    f"Error: {type(exc).__name__}: {exc}\n\n"
                    "Files present at failure:\n"
                    + "\n".join(f"- `{name}`" for name in produced) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
            raise

        print(json.dumps({"output": str(output), "sources": len(entries)}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"fpke_datax: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_cli())
