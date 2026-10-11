# MU1440 R14: read-only, original 64-MiB RCC fs0 NOR layout audit (2026-10-12)

**Scope:** one privately supplied authentic archived RCC fs0 raw backup associated with the MU1440 corpus; host-only inspection, no device access, no firmware edits, no boot/flash qualification. This is a **sample-specific observation, not a universal RCC image map**, and does NOT validate the separate Tegra/MMX 64-MiB NOR, its BCT/PT or `KERNEL_PRIMARY`. Original raw files/binaries and personal source paths remain private.

## 1. Source integrity, proof types and relationships

- Original R14 private ZIP: 58,978,614 bytes, SHA-256 `e2c6713c00afbd43c0f28b8f046fb94217f630cbe98bc9d0177c413e77806a2a`; ZIP integrity good, 19/19 SHA256SUMS and 18/18 manifest sizes/digests independently confirmed after extraction.
- Included raw `RCC_fs0.bin`: exactly `0x4000000` = 67,108,864 bytes; SHA-256 `45c88eb7fa44a721c4eb1e95f57a3331e110a6756896b7639a66ac81471136d3`.
- The *historical metainfo* source is [the preserved Bash repository `metainfo2 (1).txt`](https://github.com/CaneTLOTW/M.I.B._More-Incredible-Bash/blob/a7f362d0dbc73ba5ee978bdebc4ac0286bd8462b/docs/google-research/files/metainfo2%20(1).txt), section `RCC\\ImageLayout2`, repeated for RCC/MU29100 and several slot variants. It supplies a set of **advertised** starts/sizes; do NOT assume this archival metainfo is an exact flash dump length manifest for the specific backed-up instance.
- [This toolkit's existing image-format guide](MHI2_IMAGE_FORMATS_AND_LAYOUT.md) already distinguishes standalone RCC update `ifs-root.ifs` from full `RCC_fs0.bin`, root-part2 offset variation, Emergency UCL, Root LZO, EFS and MMX formats. This R14 audit adds **direct raw-image header/occupancy evidence**, not an entirely new file-family decoder.
- The preserved [Toolkit flash/recovery guide](MHI2_FLASH_LAYOUT_AND_RECOVERY.md) already distinguishes RCC boot/IFS from separate MMX/Tegra NOR. This raw RCC evidence must not fill its outstanding MMX partition-map gap.

## 2. Historical metainfo size vs the independently measured raw image

All ends below are exclusive. The documented `ImageSize` values are preserved *as written in the historical source*. Where the raw image extends beyond them, this proves **different sample/version or advertised-size versus on-storage extent**, not that old metainfo should universally be rewritten.

| Region | Start offset | Historic `ImageSize` | Historic end | Direct observation on this raw sample |
| --- | ---: | ---: | ---: | --- |
| IPL | `0x00000000` | 75,928 | `0x00012898` | ARM-like first word `7E 00 00 EA`; meaningful bytes beyond advertised end to about `0x00013940`; exact IPL boundary unknown |
| Emergency IFS | `0x00020000` | 3,738,964 | `0x003B0D54` | **3,738,972 bytes** incl. 8-byte preboot; actual bounded end `0x003B0D5C`, eight bytes beyond historic advertised length |
| Root IFS | `0x00540000` | 22,321,528 | `0x01A89978` | **Two QNX images + FF gap through `0x01AD061C` = 22,611,484 B**; historic value truncates 289,956 B of actual second serialized image |
| EFS-system | `0x01D40000` | 25,165,824 (24 MiB) | `0x03540000` | EFS-like prefix `10 00 4C FF 11 00 FF FF`; raw slice SHA-256 `ea75281270b7ea74f730eb912c2d601a0d6c61173cfa33a7914de93c6abe93aa`, different from equally sized update member (R14 private comparison) |
| EFS-persist | `0x03540000` | 7,340,032 (7 MiB) | `0x03C40000` | EFS-like prefix; raw 7-MiB span SHA-256 `dc648955123ac0d5221e4ed82f004c049c1034d21063afe584b0e7da01d3ffe0` |
| DSP | `0x03D00000` | 807,644 | `0x03DC52DC` | meaningful bytes persist **3,800 bytes beyond** advertised end; observed full occupied 811,444-byte span to `0x03DC61B4`, the *size* of one Toolkit-documented update member, without proof of byte equality |
| **Not in six archived rows** | **`0x03F00000`** | — | — | **`BIOSCTRL`** initial marker, additional occupied content to `0x03F5502E` (348,206-B prefix); purpose, persistence and recovery policy **unknown**, not free/erased NOR |

The exact 289,956-byte region after the archived Root end contains **289,083 non-`0xFF` bytes**; a fixed old-layout carver silently produces an **incomplete** Root image on this actual sample. Likewise, the eight Emergency footer bytes and DSP continuation should not be thrown away by treating old `ImageSize` as a universal current-dump delimiter.

## 3. Strong structural QNX evidence (separate marker scan + bounded startup_header)

A whole-file exact `EB 7E FF 00` marker scan yielded three **plausible** QNX headers after strict independent structural checks: version 1, header_size `0x100`, preboot length 0 or 8, bounded startup/stored/ImageFS declared lengths and an in-file serialized extent. Other incidental markers inside code/data were rejected. This establishes bounded serialized **candidate extents**, not decompression, all ImageFS entries, end-to-end boot integrity or a live recovery test.

| Candidate | QNX header offset | flags1 / machine | preboot | startup_size | stored_size | decoded imagefs_size | On-flash extent (preboot included) |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| Emergency | `0x00020008` | `0x0D` / 40 | 8 | 139,528 | 3,738,964 | 9,035,508 | `[0x00020000,0x003B0D5C)` |
| Root part 1 | `0x00540008` | `0x09` / 40 | 8 | 139,528 | 6,672,448 | 15,230,728 | `[0x00540000,0x00B9D048)` |
| Root part 2 | `0x00BA0000` | `0x08` / 0 | 0 | 260 | 15,926,812 | 44,521,896 | `[0x00BA0000,0x01AD061C)` |

```text
0x00540000 .. 0x00B9D048: original root part 1, 6,672,456 B incl 8 preboot
0x00B9D048 .. 0x00BA0000: exactly 12,216 bytes of 0xFF-only alignment
0x00BA0000 .. 0x01AD061C: separate second QNX header/image, 15,926,812 B
---------------------------------------------------------------------------
root logical span: 0x00540000 .. 0x01AD061C = 22,611,484 bytes
0x01AD061C .. 0x01D40000: exactly 2,554,340 bytes of 0xFF to EFS-system
```

The full 22,611,484-B logical root span matches the **original MU1440 standalone update-member SIZE** documented independently in [the flash/layout guide](MHI2_FLASH_LAYOUT_AND_RECOVERY.md). The original update member was not included in this private R14 ZIP, so **do not claim its full SHA or byte identity against the raw flash**. `imagefs_size` values above describe *declared expanded payload*, not on-flash bytes; compression subtype/entry-tree validity still requires the matching bounded reader.

### Independent raw-slice SHA-256 (no bytes published)

| Source span | SHA-256 |
| --- | --- |
| Complete emergency through 8-byte footer | `839fbf390a8c624db4a91f67ceb95d1c9f3c2fbfd1bdca58c63ca043021658cc` |
| Root part 1 | `014495a1795a36ea251628f96be20539607974ac681d07d8e4481dde67063ea3` |
| Root part 2 | `94035ff2338d0abef696665156133a61f28f870161d92845cda0b8756c4e6031` |
| Whole 22,611,484-B root incl. FF alignment | `631f8a12d4d3708a4ccd635b278f9b711d40029613eab9dd3370f4c81dd2aa48` |
| Occupied 811,444-B DSP span | `9840747442d609ee769a63609a96c74a26d9ccf35f4caa404cef0e6264757a55` |
| Unclassified 348,206-B end-area prefix (`BIOSCTRL`) | `ba0da598bdb0aea59ca678632f3ebbf4bc9726d9e5ca867b9b161cac448074ee` |

**Critical implementation implication:** the common historical RCC part-2 start `0x00BA0000` happens to be correct for this source, but [the upstream image-format guide](MHI2_IMAGE_FORMATS_AND_LAYOUT.md) documents **other real historical starts** `0x00BC0000`, `0x00BE0000`, `0x00C00000` and `0x00C20000`. A general raw-NOR carver should enumerate/validate candidates, prefer exact-dump sidecars if present, derive length from each validated header and stop on ambiguity, not assume six universal fixed regions.

## 4. What this RCC sample does NOT solve (separate MMX/Tegra domain)

A complete search of this raw RCC image found no exact outer custom MMX Stage-1 signature `41 FF 44 FF 4F FF 44 FF` and no `ANDROID!` marker. This is no direct evidence for an OEM `mifs-stage1.img` stored inside the RCC fs0 region. The 64-MiB **MMX** NOR must be inventoried as a separate source to validate any historical `KERNEL_PRIMARY`, recovery loader/kernel and BCT/PT mapping. RCC Emergency-IFS is real header-backed source evidence, but it does not prove automatic boot fallback, MMX recovery behavior or modified-image acceptance.

The R14 private bundle separately included BOTH exact original MMX `mifs-stage1.img` /50/ and /70/ wrappers. Independently repeating unchanged `zlib.compress(decoded_kernel, 9)` yielded **both** original compressed streams and complete 3-MiB OEM wrappers byte-for-byte using preserved original first page/zero+`FF` padding. Original /70/ compressed kernel is **2,984,342 B**, CRC32 at outer `0x264` = `0xD15EE9A7`; /50/ is 2,984,374 B, CRC32 = `0xFA04A09A`. Packed hashes /50/ `694c707035fea415842d222f2993e90aad69ca539c1b3608631bd8182ceffc6c` and /70/ `511bdba0f12e8a7510930ca689f7a9020656c777b11301c7eb70176825f7af0a`. Each decoded kernel is 6,841,260 B; the entire 106,760-B startup is identical and there are 3,739 changed decoded bytes, all in ImageFS. `0x7FC` remains an opaque extended wrapper field for any changed image. See [original Stage-1 procedure](MU1440_STAGE1_OEM_OFFLINE_ROUNDTRIP.md). **No binary modification or target execution was performed.**

**Voltage-source boundary:** R14 RCC `DSIIPCBridge`, `diagnosis`, `Env` contain display/supply/terminal voltage identifiers, not a verified Tegra CPU VDD measurement; no authentic read-only `VDD_CPU` source was established. A helper returning a constant `1200` must not be treated as live millivolts.

## 5. Next evidence gates

1. **Exact candidate already listed but not included in R14 ZIP:** the R14 sanitized backup catalog records a **paired original 64-MiB MMX fs0** in `BACKUP-SNAPSHOT-10`, beside the included RCC image, SHA-256 `e9d65a0b18974054e119334e320ddc7963704830dedff4fbd957670e14ca7463`. Privately acquire and independently rehash **that exact original candidate** and its unit/variant provenance; do not substitute the RCC fs0. Its BCT/PT, recovery and primary regions remain **UNVERIFIED until the matching MMX raw bytes are separately inspected**. Preserve all source data unchanged.
2. For RCC: independently validate compressed/decompressed IFS and ImageFS entry inventories of both root subparts and emergency with a matched reader, plus exact standalone original update-member hash/byte comparison. Do not infer that matching overall length implies matching bytes.
3. Identify/retain the `BIOSCTRL` block's format and policy independently. Never treat unlisted/raw-non-FF space as safe to overwrite.
4. For QNX root scanner development, add synthetic malformed and ambiguous header fixtures and support per-dump sidecar hints. Do not infer a universal candidate offset or a flash/write policy from this one instance.

**Publication:** derived tables/hashes only. Private raw backup and extracted proprietary files must not be committed, attached to a public PR, or used as a firmware/boot/recovery deployment artifact.
