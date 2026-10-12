# MU1440 R15: supplied 64-MiB MMX fs0 native PT and installed-format Stage-1 wrapper audit (2026-10-12)

**Scope:** one privately supplied 64-MiB **MMX** fs0 raw image, host-only and read-only. Source ownership, factory-original status, exact vehicle association and firmware-train provenance are supplier-reported, not independently authenticated; NO firmware, OEM binaries, overclock payload, car-side action or flashing utility published. Sample-specific proof, not proof of the *currently installed* unit's contents or universal layout. Offset ends exclusive. For the separate **RCC** fs0 audit see [Toolkit PR #7](https://github.com/harman-f/MHI2-MHI2Q-MH2P-Firmware-Toolkit/pull/7); RCC and Tegra/MMX are separate storage/boot domains.

## 1. Public source identifier and supplier-reported catalog context

The independently measured, publicly usable identifier of the supplied `MMX_fs0` sample is **67,108,864 B = 0x4000000**, SHA-256 `4011a8b81bf3a785673d9e1868d270fd37c3c6daeb2c77f0d119e10e583f0094`. The supplier's **private** archival catalog labels a record with the same digest as `BACKUP-SNAPSHOT-06`, with a MU1440 firmware-train label; neither the private catalog nor an original source-side extraction/chain-of-custody record is publicly verifiable. This report's independently checkable conclusions are restricted to the **published hash and structural observations on that one supplied image**. `BACKUP-SNAPSHOT-06` is context, **not an independently established identity or current-unit provenance**. A different privately catalogued `BACKUP-SNAPSHOT-10` digest was reported; it is not the source inspected here. Replication requires the reviewer to supply a legally obtained image matching the published whole-file SHA, not access to the private catalog or analysis output.

## 2. Native PT independently parsed: the historical G11 “Normal” table is directly supported HERE

The supplied image contains **four entirely byte-identical 64-KiB BCT copies** in `[0,0x40000)`, one copy SHA-256 `5ccd07e590c217b5d8970d685aac51ae1ffae15eaa1205a449e6e2577102a7c3`. This confirms copies, not Tegra BootROM signature/BCT authentication or a particular PLLX/SDRAM profile.

At `[0x40000,0x60000)` the supplied PT region contains **64 entirely byte-identical 2-KiB records**. Their first four bytes are `8B 8D 9E 8F`. Each has **13 named entries**, mirrored equal name fields and start/length/repeated-start/inclusive-end tuples using **0x800-byte logical address units**. Each observed record resolves to exactly the same contiguous, non-overlapping full-64-MiB layout. This proves native on-storage partition geometry for the sampled dump, **not 2-KiB NOR physical erase geometry**.

| Original named PT region | Start | End exclusive | Length |
| --- | ---: | ---: | ---: |
| BCT | `0x00000000` | `0x00040000` | 256 KiB |
| PT | `0x00040000` | `0x00060000` | 128 KiB |
| STAGE1_RECOVERY | `0x00060000` | `0x000A0000` | 256 KiB |
| STAGE2_RECOVERY | `0x000A0000` | `0x000E0000` | 256 KiB |
| STAGE1_PRIMARY | `0x000E0000` | `0x00120000` | 256 KiB |
| STAGE2_PRIMARY | `0x00120000` | `0x00160000` | 256 KiB |
| **KERNEL_RECOVERY** | **`0x00160000`** | **`0x00760000`** | **6 MiB** |
| **KERNEL_PRIMARY** | **`0x00760000`** | **`0x00A60000`** | **3 MiB** |
| MAIN_STAGE2 | `0x00A60000` | `0x03460000` | 42 MiB |
| SWDL | `0x03460000` | `0x03480000` | 128 KiB (all FF in THIS snapshot) |
| SPLASH | `0x03480000` | `0x03600000` | 1.5 MiB |
| SYSTEM | `0x03600000` | `0x03800000` | 2 MiB |
| PERSIST | `0x03800000` | `0x04000000` | 8 MiB |

The table is the historical [G11 “Normal” column](MHI2_FLASH_LAYOUT_AND_RECOVERY.md), rather than its H22 46-MiB MAIN_STAGE2/4-MiB PERSIST column. Here that classification is derived from *PT bytes observed in the supplied image*, not inferred from an update module's file size.

**Internal redundancy check on the supplied bytes:** STAGE1_RECOVERY and STAGE1_PRIMARY (entire 256-KiB regions) are byte-identical, SHA-256 `34033a305668057432f073474a747070f9ea11e89c66d0e4f4bc41b1d2f14466`; STAGE2_RECOVERY and STAGE2_PRIMARY likewise byte-identical, SHA-256 `94a59968bdbb313094ae9b90091be53839ce69dee7086059baf8811c9439e0ae`. This **does not** mean KERNEL_RECOVERY and KERNEL_PRIMARY are identical, nor prove actual automatic recovery fallback.

## 3. Exact OEM installed mapping: SWDL /70/ Stage-1 ↔ named physical PRIMARY

The raw 3-MiB KERNEL_PRIMARY has SHA-256 `65584560cb3c31abed1b2fadf33b45b0fbf6d4758346055867cf1339aac83a14` and begins with installed magic ASCII `ANDROID!`. The original **variant-70** SWDL member (SHA-256 `511bdba0f12e8a7510930ca689f7a9020656c777b11301c7eb70176825f7af0a`) has alternate transport magic `41 FF 44 FF 4F FF 44 FF`. Complete **3,145,728-byte** comparison: exactly **four** differing bytes, at original member-relative offsets `0x1,0x3,0x5,0x7`, and **all other bytes identical**. Normalizing ONLY the original transport magic to `ANDROID!` yields a complete whole-partition, byte-identical match.

This is strong, direct evidence that in THIS archived backup the logical 3-MiB `mifs-stage1.img` /70/ package member corresponds to the actual named on-storage `KERNEL_PRIMARY` slot. It does not demonstrate boot acceptance of an **altered** image or an actual safe partial-SWDL installation method.

The original installed zlib span is `[0x800,0x800+2984342)`, cleanly decompresses to **6,841,260 B**, SHA-256 `f3e9098cd9eadd48cf65a9e1dc28481be4894b64c765956046abf286ea078465`: exact known original /70/. The 106,760-B startup SHA is `9a7d54a69a5672cf13e532b262670b3ab4146d1e4d942b6cd2424a346a223b39`. Its ImageFS is 6,734,492 B, and startup/ImageFS each have independent additive LE32 checksums totaling zero modulo `2^32`.

## 4. IMPORTANT: formerly unknown outer `0x7FC` now identified

Two separate CRC32 checks appear in BOTH installed-format kernel headers in the supplied image:

| Outer field | Meaning supported by exact raw bytes | PRIMARY | RECOVERY |
| --- | --- | ---: | ---: |
| `0x008` | compressed `kernel_size` | 2,984,342 | 5,572,424 |
| `0x024` | page size / compressed stream start | 2,048 | 2,048 |
| **`0x264`** | CRC32 over **compressed span only** `image[0x800:0x800+kernel_size]` | **`0xD15EE9A7`** | **`0xA240F2F9`** |
| **`0x7FC`** | **CRC32 of installed-format header bytes `image[0:0x7FC]`**, excludes stored CRC word | **`0x9A964B9D`** | **`0x6B7E72CC`** |

All four direct installed-image CRC checks pass. Original SWDL /50/ and /70/ first pages use *transport* magic, so `CRC32(original_header[:0x7FC])` **does not** equal their stored `0x7FC`. If ONLY their first eight magic bytes are normalized to installed `ANDROID!` before calculating, both stored values match EXACTLY: /50/ `0x89513F41`, /70/ `0x9A964B9D`. This resolves the previous [Stage-1 guide](MU1440_STAGE1_OEM_OFFLINE_ROUNDTRIP.md)'s `0x7FC` uncertainty and documents a verified transport→installed normalization rule for the observed samples. Other extended fields `0x260` and `0x400` remain only measured (`1`, `0x675` in PRIMARY; `1`, `0x6D9` in RECOVERY) without established semantics. Header CRC correctness does not establish all bootloader/SWDL authentication checks.

## 5. Real recovery image and Stage-2

KERNEL_RECOVERY is a complete, distinct **6-MiB installed `ANDROID!`** image SHA-256 `d775f647f44028e643fbf20d025f284f6dc5a600308acb60fb1a888dd3ca7da0`. Bounded original zlib decoder yields **12,959,872 B**, SHA-256 `79b2cf580b951a0ea0b3014e8461e190df01422ef680e6006530ddb00d6c7038`. The inner QNX startup header starts at expanded kernel offset 8; startup region 106,760 B and ImageFS 12,853,104 B, with independent zero-sum checks. Its startup differs from PRIMARY's startup (115 byte differences) and has SHA `94b75646b7266f2deb619d04de1cadbc956e475b3a729d1e0035c5fee86eb821`. Fits Toolkit-documented 6-MiB EIFS **format/length**, but the exact original `eifs.img` member was not included in the R14 ZIP; do not assert entire OEM update-member byte identity.

MAIN_STAGE2 begins at `0xA60000` with actual `LZOZ` marker, 2,097,152-B expanded block size and **37** contiguous nonzero compressed block lengths in its header, consistent with the 42-MiB variant-70 family. Full Stage-2 decompression/member equality remains out of scope. SYSTEM/PERSIST begin at exact PT boundaries with EFS-like signatures.

## 6. What remains open

- Does this supplied raw image reflect the **currently installed** Unit, or even independently establish the supplier's `BACKUP-SNAPSHOT-06` label? Neither is proven by this public report; the whole-file digest identifies the inspected sample only.
- Exact BootROM BCT authentication, RAM_CODE/SDRAM/speed-grade, pre-QNX PLLX writer, dynamic Global Timer/qtime retiming, real CPU VDD/PMIC map: not established.
- Fallback/Recovery accessibility after a particular failure: distinct intact source regions demonstrated, **not a live recovery validation**.
- Exact physical NOR erase/program granularity, supported component-only SWDL update route, and acceptance of modified boot images: NOT validated. Logical 2-KiB PT sectors are not NOR erase sectors.
- Never infer that a full 64-MiB rewrite is necessary or desirable. BCT/PT and the separate recovery regions are proven to be real and distinct.

The source-specific claims above stand on public offsets, lengths, field relationships, hash identifiers and explicit CRC32 formulas. An independent reviewer can repeat the checks using a lawfully obtained raw image matching the published whole-file hash and standard read-only hash/struct/zlib utilities. No inaccessible private catalog, analyzer output or private session is needed **as the authority for these structural claims**. This report publishes **hashes/metadata only**; no OEM bytes, fabricated firmware, write code or flash instructions.
