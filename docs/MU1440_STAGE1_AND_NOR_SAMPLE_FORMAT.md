# MU1440 Stage-1 and NOR sample format — validated public findings

**Scope:** bounded, read-only observations on separately supplied source images from the MU1440 research set. These statements are independent structural measurements of the specified samples, **not** independently authenticated factory/vehicle provenance, a general MHI2 firmware layout, an image modification tool or a verified flash/boot/recovery procedure. All original bytes remain outside this repository.

## MMX Stage-1 SWDL wrapper: original no-change comparison

The original `/50/` and `/70/` `mifs-stage1.img` package members are **each 3,145,728 bytes**. With the matching original decoded kernel, preserved first page/padding and the tested zlib-9 environment, each reproduced the **complete original unmodified wrapper byte-for-byte** in separate offline tests. The prior one-byte diagnostic-string differential/re-decode was only on `/50/` and **did not establish accepted boot of a changed image**.

| Field in the original 0x800-byte outer header | Meaning supported by these samples |
| --- | --- |
| `0x264` | CRC32 of precisely the compressed zlib span, as bounded by `kernel_size` |
| `0x7FC` | CRC32 of the first `0x7FC` header bytes in **installed `ANDROID!` magic form**; transport-style package header uses distinct magic and must be normalized **in a read-only comparison copy** to reproduce the observed stored value |
| `0x260`, `0x400` | Observed values, **semantics still unknown** |

The two outer checksums have different inputs. Their matching the observed original samples cannot establish BootROM/SWDL authentication or safe altered-image acceptance. The older `0x7FC unknown` statements in the original R13 source-scope writeup are superseded for this sample family; a modification/boot acceptance policy is still unqualified.

## Supplied 64-MiB MMX fs0 sample

The inspected MMX sample is identified solely by **67,108,864 bytes** and whole-file SHA-256 `4011a8b81bf3a785673d9e1868d270fd37c3c6daeb2c77f0d119e10e583f0094`. A separate, privately assigned backup-catalog name has not been authenticated and is not a public dependency.

Four equal 64-KiB BCT copies occupy the first `0x40000` bytes in this sample. The following `[0x40000,0x60000)` region holds 64 equal 2-KiB partition-table records with 13 entries; observed logical units are `0x800` bytes. For this hash-identified image the resulting logical layout includes **KERNEL_RECOVERY `[0x160000,0x760000)` (6 MiB)**, **KERNEL_PRIMARY `[0x760000,0xA60000)` (3 MiB)** and MAIN_STAGE2 with its separate extent. The installed PRIMARY compared with the matching original `/70/` SWDL Stage-1 source differs in **four transport-magic bytes only** across its 3 MiB. This establishes *sample-specific package-to-stored-slot correspondence*, not the active slot or current contents of a particular car; logical PT units are **not** NOR erase-block size.

The independent RECOVERY image is 6 MiB and is not a verified identical copy of the SWDL /50/ or /70/ PRIMARY member. Do not infer rollback behavior from partition names alone.

## Separate supplied 64-MiB RCC fs0 sample

The RCC sample is a **different SoC/storage domain**, not the MMX/BCT/PT image. Independently checked host-side QNX header extents indicate separate Emergency, Root part 1 and Root part 2 image candidates. The combined observed root span was **22,611,484 bytes**, while one older metadata source advertised **22,321,528 bytes**; that advertised number is not a complete physical original dump length. The remainder, including an occupied end-area, is not licensed or validated as writable space.

## Reproduction and integration boundary

The published results can be checked by a contributor with a legally obtained, *hash-matched* image using standard offline CRC32, SHA-256, zlib and bounded read-only header tools. This repository does not redistribute images, private manifests, raw device captures, original proprietary code, or any actionable flash patch. A successful offline roundtrip does not qualify current-unit identity, OEM firmware-update acceptance, NOR physical geometry, safe rewrite or recovery.

See [image formats](MHI2_IMAGE_FORMATS_AND_LAYOUT.md), [Stage-1 original procedure and historical measurement](MU1440_STAGE1_OEM_OFFLINE_ROUNDTRIP.md) and [flash-layout interpretation](MHI2_FLASH_LAYOUT_AND_RECOVERY.md).
