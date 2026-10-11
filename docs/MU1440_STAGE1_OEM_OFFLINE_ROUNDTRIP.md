# MU1440 MIFS Stage-1 — exact OEM offline unpack/repack (2026-10-11)

**Scope:** exact `MHI2_ER_SKG13_P4526_MU1440` MMX2, **variant 50** OEM wrapper, QNX 6.5, offline forensic/build research. This guide documents a performed OEM **byte-identical no-change roundtrip** and a harmless ASCII-marker mutation with verified fresh re-decode. Neither an altered OEM image nor proprietary source bytes are shipped in this repository. **NO vehicle activity, flashing, clock writes, BootROM/SWDL acceptance test or overclock authorization.**

## 1. Where are the files and which component owns what?

```text
OEM update.7z                           PC distribution archive, not NOR image
  metainfo2.txt                         SWDL module selection, variant and integrity metadata
  MMX2/
    mifs-stage1/
      50/default/mifs-stage1.img         tested 0x300000-byte OEM Stage-1 wrapper
      70/default/mifs-stage1.img         distinct full kernel/ImageFS; same startup region
    mifs-stage2/<variant>/default/mifs-stage2.img
                                        later, SEPARATE LZOZ/LZO1Z module
    app/<variant>/default/app.img        SEPARATE large QNX6 filesystem
    eifs/50/default/eifs.img            related wrapper family, different payload
    efs-sys/...                          separate QNX EFS
    efs-pers/...                         separate QNX EFS
    qb-primary/... qb-recovery/...       opaque Quickboot candidates, NOT established BCT
  RCC/...                                separate control-unit domain
```

`50`/`70` are hardware/update variants, not old/new. A shared startup hash does **not** license swapping their different decoded kernels/ImageFS.

Actual tested processing graph:

```text
.7z -> preserve/update SWDL tree -> raw mifs-stage1.img (exactly 3 MiB)
                                         |
                original 0x800-byte extended header/page + original zlib stream
                                         |
              zlib.decompress declared kernel_size bytes starting at page_size
                                         |
              decoded 6,841,260-byte (0x6863AC) QNX boot IMAGE FILE (includes 8-byte preboot)
                   [0,8)           preboot prefix
                   [8,0x108)       256-byte QNX startup header
                   [8,0x1A110)     whole startup (header + ARM code + data + trailer)
                   [0x1A110,end)   QNX ImageFS with its own checksum
                                         |
              optional later MMX Stage-2 / app filesystems are OTHER modules
```

Do not conflate **outer member offset**, **decoded kernel file offset**, **QNX startup VA/physical RAM address**, **historical NOR offset** or **SWDL archive offset**.

### Repository tools: precise responsibility

| Path | Purpose | Does **not** do |
| --- | --- | --- |
| [`tools/extract_firmware.py`](../tools/extract_firmware.py) | 7z/ZIP inventory, exact variant/raw member extraction, hash/manifest, decoder orchestration | Full firmware OEM build |
| [`tools/mhi2-extract.sh`](../tools/mhi2-extract.sh) | shell frontend for the extractor | Separate writer |
| [`tools/android_image.py`](../tools/android_image.py) | `parse_android_header`, `decompress_module`: reads custom header/page, zlib, QNX header, ImageFS | public generic repacker or installer |
| [`tools/imagefs.py`](../tools/imagefs.py) | reads bounded ImageFS entries | generic QNX ImageFS writer |
| [`tools/mifs_stage2.py`](../tools/mifs_stage2.py) | LZOZ Stage-2, **NOT** Stage-1 zlib | Stage-1 writer |
| [`tools/metainfo2.py`](../tools/metainfo2.py) | audits/refreshes supported existing SWDL module sizes, chunk SHA-1, directory sidecars | QNX/Stage-1 encoder, authentication |
| [`tools/update_txt.py`](../tools/update_txt.py) | existing transaction CRC metadata | generates accepted firmware update |
| [`tests/test_android_image.py`](../tests/test_android_image.py) | synthetic reader/header/bounds regression | validates a modified device boot |
| Private OEM roundtrip verifier | entire no-change wrapper byte comparison and inert-byte differential re-decode | public flashing artifact |

Full image build capability/status: [REPACK_AND_METAINFO](REPACK_AND_METAINFO.md); flash evidence: [MHI2_FLASH_LAYOUT_AND_RECOVERY](MHI2_FLASH_LAYOUT_AND_RECOVERY.md).

## 2. Original variant-50 dimensions and measured fields

| Artifact | Exact bytes | SHA-256 |
| --- | ---: | --- |
| Original MU1440 OEM update | 2,288,860,862 | `b23225d68999f0613f2652c898ce36c74d6c1d63a36f29ff5d4faf500c60e5a5` |
| Original /50/ `mifs-stage1.img` | 3,145,728 (`0x300000`) | `694c707035fea415842d222f2993e90aad69ca539c1b3608631bd8182ceffc6c` |
| Its original compressed zlib stream | 2,984,374 | `d34d78358701275598d7f368bcaadcb034b0e897f03a7436623119915e029b8b` |
| Decoded /50/ complete kernel | 6,841,260 | `2dc088bb719fcb42ec0f12260f1f3a451bd328bbf0cecdec3647f5f07cb703ba` |
| Common /50/ and /70/ startup: `kernel[8:0x1A110]` | 106,760 | `9a7d54a69a5672cf13e532b262670b3ab4146d1e4d942b6cd2424a346a223b39` |
| /50/ ImageFS: `kernel[0x1A110:]` | 6,734,492 | `90142756958b1991b507a75628ee35cd7de386803b98253aedabd9ff318271cb` |

**Outer page:** 8-byte marker at `0x000` = `41 FF 44 FF 4F FF 44 FF` (AÿDÿOÿDÿ); eight LE32 fields at `0x008` as defined in `android_image.ANDROID_HEADER`:
`kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size, second_addr, tags_addr, page_size`.

| Outer offset | Original /50/ value | Interpretation |
| --- | --- | --- |
| `0x008` | `0x2D89B6` = 2,984,374 | **COMPRESSED** `kernel_size` |
| `0x024` | `0x800` = 2,048 | `page_size`; compressed stream begins at `0x800`, not `0x28` |
| `0x260` | `0x00000001` | extended first-page word; **UNKNOWN** exact semantics |
| `0x264` | `0xFA04A09A` | **VERIFIED** `CRC32` of precisely the `kernel_size` compressed bytes |
| `0x400` | `0x00000675` | extended first-page word; **UNKNOWN** |
| `0x7FC` | `0x89513F41` | extended first-page word/integrity policy; **UNKNOWN** |

zlib stream begins `78 DA`, then **1,610 original zero bytes** to next `0x800`-page alignment, then **157,696 original `0xFF` bytes** to file end `0x300000`. Do not assume generic Android `mkbootimg` preserves the extra original header-page words.

**Decoded QNX:** preboot size 8; QNX header size `0x100`; `startup_size=0x1A108`; `imagefs_size=0x66C29C`; `stored_size=0x6863A4`; `image_paddr=0x80A00808`; `startup_vaddr=0x80A06B40`. Actual header-declared ARM entry corresponds to decoded file offset `0x6340`, not the header start. The 106,760-byte startup includes code **and** non-code. Startup and ImageFS have separate terminal LE32 checksum words: their respective complete region's LE32 sums **including checksum** are each zero modulo `2^32`. Original startup checksum at `kernel[0x1A10C]` is `0xDF031729`.

## 3. Reproducible read-only inventory and extraction

1. Preserve the OEM archive/raw module in a PRIVATE immutable area and calculate SHA-256 before any other operation. Never copy OEM payloads into this public repo.
2. From repository root, check selected original modules/variants before materializing:

   ```powershell
   python .\tools\extract_firmware.py --source <PRIVATE_STOCK_UPDATE.7z> --variant both --component mmx --plan
   ```

3. If the complete MMX export is actually required, use a new private output directory and the exact expected original archive hash:

   ```powershell
   python .\tools\extract_firmware.py --source <PRIVATE_STOCK_UPDATE.7z> --output <NEW_PRIVATE_EXPORT> --variant both --component mmx --expected-sha256 b23225d68999f0613f2652c898ce36c74d6c1d63a36f29ff5d4faf500c60e5a5
   ```

   That path may unpack much larger app/EFS/Stage-2 material. For only Stage-1, prefer the previously manifest-verified standalone 3-MiB member from the private corpus.
4. Follow `android_image.py`: verify marker/outer LE32 header and `page_size + kernel_size <= source size`; read EXACTLY the declared zlib span at `page_size`, decompress with bounded output, demand stream EOF and no unused/trailing bytes inside that span; validate QNX header at decoded offset 8 and calculated ImageFS bounds/signature.
5. Independently compare raw member, zlib stream and decoded kernel hashes above; verify `8 + startup_size + imagefs_size == len(decoded_kernel)`; verify the independent startup and ImageFS LE32 sums are zero; verify outer compressed-stream CRC32 matches `0x264` in this exact sample; retain extraction manifest. Never confuse later `/proc/boot/startup.script` (an ImageFS file) with this early startup program.

## 4. Reproducible NO-CHANGE OEM wrapper reconstruction (PRIVATE/offline)

This is a **documented performed experiment**, not a public general-purpose Stage-1 writer or a deployable output format. Required input: *same-variant* original wrapper plus exact, immutable decoded kernel; keep first original `0x800` page unmodified.

1. Confirm the original exact hashes and checksum/bounds listed above; preserve the complete first header page (including unknown `0x260/0x400/0x7FC` words).
2. In the tested host runtime, `zlib.compress(unchanged_kernel, 9)` returns the original **2,984,374-byte** stream. Record Python (3.13.5) and linked runtime zlib (1.3.1); equality is empirical and may differ with another compressor/version.
3. Check **before any output** that `page_size + compressed_size <= 0x300000`. Compare compressed stream to the original and check its CRC32 against the original `0x264` field. In the no-change roundtrip the known `kernel_size` and CRC values remain identical.
4. Reconstruct with **original preserved 0x800 header page**, the actual compressed stream at `0x800`, `0x00` fill until next 0x800 boundary, and `0xFF` fill until exactly `0x300000`.
5. Require **whole outer byte-for-byte identity and SHA-256 equality** against the original OEM member; not merely equivalent decompression. Independently re-decode this newly constructed wrapper through the ordinary reader and reconfirm original kernel/startup/ImageFS hashes, the two additive QNX checksums and wrapper CRC. If whole-wrapper comparison fails, stop and document that the host environment did NOT reproduce OEM encoding.

| Python zlib level (tested original /50/) | Compressed bytes | Fits fixed 3 MiB? | Identical OEM stream? |
| ---: | ---: | --- | --- |
| 1 | 3,193,837 | **NO** (50,157 bytes over) | No |
| 6 | 2,988,743 | Yes | No |
| **9** | **2,984,374** | Yes | **YES, byte-for-byte** |

Original and unchanged reconstructed **entire** container SHA-256 = `694c707035fea415842d222f2993e90aad69ca539c1b3608631bd8182ceffc6c`. Exact /70/ wrapper roundtrip has **not** been independently performed in this specific exercise.

## 5. Separate benign OFFLINE differential test: what "patchable" actually proves

Only **after** the exact no-change roundtrip, a private fixture changed one harmless, **non-executable diagnostic string** in the decoded /50/ startup (`init_pllA` -> `init_pllB`; one ASCII byte, kernel offset `0x13C70`). This is **not** a PLL-setting or ARM-instruction patch. The independent QNX startup checksum at kernel offset `0x1A10C` changed `0xDF031729` -> `0xDF031728`; the complete independent QNX ImageFS remained byte-identical. A fresh LE32 checksum check gave zero for both regions.

The modified, private-only decoded kernel recompressed with level 9 to **2,984,373 bytes**, one fewer than stock. The actual compressed-byte count was reflected in wrapper `kernel_size` (offset `0x8`), and the verified compressed-stream CRC32 at outer `0x264` changed `0xFA04A09A` -> `0x9FC6E736`. Original extended page fields, including the **unexplained** `0x7FC`, were preserved *only as a test hypothesis*. Zero/FF padding was reconstructed for the actual new stream length. **Fresh independent re-decode PASS:** decoded kernel differed from the original only in the diagnostic character and its separate QNX checksum word; ImageFS was exactly unchanged; size remained `0x300000`; known checksum/CRC tests passed. No modified OEM wrapper is published here or qualified for boot.

This establishes a narrow, valuable engineering fact: a single decoded startup byte can be carried through an original-format **fixed-size wrapper** and recovered precisely, **without rebuilding every QNX filesystem or the 2.29-GB archive**. It does NOT prove any modified wrapper is accepted by the real stage loader, any SWDL installer or boot hardware.

## 6. Separate validation gates: build, repackage and install are NOT the same

```text
A. INNER QNX        startup last LE32 checksum; independent ImageFS last LE32 checksum
        ↓
B. zlib PAYLOAD     recompression can change many compressed bytes and its length
        ↓
C. MIFS1 WRAPPER    keep 3 MiB; kernel_size; observed compressed CRC32 at 0x264;
                   preserve/analyze unknown 0x260, 0x400, 0x7FC and fill
        ↓
D. SWDL PACKAGE     actual variant/module path; metainfo2 FileSize / CheckSumN;
                   hashes.txt / FinalScript checks / signed prefix / update.txt
        ↓
E. DEVICE ACCEPT    physical MMX partition selection, bootloader authentication,
                   erase blocks, primary/recovery policy, validated recovery route
```

**A–C:** original /50/ no-change equality passed; one inert-string modified private fixture passed known local checks, but **opaque integrity fields may still invalidate it**. **D:** `tools/metainfo2.py` can audit or refresh supported payload `FileSize` and chunked `CheckSum`/`CheckSumN` SHA-1 (observed typical `CheckSumSize=524288`) on a private *existing* SWDL tree; `hashes.txt`, `FinalScriptChecksum`, `MetafileChecksum` and the protected signed-prefix/editable-tail boundary require separate attention. `tools/update_txt.py` audits/refreshed fields of an *existing* transaction only. Neither tool gives a signature bypass or certifies accepted package semantics. Full SWDL reference: [REPACK_AND_METAINFO.md](REPACK_AND_METAINFO.md).

**E:** No public tool in this repository flashes a vehicle; the present evidence does **not** prove device-side acceptability or rollback of an altered Stage-1, nor NOR erase geometry or a unit-specific physical partition table.

### Why one original ARM byte does not mean a four-byte NOR write

The OEM Stage-1 on storage is **zlib-compressed**. A single byte edit in the decoded startup can change many bytes in the compressed stream, its length, its CRC, header fields and package checksums. The conservative logical update unit is therefore the **complete 3-MiB Stage-1 module**, not the kernel-relative four-byte instruction location. However, it is *not proven* that the whole physical 64-MiB NOR must be erased/programmed: [MHI2_FLASH_LAYOUT_AND_RECOVERY.md](MHI2_FLASH_LAYOUT_AND_RECOVERY.md) records a **historical G11** 64-MiB MMX map with **separate** `KERNEL_PRIMARY=[0x00760000,0x00A60000)` (3 MiB) and `KERNEL_RECOVERY` (6 MiB). The matching size is suggestive, but this map was **not verified on this exact MU1440 unit**. A firmware archive member size, boot image load address and reported flash slot address are different kinds of evidence.

## 7. Capability table, private evidence requirements and stopping rules

| Task | Evidence / current tool | Status |
| --- | --- | --- |
| Original .7z inventory and selected /50/ /70/ raw copy | `extract_firmware.py`, manifests | VALIDATED |
| Stage-1 custom wrapper read, zlib decode and ImageFS carve | `android_image.py` | VALIDATED read-only |
| Same-source QNX startup/header/checksum provenance | original private /50/ and R12/R13 comparison | VALIDATED for exact original |
| /50/ unchanged wrapper rebuild, level-9 zlib | private recorded check; original whole-byte identity | **PASS** (Python 3.13.5, zlib runtime 1.3.1) |
| One inert ASCII byte differential rewrap/re-decode | private recorded check; original ImageFS untouched | **PASS**, host-only, not boot-qualified |
| /70/ unchanged wrapper equality | need exact /70/ original wrapper as test input | NOT independently tested in this round |
| Generic QNX6/ImageFS tree writer | not integrated | NOT IMPLEMENTED |
| Extended header `0x260/0x400/0x7FC` semantics for modified images | one OEM sample is insufficient | UNKNOWN |
| Exact-device NOR partition, selected slot and updater validation | historical table only, no original raw MMX NOR/PT | UNKNOWN |
| Modified image accepted by BootROM/Quickboot/SWDL | NO live/boot/flash test | UNKNOWN |

**Completion checklist for any future private, host-only wrapper study:** exact source member and variant; immutable file length and SHA-256; Python/zlib versions; all header and field offsets; exact compressed stream length/CRC/SHA; QNX header/entry/bounds; startup and ImageFS SHA/checksum; original padding lengths; byte-by-byte no-change outer comparison; independent freshly decoded equality; all unknown extended fields; explicit confirmation that no image was flashed or executed. Store raw firmware, reconstructed binaries, altered fixtures and absolute local paths in private storage only. Public reports may include short generic format metadata, hashes, validation steps and evidence grades.

Related [MU1440 first-stage CPU-clock and qtime analysis](https://github.com/harman-f/mhi2_altscreen_carplay/pull/40) and [R12 source audit](https://github.com/harman-f/mhi2_altscreen_carplay/pull/38). These prove separate *analytical* properties; this wrapper reconstruction does not establish a safe early PLLX writer, voltage/OPP support, runtime qtime retiming, or BCT/SDRAM configuration.
