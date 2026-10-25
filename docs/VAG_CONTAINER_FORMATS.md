# VAG FRF, ODX and FPK_E/Data_X containers

This page covers the three supported VAG update layers in this toolkit. Each
step retains the source and writes into a new output directory. Extraction is
read-only and does not modify, sign, rebuild or flash firmware.

## Key requirements

The inner AES-128 key is required to decode ODX method `AA` payloads and
Skoda-style FPK_E/Data_X payloads. Supply it at run time using
`--key-file` (preferred) or the `FPKE_AES_KEY` environment variable. A key
file may contain either exactly 16 raw bytes or exactly 32 ASCII hexadecimal
digits (one final line ending is accepted); the environment variable accepts
exactly 32 ASCII hexadecimal digits. Do not put a key in a
command-line argument, source file, repository, report or output manifest.
The program records only whether a key was supplied; it never records key
bytes or a key hash.

FRF adds a separate outer rolling-XOR layer. Unwrapping an FRF therefore also
requires the corresponding VW_Flash-compatible **FRF key-material file** via
`--frf-key-file`. This is distinct from the 16-byte inner AES key. The FRF key
file is an external runtime dependency and is not bundled here.

## FRF outer layer

Decrypt one FRF to its single ODX member, without extracting arbitrary ZIP
paths:

```powershell
python tools/frf_odx_extract.py frf `
  --source .\update.frf `
  --output .\exports\frf-unwrapped `
  --frf-key-file .\secrets\frf.key
```

The tool checks the decrypted ZIP structure, rejects unsafe paths, links,
encrypted members and oversized members, requires exactly one ODX file, then
writes `unwrapped.odx` and `frf_manifest.json`. It does not decode the ODX's
FLASHDATA method.

The rolling-XOR algorithm follows `bri3d/VW_Flash` commit
`293f46d782bae2ced930497889b71eb782f122cb`, licensed under BSD-2-Clause. The
implementation is attributed in the source file and the license is included
in the repository's third-party notices.

## ODX payloads

Extract each `FLASHDATA/DATA` hex value to bytes and write an inventory:

```powershell
python tools/frf_odx_extract.py odx `
  --source .\update.odx `
  --output .\exports\odx-raw
```

For an FRF, use the `unwrapped.odx` output from the first step as the ODX
source. The resulting `flashdata/` files are raw bytes after XML hex
conversion. To also decode supported `AA` records, provide the separate inner
AES-128 key:

```powershell
python tools/frf_odx_extract.py odx `
  --source .\exports\frf-unwrapped\unwrapped.odx `
  --output .\exports\odx-decoded `
  --decode-aa `
  --key-file .\secrets\inner-aes128.key
```

For the observed three-FF terminal variant, add
`--allow-three-byte-ff-terminator`. It is opt-in; other unrecognized methods
remain inventoried raw. AES decoding requires the optional `cryptography`
Python package.

## FPK_E / Data_X

Decode Skoda `Data_X.bin` files, individually or in a directory, using the
maintained FPK_E reader:

```powershell
python tools/fpke_datax.py `
  --source .\Data_X `
  --output .\exports\fpke-decoded `
  --key-file .\secrets\inner-aes128.key
```

The source format version and all wrapper bounds are validated. The output
contains decoded streams, sparse records and hashes. `--analysis-fill 00` or
`--analysis-fill ff` may additionally create an explicitly synthetic image;
unknown gaps are not original firmware bytes. Cryptographic decoding requires
the optional `cryptography` Python package.

## Current limits

- A successful FRF or ODX extraction proves only the package/XML layer.
- ODX records with methods other than supported `AA` are retained raw.
- FPK_E/Data_X support applies only where the validated version-3 container
  structure matches; it is not a claim for every ECU or every ODX method.
- Decoded sparse records do not prove physical flash placement, signature
  validity or an original filesystem tree.
- Store proprietary firmware and all keys outside this public repository.
