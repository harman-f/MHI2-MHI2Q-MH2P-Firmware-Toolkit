# AGENTS.md

## Repository purpose

This repository is the public, standalone MHI2/MHI2Q/MH2P firmware analysis toolkit.
Treat it as an independent project. Do not depend on private research repositories,
private workstations, private caches, or unpublished firmware corpora.

## Public-repository boundary

- Never add references to private/internal research repositories, issue trackers,
  local drive layouts, user names, machine-specific cache paths, or private source trees.
- Do not commit firmware archives, extracted firmware trees, device dumps, JXE/JAR/class
  outputs, reverse-engineering databases, generated unit data, private keys, credentials,
  or vehicle-identifying data.
- External projects without a clear redistribution license may be documented and pinned,
  but their source/binaries must not be vendored here.
- Keep generated analysis outputs outside Git. Prefer small synthetic fixtures for tests.

## Mandatory MMX/RCC on-unit shell handoff boundary

**This toolkit is a HOST-SIDE firmware inspection project.** Its host `bash`,
Python, 7z, zlib and GNU tool availability must **never** be transferred to
QNX MMX or RCC command instructions. Before authoring or handing over a target
`.sh`/`.ksh`, a diagnostic ZIP, or even a short direct-shell command:

- Consult the public exact-target [MU1440 QNX compatibility contract](https://github.com/harman-f/mhi2_altscreen_carplay/blob/main/docs/testing/MU1440_QNX_SHELL_COMPATIBILITY.md) and the corresponding CarPlay root `AGENTS.md` (tracked in its [agent/preflight PR #42](https://github.com/harman-f/mhi2_altscreen_carplay/pull/42)).
- **Vehicle-proven MMX:** external `printf` fails with `cannot execute - No such file or directory`. Avoid it entirely. Also do not assume `sed`, `tr`, stock `sha256sum`/`tee`, GNU `date` options, `grep 'A\\|B'`, or an existing M.I.B. apps/sbin tree.
- Keep MMX (Tegra) and RCC (Jacinto) separate. A command, `/dev` getter, mount or sensor proven on one is not automatically available on the other. Every program, option, path and output-format dependency requires evidence appropriate to the target board.
- Run the CarPlay project's standalone HOST-ONLY QNX script checker (or exact copy) on **every** delivered on-unit shell script, including private external ZIP contents, with its `printf` regression fixture. Linux `bash -n`/mock tests do not establish QNX command compatibility. Preserve logs from the first actual hardware test. If any check cannot establish availability, stop or mark as an optional failure.
- This is an **authoring/packaging gate**; it does not make QNX executables mandatory for this repository's normal host-side extraction tools and does not authorize any flashing, PLL, PMIC, QNX qtime or production-unit write.

## Safety and scope

The default toolkit is host-side and read-only with respect to firmware inputs. Do not add
vehicle-side flashing, destructive update, credential deployment, bypass, or write paths
without a separate explicit design review. Parsers must reject unsafe paths, bounds errors,
collisions, malformed containers, and output-directory reuse.

## Maturity labels

- `tools/` contains the supported public core.
- `tools/experimental/` contains bounded research-derived probes whose format coverage is
  intentionally incomplete. The MH2P/Alpine Stage-2 probes are validated against one VW G36
  P2838 baseline; do not describe that as universal MH2P support.
- External LSD/JXE tooling remains external. The wrapper under `tools/jxe2jar/` must pin
  and verify an upstream commit rather than copy unlicensed upstream code.

## Changes

For every code change:

1. preserve standalone imports and public paths;
2. add or update synthetic tests for parser behavior and malformed-input bounds;
3. run `python -m compileall -q tools tests`;
4. run `python -m unittest discover -s tests -v`;
5. update user-facing documentation when capability, dependency, or support boundaries change;
6. record exact upstream repository/commit references for external tooling changes.

Do not weaken path validation, size limits, fresh-output rules, checksum verification,
or metadata-only handling of symlinks/device nodes merely to accept one sample.

## Operational documentation

Before choosing or invoking a tool, read `docs/FIRMWARE_IMAGE_PRIMER.md`, `docs/TOOL_GUIDE.md` and `docs/AGENT_PLAYBOOK.md`. For MH2P/Alpine work, also read `docs/MH2P_GUIDE.md`. Treat these files as the public operational entry points for humans and AI agents; source docstrings remain implementation-level documentation and do not override stated support boundaries.

## Documentation claims

Separate measured evidence from inference. State the exact firmware family or sample used
for validation. A successful extraction from one firmware train is not evidence of universal
compatibility. In particular, the current MH2P/Alpine evidence is one VW G36 P2838 baseline. Keep historical validation reports dated and do not silently rewrite their
measurements to match later tooling.

## GitHub / CI

Actions should use least-privilege permissions and immutable commit SHAs where practical.
Pull requests must pass the Python test matrix and public-hygiene checks before merge.
Do not modify or publish from the archived `_old` repository; all active development belongs
in this repository.
