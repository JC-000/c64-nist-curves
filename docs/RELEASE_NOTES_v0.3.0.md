# c64-nist-curves v0.3.0 — Release Notes

Released 2026-05-20. Compared to v0.2.0 (2026-05-12).

This is a MINOR release. v0.3.0 lands full [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
SPEC §1–§6 + §8.1 adoption — downstream consumers (`c64-https`,
`c64-wireguard`, future TLS / IPsec clients) now integrate the library
via `make lib-<variant>` archive targets and per-section override
equates without patching library sources. Additionally adds full
Jacobian+Jacobian point addition primitives, a streaming SHA-384
implementation with a one-shot ECDSA-with-message wrapper, and
expanded benchmark coverage. No public symbols were removed or
renamed; `LIB_ABI_VERSION` remains `0`.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md); this
file is the concise release summary.

## What's new

### Added — c64-lib-contract integration

- **SPEC §1 — version equates.** Added `LIB_ABI_VERSION = 0` to
  `src/lib_version.s` alongside the existing
  `LIB_VERSION_MAJOR/MINOR/PATCH`. Bumps in lockstep on breaking
  exports. PR #48.
- **SPEC §3 — REU symbol contract.** New `src/reu_config.s` exports
  four `.ifndef`-guarded `:abs` equates: `LIB_NISTCURVES_REU_BANK_MUL`
  (default `$00`; claims banks MUL and MUL+1),
  `LIB_NISTCURVES_REU_BANK_COMB` (default `$02`),
  `LIB_NISTCURVES_REU_OFFSET_COMB_P256` / `_P384`. Consumer override:
  `ca65 --asm-define LIB_NISTCURVES_REU_BANK_COMB=$05 ...`. PR #43.
- **SPEC §4 — segment naming.** Per-curve / per-feature
  `LIB_NISTCURVES_*` segments: `LIB_NISTCURVES_P256_CODE` / `_RODATA`,
  `LIB_NISTCURVES_P384_CODE` / `_RODATA` / `_BSS`,
  `LIB_NISTCURVES_SHA384_CODE` / `_RODATA` / `_TABLES`,
  `LIB_NISTCURVES_MUL_CODE`, `LIB_NISTCURVES_TABLES`,
  `LIB_NISTCURVES_BSS`. `src/c64.cfg` SEGMENTS{} alias block keeps the
  standalone PRG byte-identical (37302 B). Closes #41. PR #45.
- **SPEC §5 — aggregate manifest equates.** New `src/lib_manifest.s`
  exports `LIB_NISTCURVES_REU_BANKS_USED = $07`,
  `LIB_NISTCURVES_ZP_USAGE_BYTES = 31`,
  `LIB_NISTCURVES_RESIDENT_BYTES = 27000`,
  `LIB_NISTCURVES_COLD_BYTES = 2500`. Consumer cfgs use these for
  assemble-time fit checks against ld65 `__<MEMORY>_SIZE__` symbols.
  Closes #42. PR #46.
- **SPEC §6 — build target variants.** Five `make lib*` archive
  targets published under `build/lib/nistcurves-*.a`:
  - `lib` — full archive (26 objects).
  - `lib-p256-verify` — P-256 verify-path only (12 objects).
  - `lib-p384-verify` — P-384 verify-path only (12 objects).
  - `lib-p384-sha384` — SHA-384-only (4 objects; no REU, no multiply
    tables, since SHA-384 is self-contained).
  - `lib-p384-curve` — full P-384 incl. comb tables (15 objects).
  Closes #40. PR #47.
- **SPEC §8.1 — shared `sqtab` primitive.** `sqtab_lo` / `sqtab_hi`
  in `src/mul_8x8.s` now derive from `LIB_SHARED_SQTAB_BASE` —
  `.ifndef`-guarded with default `$9c00`, overridable via
  `ca65 --asm-define LIB_SHARED_SQTAB_BASE=$<addr>` so multiple
  sqtab-using sibling libs (this lib, `c64-x25519`,
  `c64-ChaCha20-Poly1305`) linked into one PRG agree on placement.
  Two `.assert` guards catch placement misconfigurations at assemble
  time. `sqtab_init` body gated on `.ifndef SHARED_SQTAB_INIT` so a
  shared-primitives module can supply the canonical `mul_tables_init`.
  Manifest bitmask: `LIB_NISTCURVES_SHARED_PRIMITIVES = $0001`. PR #50.
  Tracking issue [JC-000/c64-lib-contract#5](https://github.com/JC-000/c64-lib-contract/issues/5);
  SPEC patch [JC-000/c64-lib-contract#6](https://github.com/JC-000/c64-lib-contract/pull/6).

### Added — public API surface

- **`ec_point_add_jj`, `ec_point_add_jj_384`** — full Jacobian +
  Jacobian point addition (Bernstein-Lange add-2007-bl formula:
  11M + 5S + ~10 add/sub). Handles `P1=∞`, `P2=∞`, both-∞, same
  projective point (tail-calls `ec_point_double`), and `P1=-P2`
  (zeros result) natively. Used by `ecdsa_verify_*` at the
  `u1*G + u2*Q` join — eliminates the affine conversion + binary-GCD
  inversion the v0.2.0 mixed-add path used to need. One added scratch
  slot per curve (`ec_jj_tmp` 32 B / `ec384_jj_tmp` 48 B). The
  existing mixed `ec_point_add` / `ec_point_add_384` stay load-bearing
  for the Lim-Lee comb evaluate loop. PR #34.
- **`sha384_init`, `sha384_update`, `sha384_final`** — streaming
  SHA-384 implementation (FIPS 180-4 §6.4). Algorithm is SHA-512
  compression with the SHA-384 IV; on-chip output is `H[0..5]`
  truncated to 48 bytes. Self-contained — no REU DMA, no shared
  `mul_*` / `fp_*` ZP slots. ~2 KB DATA + ~1.7 KB code. Test coverage
  in `tools/test_sha384.py` (25/25 in `--full` mode: 4 FIPS KATs + 17
  boundary lengths + 4 multi-block stress lengths). PR #38.
- **`ecdsa_verify_with_message_384`** — one-shot SHA-384-then-verify
  wrapper with the same A/X-pointer ABI and 240 B BE struct layout as
  `ecdsa_verify_384`. The `h` slot is overwritten with the computed
  digest, so callers may leave it zero. Caller pre-sets ZP
  `sha_src` / `sha_len` to point at the message; the wrapper runs
  `sha384_init / sha384_update / sha384_final`, splices `sha384_digest`
  into the struct, then tail-calls `ecdsa_verify_384`. Streaming
  caveat: single `update` call; TLS-style multi-buffer transcripts
  drive `sha384_*` directly + `jsr ecdsa_verify_384` with the digest
  pre-spliced. Lives in `src/ecdsa384_msg.s` so `lib-p384-verify` /
  `lib-p384-sha384` archives can exclude it cleanly. PR #38.

### Added — tooling

- **`build/nist-curves.dbg`** — cc65 `.dbg` source-line debug-info
  artifact. Generated via ca65 `-g` + ld65 `--dbgfile`. Loadable by
  VICE binary monitor (`monitor> dbgfile build/nist-curves.dbg`) for
  source-level stepping / breakpoints / span lookup. PRG is
  byte-identical with or without `-g` (verified by sha256 round-trip).
- **Bench coverage for J+J + mod-n mul primitives** — four new rows
  in `tools/bench_p256.py` / `bench_p384.py` (VICE) and
  `bench_p256_u64.py` / `bench_p384_u64.py` (U64E). Closes the
  primitive-vs-compound divergence gap the PR #26 / PR #34
  measured-vs-predicted retrospective surfaced (see
  `feedback_empirical_validation_required`). PR #37.
- **`tools/build_release.sh`** unchanged from v0.2.0 — `make dist
  VERSION=v0.3.0` produces a deterministic tarball.

### Fixed

- **Issue #18-class** — `reu_fetch_mul_row` confirmed living in
  `src/mul_8x8.s` (not `src/main.s`) so standalone-link consumer
  builds resolve `fp_sqr_384` cleanly. Verified by the SPEC §6
  archive targets which exclude `main.s`. (Originally landed in v0.2.0;
  preserved through the §4 segment-rename refactor.)
- **`sqtab` memory-map robustness** — the 2026-05-17 corruption
  failure mode (code growth pushing neighbouring data into the fixed
  sqtab base and silently corrupting the multiply table at boot) is
  now caught at assemble time by the SPEC §8.1 `.assert` guards
  (page-aligned base + `$0200` lo→hi delta). PR #50.

See [`CHANGELOG.md`](../CHANGELOG.md) `## [0.3.0]` for the complete
per-bullet list, including earlier `[Unreleased]` items not
summarised above (the J+J formula derivation notes, the SHA-384
endianness contract, the `fp_mod_mul_n` callsite measurements, the
Wave 5c / cofactor-compare retrospective entries, etc.).

## Upgrade notes for consumers

- **Semver minor bump.** Additive only. Existing v0.2.0 symbol calls
  remain ABI-compatible — `ec_scalar_mul_var`, `ecdsa_verify_*`,
  `ec_point_add`, `ec_point_double`, `fp_mod_mul_n`, `fp_reverse*` all
  unchanged in calling convention.
- **`LIB_VERSION_MINOR` is now `3`** in `src/lib_version.s`. Update
  any `.if LIB_VERSION_MINOR < ... / .error` compatibility gates.
  `LIB_ABI_VERSION` remains `0`.
- **Consumer integration shape.** New consumers should target the
  SPEC §6 archive (`make lib-p256-verify` / `make lib-p384-verify` /
  etc.) and override §3 REU equates / §8.1 `LIB_SHARED_SQTAB_BASE`
  via `ca65 --asm-define`. No source patching at integration time.
  See `API.md` §8.2–§8.4 for the archive contract.
- **`ecdsa_verify_with_message_384`** is the recommended entry point
  for TLS 1.3 secp384r1 verify with a contiguous message buffer.
  Multi-buffer transcripts drive SHA-384 streaming directly.

## Tarball

`c64-nist-curves-v0.3.0.tar.gz` is produced reproducibly by
`make dist VERSION=v0.3.0`. Canonical artifact:

- Size:   131703 bytes
- SHA256: `4af116343458fce4059b5f1372ac1b49fe9326fdb8c78cef0bddd54a8fa3715e`

Re-running `make dist VERSION=v0.3.0` against this tag must reproduce
the recorded SHA256 byte-for-byte (`git archive` is deterministic;
`gzip -n` drops the gzip timestamp header). The canonical vendoring
file list lives in `tools/build_release.sh`; if you add a new
`src/*.s` file, update both the `MODULES` list in `Makefile:19` AND
the `git archive` invocation in `tools/build_release.sh`.

## Verification

All 1082 VICE oracle-gated tests pass on a quiet machine (no
contending VICE processes):

| Suite                       | Result            |
|-----------------------------|-------------------|
| `test_fp256.py`             | 471 / 471 PASS    |
| `test_fp384.py`             | 473 / 473 PASS    |
| `test_points256.py`         | 41 / 41 PASS      |
| `test_points384.py`         | 41 / 41 PASS      |
| `test_ecdsa_verify.py`      | 35 / 35 PASS      |
| `test_sha384.py`            | 21 / 21 PASS      |

Per-suite counts increased from v0.2.0 (then 1038 across 5 suites)
because the v0.3.0 surface adds:

- `test_sha384.py` (new — 21 vectors: 4 FIPS 180-4 KATs + 17
  boundary lengths).
- `test_points256.py` / `test_points384.py` (41 each, up from 33)
  — bench-coverage additions in PR #37 require new oracle
  cross-checks for the J+J primitive at non-trivial-Z inputs.
- `test_ecdsa_verify.py` (35, up from 28) — CAVP SigVer slice
  expanded as part of the SHA-384 wrapper coverage.

VICE bench primitive cycles were re-measured against this release
prep and match the published `README.md` table within ~3%
(sub-jiffy precision on small-cost routines; ~0.2% on the
headline `ec_scalar_mul`). No `README.md` numbers needed
refresh.

U64E (Ultimate 64 Elite hardware) cycle benchmarks for `v0.3.0`
were SKIPPED during release prep — the lab fixture (`U64_HOST`)
was unavailable to the release-gate test runner. The library
code path for ECDSA verify and point operations is byte-identical
to the PR #50 merge commit on master (`0b601b9`), so the v0.2.0
U64E numbers in `README.md` (captured 2026-05-18 at master
`788adc3`) remain approximately valid for primitives that did not
gain measurement coverage in this release. The new J+J +
`fp_mod_mul_n` primitive numbers from PR #37 measurements (already
in `README.md` and in `CHANGELOG.md` under "Bench coverage for
`ec_point_add_jj{,_384}` and `fp_mod_mul_n{,_384}`") are the
authoritative numbers for those rows. A post-release U64E
retrospective will publish refreshed numbers once the lab
fixture is back online.

## Cross-references

- [c64-lib-contract](https://github.com/JC-000/c64-lib-contract) —
  the umbrella SPEC this release integrates with. Specifically:
  - PR [#6](https://github.com/JC-000/c64-lib-contract/pull/6) — SPEC §8 + §8.1 patch (merged 2026-05-20).
  - PR [#7](https://github.com/JC-000/c64-lib-contract/pull/7) — adopters.md §8 column (merged 2026-05-20).
  - PR [#8](https://github.com/JC-000/c64-lib-contract/pull/8) — adopters.md §8 status corrections (merged 2026-05-20).
- [c64-x25519 PR #56](https://github.com/JC-000/c64-x25519/pull/56) — concurrent §8.1 adopter (sibling lib).
- [c64-ChaCha20-Poly1305 issue #40](https://github.com/JC-000/c64-ChaCha20-Poly1305/issues/40) — §8.1 adoption tracking.
- This release's PRs against the c64-nist-curves repo: #34 (J+J),
  #37 (bench coverage), #38 (SHA-384 + msg wrapper), #43 (§3 REU),
  #45 (§4 segments), #46 (§5 manifest), #47 (§6 archives), #48 (§1
  `LIB_ABI_VERSION`), #49 (docs refresh), #50 (§8.1 sqtab).
