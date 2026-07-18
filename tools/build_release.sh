#!/bin/bash
# tools/build_release.sh -- build a reproducible source tarball for a tagged release.
#
# Usage:
#   tools/build_release.sh <tag>
#   e.g. tools/build_release.sh v0.2.0
#
# Output: c64-nist-curves-<tag>.tar.gz in the repo root, plus the byte
# size and SHA256 printed to stdout. The script is location-aware and
# can be invoked from anywhere.
#
# Determinism: git archive is byte-deterministic for a given commit,
# and `gzip -n` drops the gzip timestamp/filename header. The same tag
# therefore always produces a byte-identical tarball. Re-running this
# script must reproduce the SHA256 recorded in the matching
# docs/RELEASE_NOTES_<tag>.md.
#
# File list: the canonical v0.3.0+ vendoring set. `src/*.s` (canonical
# ca65 sources only; legacy `.asm` ACME variants are excluded), the
# linker config, the exports header, and the top-level docs that
# consumers reference. The Makefile is included so consumers can
# `make` from the extracted tarball without re-deriving the build
# rules. `src/main.s` is included; per API.md §8.2 consumers should
# omit it from their own link list because it is the library's own
# test/bench driver, but it ships in the tarball so the upstream's
# bench/test driver is reproducible from the artifact.
#
# v0.3.0 file-list refresh: source tree split per c64-lib-contract
# SPEC §4/§6 adoption (PRs #45/#47). The `src/data.s`/`src/points*.s`
# entries from the v0.2.0 list are split into per-curve/per-feature
# files, and SPEC §1/§3/§5/§8.1 + SHA-384 land new source modules
# (`reu_config.s`, `lib_manifest.s`, `sha384.s`, `ecdsa384_msg.s`).
# The MODULES list in the Makefile is the authoritative source — if
# you add a new src/*.s file, add it both to MODULES (Makefile:19)
# AND to the git-archive call below.
#
# v0.4.0 file-list refresh: src/data_p256_invref.s (issue #54 BSS
# split, PR #59) and the two tools that back Makefile targets shipped
# in the tarball — tools/check_archives.py (make check-archives, PR #62)
# and tools/bench_reu_mult.py (PR #58) — are now vendored so an
# extracted tarball can run those targets without re-fetching the repo.
#
# Make convenience target: `make dist VERSION=v0.4.0`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

if ! git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "tag '$TAG' not found (run 'git fetch --tags' to refresh)" >&2
  exit 1
fi

NOTES="docs/RELEASE_NOTES_${TAG}.md"
if ! git cat-file -e "${TAG}:${NOTES}" 2>/dev/null; then
  echo "release notes '${NOTES}' not present at tag '${TAG}'" >&2
  exit 1
fi

OUT="c64-nist-curves-${TAG}.tar.gz"

git archive \
  --prefix="c64-nist-curves-${TAG}/" \
  --format=tar \
  "$TAG" \
  src/c64.cfg src/exports.inc \
  src/constants.s src/zp_config.s \
  src/lib_version.s src/lib_manifest.s src/reu_config.s \
  src/main.s src/mul_8x8.s \
  src/fp256.s src/mod256.s src/curve256.s src/inv256.s \
  src/points256_core.s src/points256_comb.s src/ecdsa256.s \
  src/fp384.s src/mod384.s src/curve384.s \
  src/points384_core.s src/points384_comb.s \
  src/ecdsa384.s src/ecdsa384_msg.s src/sha384.s \
  src/data_shared.s \
  src/data_p256.s src/data_p256_invref.s src/data_p256_limlee.s \
  src/data_p384.s src/data_p384_limlee.s \
  src/data_sha.s src/data_test.s \
  Makefile tools/build_release.sh \
  tools/check_archives.py tools/bench_reu_mult.py \
  README.md API.md CHANGELOG.md CLAUDE.md VERSION \
  "$NOTES" \
  | gzip -n -9 > "$OUT"

SIZE=$(wc -c < "$OUT" | tr -d ' ')
SHA=$(shasum -a 256 "$OUT" | cut -d' ' -f1)

echo "Built ${OUT}"
echo "  Size:   ${SIZE} bytes"
echo "  SHA256: ${SHA}"
