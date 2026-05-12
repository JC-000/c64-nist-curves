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
# File list: the canonical v0.2.0+ vendoring set. `src/*.s` (canonical
# ca65 sources only; legacy `.asm` ACME variants are excluded), the
# linker config, the exports header, and the top-level docs that
# consumers reference. `src/main.s` is included; per API.md §8.2
# consumers should omit it from their own link list because it is the
# library's own test/bench driver, but it ships in the tarball so the
# upstream's bench/test driver is reproducible from the artifact.
#
# Make convenience target: `make dist VERSION=v0.2.0`.

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
  src/constants.s src/curve256.s src/curve384.s src/data.s \
  src/ecdsa256.s src/ecdsa384.s src/exports.inc src/fp256.s \
  src/fp384.s src/inv256.s src/lib_version.s src/main.s \
  src/mod256.s src/mod384.s src/mul_8x8.s src/points256.s \
  src/points384.s src/zp_config.s src/c64.cfg \
  README.md API.md CHANGELOG.md CLAUDE.md VERSION \
  "$NOTES" \
  | gzip -n -9 > "$OUT"

SIZE=$(wc -c < "$OUT" | tr -d ' ')
SHA=$(shasum -a 256 "$OUT" | cut -d' ' -f1)

echo "Built ${OUT}"
echo "  Size:   ${SIZE} bytes"
echo "  SHA256: ${SHA}"
