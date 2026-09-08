#!/bin/sh
# Negative-test driver for issue #142.
#
# Runs `make check-archives` with a fault-injecting od65 on PATH, so the
# sentinel branches in od65_export_names() / od65_export_records() -- the
# COUNT_MISMATCH and unreadable-dump paths that no real input produces -- can
# be observed firing.
#
#   usage: tools/negative/run_od65_fault.sh <object-basename> <count|unread> <outfile>
#
#   <object-basename>  e.g. lib_version_ungated.o  (the ungated arm of the
#                      gated-surface leg) or lib_version.o (the gated arm).
#                      Objects under a build/ directory are passed through
#                      untouched unless OD65_ALLOW_BUILD is set, so the shim
#                      hits only the leg's own scratch assembly.
#   count              delete one `Name:` line, leaving od65's own Count
#                      record intact  -> COUNT_MISMATCH
#   unread             exit 1 with no output                 -> None
#
# Observed results are recorded in the issue #142 audit table.
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
OD65_REAL=$(command -v od65)
export OD65_REAL
OD65_TARGET="$1"
OD65_MODE="$2"
export OD65_TARGET OD65_MODE
PATH="$DIR/shimbin:$PATH"
export PATH
set +e
make -C "$DIR/../.." check-archives > "$3" 2>&1
echo "rc=$?"
