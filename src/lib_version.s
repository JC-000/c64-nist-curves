.setcpu "6502"

; =============================================================================
; c64-nist-curves library version constants (c64-lib-contract SPEC §1)
;
; Consumers import these for assembly-time compatibility checks:
;
;   .import LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH
;   .import LIB_ABI_VERSION
;
;   .if LIB_VERSION_MAJOR <> 0 .or LIB_VERSION_MINOR < 1
;       .error "c64-nist-curves v0.1.0 or newer is required"
;   .endif
;
;   .if LIB_ABI_VERSION <> 0
;       .error "c64-nist-curves ABI v0 expected; rebuild consumer"
;   .endif
;
; Versioning policy: semver 2.0.0 — https://semver.org/
;   MAJOR — incompatible API changes (symbol removals, calling convention)
;   MINOR — additive API changes (new exports, no removals/renames)
;   PATCH — bugfix or perf improvement with no API change
;   ABI   — bumped on any breaking export change; matches MAJOR per
;           c64-lib-contract SPEC §1. The load-bearing breakage gate
;           for consumers pinning to a specific ABI generation.
;
; The library is currently in the v0.x pre-stable series. MINOR bumps may
; add public symbols but will not remove or rename existing symbols without
; a MAJOR bump. Consumers should pin to a specific git tag, not track the
; mainline branch.
; =============================================================================

LIB_VERSION_MAJOR = 0
LIB_VERSION_MINOR = 2
LIB_VERSION_PATCH = 0
LIB_ABI_VERSION   = 0

.export LIB_VERSION_MAJOR
.export LIB_VERSION_MINOR
.export LIB_VERSION_PATCH
.export LIB_ABI_VERSION:abs
