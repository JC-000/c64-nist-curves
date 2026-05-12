.setcpu "6502"

; =============================================================================
; c64-nist-curves library version constants
;
; Consumers import these for assembly-time compatibility checks:
;
;   .import LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH
;
;   .if LIB_VERSION_MAJOR <> 0 .or LIB_VERSION_MINOR < 1
;       .error "c64-nist-curves v0.1.0 or newer is required"
;   .endif
;
; Versioning policy: semver 2.0.0 — https://semver.org/
;   MAJOR — incompatible API changes (symbol removals, calling convention)
;   MINOR — additive API changes (new exports, no removals/renames)
;   PATCH — bugfix or perf improvement with no API change
;
; The library is currently in the v0.x pre-stable series. MINOR bumps may
; add public symbols but will not remove or rename existing symbols without
; a MAJOR bump. Consumers should pin to a specific git tag, not track the
; mainline branch.
; =============================================================================

LIB_VERSION_MAJOR = 0
LIB_VERSION_MINOR = 2
LIB_VERSION_PATCH = 0

.export LIB_VERSION_MAJOR
.export LIB_VERSION_MINOR
.export LIB_VERSION_PATCH
