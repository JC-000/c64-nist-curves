.setcpu "6502"

; =============================================================================
; c64-nist-curves library version constants (c64-lib-contract SPEC §1)
;
; Consumers import these for assembly-time compatibility checks:
;
;   .import LIB_NISTCURVES_VERSION_MAJOR, LIB_NISTCURVES_VERSION_MINOR
;   .import LIB_NISTCURVES_VERSION_PATCH, LIB_NISTCURVES_ABI_VERSION
;
;   .if LIB_NISTCURVES_VERSION_MAJOR <> 0 .or LIB_NISTCURVES_VERSION_MINOR < 1
;       .error "c64-nist-curves v0.1.0 or newer is required"
;   .endif
;
;   .if LIB_NISTCURVES_ABI_VERSION <> 0
;       .error "c64-nist-curves ABI v0 expected; rebuild consumer"
;   .endif
;
; TU isolation (SPEC §1, required as of contract v0.7.0): this file
; exports the four version equates and NOTHING else -- no §5 aggregate
; manifest equates (those live in src/lib_manifest.s), no §8.4 precalc
; table equates (src/precalc_manifest.s), no code. ld65 pulls in whole
; object members, so if the deprecated bare names below shared a member
; with anything a consumer legitimately imports they would enter the link
; uninvited and collide even when the consumer never referenced them.
; Keep this file single-purpose.
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

; -----------------------------------------------------------------------------
; Library-prefixed forms (SPEC §1, canonical since contract v0.7.0)
; -----------------------------------------------------------------------------
; `NISTCURVES` is this library's UPPER_SNAKE_CASE `<X>` -- the same prefix
; used by the §5 aggregate equates in src/lib_manifest.s. The prefix is
; what makes these importable alongside a sibling library's manifest.
; -----------------------------------------------------------------------------
LIB_NISTCURVES_VERSION_MAJOR = 0
LIB_NISTCURVES_VERSION_MINOR = 8
LIB_NISTCURVES_VERSION_PATCH = 0
LIB_NISTCURVES_ABI_VERSION   = 0

.export LIB_NISTCURVES_VERSION_MAJOR:abs
.export LIB_NISTCURVES_VERSION_MINOR:abs
.export LIB_NISTCURVES_VERSION_PATCH:abs
.export LIB_NISTCURVES_ABI_VERSION:abs


; -----------------------------------------------------------------------------
; Deprecated bare forms (SPEC §1; removed at contract v1.0)
; -----------------------------------------------------------------------------
; These names are identical across every adopter of the contract, so a
; consumer that links two sibling libraries and imports both manifests
; gets `ld65: Error: Duplicate external identifier` (lib-contract #43 --
; measured upstream between c64-x25519 v0.8.0 and c64-ChaCha20-Poly1305
; v0.6.0). They stay emitted BY DEFAULT so every existing single-library
; consumer keeps working unchanged; a consumer composing two or more
; libraries suppresses them build-wide with
;
;   ca65 -D LIB_NO_BARE_EXPORTS=1
;
; and imports the prefixed forms above instead -- which additionally lets
; a version guard name WHICH library is out of date rather than reporting
; one anonymous version.
;
; Aliased to the prefixed equates rather than restating the literals, so a
; release bump touches four lines instead of eight and the two forms
; cannot drift.
; -----------------------------------------------------------------------------
.ifndef LIB_NO_BARE_EXPORTS
    LIB_VERSION_MAJOR = LIB_NISTCURVES_VERSION_MAJOR
    LIB_VERSION_MINOR = LIB_NISTCURVES_VERSION_MINOR
    LIB_VERSION_PATCH = LIB_NISTCURVES_VERSION_PATCH
    LIB_ABI_VERSION   = LIB_NISTCURVES_ABI_VERSION

    .export LIB_VERSION_MAJOR:abs
    .export LIB_VERSION_MINOR:abs
    .export LIB_VERSION_PATCH:abs
    .export LIB_ABI_VERSION:abs
.endif
