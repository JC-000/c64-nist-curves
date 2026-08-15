.setcpu "6502"

; =============================================================================
; c64-nist-curves library version constants (c64-lib-contract SPEC §1)
;
; Consumers import these for link-time compatibility checks:
;
;   .import LIB_NISTCURVES_VERSION_MAJOR, LIB_NISTCURVES_VERSION_MINOR
;   .import LIB_NISTCURVES_VERSION_PATCH, LIB_NISTCURVES_ABI_VERSION
;
;   .assert (LIB_NISTCURVES_VERSION_MAJOR > 0) .or (LIB_NISTCURVES_VERSION_MINOR >= 9), lderror, "c64-nist-curves v0.9 or newer is required"
;   .assert LIB_NISTCURVES_ABI_VERSION = 1, lderror, "c64-nist-curves ABI v1 expected; rebuild consumer"
;
; Why `.assert`/`lderror` and not `.if`/`.error`: `.if` requires an
; assembly-time constant, but an `.import`ed symbol has no value until
; link -- ca65 rejects the `.if` form outright with "Error: Constant
; expression expected" rather than silently accepting or skipping it
; (c64-lib-contract issue #73). `.assert ..., lderror, ...` defers the
; check to ld65, which is the first stage that actually knows the
; imported constant's value. The trade: the guard now fires at LINK
; time instead of assemble time -- one step later in the build, but
; still strictly before any generated code runs, so a consumer that
; violates the requirement still finds out with the same immediacy
; a broken build implies, just not until `ld65` runs rather than at
; `ca65` on the guard's own translation unit.
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
;   ABI   — bumped on any breaking export change. The load-bearing
;           breakage gate for consumers pinning to a specific ABI
;           generation.
;
;           NOTE on the value. SPEC §1/§7 describe this as "matching the
;           MAJOR component", but that reading cannot hold pre-1.0: §7
;           also states breaking changes ride MINOR bumps while the
;           contract is in v0.x, so MAJOR stays 0 across exactly the
;           breakage this gate exists to catch. Every sibling adopter
;           (c64-x25519, c64-ChaCha20-Poly1305, c64-polyval) treats it as
;           an independent generation counter starting at 1, and SPEC §7's
;           own worked example gates on `!= 1`. This library shipped 0
;           from v0.3.0 through v0.8.0 — the outlier — which left the gate
;           silent on the v0.9.0 export removals. Bumped to 1 at v0.9.0.
;
; The library is currently in the v0.x pre-stable series. Per SPEC §7,
; breaking changes ride MINOR bumps while pre-1.0, so a MINOR bump CAN
; remove or rename exported symbols — v0.9.0 removed 17. Watch
; LIB_NISTCURVES_ABI_VERSION rather than assuming MINOR is always safe,
; and pin to a specific git tag rather than tracking the mainline branch.
; =============================================================================

; -----------------------------------------------------------------------------
; Library-prefixed forms (SPEC §1, canonical since contract v0.7.0)
; -----------------------------------------------------------------------------
; `NISTCURVES` is this library's UPPER_SNAKE_CASE `<X>` -- the same prefix
; used by the §5 aggregate equates in src/lib_manifest.s. The prefix is
; what makes these importable alongside a sibling library's manifest.
; -----------------------------------------------------------------------------
LIB_NISTCURVES_VERSION_MAJOR = 0
LIB_NISTCURVES_VERSION_MINOR = 11
LIB_NISTCURVES_VERSION_PATCH = 0
LIB_NISTCURVES_ABI_VERSION   = 2

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
