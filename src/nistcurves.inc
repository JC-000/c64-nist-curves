; =============================================================================
; nistcurves.inc — consumer-facing header for c64-nist-curves
;                  (c64-lib-contract SPEC §6.1: `make lib` ships the archive
;                   PLUS this header and an example .cfg)
;
; `make lib`, and every `make lib-*` variant target, copies this file to
; build/lib/nistcurves.inc next to the archive. Vendor it with the archive
; and `.include "nistcurves.inc"` from your own translation units; it gives
; you the import surface without transcribing symbol names out of API.md.
;
; It is a HEADER, not a source module: it emits no bytes and defines no code.
; It is safe to include from every TU in your project (it carries its own
; include-once guard).
;
;   .include "nistcurves.inc"
;   .segment "CODE"
;   boot:
;           jsr sqtab_init          ; §8.1
;           jsr reu_mul_init        ; §8.2 (default profile only)
;           jsr ec_precompute_256   ; comb archives only
;           ...
;
; -----------------------------------------------------------------------------
; 1. TELL THE HEADER WHICH ARCHIVE YOU LINKED
; -----------------------------------------------------------------------------
; This library ships twelve archives. They differ in which objects they
; contain, so an unconditional `.import` of the whole surface would be an
; UNRESOLVED EXTERNAL against every archive but the full one. Define the
; matching switch (`ca65 -D <switch>`) BEFORE including this file — these are
; the same switch names the library's own build uses for its per-variant
; manifest objects, so there is one vocabulary, not two:
;
;   archive                            switches to define
;   ---------------------------------  --------------------------------------
;   nistcurves.a                       (none)
;   nistcurves-onchip.a                FP_ONCHIP_MUL
;   nistcurves-app-owned.a             SHARED_SQTAB_INIT SHARED_REU_MUL_INIT
;                                      SHARED_REU_MUL_FETCH SHARED_CT_MUL_8X8
;   nistcurves-p256-verify.a           LIB_P256_VERIFY_ONLY
;   nistcurves-p256-verify-onchip.a    LIB_P256_VERIFY_ONLY FP_ONCHIP_MUL
;   nistcurves-p256-comb.a             LIB_P256_COMB_ONLY
;   nistcurves-p256-comb-onchip.a      LIB_P256_COMB_ONLY FP_ONCHIP_MUL
;   nistcurves-p384-verify.a           LIB_P384_VERIFY_ONLY
;   nistcurves-p384-verify-onchip.a    LIB_P384_VERIFY_ONLY FP_ONCHIP_MUL
;   nistcurves-p384-curve.a            LIB_P384_CURVE_ONLY
;   nistcurves-p384-curve-onchip.a     LIB_P384_CURVE_ONLY FP_ONCHIP_MUL
;   nistcurves-p384-sha384.a           LIB_SHA384_ONLY
;
; Add `-D LIB_NO_BARE_EXPORTS=1` if you are composing two or more
; c64-lib-contract libraries: it suppresses the deprecated unprefixed
; `LIB_VERSION_*` / `LIB_PRECALC_*` / `mul_*` names on BOTH sides — the
; library build and this header — so the two stay in step. Pass it to
; `make lib CONTRACT_DEFINES='-D LIB_NO_BARE_EXPORTS=1'` as well.
;
; Getting the switch wrong is a LINK error naming the symbol, never a silent
; wrong build.
;
; -----------------------------------------------------------------------------
; 2. WHAT IS *NOT* HERE
; -----------------------------------------------------------------------------
; * Zero-page slots (SPEC §2). They are `.exportzp`-ed from src/zp_config.s
;   and are library-internal addresses, not an API you call through; the
;   aggregate claim you need is `LIB_NISTCURVES_ZP_USAGE_BYTES` below.
;   Relocate a slot by rebuilding the archive:
;     make lib CONTRACT_ZP_DEFINES='-D fp_src1=0x50'
;   The two exceptions your code does write are `sha_src` / `sha_len`, the
;   SHA-384 input pointer/length; `.importzp` those yourself if you drive
;   SHA-384 directly.
; * `sqtab_lo` / `sqtab_hi` (SPEC §8.1). Consumer INPUT derived from
;   `LIB_SHARED_SQTAB_BASE`, not an import: derive them in your own TU with
;   the §8.1 pattern, or `.include "sqtab_base.inc"`.
; * The `LIB_SHARED_*` placement knobs (§8.1 / §8.2). Those are consumer
;   input, deliberately unexported by every adopter — two exporters of an
;   unprefixed name collide in a composed link. What you read back instead
;   are this library's prefixed OUTPUT counterparts, below.
; * C64 hardware equates from src/constants.s (`screen_ram`, `chrout`, the
;   `$DFxx` REU registers). Internal to the library's own build.
;
; -----------------------------------------------------------------------------
; 3. THE §3 GUARD RULE, AND WHY HALF THESE IMPORTS LOOK ODD
; -----------------------------------------------------------------------------
; SPEC §3: "A consumer-facing header (.inc) that .imports an overridable
; equate MUST guard the import. Guard the .import with .ifndef IFF the
; defining TU guards the definition, and pair every such guard with an .else
; branch asserting the override against the library's exported value."
;
; Both halves are load-bearing, for opposite reasons:
;
;   * Without the `.ifndef`, the override the library documents fails to
;     assemble. A `-D LIB_NISTCURVES_REU_BANK_COMB=0x05` that reaches a TU
;     which also `.import`s that name is `Symbol already defined` — so the
;     header would break exactly the consumers following the manual.
;   * Without the `.else`, the guard is WORSE than the collision it removes:
;     it converts a compile error into silent divergence. A consumer at bank
;     5 would link cleanly against an archive built for bank 2, and the
;     mismatch would surface as corrupted comb tables at run time.
;
; The `.else` asserts against the library's exported symbol OF THE SAME NAME.
; That cannot be a plain `.import` — the name is already defined in this TU —
; so it is imported into a private scope and compared across the boundary:
;
;     .scope _nc_ovr_x
;         .import LIB_FOO          ; the ARCHIVE's value
;     .endscope
;     .assert LIB_FOO = _nc_ovr_x::LIB_FOO, lderror, "..."
;
; `.assert` + `lderror`, never `.if` + `.error`: an imported symbol has no
; value until link, and ca65 rejects an `.if` over one outright with
; `Constant expression expected` (SPEC §1). The check fires at link, still
; before anything runs. NISTCURVES_PIN_OVERRIDE below is that four-line
; shape as a macro.
;
; Where the defining TU assigns UNCONDITIONALLY the equate is derived, not
; overridable, so the import is left bare on purpose and a `-D` on it MUST
; collide loudly — a guard there would mask a deliberate rejection. Every
; import below is annotated with which case it is and which line of which
; file decides it.
; =============================================================================

.ifndef NISTCURVES_INC_INCLUDED
NISTCURVES_INC_INCLUDED = 1

; -----------------------------------------------------------------------------
; Override-pin macro (see §3 above). Namespaced `NISTCURVES_` so it cannot
; collide with a sibling library's header. `scopename` must be unique within
; the including TU; the names used below are all `_nc_ovr_*`.
; -----------------------------------------------------------------------------
.macro NISTCURVES_PIN_OVERRIDE scopename, sym, msg
    .scope scopename
        .import sym
    .endscope
    .assert sym = scopename::sym, lderror, msg
.endmacro

; -----------------------------------------------------------------------------
; Archive-content flags, derived from the switches in §1 above. These mirror
; the row-presence flags in src/precalc_manifest.s and the mask arms in
; src/lib_manifest.s one-for-one — if a table or a symbol is absent from an
; archive there, it is absent here.
; -----------------------------------------------------------------------------

; Field arithmetic at all. Everything except the SHA-384-only archive, which
; ships sha384.o + data_sha.o and nothing else: no constants.o, no
; reu_config.o, no mul_8x8.o.
.ifdef LIB_SHA384_ONLY
  _NC_FIELD = 0
.else
  _NC_FIELD = 1
.endif

; P-256 surface (fp_*, ec_*, ecdsa_verify_256).
.if .defined(LIB_SHA384_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P384_CURVE_ONLY)
  _NC_P256 = 0
.else
  _NC_P256 = 1
.endif

; P-384 surface (fp*_384, ec*_384, ecdsa_verify_384).
.if .defined(LIB_SHA384_ONLY) .or .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P256_COMB_ONLY)
  _NC_P384 = 0
.else
  _NC_P384 = 1
.endif

; Lim-Lee fixed-base combs. The verify archives take the ECDSA_NO_COMB
; verifiers and link neither comb object; the P-256 comb archive (issue #117)
; ships points256_comb.o only. Same split as the two `lim_lee_comb_*` §8.4
; rows.
.if .defined(LIB_SHA384_ONLY) .or .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P384_CURVE_ONLY)
  _NC_COMB_P256 = 0
  _NC_COMB_P384 = 0
.elseif .defined(LIB_P256_COMB_ONLY)
  _NC_COMB_P256 = 1
  _NC_COMB_P384 = 0
.else
  _NC_COMB_P256 = 1
  _NC_COMB_P384 = 1
.endif

; SHA-384 (sha384.o + data_sha.o). Same gate as the §8.4 sha384_k row.
.if .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P256_COMB_ONLY)
  _NC_SHA384 = 0
.else
  _NC_SHA384 = 1
.endif

; The one-shot hash-then-verify wrapper needs BOTH halves in the archive.
.if _NC_SHA384 .and _NC_P384
  _NC_SHA384_MSG = 1
.else
  _NC_SHA384_MSG = 0
.endif

; inv256.o (the Fermat-inverse reference path, 41x slower than the binary
; GCD) rides only with the whole-library archives.
.if .defined(LIB_SHA384_ONLY) .or .defined(LIB_P256_VERIFY_ONLY) .or .defined(LIB_P384_VERIFY_ONLY) .or .defined(LIB_P384_CURVE_ONLY) .or .defined(LIB_P256_COMB_ONLY)
  _NC_INVREF = 0
.else
  _NC_INVREF = 1
.endif

; The §8.2 REU multiply table is built and read only by the default profile:
; FP_ONCHIP_MUL generates rows on-chip and no onchip archive contains
; reu_mul_init.o at all. SHARED_REU_MUL_INIT defers the init body to a
; provider, which also removes the object from the archive.
.if _NC_FIELD .and (.not .defined(FP_ONCHIP_MUL)) .and (.not .defined(SHARED_REU_MUL_INIT))
  _NC_REU_MUL_INIT = 1
.else
  _NC_REU_MUL_INIT = 0
.endif


; =============================================================================
; SPEC §1 — version identification
; =============================================================================
; src/lib_version.s:68-71 assigns all four UNCONDITIONALLY, so these imports
; are bare: they are not overridable, and a `-D` on one must collide.
;
; Gate your integration on the ABI counter, not on MAJOR — it is a generation
; counter for the exported surface and moves independently of the semantic
; version (§1/§7):
;   .assert LIB_NISTCURVES_ABI_VERSION = 2, lderror, "c64-nist-curves exported surface changed; re-check the integration"
.import LIB_NISTCURVES_VERSION_MAJOR, LIB_NISTCURVES_VERSION_MINOR
.import LIB_NISTCURVES_VERSION_PATCH, LIB_NISTCURVES_ABI_VERSION

; Deprecated bare aliases (src/lib_version.s:100-109). Present in the archive
; only when it was built WITHOUT LIB_NO_BARE_EXPORTS, so the same define gates
; the import. They collide across libraries by construction — every adopter
; exports the same four names — so a composing consumer suppresses them on
; both sides and uses the prefixed forms above.
.ifndef LIB_NO_BARE_EXPORTS
.import LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH
.import LIB_ABI_VERSION
.endif


; =============================================================================
; SPEC §5 — aggregate manifest equates
; =============================================================================
; Bind these to your own budget at ASSEMBLE time. Footprint values are
; safe-direction (rounded up, never down), and RESIDENT/COLD are a pair — COLD
; is reclaimable after init and may live in a different region, so a consumer
; sizing ONE region must budget for both:
;
;   .import __CRYPTO_SIZE__          ; ld65-published region size
;   .assert LIB_NISTCURVES_RESIDENT_BYTES + LIB_NISTCURVES_COLD_BYTES < __CRYPTO_SIZE__, error, "no room"
;
; Each archive carries its OWN manifest object, so the values describe the
; archive you linked, not the whole library (§6.4).
;
; GUARDED: src/lib_manifest.s wraps every one of these in `.ifndef` (lines
; 76, 196, 308, 459, 609, 688, 739) so a consumer may override a figure — the
; documented case is an onchip verify archive, which issues no REU DMA at all
; and may legitimately be pinned to REU_BANKS_USED = $00. Per §3 each guard
; therefore carries an `.else` that asserts your value against the archive's.

.ifndef LIB_NISTCURVES_REU_BANKS_USED
.import LIB_NISTCURVES_REU_BANKS_USED
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_banks, LIB_NISTCURVES_REU_BANKS_USED, "LIB_NISTCURVES_REU_BANKS_USED override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_ZP_USAGE_BYTES
.import LIB_NISTCURVES_ZP_USAGE_BYTES
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_zp, LIB_NISTCURVES_ZP_USAGE_BYTES, "LIB_NISTCURVES_ZP_USAGE_BYTES override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_RESIDENT_BYTES
.import LIB_NISTCURVES_RESIDENT_BYTES
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_res, LIB_NISTCURVES_RESIDENT_BYTES, "LIB_NISTCURVES_RESIDENT_BYTES override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_COLD_BYTES
.import LIB_NISTCURVES_COLD_BYTES
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_cold, LIB_NISTCURVES_COLD_BYTES, "LIB_NISTCURVES_COLD_BYTES override disagrees with the archive this header ships against"
.endif

; §8.0 mask pair. SHARED_PRIMITIVES = what this build OWNS; SHARED_CONSUMES =
; what it READS. They differ by design: a deferral switch clears ownership
; only, which is what distinguishes "deferring consumer, needs a provider in
; the link" from "non-consumer, needs none". Compose them across your linked
; libraries with the two §8.0 asserts:
;   .assert (LIB_NISTCURVES_SHARED_PRIMITIVES & LIB_<other>_SHARED_PRIMITIVES) = 0, error, "shared-primitive double-ownership"
;   .assert ((LIB_NISTCURVES_SHARED_CONSUMES | LIB_<other>_SHARED_CONSUMES) & ~(LIB_NISTCURVES_SHARED_PRIMITIVES | LIB_<other>_SHARED_PRIMITIVES | APP_OWNED)) = 0, error, "consumed shared primitive with no owner in the link"
.ifndef LIB_NISTCURVES_SHARED_PRIMITIVES
.import LIB_NISTCURVES_SHARED_PRIMITIVES
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_own, LIB_NISTCURVES_SHARED_PRIMITIVES, "LIB_NISTCURVES_SHARED_PRIMITIVES override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_SHARED_CONSUMES
.import LIB_NISTCURVES_SHARED_CONSUMES
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_con, LIB_NISTCURVES_SHARED_CONSUMES, "LIB_NISTCURVES_SHARED_CONSUMES override disagrees with the archive this header ships against"
.endif

; §5 published input bound: the maximum bytes ONE `sha384_update` call may
; absorb (`sha_len` is 16-bit). The STREAM is unbounded — chain as many
; updates as you like — and `sha_len = 0` is a legal no-op. Emitted only by
; the archives that ship sha384.o (src/lib_manifest.s:738-744), and guarded
; there, so it is gated and pinned here the same way.
.if _NC_SHA384
.ifndef LIB_NISTCURVES_SHA384_UPDATE_MAX
.import LIB_NISTCURVES_SHA384_UPDATE_MAX
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_shamax, LIB_NISTCURVES_SHA384_UPDATE_MAX, "LIB_NISTCURVES_SHA384_UPDATE_MAX override disagrees with the archive this header ships against"
.endif
.endif

; §8.0 per-primitive bit constants. Plain assemble-time equates, deliberately
; NOT link symbols: every §8 adopter carries the same names and values, and
; only EXPORTED names can collide at link. `.ifndef`-guarded so a consumer who
; already has them (from a sibling library's header, or a build-wide `-D`)
; does not get a redefinition error. Copied verbatim from SPEC §8.0.
.ifndef LIB_SHARED_PRIMITIVES_SQTAB
LIB_SHARED_PRIMITIVES_SQTAB      = $0001   ; §8.1 quarter-square table
.endif
.ifndef LIB_SHARED_PRIMITIVES_REU_MUL
LIB_SHARED_PRIMITIVES_REU_MUL    = $0002   ; §8.2 REU multiply table
.endif
.ifndef LIB_SHARED_PRIMITIVES_CT_MUL_8X8
LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004   ; §8.3 CT multiply body
.endif


; =============================================================================
; SPEC §3 — REU layout, and §8.2 prefixed placement outputs
; =============================================================================
; Absent from the SHA-384-only archive: SHA-384 issues no REU DMA whatsoever,
; so that archive contains no reu_config.o.
.if _NC_FIELD

; --- Overridable §3 equates (GUARDED) ---------------------------------------
; src/reu_config.s guards each of these with `.ifndef` (lines 85, 140, 144,
; 148, 162), which is precisely the SPEC §3 override path:
;   make lib CONTRACT_DEFINES='-D LIB_NISTCURVES_REU_BANK_COMB=0x05'
; `0x` form, never `$` — through make a `$` value silently becomes 0, or the
; shell's PID (SPEC §2).
;
; Relocating the comb bank does NOT recompute `LIB_NISTCURVES_REU_BANKS_USED`
; (src/lib_manifest.s hard-codes the mask per variant), so override the mask
; alongside the bank or your §5 collision assert will check the wrong banks.

.ifndef LIB_NISTCURVES_REU_BANK_MUL
.import LIB_NISTCURVES_REU_BANK_MUL
.else
; Asserted against the §8.2 prefixed OUTPUT rather than a scope-import,
; because one exists and is defined as an alias of this very symbol
; (src/reu_config.s:205) — i.e. of the value fp256.s/fp384.s actually load
; into the REU bank register. Either spelling of the override moves it.
.import LIB_NISTCURVES_SHARED_REU_MUL_BANK
.assert LIB_NISTCURVES_REU_BANK_MUL = LIB_NISTCURVES_SHARED_REU_MUL_BANK, lderror, "LIB_NISTCURVES_REU_BANK_MUL override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_REU_BANK_COMB
.import LIB_NISTCURVES_REU_BANK_COMB
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_comb, LIB_NISTCURVES_REU_BANK_COMB, "LIB_NISTCURVES_REU_BANK_COMB override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_REU_OFFSET_COMB_P256
.import LIB_NISTCURVES_REU_OFFSET_COMB_P256
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_off256, LIB_NISTCURVES_REU_OFFSET_COMB_P256, "LIB_NISTCURVES_REU_OFFSET_COMB_P256 override disagrees with the archive this header ships against"
.endif

.ifndef LIB_NISTCURVES_REU_OFFSET_COMB_P384
.import LIB_NISTCURVES_REU_OFFSET_COMB_P384
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_off384, LIB_NISTCURVES_REU_OFFSET_COMB_P384, "LIB_NISTCURVES_REU_OFFSET_COMB_P384 override disagrees with the archive this header ships against"
.endif

; §8.2 post-execute settle length, in 9-cycle iterations of the loop inside
; `nistcurves_reu_dma_wait`. Default 8 -> ~106 cycles from REU execute to the
; next REU register write, 2.16x the measured floor (>= 49 cy at 48 MHz, U64E
; fw 3.15). 64 MHz is UNBRACKETED: a consumer claiming that clock raises this
; (1..255) until a FAIL/PASS bracket exists. Exported as the code-read value,
; so what you assert here is what the archive really settles for.
.ifndef LIB_NISTCURVES_REU_SETTLE_ITER
.import LIB_NISTCURVES_REU_SETTLE_ITER
.else
NISTCURVES_PIN_OVERRIDE _nc_ovr_settle, LIB_NISTCURVES_REU_SETTLE_ITER, "LIB_NISTCURVES_REU_SETTLE_ITER override disagrees with the archive this header ships against"
.endif

; --- §8.2 prefixed OUTPUT counterparts (BARE) --------------------------------
; src/reu_config.s:205-207,218-219 assigns all five UNCONDITIONALLY — they are
; derived from the code-read symbols above, not knobs — so the imports are
; bare and a `-D` on one must collide loudly. These are what you compare
; against a co-linked sibling §8.2 adopter:
;   .assert LIB_NISTCURVES_SHARED_REU_MUL_BANK = LIB_X25519_SHARED_REU_MUL_BANK, lderror, "shared mul-table placement disagreement"
; The unprefixed LIB_SHARED_REU_MUL_* spellings are consumer INPUT and are
; exported by nobody (see §2 of the preamble).
.import LIB_NISTCURVES_SHARED_REU_MUL_BANK
.import LIB_NISTCURVES_SHARED_REU_MUL_OFFSET
.import LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED
.import LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO
.import LIB_NISTCURVES_SHARED_REU_MUL_STAGE_HI

.endif ; _NC_FIELD


; =============================================================================
; SPEC §8.4 — precalc-table enumeration
; =============================================================================
; Macro-emitted by src/precalc_manifest.s, one triple per table the archive
; actually contains, with UNCONDITIONAL assignment (src/precalc_table.inc:86-88)
; — so every import below is bare. The gates mirror that file's row-presence
; flags exactly.
;
; The `_SIZE` exports carry no address-size hint (the 131072-byte reu_mul
; table does not fit 16 bits); the other two are `: abs`.

.if _NC_FIELD
.import LIB_NISTCURVES_PRECALC_sqtab_SIZE
.import LIB_NISTCURVES_PRECALC_sqtab_REGION
.import LIB_NISTCURVES_PRECALC_sqtab_SHARED
.endif

.if _NC_FIELD .and (.not .defined(FP_ONCHIP_MUL))
.import LIB_NISTCURVES_PRECALC_reu_mul_SIZE
.import LIB_NISTCURVES_PRECALC_reu_mul_REGION
.import LIB_NISTCURVES_PRECALC_reu_mul_SHARED
.endif

.if _NC_COMB_P256
.import LIB_NISTCURVES_PRECALC_lim_lee_comb_p256_SIZE
.import LIB_NISTCURVES_PRECALC_lim_lee_comb_p256_REGION
.import LIB_NISTCURVES_PRECALC_lim_lee_comb_p256_SHARED
.endif

.if _NC_COMB_P384
.import LIB_NISTCURVES_PRECALC_lim_lee_comb_p384_SIZE
.import LIB_NISTCURVES_PRECALC_lim_lee_comb_p384_REGION
.import LIB_NISTCURVES_PRECALC_lim_lee_comb_p384_SHARED
.endif

.if _NC_SHA384
.import LIB_NISTCURVES_PRECALC_sha384_k_SIZE
.import LIB_NISTCURVES_PRECALC_sha384_k_REGION
.import LIB_NISTCURVES_PRECALC_sha384_k_SHARED
.import LIB_NISTCURVES_PRECALC_sha384_rotr_lut_SIZE
.import LIB_NISTCURVES_PRECALC_sha384_rotr_lut_REGION
.import LIB_NISTCURVES_PRECALC_sha384_rotr_lut_SHARED
.endif


; =============================================================================
; SPEC §8.1 / §8.2 / §8.3 — shared primitives
; =============================================================================
; Each primitive's body is present unless this archive defers it. A deferral
; switch means the library IMPORTS the canonical name instead of exporting it
; (never a stub — that would put two same-named canonical bodies into a
; composed link), so a deferring archive resolves through YOUR provider and
; the import below must not be repeated here.
.if _NC_FIELD

; --- §8.1 quarter-square multiply table -------------------------------------
.ifndef SHARED_SQTAB_INIT
.import mul_tables_init          ; §8.1 canonical entry
.import sqtab_init               ; historical nist-curves alias, same address
.endif

; --- §8.2 REU multiply table -------------------------------------------------
.if _NC_REU_MUL_INIT
.import reu_mul_tables_init      ; §8.2 canonical entry
.import reu_mul_init             ; historical nist-curves alias, same address
.endif
.ifndef SHARED_REU_MUL_FETCH
; Canonical per-row fetch: A = row index on entry; on return the 512 bytes are
; at LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO / _STAGE_HI. Offered to consumers
; that want to drive the fetch themselves — the library's own fp_mul / fp_sqr
; inline their three-register-write fetch instead, which is why this symbol is
; classified COLD in the §5 footprint.
.import reu_fetch_mul_row
.endif

; The §8.2 completion-confirm + post-execute settle every tight REU execute
; site calls. Ungated and always present in a field archive: the hot path's
; slow branch calls it, so it is RESIDENT, not COLD.
.import nistcurves_reu_dma_wait
; Sticky fault byte: set non-zero if a bounded DMA-completion spin ever
; expired. Zero on a healthy machine; read it after your boot init.
.import nistcurves_reu_dma_timeout

; --- §8.3 constant-time 8x8->16 multiply body --------------------------------
.ifndef SHARED_CT_MUL_8X8
; Full §8.3 provider surface. `a` is baked into the two SMC `adc #imm` sites
; by the caller (smc_sum_a_imm+1 / smc_diff_a_imm+1), `b` passed in Y; the
; 16-bit product returns in poly_prod_lo / poly_prod_hi. The SMC sites are
; load-bearing entry state, not internals.
.import ct_mul_8x8               ; §8.3 canonical entry
.import mul_8x8                  ; historical nist-curves alias, same address
.import smc_sum_a_imm, smc_diff_a_imm
.import poly_prod_lo, poly_prod_hi
.endif

; --- Shared multiply scratch / DMA landing pages ------------------------------
; Page-aligned, contiguous, and read in the hottest inner loop in the library
; (see the LIB_NISTCURVES_TABLES notes in cfg/nistcurves-example.cfg).
.import nistcurves_mul_dma_lo, nistcurves_mul_dma_hi
.import nistcurves_mul_cached_a, nistcurves_mul_src2_buf

; Deprecated unprefixed aliases at the same addresses (§6.5 rename window —
; the `mul_` prefix is registered to c64-x25519 in the §2 ZP registry).
; Present only in an archive built without LIB_NO_BARE_EXPORTS; removed at the
; next MAJOR. Use the `nistcurves_`-prefixed names above.
.ifndef LIB_NO_BARE_EXPORTS
.import mul_dma_lo, mul_dma_hi
.import mul_cached_a, mul_src2_buf
.endif

; Operand widths (src/constants.s).
.import FP256_SIZE, FP384_SIZE

.endif ; _NC_FIELD


; =============================================================================
; P-256 surface
; =============================================================================
; All field elements, curve parameters and coordinates are LITTLE-endian
; (byte 0 = LSB). Scalars on the packaged-verifier ABI are big-endian.
; A Jacobian point is 96 bytes: X at +0, Y at +32, Z at +64.
.if _NC_P256

; Packaged ECDSA verifier. Pointer to a 160-byte BE struct in A (low) / X
; (high): r(32) | s(32) | h(32) | Qx(32) | Qy(32). Returns C=0 VALID,
; C=1 INVALID or malformed. NOT constant-time — it branches on r, s, h, Qx,
; Qy, all public in the verify context. Do not repurpose it for signing.
.import ecdsa_verify_256
.import fp_reverse32             ; BE<->LE helper, 32 bytes

; Point arithmetic. `ec_point_add` is MIXED Jacobian+affine (P2 read as
; affine, Z2 implicitly 1); `ec_point_add_jj` is full Jacobian+Jacobian and
; handles infinity and P1 = -P2 natively. Pick by operand shape.
.import ec_point_double, ec_point_add, ec_point_add_jj
.import ec_scalar_mul_var        ; variable-base ladder
.import ec_jacobian_to_affine    ; C=1 + zeroed output if Z = 0

; Field / modular arithmetic.
.import fp_add, fp_sub, fp_mul, fp_sqr
.import fp_copy, fp_zero, fp_cmp, fp_is_zero, fp_rshift1
.import fp_mod_add, fp_mod_sub, fp_mod_mul, fp_mod_sqr, fp_mod_mul_n
.import fp_mod_reduce256, fp_chk_one
.import fp_mod_inv               ; binary GCD; C=1 + zeroed output on 0 or modulus
.import ec_set_modp, ec_set_modn, ec_mulp, ec_sqrp

; §5 published bounds that cannot be equates: a 256-bit modulus is not a ca65
; integer, so it is published as an exported label instead.
.import ec_p256, ec_n256
.import ec_a256, ec_b256, ec_gx256, ec_gy256

; Operand / result buffers on the documented ABI.
.import ec_p1, ec_p2, ec_p3
.import ec_affine_x, ec_affine_y
.import ec_base_x, ec_base_y
.import fp_r0, fp_wide

.if _NC_COMB_P256
; Lim-Lee h=8 fixed-base comb. `ec_precompute_256` must run once at boot
; (~1038 Mcyc at 1 MHz — budget for it) before `ec_scalar_mul`.
.import ec_precompute_256, ec_scalar_mul
.endif

.if _NC_INVREF
.import fp_mod_inv_fast          ; Fermat addition-chain reference; 41x slower
.endif

.endif ; _NC_P256


; =============================================================================
; P-384 surface
; =============================================================================
; A Jacobian point is 144 bytes: X at +0, Y at +48, Z at +96.
.if _NC_P384

; Pointer to a 240-byte BE struct in A (low) / X (high):
; r(48) | s(48) | h(48) | Qx(48) | Qy(48). C=0 VALID, C=1 INVALID. Same
; not-constant-time caveat as the P-256 verifier.
.import ecdsa_verify_384
.import fp_reverse48

.import ec_point_double_384, ec_point_add_384, ec_point_add_jj_384
.import ec_scalar_mul_var_384
.import ec_jacobian_to_affine_384

.import fp_add_384, fp_sub_384, fp_mul_384, fp_sqr_384
.import fp_copy_384, fp_zero_384, fp_cmp_384, fp_is_zero_384, fp_rshift1_384
.import fp_mod_add_384, fp_mod_sub_384, fp_mod_mul_384, fp_mod_sqr_384
.import fp_mod_mul_n_384, fp_mod_reduce384
.import fp_mod_inv_384
.import ec_set_modp_384, ec_set_modn_384

.import ec_p384, ec_n384
.import ec_a384, ec_b384, ec_gx384, ec_gy384

.import ec384_p1, ec384_p2, ec384_p3
.import ec384_affine_x, ec384_affine_y
.import ec_base384_x, ec_base384_y
.import fp384_r0, fp384_wide

.if _NC_COMB_P384
; ~2108 Mcyc at 1 MHz for the boot precompute.
.import ec_precompute_384, ec_scalar_mul_384
.endif

.endif ; _NC_P384


; =============================================================================
; SHA-384 surface (FIPS 180-4 §6.4)
; =============================================================================
; Self-contained: no REU DMA, no shared field/multiply scratch, no sqtab. Safe
; to call without any curve init. NOT re-entrant — one stream at a time.
;
; Drive it as init / update (n times) / final. `sha384_update` consumes
; `sha_len` bytes from `sha_src` (both ZERO PAGE — `.importzp` them yourself,
; they are not imported here); at most LIB_NISTCURVES_SHA384_UPDATE_MAX per
; call. `sha384_final` writes 48 big-endian bytes to `sha384_digest`; the
; state must be reset with `sha384_init` before any further use.
.if _NC_SHA384
.import sha384_init, sha384_update, sha384_final
.import sha384_digest
.endif

.if _NC_SHA384_MSG
; One-shot hash-then-verify. Same A/X pointer ABI and 240-byte BE struct as
; ecdsa_verify_384; the `h` slot is overwritten with the computed digest, so
; you may leave it zero. Set sha_src / sha_len first. C=0 valid, C=1 invalid.
; STREAMING CAVEAT: it issues exactly ONE sha384_update. For a TLS-style
; transcript spanning several buffers, drive init/update.../final yourself and
; then jsr ecdsa_verify_384 with the digest already spliced into the h slot.
.import ecdsa_verify_with_message_384
.endif

.endif ; NISTCURVES_INC_INCLUDED
