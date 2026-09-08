#!/usr/bin/env python3
"""Archive linkability contract ratchet for the c64-nist-curves .a targets.

The five ``make lib*`` archives (Makefile SEGMENTS §6) each ship a documented
subset of the library's objects, so a consumer linking one archive gets a
*known* set of resolvable symbols -- and a *known* set of deliberate gaps.
The most important gap: the trimmed verify archives exclude the Lim-Lee
fixed-base comb, so the packaged verifiers ``ecdsa_verify_256`` /
``ecdsa_verify_384`` (which call ``ec_scalar_mul`` / ``ec_scalar_mul_384``)
are NOT linkable from those archives alone -- see issue #60 and API.md §8.4.1.

This script is a *ratchet*: it pins that contract so it cannot silently drift.
For each archive it checks two things against the documented ``KNOWN_EXTERNAL``
allowlist below:

  (a) Import/export closure sweep (od65). Every import of every object in the
      archive's object set must be exported somewhere within that same set,
      OR appear on the archive's allowlist. A NEW unresolved import that is
      not on the allowlist fails the ratchet (a real regression). An allowlist
      entry that is now satisfied within the set also fails (the gap closed --
      update the docs and shrink the allowlist).

  (b) ld65 dummy-link smoke tests. A small table of supported / documented-
      broken entry points per archive is assembled with ca65 and linked
      against the built archive. An entry point documented as linkable must
      link clean; one documented as broken must fail with unresolved symbols
      that are a subset of the allowlist (never a fresh symbol, never zero).

Both directions are violations, which is what makes it a ratchet rather than a
one-way smoke test: reality drifting looser OR tighter than the documented
contract exits non-zero, forcing the docs and this table to move together.

Object lists are derived by parsing the Makefile ``ar65 a`` recipe lines
(the single source of truth for archive composition) rather than hardcoded.

Dependencies: python3 stdlib + the cc65 toolchain (od65, ca65, ld65) on PATH.
Requires the archives to be built first (the ``check-archives`` Makefile
target builds them, then runs this). Exit 0 = contract intact, 1 = drift.
"""

import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BUILD = REPO / "build"
LIBDIR = BUILD / "lib"
MAKEFILE = REPO / "Makefile"

# --- Documented contract: deliberate unresolved externals per archive --------
# Each entry is a gap stated in API.md §8.4.1 / the Makefile banner. Changing
# reality without changing this table (and the docs) trips the ratchet.
KNOWN_EXTERNAL = {
    # No archive has documented gaps anymore. Issue #63 fixed the
    # test-trampoline leak (trampoline moved to the never-archived main.s);
    # issue #61 closed the comb gaps: the verify archives ship the
    # -D ECDSA_NO_COMB ecdsa*_nocomb.o variants whose u1*G routes through
    # the variable-base ladder seeded at G, so the packaged verifiers link
    # standalone without points256_comb.o / points384_comb.o.
    "nistcurves.a": set(),
    "nistcurves-p256-verify.a": set(),
    "nistcurves-p384-verify.a": set(),
    "nistcurves-p384-sha384.a": set(),
    "nistcurves-p384-curve.a": set(),
    # FP_ONCHIP_MUL turbo-profile archives (issue #69): same contract as
    # their DMA-table counterparts -- link-complete, no documented gaps.
    # The onchip mul_8x8 object exports the shared og_common row generator;
    # each curve object carries its own entry stub, so no cross-curve
    # buffer import exists to allowlist.
    # SPEC §6.3 lib-app-owned: every §8.x primitive is deferred, so the four
    # canonical symbols are unresolved BY DESIGN -- the consumer's own modules
    # provide them. That is the whole point of the configuration, and it is why
    # this archive is the one place a documented gap is correct rather than a
    # regression. §8.1's import-never-stub rule forbids satisfying them with a
    # local stub.
    # SPEC §6.3 lib-app-owned: every §8.x primitive is deferred to the consumer.
    # No archived object imports the four canonical ENTRY symbols: the only
    # in-archive caller of ct_mul_8x8 was reu_mul_init.o (excluded under
    # SHARED_REU_MUL_INIT), the fetch has no callers at all, and sqtab_init /
    # reu_mul_tables_init are called only from the never-archived main.s.
    # poly_prod_lo/hi WERE unresolved here from issue #123 until issue #155.
    # #123 moved the §8.3 product cells inside the deferral gate, correctly:
    # they are the canonical body's output interface, so a deferring runtime
    # caller must read the PROVIDER's cells. That still holds for og_common
    # under FP_ONCHIP_MUL, which calls the deferred body for real.
    # What did NOT hold was fp256.o/fp384.o importing them: fp_sqr's diagonal
    # pass only ever used them as two bytes of local scratch, write-then-read
    # within three instructions, never as the §8.3 product channel. That
    # borrow made every field-op link pull mul_8x8.o and, with it, the
    # displaceable bare sqtab_lo/sqtab_hi -- issue #155's §6.1 collision.
    # The curves now carry their own fp_diag_lo/_hi (data_p256.s) and
    # fp384_diag_lo/_hi (data_p384.s), so this archive resolves closed and an
    # APP_OWNED consumer owes two fewer definitions than before.
    "nistcurves-app-owned.a": set(),
    "nistcurves-onchip.a": set(),
    "nistcurves-p256-verify-onchip.a": set(),
    "nistcurves-p384-verify-onchip.a": set(),
    "nistcurves-p384-curve-onchip.a": set(),
    # P-256 comb archives (issue #117): the comb-calling ecdsa256.o plus
    # points256_comb.o / data_p256_limlee.o, link-complete in both profiles.
    "nistcurves-p256-comb.a": set(),
    "nistcurves-p256-comb-onchip.a": set(),
}

# --- SPEC §8.2 provider pins (issue #81) -------------------------------------
# The reu_mul provider (reu_mul_init / reu_mul_tables_init, src/reu_mul_init.s)
# must be PRESENT in every default-profile REU-consuming archive (API.md §3
# makes the boot call mandatory, and lib_manifest.o's §8.0 ownership claim
# $0002 must be backed by a shipped body) and ABSENT from the sha384 archive
# (no REU at all) and the FP_ONCHIP_MUL archives (the profile never builds or
# reads the REU multiply table; verify-onchip archives are advertised as
# containing zero REU DMA code, API.md §8.4.2). Both directions ratchet.
REU_MUL_PROVIDER_SYMS = {"reu_mul_init", "reu_mul_tables_init"}

# --- SPEC §8.3 provider surface (issue #123) ---------------------------------
# The canonical body's caller-facing surface: entry, the two SMC bake sites a
# caller patches `a` into, and the 16-bit product cells the body writes. A
# §8.3-owning archive must export all five (og_common and any deferring
# sibling resolve against them); a deferring build must NOT re-export any --
# a re-export collides with the real provider at link. Enumerated explicitly
# upstream by the in-flight §8.3-surface SPEC PR.
CT_MUL_PROVIDER_SYMS = {"ct_mul_8x8", "smc_sum_a_imm", "smc_diff_a_imm",
                        "poly_prod_lo", "poly_prod_hi"}

# --- SPEC §1/§5/§8.4 manifest-surface pins (issue #86) -----------------------
# Every archive carries lib_version.o + lib_manifest.o + precalc_manifest.o
# (Makefile LIB_CORE_OBJS / LIB_CORE_ONCHIP_OBJS), so the consumer-facing
# manifest surface is uniform across all nine and ratchets here.
#
# Library-PREFIXED forms are canonical since contract v0.7.0 (lib-contract
# #43): the bare LIB_VERSION_* / LIB_PRECALC_* families are byte-identical
# across every adopter, so a consumer linking two sibling libraries and
# importing both manifests hits `ld65: Duplicate external identifier`. The
# bare forms stay emitted by default for back-compat and are suppressed
# build-wide with `ca65 -D LIB_NO_BARE_EXPORTS=1`; they are removed at
# contract v1.0. Pinning the prefixed set guards against a regression that
# drops the fifth "NISTCURVES" LIB_PRECALC_TABLE argument or reverts
# src/lib_version.s to bare-only.
MANIFEST_VERSION_SYMS = {
    "LIB_NISTCURVES_VERSION_MAJOR",
    "LIB_NISTCURVES_VERSION_MINOR",
    "LIB_NISTCURVES_VERSION_PATCH",
    "LIB_NISTCURVES_ABI_VERSION",
}
# §5 + §8.0 v0.5.0: the ownership mask and its required companion consumes
# mask. Shipping PRIMITIVES without CONSUMES leaves a consumer unable to
# tell "deferring consumer" (needs a provider in the link) from
# "non-consumer" (needs none) -- the exact ambiguity lib-contract #44 was
# filed against, with this library's own $0005-vs-$0005 pair as the
# demonstrator.
MANIFEST_SHARED_SYMS = {
    "LIB_NISTCURVES_SHARED_PRIMITIVES",
    "LIB_NISTCURVES_SHARED_CONSUMES",
}
MANIFEST_SYMS = MANIFEST_VERSION_SYMS | MANIFEST_SHARED_SYMS

def _precalc_syms(*names):
    """Both the prefixed and the deprecated bare triple, for each table."""
    return {
        f"LIB{p}_PRECALC_{n}_{f}"
        for n in names
        for p in ("", "_NISTCURVES")
        for f in ("SIZE", "REGION", "SHARED")
    }


# §8.4 reu_mul precalc row. Gated out under FP_ONCHIP_MUL (issue #78) -- the
# profile never builds or reads an REU multiply table, so an onchip archive
# that advertised the row would be describing a table it does not have. This
# mirrors the REU_MUL_PROVIDER_SYMS direction at the manifest layer.
PRECALC_REU_MUL_SYMS = _precalc_syms("reu_mul")

# The remaining rows, split so each archive can pin exactly the tables it
# carries (issue #90). Before that, sqtab / lim_lee_comb_* were gated only on
# LIB_SHA384_ONLY and sha384_k was emitted unconditionally, so the six
# minimal-variant archives each enumerated 2-3 tables they do not contain.
PRECALC_SQTAB_SYMS = _precalc_syms("sqtab")
# Split per curve (issue #117): the P-256 comb archives carry the p256 row
# and must NOT advertise the 24 KB p384 table they lack.
PRECALC_COMB_P256_SYMS = _precalc_syms("lim_lee_comb_p256")
PRECALC_COMB_P384_SYMS = _precalc_syms("lim_lee_comb_p384")
PRECALC_COMB_SYMS = PRECALC_COMB_P256_SYMS | PRECALC_COMB_P384_SYMS
PRECALC_SHA384_K_SYMS = _precalc_syms("sha384_k")

# --- §8.2 placement equates must stay unexported (issue #82) -----------------
# LIB_SHARED_REU_MUL_BANK / _OFFSET / _BANKS_USED are consumer-supplied
# placement values: .ifndef-guarded and overridden with `ca65 -D`, exactly like
# §8.1's LIB_SHARED_SQTAB_BASE. Exporting them puts unprefixed names into the
# link namespace, and every §8.2 consumer defines the same three -- so a
# consumer linking two REU adopters gets `Duplicate external identifier`.
# Reproduced against c64-x25519 v0.10.1, the pair c64-https ships.
# Pinned absent from every archive; the bare names must not come back. If the
# contract later publishes them, it will be in the prefixed
# LIB_NISTCURVES_SHARED_REU_MUL_* form, which this pin does not block.
# --- §8.2 prefixed OUTPUT counterparts (contract v0.8.5) ---------------------
# The other half of the v0.8.5 ruling: each §8.2-consuming library MUST export
# library-prefixed outputs whose values are the values its code reads, so a
# consumer can assert co-linked libraries agree on placement. Pinned present in
# every archive that consumes §8.2 -- i.e. every default-profile archive with
# field arithmetic. Absent from the onchip archives (no REU multiply table) and
# the sha384 archive (no REU at all), which is checked below.
REU_OUTPUT_SYMS = {
    "LIB_NISTCURVES_SHARED_REU_MUL_BANK",
    "LIB_NISTCURVES_SHARED_REU_MUL_OFFSET",
    "LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED",
}

REU_PLACEMENT_SYMS = {
    "LIB_SHARED_REU_MUL_BANK",
    "LIB_SHARED_REU_MUL_OFFSET",
    "LIB_SHARED_REU_MUL_BANKS_USED",
}

# --- RFC 6979 self-test vector pins (issue #91) ------------------------------
# curve256.s / curve384.s used to carry 384 B of RFC 6979 self-test vectors in
# the same translation units as the curve parameters, so ld65's whole-member
# pull shipped them into 7 of 9 consumer archives. Nothing referenced them --
# zero importers across every built object, and the test suites take their
# expected values from the oracle and tools/vectors/, never from on-chip
# constants -- so issue #91 deleted them outright rather than relocating them.
# Pinned absent from every archive so a future edit cannot reintroduce dead
# data into the consumer surface the way the originals did.
TESTVEC_SYMS = {
    "ecdsa_test_privkey", "ecdsa_test_k", "ecdsa_test_hash",
    "ecdsa_test_r", "ecdsa_test_s", "ecdsa_test_pubx", "ecdsa_test_puby",
    "ecdsa_test_2gx", "ecdsa_test_2gy",
    "ecdsa_test_2gx_384", "ecdsa_test_2gy_384",
}

# The lib-p384-sha384 archive contains no field, point, or multiply code,
# so sha384_k is the only precalc table it actually has (issue #88). It
# previously shipped the default-profile manifest pair and enumerated all
# five, describing four tables it does not carry — and, because the §8.0
# cross-adopter audit greps exactly these symbols, advertising itself as an
# sqtab provider to any sibling library that genuinely ships one.
PRECALC_NON_SHA_SYMS = PRECALC_SQTAB_SYMS | PRECALC_REU_MUL_SYMS | PRECALC_COMB_SYMS

# --- Zero-page claim pins (issues #88 / #90) ---------------------------------
# Each archive exports only the slots its own objects .importzp; everything
# else must NOT ship in it. Zero page is the scarcest resource on a 6502 -- on
# a C64 with BASIC and KERNAL live the genuinely free bytes number in the low
# tens -- so exporting the whole-library set against a real need of 8-15 can
# make a consumer's collision check reject an integration that would have fit.
# Both directions ratchet: the slots an archive's objects import must be
# present (it cannot link without them) and the rest absent.
#
# The field/point layer plus an ecdsa*_nocomb verifier -- what every curve
# archive has in common (9 slots, 15 B).
ZP_VERIFY_SYMS = {
    "fp_src1", "fp_src2", "fp_dst", "fp_misc",
    "fp_carry", "fp_mul_i", "fp_mul_j",
    "ec_scalar_ptr", "zp_ptr2", "nistcurves_zp_ptr2",
}
# Used only by points256_comb.o / points384_comb.o. Split per curve (issue
# #117): zp_ptr1 is the anchor-copy pointer both ec_precompute_* bodies use,
# but zp_tmp1/zp_tmp2 belong to sm384w_calc_reu_offset alone -- the P-256
# comb archives import zp_ptr1 and must not export the two temps.
ZP_COMB_P256_SYMS = {"zp_ptr1", "nistcurves_zp_ptr1"}
ZP_COMB_P384_ONLY_SYMS = {"zp_tmp1", "zp_tmp2",
                          "nistcurves_zp_tmp1", "nistcurves_zp_tmp2"}
ZP_COMB_SYMS = ZP_COMB_P256_SYMS | ZP_COMB_P384_ONLY_SYMS
ZP_SHA384_SYMS = {"sha_src", "sha_len", "sha_w_ptr", "sha_w_ptr2"}
# Default profile: 16 slots, 27 B.
ZP_DEFAULT_SYMS = ZP_VERIFY_SYMS | ZP_COMB_SYMS | ZP_SHA384_SYMS
ZP_NON_SHA_SYMS = ZP_VERIFY_SYMS | ZP_COMB_SYMS
# proc_port, fp_loop, and poly_i/poly_j/poly_carry/poly_tmp are deliberately
# absent from every set above: issue #90 established that no archived object
# references any of them and removed their definitions from zp_config.s
# (proc_port survives as a local equate in the never-archived main.s).

# --- §5 manifest VALUE pins (issues #88 / #90) -------------------------------
# Each archive's §5 equates must describe THAT archive, not the library as a
# whole. Every load-bearing value is pinned for all nine:
#
#   ZP_USAGE_BYTES     over-claiming can push a consumer's collision check into
#                      rejecting an integration that would have fit; under-
#                      claiming lets it place a variable in a byte the library
#                      silently clobbers mid-operation
#   REU_BANKS_USED     over-claiming makes a consumer reserve banks it could
#                      have used for something else
#   RESIDENT_BYTES     over-claiming fails the §5 fit check closed against a
#                      region the archive would actually have fit in
#   COLD_BYTES         mis-states how much the consumer can page-overlay
#   SHARED_PRIMITIVES  over-claiming trips a co-linked sibling's §8.0
#                      disjointness assert on a valid composition
#   SHARED_CONSUMES    over-claiming makes the v0.5.0 coverage assert demand a
#                      provider the link has no use for
#
# RESIDENT_BYTES / COLD_BYTES for the curve archives were previously left
# unpinned because they carried whole-library figures pending issue #90; that
# re-derivation has now landed, so they ratchet here like everything else.
# Values are the per-variant measurement: ZP by variant only (the profile does
# not change which ZP scratch the field layer uses), REU banks and COLD by
# variant AND profile (the onchip archives ship no reu_mul table and no
# reu_mul_init body), RESIDENT by variant only (the four default/onchip pairs
# measure within 0.3-1.3%, inside SPEC §5's ±5% band).
MANIFEST_VALUES = {
    "nistcurves-p384-sha384.a": {
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0000,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0000,
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 8,
        "LIB_NISTCURVES_RESIDENT_BYTES": 9400,
        "LIB_NISTCURVES_COLD_BYTES": 0,
    },
    "nistcurves.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 27,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x07,
        "LIB_NISTCURVES_RESIDENT_BYTES": 27400,
        "LIB_NISTCURVES_COLD_BYTES": 1840,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 27,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x04,
        "LIB_NISTCURVES_RESIDENT_BYTES": 27400,
        "LIB_NISTCURVES_COLD_BYTES": 1650,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p256-verify.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x03,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8800,
        "LIB_NISTCURVES_COLD_BYTES": 430,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p256-verify-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8800,
        "LIB_NISTCURVES_COLD_BYTES": 250,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p384-verify.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x03,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8450,
        "LIB_NISTCURVES_COLD_BYTES": 430,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p384-verify-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8450,
        "LIB_NISTCURVES_COLD_BYTES": 250,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p384-curve.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 23,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x03,
        "LIB_NISTCURVES_RESIDENT_BYTES": 17800,
        "LIB_NISTCURVES_COLD_BYTES": 430,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p384-curve-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 23,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_RESIDENT_BYTES": 17800,
        "LIB_NISTCURVES_COLD_BYTES": 250,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-app-owned.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 27,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0000,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    # P-256 comb archives (issue #117). REU banks: the comb bank $02 is
    # claimed in BOTH profiles (ec_precompute_256 populates it, the comb
    # evaluate loop DMA-fetches from it); onchip drops only the mul-table
    # banks. RESIDENT is variant-shared (measured 8991 DMA / 9094 onchip,
    # 1.1% apart); COLD splits per profile (the 186 B reu_mul_init delta).
    "nistcurves-p256-comb.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 17,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x07,
        "LIB_NISTCURVES_RESIDENT_BYTES": 9300,
        "LIB_NISTCURVES_COLD_BYTES": 1050,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p256-comb-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 17,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x04,
        "LIB_NISTCURVES_RESIDENT_BYTES": 9300,
        "LIB_NISTCURVES_COLD_BYTES": 870,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
}

# Per-archive precalc row sets, straight from what each archive contains:
# the comb rows only where points*_comb.o ships (the two full archives), the
# sha384_k row only where sha384.o ships, the reu_mul row only in the DMA
# profile. Pinning both directions is what regression-tests the issue #90 bug
# class -- a future edit that re-broadens a gate would otherwise stay green.
PRECALC_FULL = PRECALC_SQTAB_SYMS | PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
PRECALC_VERIFY = PRECALC_SQTAB_SYMS
PRECALC_CURVE = PRECALC_SQTAB_SYMS | PRECALC_SHA384_K_SYMS

MUST_EXPORT = {
    "nistcurves.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                     | PRECALC_FULL | PRECALC_REU_MUL_SYMS | ZP_DEFAULT_SYMS | REU_OUTPUT_SYMS),
    "nistcurves-p256-verify.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                                 | PRECALC_VERIFY | PRECALC_REU_MUL_SYMS
                                 | ZP_VERIFY_SYMS | REU_OUTPUT_SYMS),
    "nistcurves-p384-verify.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                                 | PRECALC_VERIFY | PRECALC_REU_MUL_SYMS
                                 | ZP_VERIFY_SYMS | REU_OUTPUT_SYMS),
    "nistcurves-p384-curve.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                                | PRECALC_CURVE | PRECALC_REU_MUL_SYMS
                                | ZP_VERIFY_SYMS | ZP_SHA384_SYMS | REU_OUTPUT_SYMS),
    "nistcurves-p384-sha384.a": MANIFEST_SYMS | PRECALC_SHA384_K_SYMS | ZP_SHA384_SYMS,
    "nistcurves-onchip.a": MANIFEST_SYMS | PRECALC_FULL | ZP_DEFAULT_SYMS,
    "nistcurves-p256-verify-onchip.a": MANIFEST_SYMS | PRECALC_VERIFY | ZP_VERIFY_SYMS,
    "nistcurves-p384-verify-onchip.a": MANIFEST_SYMS | PRECALC_VERIFY | ZP_VERIFY_SYMS,
    "nistcurves-p384-curve-onchip.a": (MANIFEST_SYMS | PRECALC_CURVE
                                       | ZP_VERIFY_SYMS | ZP_SHA384_SYMS),
    "nistcurves-app-owned.a": MANIFEST_SYMS | REU_OUTPUT_SYMS,
    "nistcurves-p256-comb.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                               | PRECALC_SQTAB_SYMS | PRECALC_REU_MUL_SYMS
                               | PRECALC_COMB_P256_SYMS
                               | ZP_VERIFY_SYMS | ZP_COMB_P256_SYMS
                               | REU_OUTPUT_SYMS),
    "nistcurves-p256-comb-onchip.a": (MANIFEST_SYMS | PRECALC_SQTAB_SYMS
                                      | PRECALC_COMB_P256_SYMS
                                      | ZP_VERIFY_SYMS | ZP_COMB_P256_SYMS),
}
MUST_NOT_EXPORT = {
    "nistcurves.a": set() | TESTVEC_SYMS | REU_PLACEMENT_SYMS,
    "nistcurves-p256-verify.a": (PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                 | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
    "nistcurves-p384-verify.a": (PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                 | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
    "nistcurves-p384-curve.a": PRECALC_COMB_SYMS | ZP_COMB_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS,
    "nistcurves-p384-sha384.a": REU_MUL_PROVIDER_SYMS | PRECALC_NON_SHA_SYMS | ZP_NON_SHA_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS,
    "nistcurves-onchip.a": REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS,
    "nistcurves-p256-verify-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                        | PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                        | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
    "nistcurves-p384-verify-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                        | PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                        | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
    "nistcurves-p384-curve-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                       | PRECALC_COMB_SYMS | ZP_COMB_SYMS | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
    "nistcurves-app-owned.a": REU_MUL_PROVIDER_SYMS | REU_PLACEMENT_SYMS | TESTVEC_SYMS,
    "nistcurves-p256-comb.a": (PRECALC_COMB_P384_SYMS | PRECALC_SHA384_K_SYMS
                               | ZP_COMB_P384_ONLY_SYMS | ZP_SHA384_SYMS
                               | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
    "nistcurves-p256-comb-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                      | PRECALC_COMB_P384_SYMS | PRECALC_SHA384_K_SYMS
                                      | ZP_COMB_P384_ONLY_SYMS | ZP_SHA384_SYMS
                                      | TESTVEC_SYMS | REU_PLACEMENT_SYMS),
}

# §8.3 provider-surface pins (issue #123): every §8.3-OWNING archive exports
# the five-symbol surface; the deferring app-owned archive must export none of
# it (a re-export collides with the app's provider at link). The sha384
# archive carries no field layer and is exempt from both directions.
for _a in MUST_EXPORT:
    if _a not in ("nistcurves-p384-sha384.a", "nistcurves-app-owned.a"):
        MUST_EXPORT[_a] = MUST_EXPORT[_a] | CT_MUL_PROVIDER_SYMS
MUST_NOT_EXPORT["nistcurves-app-owned.a"] = (
    MUST_NOT_EXPORT["nistcurves-app-owned.a"] | CT_MUL_PROVIDER_SYMS)

# --- Dummy-link smoke tests: (label, [import symbols], expect_link) ----------
# expect_link True  -> documented as linkable, must link clean.
# expect_link False -> documented as broken, must fail with unresolved symbols
#                      that are a subset of that archive's KNOWN_EXTERNAL set.
SMOKE = {
    "nistcurves.a": [
        ("packaged ecdsa_verify_256", ["ecdsa_verify_256"], True),
        ("packaged ecdsa_verify_384", ["ecdsa_verify_384"], True),
        ("sha384 streaming", ["sha384_init", "sha384_update", "sha384_final"], True),
        ("packaged ecdsa_verify_with_message_384", ["ecdsa_verify_with_message_384"], True),
        ("boot init sequence incl. SPEC 8.2 provider (issue #81)",
         ["sqtab_init", "reu_mul_init", "reu_mul_tables_init"], True),
    ],
    "nistcurves-p256-verify.a": [
        ("variable-base building blocks",
         ["ec_scalar_mul_var", "ec_jacobian_to_affine", "fp_mod_inv", "fp_mod_mul"], True),
        ("packaged ecdsa_verify_256 (nocomb variant)", ["ecdsa_verify_256"], True),
        ("boot init sequence incl. SPEC 8.2 provider (issue #81)",
         ["sqtab_init", "reu_mul_init", "reu_mul_tables_init"], True),
    ],
    "nistcurves-p384-verify.a": [
        ("variable-base building blocks",
         ["ec_scalar_mul_var_384", "ec_jacobian_to_affine_384",
          "fp_mod_inv_384", "fp_mod_mul_384"], True),
        ("packaged ecdsa_verify_384 (nocomb variant)", ["ecdsa_verify_384"], True),
        ("boot init sequence incl. SPEC 8.2 provider (issue #81)",
         ["sqtab_init", "reu_mul_init", "reu_mul_tables_init"], True),
    ],
    "nistcurves-p384-sha384.a": [
        ("sha384 streaming", ["sha384_init", "sha384_update", "sha384_final"], True),
    ],
    "nistcurves-p384-curve.a": [
        ("sha384 streaming", ["sha384_init", "sha384_update", "sha384_final"], True),
        ("variable-base building blocks",
         ["ec_scalar_mul_var_384", "ec_jacobian_to_affine_384",
          "fp_mod_inv_384", "fp_mod_mul_384"], True),
        ("packaged ecdsa_verify_384 (nocomb variant)", ["ecdsa_verify_384"], True),
        ("packaged ecdsa_verify_with_message_384 (nocomb variant)",
         ["ecdsa_verify_with_message_384"], True),
        ("boot init sequence incl. SPEC 8.2 provider (issue #81)",
         ["sqtab_init", "reu_mul_init", "reu_mul_tables_init"], True),
    ],
    "nistcurves-onchip.a": [
        ("packaged ecdsa_verify_256", ["ecdsa_verify_256"], True),
        ("packaged ecdsa_verify_384", ["ecdsa_verify_384"], True),
        ("sha384 streaming", ["sha384_init", "sha384_update", "sha384_final"], True),
        ("packaged ecdsa_verify_with_message_384",
         ["ecdsa_verify_with_message_384"], True),
    ],
    "nistcurves-p256-verify-onchip.a": [
        ("variable-base building blocks",
         ["ec_scalar_mul_var", "ec_jacobian_to_affine", "fp_mod_inv", "fp_mod_mul"], True),
        ("packaged ecdsa_verify_256 (nocomb variant)", ["ecdsa_verify_256"], True),
    ],
    "nistcurves-p384-verify-onchip.a": [
        ("variable-base building blocks",
         ["ec_scalar_mul_var_384", "ec_jacobian_to_affine_384",
          "fp_mod_inv_384", "fp_mod_mul_384"], True),
        ("packaged ecdsa_verify_384 (nocomb variant)", ["ecdsa_verify_384"], True),
    ],
    "nistcurves-p384-curve-onchip.a": [
        ("sha384 streaming", ["sha384_init", "sha384_update", "sha384_final"], True),
        ("variable-base building blocks",
         ["ec_scalar_mul_var_384", "ec_jacobian_to_affine_384",
          "fp_mod_inv_384", "fp_mod_mul_384"], True),
        ("packaged ecdsa_verify_384 (nocomb variant)", ["ecdsa_verify_384"], True),
        ("packaged ecdsa_verify_with_message_384 (nocomb variant)",
         ["ecdsa_verify_with_message_384"], True),
    ],
    # P-256 comb archives (issue #117): the comb-fast packaged verifier and
    # the fixed-base machinery it needs must both link -- this is the whole
    # point of the target. The DMA arm also carries the §8.2 boot provider.
    "nistcurves-p256-comb.a": [
        ("packaged ecdsa_verify_256 (comb-fast variant)", ["ecdsa_verify_256"], True),
        ("fixed-base comb machinery",
         ["ec_scalar_mul", "ec_precompute_256"], True),
        ("variable-base building blocks",
         ["ec_scalar_mul_var", "ec_jacobian_to_affine", "fp_mod_inv", "fp_mod_mul"], True),
        ("boot init sequence incl. SPEC 8.2 provider (issue #81)",
         ["sqtab_init", "reu_mul_init", "reu_mul_tables_init"], True),
    ],
    "nistcurves-p256-comb-onchip.a": [
        ("packaged ecdsa_verify_256 (comb-fast variant)", ["ecdsa_verify_256"], True),
        ("fixed-base comb machinery",
         ["ec_scalar_mul", "ec_precompute_256"], True),
        ("variable-base building blocks",
         ["ec_scalar_mul_var", "ec_jacobian_to_affine", "fp_mod_inv", "fp_mod_mul"], True),
    ],
}

# Minimal ld65 config: ZP + one catch-all region, every LIB_NISTCURVES_*
# segment optional so any archive subset places cleanly.
CONSUMER_CFG = """\
MEMORY {
    ZP:   file = "", start = $0002, size = $00FE, type = rw, define = yes;
    MAIN: file = %O, start = $0801, size = $B000;
}
SEGMENTS {
    ZEROPAGE:                       load = ZP,   type = zp,  optional = yes;
    CODE:                           load = MAIN, type = rw;
    LIB_NISTCURVES_MAIN_CODE:       load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_MUL_CODE:        load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P256_CODE:       load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P384_CODE:       load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_SHA384_CODE:     load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_MAIN_RODATA:     load = MAIN, type = ro,  optional = yes;
    LIB_NISTCURVES_P256_RODATA:     load = MAIN, type = ro,  optional = yes;
    LIB_NISTCURVES_P384_RODATA:     load = MAIN, type = ro,  optional = yes;
    LIB_NISTCURVES_SHA384_RODATA:   load = MAIN, type = ro,  optional = yes;
    LIB_NISTCURVES_SHA384_TABLES:   load = MAIN, type = ro,  align = $100, optional = yes;
    LIB_NISTCURVES_TABLES:          load = MAIN, type = rw,  align = $100, optional = yes;
    LIB_NISTCURVES_BSS:             load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P256_BSS:        load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P256_INVREF_BSS: load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P256_LIMLEE_BSS: load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P384_BSS:        load = MAIN, type = bss, optional = yes;
    LIB_NISTCURVES_P384_DATA_BSS:   load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_P384_LIMLEE_BSS: load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_SHA384_BSS:      load = MAIN, type = rw,  optional = yes;
    LIB_NISTCURVES_TEST_BSS:        load = MAIN, type = rw,  optional = yes;
}
"""


def sh(cmd):
    """Run a command, return (returncode, stdout+stderr)."""
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def od65_names(obj, mode):
    """Set of symbol names from od65 --dump-{imports,exports} on one object."""
    _, out = sh(["od65", mode, str(obj)])
    return set(re.findall(r'Name:\s*"([^"]+)"', out))


def od65_value(objs, sym):
    """Exported integer value of `sym`, searched across an archive's objects.

    od65 reads single .o files only -- pointed at a .a it prints
    '(no xo65 object file)' and exits 0 -- so callers pass the archive's
    constituent objects, which is how this tool resolves archives anyway.
    """
    for obj in objs:
        _, out = sh(["od65", "--dump-exports", str(obj)])
        m = re.search(
            r'Name:\s*"' + re.escape(sym) + r'"(?:.|\n)*?Value:\s*0x([0-9A-Fa-f]+)',
            out,
        )
        if m:
            return int(m.group(1), 16)
    return None


class _CountMismatch:
    """od65_export_names() read the dump but extraction disagreed with od65's
    declared export Count. Distinct from None ("could not read it at all")."""
    def __repr__(self):
        return "<extraction dropped names vs od65 Count>"


COUNT_MISMATCH = _CountMismatch()


# --- §5 footprint measurement (issue #142) -----------------------------------
# Which segments count as the "code+rodata footprint" §5's RESIDENT/COLD pair
# describes. Stated as an explicit classification rather than a name pattern so
# that a segment added later lands in neither set and trips the unclassified
# failure above -- the accounting stays a decision, not an accident.
#
# Counted: executable code and read-only data, including the SHA-384 rotate
# LUTs, which are page-aligned RODATA read on every compression.
# Not counted: RW state. §5 scopes both equates to code+rodata, and the manifest
# derivations exclude BSS on the same basis -- LIB_NISTCURVES_TABLES holds the
# two 256-byte REU DMA landing pages, which are RW buffers, not rodata.
FOOTPRINT_SEGMENTS = {
    "LIB_NISTCURVES_MAIN_CODE", "LIB_NISTCURVES_MUL_CODE",
    "LIB_NISTCURVES_P256_CODE", "LIB_NISTCURVES_P384_CODE",
    "LIB_NISTCURVES_SHA384_CODE",
    "LIB_NISTCURVES_MAIN_RODATA", "LIB_NISTCURVES_P256_RODATA",
    "LIB_NISTCURVES_P384_RODATA", "LIB_NISTCURVES_SHA384_RODATA",
    "LIB_NISTCURVES_SHA384_TABLES",
}
FOOTPRINT_EXCLUDED = {
    "LIB_NISTCURVES_TABLES",            # RW: the REU DMA landing pages
    "LIB_NISTCURVES_BSS", "LIB_NISTCURVES_P256_BSS",
    "LIB_NISTCURVES_P256_INVREF_BSS", "LIB_NISTCURVES_P256_LIMLEE_BSS",
    "LIB_NISTCURVES_P384_BSS", "LIB_NISTCURVES_P384_LIMLEE_BSS",
    "LIB_NISTCURVES_P384_DATA_BSS",
    "LIB_NISTCURVES_SHA384_BSS", "LIB_NISTCURVES_TEST_BSS",
    # ca65 emits these as zero-length placeholders in every object.
    "CODE", "RODATA", "DATA", "BSS", "ZEROPAGE", "NULL", "LOADADDR",
}

_SEG_RE = re.compile(
    r'Name: *"([^"]+)"\s*\n\s*Flags:\s*\d+\s*\n\s*Size:\s*(\d+)')


# Segments the cfg page-aligns. ld65 inserts 0-255 bytes of padding AHEAD of
# each when it places them. That padding is NOT part of the §5 measurand and is
# deliberately not charged here (issue #161): the draft §5 measurand clause --
# "charge what is inside each segment, and nothing between or before them" --
# scopes it out, because `(-previous_end) mod alignment` is fixed by where the
# CONSUMER places our segments and in what order. Reordering relocates such a
# pad rather than removing it, and only the consumer's own link map has the
# per-segment extents needed to compute it. Charging it billed every consumer
# 255 B they may not spend, in an amount they can derive exactly and we cannot.
#
# The set is still needed: footprint_basis_check() uses it to locate the
# page-aligned segments whose real inter-segment gap it measures as a bounded
# change detector, against INTER_SEGMENT_FILL_BOUND below.
FOOTPRINT_ALIGNED = {"LIB_NISTCURVES_SHA384_TABLES", "LIB_NISTCURVES_TABLES"}
# Not a budget line. The most fill a single page-aligned segment boundary can
# carry; footprint_basis_check() asserts the measured inter-segment fill stays
# under this so a structural change to the placement shows up as a failure.
INTER_SEGMENT_FILL_BOUND = 255


def measured_code_rodata(mods):
    """Placed code+rodata bytes an archive's members contain.

    The raw sum of the footprint segments' sizes across the archive's member
    objects -- no pre-segment alignment padding is added (see FOOTPRINT_ALIGNED
    above and issue #161).

    §5's measurand is "the placed span ... not the sum of member object sizes",
    and a sum equals the placed span only while no segment takes fragments from
    two objects with alignment between them. That is a property of this tree,
    not a guarantee, so it is verified rather than assumed:
    footprint_basis_check() links for real, reads the ld65 map, and asserts
    `od65 sums == placed sizes` over every segment. That leg is what makes this
    sum-based measurand conformant -- if it goes, so does the basis for this
    function.

    Returns (total, unknown_segment_names). Zero-length segments are ignored --
    ca65 emits placeholders for the default names in every object. Missing
    objects are a hard failure, not a skip: a partially-built tree would
    otherwise measure low and pass.
    """
    total = 0
    unknown = set()
    for m in mods:
        obj = BUILD / (m + ".o")
        if not obj.exists():
            unknown.add(f"<missing object {obj.name}>")
            continue
        dump = sh(["od65", "--dump-segments", str(obj)])[1]
        for seg, size in _SEG_RE.findall(dump):
            size = int(size)
            if size == 0:
                continue
            if seg in FOOTPRINT_SEGMENTS:
                total += size
            elif seg not in FOOTPRINT_EXCLUDED:
                unknown.add(seg)
    return total, unknown


def _makefile_text_and_expand():
    """(joined Makefile text, expand()) -- shared by the archive-member parser
    and the object-rule parser below.

    `expand` resolves simple `$(VAR)` / `${VAR}` references only. A GNU make
    function call (`$(subst ...)`, `$(patsubst ...)`) contains commas and so
    does NOT match the name pattern -- it survives expansion literally, and
    the object-rule parser treats a surviving `$(` as a hard failure rather
    than quietly reading the wrong switches. That is deliberate: the Makefile
    writes its archive member lists and its per-variant `-D` sets out longhand
    for exactly this reason (see the comment above LIB_CORE_APP_OWNED_OBJS),
    and a parser that silently degraded to the default objects would pass an
    archive -- or an arm -- it had never inspected.

    ONE ASYMMETRY, deliberate and currently harmless: `expand` resolves an
    UNKNOWN `$(VAR)` to "" silently, and only `expand_checked` rejects a
    surviving `$(`. That matches make, which also expands an undefined
    variable to nothing, so today the two agree. It stops matching the moment
    the Makefile grows a `define`/`endef` block or an assignment inside a
    conditional -- neither of which the `^NAME =` scan below sees -- and the
    disagreement would again be a silently SHORTER token list. The
    reconciliations downstream (rule heads vs parsed rules, parsed members vs
    `ar65 t`, parsed -D sets vs build/*.o) are what would catch it; this note
    exists so the next reader does not mistake the asymmetry for a guarantee.
    """
    text = MAKEFILE.read_text()
    joined = re.sub(r"\\\n\s*", " ", text)  # fold backslash continuations

    # `:=`, `?=` and `+=` are matched too. Reading only `NAME =` left every
    # other flavour undefined, and an undefined variable expands to the empty
    # string -- so one character (`OBJS :=`) silently shrank an archive's
    # parsed member list, and the tokens that vanished did not end in `.o`, so
    # nothing downstream noticed. `+=` is accumulated rather than overwritten.
    vars_ = {}
    for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\+?[:?]?=)\s*(.*)$",
                         joined, re.M):
        name, op = m.group(1), m.group(2)
        # make treats an unescaped `#` as a comment, and several assignments
        # here carry a trailing one. Reading it as part of the VALUE injected
        # prose into the expansion of every recipe using the variable.
        val = re.split(r"(?<!\\)#", m.group(3))[0].strip()
        if op == "+=":
            vars_[name] = (vars_.get(name, "") + " " + val).strip()
        else:
            vars_[name] = val

    def expand(s, depth=0):
        if depth > 20:
            raise RuntimeError(f"variable expansion too deep: {s!r}")
        out = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]",
                     lambda mm: expand(vars_.get(mm.group(1), ""), depth + 1), s)
        return out

    def expand_checked(s, what):
        """expand(), but a surviving `$(` is a hard failure.

        Without this the degradation is silent AND in the green direction: an
        unexpandable token simply does not end in `.o`, so it drops out of a
        member list and the population shrinks with no diagnostic. Losing one
        equate-only member (nothing imports it) took a gate-owning arm out of
        the sweep while every leg still printed OK."""
        out = expand(s)
        residue = out.replace("$(SRC_DIR)", "").replace("$(BUILD_DIR)", "")
        if "$(" in residue or "${" in residue:
            raise RuntimeError(
                f"{what}: unexpandable make function or unknown variable "
                f"survives expansion, so the parsed token list is a SUBSET of "
                f"the real one: {out!r}")
        return out

    return joined, expand, expand_checked


# Explicit per-object rules: `$(BUILD_DIR)/<obj>.o: $(SRC_DIR)/<tu>.s` with a
# one-line ca65 recipe. An object NOT matched here is built by the catch-all
# pattern rule, i.e. the default arm with no variant define.
#
# The recipe is the WHOLE block of tab-indented lines that follows, with
# blank/comment lines between head and body tolerated. Binding only "the one
# line immediately after the head" made two benign Makefile edits silently
# wrong in the green direction: prepending an `@echo` to a recipe made the
# parser read that line, find no `-D`, and sweep the arm as the DEFAULT arm
# (issue #159's own fixture then passed again); inserting a `# comment` made
# the rule vanish entirely, dropping the arm from the roster.
_OBJ_RULE_RE = re.compile(
    r"^\$[({]BUILD_DIR[)}]/(?P<obj>[A-Za-z0-9_]+)\.o:\s*"
    r"\$[({]SRC_DIR[)}]/(?P<src>[A-Za-z0-9_]+)\.s[^\n]*\n"
    r"(?P<recipe>(?:[ \t]*#[^\n]*\n|[ \t]*\n)*(?:\t[^\n]*\n)+)", re.M)
# Any explicit object rule head at all, used to reconcile what the regex above
# actually matched against what the Makefile actually declares.
#
# This must be INDEPENDENT of _OBJ_RULE_RE in the dimension that matters, or
# it is not a reconciliation at all -- it was sharing the "colon immediately
# after .o" assumption, so `target : deps` (legal GNU make, one space) and
# multi-target heads were missed by BOTH and no mismatch was reported. The arm
# then vanished through shipped_object_arms()'s `rules.get(mod, (mod, ()))`
# fallback. That was loud only by accident: the fallback sets the source stem
# to the OBJECT name, and no such .s file exists -- which stops being true the
# moment any rule has obj == src stem. So: optional whitespace before the
# colon, and every `$(BUILD_DIR)/x.o` target on a possibly-multi-target head.
_OBJ_HEAD_LINE_RE = re.compile(
    r"^(?P<targets>\$[({]BUILD_DIR[)}]/[A-Za-z0-9_]+\.o"
    r"(?:[ \t]+\$[({]BUILD_DIR[)}]/[A-Za-z0-9_]+\.o)*)[ \t]*:(?!=)", re.M)
_OBJ_TARGET_RE = re.compile(r"\$[({]BUILD_DIR[)}]/([A-Za-z0-9_]+)\.o")


def _declared_object_rule_heads(joined):
    """Every object name that appears as an explicit rule target."""
    heads = set()
    for m in _OBJ_HEAD_LINE_RE.finditer(joined):
        heads |= set(_OBJ_TARGET_RE.findall(m.group("targets")))
    return heads


def parse_makefile_object_rules():
    """objname -> (source stem, tuple of ca65 `-D` switches) for every object
    with an explicit rule.

    DERIVED, not restated. The per-variant define sets already live in the
    Makefile -- they are what actually produces `precalc_manifest_sha384.o` --
    and a second hand-maintained copy here would be a roster that can drift
    from the build it claims to describe. This tree has been burned by exactly
    that twice: BARE_GATED listed none of the bare LIB_PRECALC_* names it was
    supposed to police, and GATE_TUS kept `zp_config` after its aliases moved
    away. A restated table is green about the arms it happens to list; a
    derived one grows the moment the Makefile grows a variant, and an arm that
    disappears from the Makefile disappears from the sweep instead of sitting
    here proving nothing.
    """
    joined, _expand, expand_checked = _makefile_text_and_expand()
    rules = {}
    for m in _OBJ_RULE_RE.finditer(joined):
        obj = m.group("obj")
        recipe = expand_checked(m.group("recipe"), f"object rule for {obj}.o")
        # The switch set must come from the ASSEMBLER line, not from whatever
        # line happened to be first. Requiring exactly one ca65 invocation
        # means an `@echo` preamble, a second assemble, or a rename of the
        # assembler variable fails loudly instead of yielding a wrong -- and
        # always weaker -- arm.
        ca_lines = [ln for ln in recipe.splitlines() if re.search(r"\bca65\b", ln)]
        if len(ca_lines) != 1:
            raise RuntimeError(
                f"object rule for {obj}.o has {len(ca_lines)} ca65 lines in its "
                f"recipe; the arm's -D set cannot be read unambiguously and a "
                f"wrong read is silently the DEFAULT arm: {recipe!r}")
        defines = tuple(re.findall(r"-D\s+(\S+)", ca_lines[0]))
        rules[obj] = (m.group("src"), defines)
    # RECONCILIATION. Everything above is regex against a hand-written
    # Makefile, and its failure mode is a smaller roster, silently. Every
    # explicit object-rule head the Makefile declares must have been parsed;
    # a head the pattern missed is an arm the sweep would never look at while
    # printing a clean count.
    heads = _declared_object_rule_heads(joined)
    unparsed = sorted(heads - set(rules))
    if unparsed:
        raise RuntimeError(
            f"Makefile declares explicit object rules for {unparsed} that this "
            f"parser did not match (rule head shape changed?). Their arms would "
            f"silently fall back to the default arm or vanish from the sweep.")
    return rules


def shipped_object_arms(archives):
    """objname -> (source stem, defines tuple, [archives shipping it]).

    The population is the objects that actually SHIP, taken from the parsed
    ar65 member lists, so a rule the build no longer uses is not swept, and a
    member with no explicit rule falls back to the pattern rule's default arm.
    """
    rules = parse_makefile_object_rules()
    arms = {}
    for aname, mods in archives.items():
        for mod in mods:
            src, defines = rules.get(mod, (mod, ()))
            arms.setdefault(mod, (src, defines, []))[2].append(aname)
    return {k: (v[0], v[1], sorted(set(v[2]))) for k, v in arms.items()}


def _arm_label(obj, defines, archives_using):
    """One-line identification of an arm: the object, the switches that build
    it, and the archives that ship it. A failure naming only the TU cannot be
    acted on -- eleven of the twelve archives use a variant arm."""
    d = " ".join(f"-D {x}" for x in defines) or "(default arm, no -D)"
    return f"{obj}.o [{d}] in {', '.join(archives_using)}"


def parse_makefile_archives():
    """Map archive filename -> [object module names], from the ar65 recipes.

    Parses the Make variable assignments (LIB_*_OBJS, BUILD_DIR) with line
    continuations, then the `ar65 a $(LIB_DIR)/<name>.a <tokens>` lines, and
    expands $(VAR) / $(BUILD_DIR) references down to build/<mod>.o paths.

    Expansion is CHECKED. This parser used to drop anything that failed to
    expand -- an unknown variable became "", a `$(subst ...)` survived
    literally, and either way the token no longer ended in `.o` and simply
    left the member list. The population then shrank silently, which every
    downstream leg reports as a smaller-but-clean count. Losing a single
    equate-only member that nothing imports took a gate-owning arm out of the
    sweep with all twelve archives still reporting OK.
    """
    joined, _expand, expand_checked = _makefile_text_and_expand()

    # Each archive rule is `$(LIB_DIR)/<name>.a: <prereqs>` followed by its
    # recipe. Capture the target name from the rule head and the WHOLE recipe
    # block, then take the object tokens from every `ar65 a $@` line in it.
    #
    # EVERY such line, not the first. `ar65 a` APPENDS -- which is why each
    # recipe does `rm -f $@` first -- so splitting a member list across two
    # `ar65 a` lines is an ordinary, legal Makefile shape that make builds
    # identically. Binding only the first line silently dropped the members on
    # the second: 21 arms -> 20, 72 objects -> 71, every leg still OK, and the
    # gated link rebuilt and linked an archive missing a real member and
    # called it OK. With #159's own fixture also planted, the gated-surface
    # leg printed OK and never named the leak; the run went red only through a
    # neighbouring leg with a wrong diagnosis.
    archives = {}
    rule = re.compile(
        r"^\$[({]LIB_DIR[)}]/(?P<name>\S+\.a):[^\n]*\n"
        r"(?P<recipe>(?:[ \t]*#[^\n]*\n|[ \t]*\n)*(?:\t[^\n]*\n)+)",
        re.M,
    )
    for m in rule.finditer(joined):
        name = m.group("name")
        recipe = m.group("recipe")
        ar_lines = re.findall(r"^\tar65 a \$@ ([^\n]*)$", recipe, re.M)
        if not ar_lines:
            raise RuntimeError(f"archive rule for {name} has no `ar65 a $@` line")
        mods = []
        for raw in ar_lines:
            tokens = expand_checked(raw, f"ar65 recipe for {name}")
            toks = tokens.split()
            # Every token on an ar65 line is an object path. One that is not
            # means the expansion produced something this parser does not
            # understand, and the list it just built is a subset of the real one.
            stray = [t for t in toks if not t.endswith(".o")]
            if stray:
                raise RuntimeError(
                    f"ar65 recipe for {name} has non-object tokens {stray} after "
                    f"expansion; the parsed member list is a SUBSET of the real one")
            mods += [Path(t).stem for t in toks]
        if not mods:
            raise RuntimeError(f"ar65 recipe for {name} parsed to zero members")
        archives[name] = mods
    return archives


def link_test(archive_path, imports):
    """Assemble a tiny consumer importing `imports`, link vs archive.

    Returns (ok, unresolved_set, raw_output).
    """
    src = ".import " + ", ".join(imports) + "\n.segment \"CODE\"\nentry:\n"
    src += "".join(f"\tjsr {s}\n" for s in imports) + "\trts\n"
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "cfg").write_text(CONSUMER_CFG)
        (td / "c.s").write_text(src)
        rc, out = sh(["ca65", "--cpu", "6502", "-o", str(td / "c.o"), str(td / "c.s")])
        if rc != 0:
            return False, set(), "ca65 failed:\n" + out
        rc, out = sh(["ld65", "-C", str(td / "cfg"), "-o", str(td / "out.prg"),
                      str(td / "c.o"), str(archive_path)])
        unresolved = set(re.findall(r"Unresolved external '([^']+)'", out))
        return rc == 0, unresolved, out


# --- src/c64.cfg placement invariant (issue #98) -----------------------------
# A `type = bss` segment emits no bytes but still advances the address counter.
# Placed AHEAD of any file-emitting segment in the same memory area, it makes
# the image shorter than its address span, so every following byte loads low by
# that segment's size. ld65 gives no diagnostic when the segment is zero-filled
# -- and zero-filled `.res` is the normal shape for library scratch, so the
# silent case is the common one, not the exotic one.
#
# That shipped for several releases: LIB_NISTCURVES_P384_BSS was `bss` while
# every sibling was `rw`, leaving the PRG 53 bytes short with everything above
# $83C6 loading low. It was benign only because the trailing content happened
# to be zeros and every affected buffer happened to be written before read --
# two properties nothing enforced. Fixed in issue #98; pinned here so the class
# cannot return, since neither ld65 nor a reviewer reliably catches it.
CFG = REPO / "src" / "c64.cfg"


def cfg_bss_before_emitting():
    """Segments declared `bss` that precede a file-emitting segment."""
    text = CFG.read_text()
    m = re.search(r"^SEGMENTS\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        return None, []
    seen_bss = []
    offenders = []
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        d = re.match(r"([A-Za-z_][\w]*)\s*:(.*)", line)
        if not d:
            continue
        name, attrs = d.group(1), d.group(2)
        if "load = MAIN" not in attrs:
            continue
        if re.search(r"type\s*=\s*bss", attrs):
            seen_bss.append(name)
        elif seen_bss:
            # this segment emits bytes and sits after a bss one
            offenders.extend((b, name) for b in seen_bss)
            seen_bss = []
    return m, offenders


BARE_GATED = {
    # every deprecated bare name the LIB_NO_BARE_EXPORTS gate must suppress
    "zp_tmp1", "zp_tmp2", "zp_ptr1", "zp_ptr2",
    "mul_dma_lo", "mul_dma_hi", "mul_cached_a", "mul_src2_buf",
    "sqtab_lo", "sqtab_hi",
    "LIB_VERSION_MAJOR", "LIB_VERSION_MINOR", "LIB_VERSION_PATCH",
    "LIB_ABI_VERSION",
}
# ...plus the whole bare LIB_PRECALC_<name>_{SIZE,REGION,SHARED} family, which
# the §8.4 macro GENERATES one triple per table and so cannot be enumerated by
# hand. Enumerating it by hand is exactly what went wrong: the roster above
# listed none of the 18 bare LIB_PRECALC_* names precalc_manifest.o exports, so
# gated_surface_check's `names & BARE_GATED` was the empty set for that TU on
# every run from issue #113 until the ungated-ownership sentinel added at issue
# #154 refused to accept it. The leg printed "0 bare names" for a TU it had
# never actually examined. (LIB_NISTCURVES_PRECALC_* is the prefixed form and
# must NOT match -- it does not, the prefix differs from the first character.)
BARE_GATED_RE = re.compile(r"^LIB_PRECALC_")


def bare_gated(names):
    """Subset of `names` that the LIB_NO_BARE_EXPORTS gate is required to
    suppress: the fixed roster plus the generated bare LIB_PRECALC_* family."""
    return {n for n in names if n in BARE_GATED or BARE_GATED_RE.match(n)}
# TUs that OWN at least one deprecated bare name, i.e. whose ungated build
# exports something in BARE_GATED and whose gated build must export none.
#
# `zp_config` is deliberately NOT in this list any more (issue #154): its bare
# aliases moved to `zp_aliases`. Leaving it here would have been the exact
# vacuous-pass trap this file is otherwise careful about -- the leg would have
# gone on printing "0 bare names" for a TU that no longer has any to suppress,
# reporting green whether the gate worked, the split worked, or the file failed
# to build. Membership is now SENTINELLED: each listed TU must export >= 1 bare
# name UNGATED, or the leg fails and says so. `zp_config`'s own obligation --
# it must export no bare name in either configuration -- is asserted by
# zp_alias_audit() below, which has the populated-dump sentinel that makes an
# absence assertion mean something.
GATE_TUS = ["zp_aliases", "mul_aliases", "data_shared", "sqtab_aliases",
            "lib_version", "precalc_manifest"]
# `mul_8x8` left this list at issue #155: it owns no bare name any more, the
# two it used to own (sqtab_lo/sqtab_hi) having moved to `sqtab_aliases.s`.
# The sentinel above would fail it as a permanently-green entry -- which is
# the check working, and is how this edit was found rather than remembered.


# --- R2 exported-vs-summed ZP audit (issue #113, chacha-template method) -----
# Canonical slot table: name -> (address-agnostic) width in bytes. Width truth
# was established by usage audit (issue #90: `sta slot+1` / `lda (slot),y`
# prove 2-byte pointers), not by comments -- the ec_scalar_ptr comment said
# 1 byte for months while the code used 2.
ZP_CANONICAL_WIDTHS = {
    "nistcurves_zp_tmp1": 1, "nistcurves_zp_tmp2": 1,
    "nistcurves_zp_ptr1": 2, "nistcurves_zp_ptr2": 2,
    "fp_src1": 2, "fp_src2": 2, "fp_dst": 2, "fp_misc": 2,
    "fp_carry": 1, "fp_mul_i": 1, "fp_mul_j": 1,
    "ec_scalar_ptr": 2,
    "sha_src": 2, "sha_len": 2, "sha_w_ptr": 2, "sha_w_ptr2": 2,
}
# Intended §2 bare->canonical alias pairs (the §6.5 gated window). Any OTHER
# name sharing an address with a canonical slot is a defect: an unintended
# alias SHRINKS the address union and can hide a real collision -- the case
# total-only comparison cannot see.
ZP_INTENDED_ALIASES = {
    "zp_tmp1": "nistcurves_zp_tmp1", "zp_tmp2": "nistcurves_zp_tmp2",
    "zp_ptr1": "nistcurves_zp_ptr1", "zp_ptr2": "nistcurves_zp_ptr2",
}
ZP_ARM_OBJECTS = {   # zp_config variant object -> archives sharing that arm
    "zp_config": ["nistcurves.a", "nistcurves-onchip.a", "nistcurves-app-owned.a"],
    "zp_config_p256verify": ["nistcurves-p256-verify.a", "nistcurves-p256-verify-onchip.a"],
    "zp_config_p384verify": ["nistcurves-p384-verify.a", "nistcurves-p384-verify-onchip.a"],
    "zp_config_p384curve": ["nistcurves-p384-curve.a", "nistcurves-p384-curve-onchip.a"],
    "zp_config_p256comb": ["nistcurves-p256-comb.a", "nistcurves-p256-comb-onchip.a"],
    "zp_config_sha384": ["nistcurves-p384-sha384.a"],
}
# ca65 switches selecting each arm, hoisted out of zp_alias_audit so the
# zp_config and zp_aliases builds of an arm are guaranteed to use the same set.
ZP_ARM_DEFINES = {
    "zp_config": [],
    "zp_config_p256verify": ["-D", "LIB_P256_VERIFY_ONLY"],
    "zp_config_p384verify": ["-D", "LIB_P384_VERIFY_ONLY"],
    "zp_config_p384curve": ["-D", "LIB_P384_CURVE_ONLY"],
    "zp_config_p256comb": ["-D", "LIB_P256_COMB_ONLY"],
    "zp_config_sha384": ["-D", "LIB_SHA384_ONLY"],
}
# Issue #154: the alias TU that ships beside each zp_config arm, and the EXACT
# bare set that arm must export. Both halves are asserted -- the negative one
# (no bare name in zp_config*.o) and the positive one (exactly these names in
# zp_aliases*.o) -- because after a TU split an absence assertion alone goes
# green for the wrong reasons: an empty dump satisfies "must not export X"
# trivially, so a build failure, a wrong object path or a dropped archive
# member would all read as success. The positive half is what distinguishes
# "the alias moved" from "the alias vanished", and a vanished alias is a
# removed export -- a §6.5 event we must not commit by accident.
#
# The SHA arm's expected set is EMPTY on purpose (that archive exports only
# sha_*, none of which ever had a bare spelling). An empty expectation cannot
# sentinel itself, so zp_alias_audit additionally requires the union across
# all arms to be non-empty and every alias object to be od65-readable.
ZP_ALIAS_ARMS = {
    "zp_config":            ("zp_aliases",            {"zp_tmp1", "zp_tmp2",
                                                       "zp_ptr1", "zp_ptr2"}),
    "zp_config_p256verify": ("zp_aliases_p256verify", {"zp_ptr2"}),
    "zp_config_p384verify": ("zp_aliases_p384verify", {"zp_ptr2"}),
    "zp_config_p384curve":  ("zp_aliases_p384curve",  {"zp_ptr2"}),
    "zp_config_p256comb":   ("zp_aliases_p256comb",   {"zp_ptr1", "zp_ptr2"}),
    "zp_config_sha384":     ("zp_aliases_sha384",     set()),
}


def od65_zp_exports(obj):
    """name -> address for zeropage-sized exports of one object.
    Sentinel: od65 exits 0 on non-objects, so an unreadable input must fail
    loudly here rather than return an empty (= vacuously passing) set."""
    rc, out = sh(["od65", "--dump-exports", str(obj)])
    if "(no xo65 object file)" in out or rc:
        return None
    got, name = {}, None
    for block in re.split("\\n(?=\\s+Index:)", out):
        n = re.search(r'Name:\s*"([^"]+)"', block)
        a = re.search(r"Address size:\s*0x01", block)
        v = re.search(r"Value:\s*0x([0-9A-Fa-f]+)", block)
        if n and a and v:
            got[n.group(1)] = int(v.group(1), 16)
    return got


def od65_export_names(obj):
    """Set of export names for one object, or None if the dump is not
    trustworthy. Distinguishes "this object exports nothing" from "od65 could
    not read this", which a bare set() cannot -- and that distinction is the
    whole sentinel: every absence assertion downstream is meaningless over an
    unread dump. The declared Count is cross-checked against the number of
    Name: lines so a truncated dump fails rather than under-reporting."""
    rc, out = sh(["od65", "--dump-exports", str(obj)])
    if rc or "(no xo65 object file)" in out:
        return None                       # unreadable: no dump at all
    m = re.search(r"Exports:\s*\n\s*Count:\s*(\d+)", out)
    if not m:
        return None                       # unreadable: no Count record
    names = set(re.findall(r'Name:\s*"([^"]+)"', out))
    if len(names) != int(m.group(1)):
        # Readable, but the extraction disagrees with od65's own declared
        # Count -- names were dropped. Distinct from "unreadable", and callers
        # conflating the two report a file that assembles fine as one that does
        # not. Sentinel rather than None so they cannot.
        return COUNT_MISMATCH
    return names


def _vfmt(v):
    return "(label)" if v is None else f"{v}"


def od65_export_records(obj):
    """{name: value-or-None} for one object's exports, or None / COUNT_MISMATCH
    on the same terms as od65_export_names().

    Values exist only for constant equates -- a label's address is unresolved
    until link, so od65 prints no Value: line for one. That is precisely the
    class at risk here: the SPEC 1 version and ABI equates, the SPEC 8.4
    precalc triples and the SPEC 3 placement equates are all constants a
    consumer compiles against, and a name-only comparison cannot see one of
    them change value across the gate (issue #158 review finding F3).
    """
    rc, out = sh(["od65", "--dump-exports", str(obj)])
    if rc or "(no xo65 object file)" in out:
        return None
    m = re.search(r"Exports:\s*\n\s*Count:\s*(\d+)", out)
    if not m:
        return None
    recs = {}
    for block in re.split(r"\n\s*Index:", out)[1:]:
        nm = re.search(r'Name:\s*"([^"]+)"', block)
        if not nm:
            continue
        vm = re.search(r"Value:\s*(0x[0-9a-fA-F]+)", block)
        recs[nm.group(1)] = int(vm.group(1), 16) if vm else None
    if len(recs) != int(m.group(1)):
        return COUNT_MISMATCH
    return recs


def zp_alias_audit(failures):
    """Issue #113 + #154: per variant arm --

    (1) union the exported slot ADDRESSES of zp_config<arm>.o with canonical
        widths and compare against the exported ZP_USAGE_BYTES equate;
    (2) account for every address shared by two exported names -- it must be
        exactly an intended bare->canonical pair;
    (3) §6.1: zp_config<arm>.o must export NO bare `zp_` name at all -- they
        live in zp_aliases<arm>.o since issue #154;
    (4) zp_aliases<arm>.o must export EXACTLY the arm's expected bare set and
        nothing else;
    (5) a LIB_NO_BARE_EXPORTS build of BOTH files must export no bare name,
        with the canonical union unchanged.

    (3) is an absence assertion and (4)'s SHA arm is an empty expectation, so
    both are sentinelled: (3) only runs once the zp_config dump is confirmed
    populated and carrying canonical slots, (4) fails if od65 cannot read the
    alias object, and the union of alias exports across all six arms must be
    non-empty before the leg reports OK. Without that, "no bare names here"
    and "nothing here at all" are the same observation."""
    import tempfile
    print("\n=== R2 ZP audit: exported union vs equate + alias accounting ===")
    alias_seen = set()
    for arm, archives in ZP_ARM_OBJECTS.items():
        alias_obj, want_bare = ZP_ALIAS_ARMS[arm]
        exports = od65_zp_exports(BUILD / (arm + ".o"))
        if exports is None:
            failures.append(f"zp-audit: cannot read build/{arm}.o")
            print(f"  AUDIT FAIL: build/{arm}.o unreadable")
            continue
        # SENTINEL for the absence leg below: an empty or canonical-free dump
        # would satisfy "exports no bare zp_ name" for the wrong reason.
        if not (set(exports) & set(ZP_CANONICAL_WIDTHS)):
            failures.append(
                f"zp-audit {arm}: build/{arm}.o exports no canonical slot "
                "-- absence assertions over this dump would be vacuous")
            print(f"  AUDIT FAIL {arm}: dump carries no canonical slot; "
                  "refusing to conclude anything from what is missing")
            continue
        bad = False
        # (0) PARTITION RECONCILIATION. The sentinel above proves the dump has
        # something in it; this proves we have accounted for ALL of it. Every
        # name in the member must land in exactly one known bucket -- bare
        # alias / prefixed canonical / other importable slot -- and the buckets
        # must sum to od65's own declared export Count (od65_export_names fails
        # closed if they do not). Without it, a name lost by the extraction and
        # a name genuinely absent look identical, and so do "no bare names
        # here" and "nothing examined here".
        allnames = od65_export_names(BUILD / (arm + ".o"))
        if allnames is None:
            failures.append(f"zp-audit {arm}: export dump of build/{arm}.o "
                            "does not reconcile against its declared Count")
            print(f"  AUDIT FAIL {arm}: build/{arm}.o dump truncated or "
                  "unreadable -- every conclusion below would be unfounded")
            continue
        bare_n = {n for n in allnames if n.startswith("zp_")}
        pref_n = {n for n in allnames if n.startswith("nistcurves_")}
        othr_n = allnames - bare_n - pref_n
        unknown = (pref_n | othr_n) - set(ZP_CANONICAL_WIDTHS)
        if unknown:
            failures.append(f"zp-audit {arm}: unaccounted exports {sorted(unknown)}")
            print(f"  AUDIT FAIL {arm}: exports {sorted(unknown)} fall in no "
                  "known bucket -- the partition does not cover the dump")
            bad = True
        if allnames != set(exports):
            # every export must also have been visible to the address audit
            failures.append(
                f"zp-audit {arm}: {sorted(allnames ^ set(exports))} appear in "
                "one dump reading but not the other")
            print(f"  AUDIT FAIL {arm}: address audit saw {len(exports)} of "
                  f"{len(allnames)} exports -- {sorted(allnames ^ set(exports))} "
                  "unexamined")
            bad = True
        if len(bare_n) + len(pref_n) + len(othr_n) != len(allnames):
            failures.append(f"zp-audit {arm}: bucket counts do not sum to the "
                            f"member's {len(allnames)} exports")
            bad = True
        # (3) §6.1 absence leg (issue #154), now that the dump is known good.
        stray = sorted(n for n in exports if n.startswith("zp_"))
        if stray:
            failures.append(f"zp-audit {arm}: zp_config exports bare {stray} "
                            "(§6.1: they belong in src/zp_aliases.s)")
            print(f"  AUDIT FAIL {arm}: build/{arm}.o exports bare {stray} "
                  f"beside {len(exports) - len(stray)} importable slots -- "
                  "the issue #154 defect is back")
            bad = True
        # (4) positive leg: the alias TU must carry EXACTLY this arm's bare set.
        anames = od65_export_names(BUILD / (alias_obj + ".o"))
        if anames is None:
            failures.append(f"zp-audit {arm}: cannot read build/{alias_obj}.o")
            print(f"  AUDIT FAIL {arm}: build/{alias_obj}.o unreadable -- "
                  "the alias half of this arm is unverified")
            bad = True
        else:
            alias_seen |= anames
            notbare = sorted(n for n in anames if n not in ZP_INTENDED_ALIASES)
            if notbare:
                failures.append(f"zp-audit {arm}: {alias_obj}.o exports "
                                f"non-alias {notbare} -- §6.1 requires this TU "
                                "to carry the displaceable names and nothing else")
                print(f"  AUDIT FAIL {arm}: {alias_obj}.o exports {notbare}, "
                      "which are not bare aliases")
                bad = True
            if anames != want_bare:
                missing = sorted(want_bare - anames)
                extra = sorted(anames - want_bare)
                failures.append(
                    f"zp-audit {arm}: {alias_obj}.o exports {sorted(anames)}, "
                    f"want {sorted(want_bare)}")
                print(f"  AUDIT FAIL {arm}: {alias_obj}.o missing {missing}, "
                      f"unexpected {extra}")
                if missing:
                    print("             a dropped alias is a REMOVED EXPORT "
                          "(§6.5 window), not a tidy-up")
                bad = True
        # (2) alias accounting, by address
        by_addr = {}
        for name, addr in exports.items():
            by_addr.setdefault(addr, set()).add(name)
        covered = set()
        for addr, names in sorted(by_addr.items()):
            canon = [n for n in names if n in ZP_CANONICAL_WIDTHS]
            others = names - set(canon)
            if len(canon) != 1:
                failures.append(f"zp-audit {arm}: address ${addr:02x} has canonical set {sorted(canon)}")
                print(f"  AUDIT FAIL {arm}: ${addr:02x} exported by {sorted(names)} -- not exactly one canonical slot")
                bad = True
                continue
            for o in others:
                if ZP_INTENDED_ALIASES.get(o) != canon[0]:
                    failures.append(f"zp-audit {arm}: unintended alias {o} -> {canon[0]} at ${addr:02x}")
                    print(f"  AUDIT FAIL {arm}: '{o}' shares ${addr:02x} with '{canon[0]}' but is not an intended pair")
                    bad = True
            covered |= set(range(addr, addr + ZP_CANONICAL_WIDTHS[canon[0]]))
        # (1) union vs equate, against each archive sharing this arm.
        # A missing equate used to be silently skipped, which made the union
        # -- this leg's own populated-dump evidence -- assert nothing at all
        # for that arm. An arm with no equate to compare against is a failure.
        union = len(covered)
        matched = 0
        for a in archives:
            want = MANIFEST_VALUES.get(a, {}).get("LIB_NISTCURVES_ZP_USAGE_BYTES")
            if want is None:
                continue
            matched += 1
            if want != union:
                failures.append(f"zp-audit {arm}: union {union} != {a} equate {want}")
                print(f"  AUDIT FAIL {arm}: address-union {union} B != {a}'s ZP_USAGE_BYTES {want}")
                bad = True
        if not matched:
            failures.append(f"zp-audit {arm}: no archive pins ZP_USAGE_BYTES "
                            "-- the union was computed and compared to nothing")
            print(f"  AUDIT FAIL {arm}: union {union} B compared against no equate")
            bad = True
        # (5) gated builds of BOTH files: no bare name survives, and the
        # canonical union is unmoved (the gate must not drop a real slot).
        with tempfile.TemporaryDirectory() as td:
            defines = ZP_ARM_DEFINES[arm]
            gobj = Path(td) / "g.o"
            rc, _ = sh(["ca65", "--cpu", "6502", "-D", "LIB_NO_BARE_EXPORTS=1", *defines,
                        "-I", "src", "-o", str(gobj), "src/zp_config.s"])
            g = od65_zp_exports(gobj) if not rc else None
            if g is None:
                failures.append(f"zp-audit {arm}: gated assemble failed")
                bad = True
            else:
                leftover = [n for n in g if n in ZP_INTENDED_ALIASES]
                gunion = set()
                for n, addr in g.items():
                    if n in ZP_CANONICAL_WIDTHS:
                        gunion |= set(range(addr, addr + ZP_CANONICAL_WIDTHS[n]))
                if leftover:
                    failures.append(f"zp-audit {arm}: gated build still exports bare {leftover}")
                    bad = True
                if len(gunion) != union:
                    failures.append(f"zp-audit {arm}: gated union {len(gunion)} != default union {union}")
                    bad = True
            aobj = Path(td) / "ga.o"
            rc, _ = sh(["ca65", "--cpu", "6502", "-D", "LIB_NO_BARE_EXPORTS=1", *defines,
                        "-I", "src", "-o", str(aobj), "src/zp_aliases.s"])
            ga = od65_export_names(aobj) if not rc else None
            if ga is None:
                failures.append(f"zp-audit {arm}: gated zp_aliases assemble failed")
                bad = True
            elif ga:
                failures.append(f"zp-audit {arm}: gated zp_aliases.o still exports {sorted(ga)}")
                bad = True
        if not bad:
            names = len(exports)
            print(f"  {arm:24s} union={union:2d} B  "
                  f"exports={names:2d} = {len(bare_n)} bare + {len(pref_n)} "
                  f"prefixed + {len(othr_n)} other  "
                  f"aliases={len(want_bare)} in {alias_obj}.o  "
                  f"equate match: {', '.join(archives)}")
    # Global sentinel: at least one arm must actually have exported a bare
    # alias. If the split ever leaves every alias object empty, each arm's
    # per-arm comparison could still pass (the SHA arm expects nothing, and a
    # global regression would be caught only here).
    if not alias_seen:
        failures.append("zp-audit: no arm exported ANY bare alias -- the whole "
                        "alias surface is missing, not merely relocated")
        print("  AUDIT FAIL: not one bare alias found across six arms")
    else:
        print(f"  alias surface present: {sorted(alias_seen)}")


def zp_alias_link_identity(failures):
    """Issue #154: drive every bare alias through a REAL ld65 link against the
    archive that is supposed to carry it, and require it to resolve to its
    canonical slot's address.

    This is the leg that cannot go vacuous, and it is here because the object
    dumps cannot do this job: `zp_aliases*.o` re-exports each alias as an
    EXPRESSION over an import (`Type: SYM_EQUATE,SYM_EXPR`, no `Value:`), which
    is precisely what makes the two spellings undriftable -- and precisely what
    stops od65 from reporting an address for them. Only the linker knows.

    Three failures are caught in one mechanism:
      * alias missing from the archive  -> ld65 'Unresolved external' (this is
        the check that a dropped member is a removed export, not a tidy-up);
      * alias resolving elsewhere       -> address mismatch;
      * archive not linkable at all     -> non-zero ld65.

    The SHA archive is checked in the OPPOSITE direction: it must NOT resolve
    a bare alias. An empty expectation asserted by 'we found nothing' would be
    satisfied by a broken probe, so it is asserted by 'the link fails with
    exactly this unresolved external' instead."""
    import tempfile
    print("\n=== §6.1 bare-alias link identity (issue #154) ===")
    for arm, archives in ZP_ARM_OBJECTS.items():
        _, want_bare = ZP_ALIAS_ARMS[arm]
        for name in archives:
            archive = LIBDIR / name
            if not archive.exists():
                failures.append(f"zp-alias link: {name} not built")
                print(f"  LINK FAIL: {name} missing -- run `make lib*` first")
                continue
            probe = want_bare or {"zp_ptr2"}   # SHA arm: expect a hard failure
            pairs = sorted((b, ZP_INTENDED_ALIASES[b]) for b in probe)
            src = "".join(f".importzp {b}\n.importzp {c}\n" for b, c in pairs)
            src += '.segment "CODE"\nentry:\n'
            src += "".join(f"\tlda {b}\n\tlda {c}\n" for b, c in pairs)
            src += "\trts\n"
            with tempfile.TemporaryDirectory() as td:
                td = Path(td)
                (td / "cfg").write_text(CONSUMER_CFG)
                (td / "p.s").write_text(src)
                rc, out = sh(["ca65", "--cpu", "6502", "-o", str(td / "p.o"),
                              str(td / "p.s")])
                if rc:
                    failures.append(f"zp-alias link {name}: probe will not assemble")
                    print(f"  LINK FAIL {name}: probe will not assemble:\n{out}")
                    continue
                rc, out = sh(["ld65", "-C", str(td / "cfg"), "-Ln", str(td / "lbl"),
                              "-o", str(td / "o.prg"), str(td / "p.o"), str(archive)])
                unresolved = set(re.findall(r"Unresolved external '([^']+)'", out))
                if not want_bare:
                    # SHA arm: the bare name must be absent from this archive.
                    if rc == 0 or "zp_ptr2" not in unresolved:
                        failures.append(
                            f"zp-alias link {name}: bare zp_ptr2 resolved, but "
                            f"{arm} exports no alias -- an unexpected member "
                            "is exporting it")
                        print(f"  LINK FAIL {name}: bare zp_ptr2 unexpectedly resolved")
                    else:
                        print(f"  {name:34s} correctly exports NO bare alias "
                              "(link fails with Unresolved external 'zp_ptr2')")
                    continue
                if rc:
                    failures.append(f"zp-alias link {name}: link failed "
                                    f"(unresolved {sorted(unresolved)})")
                    print(f"  LINK FAIL {name}: {sorted(unresolved) or out.strip()}")
                    if unresolved & set(ZP_INTENDED_ALIASES):
                        print("             a bare alias no longer resolves from "
                              "this archive: that is a REMOVED EXPORT (§6.5), "
                              "not a relocation")
                    continue
                labels = {sym: int(addr, 16) for addr, sym in re.findall(
                    r"^al\s+([0-9A-Fa-f]+)\s+\.(\S+)",
                    (td / "lbl").read_text(), re.M)}
                bad = False
                shown = []
                for b, c in pairs:
                    if b not in labels or c not in labels:
                        failures.append(f"zp-alias link {name}: {b}/{c} absent "
                                        "from the link map")
                        print(f"  LINK FAIL {name}: {b} or {c} missing from -Ln map")
                        bad = True
                        continue
                    if labels[b] != labels[c]:
                        failures.append(
                            f"zp-alias link {name}: {b}=${labels[b]:02x} != "
                            f"{c}=${labels[c]:02x} -- the alias has DRIFTED")
                        print(f"  LINK FAIL {name}: {b} resolves to "
                              f"${labels[b]:02x}, {c} to ${labels[c]:02x}")
                        bad = True
                    else:
                        shown.append(f"{b}=${labels[b]:02x}")
                if not bad:
                    print(f"  {name:34s} {', '.join(shown)} (each == its canonical slot)")


def version_identity_check(failures):
    """§1 identity: the VERSION file and the lib_version.o equates MUST agree.
    v0.10.0 shipped self-misreporting as 0.10.1 -- PATCH carried over from the
    previous release because the bump edited MINOR/ABI and a human 'lockstep
    verified' grep never printed the PATCH line. A tag that misstates itself is
    exactly what §1 exists to prevent, so the comparison is now mechanical and
    total: all three components, read from the BUILT object, against the
    VERSION file."""
    print("\n=== §1 version identity (VERSION file vs built equates) ===")
    want = (REPO / "VERSION").read_text().strip().split(".")
    obj = BUILD / "lib_version.o"
    got = []
    for part in ("MAJOR", "MINOR", "PATCH"):
        _, out = sh(["od65", "--dump-exports", str(obj)])
        m = re.search(r'Name:\s*"LIB_NISTCURVES_VERSION_' + part
                      + r'"(?:.|\n)*?Value:\s*0x([0-9A-Fa-f]+)', out)
        got.append(str(int(m.group(1), 16)) if m else "?")
    if got != want:
        failures.append(f"version identity: VERSION file {'.'.join(want)} != equates {'.'.join(got)}")
        print(f"  IDENTITY FAIL: VERSION file says {'.'.join(want)}, built equates say {'.'.join(got)}")
    else:
        print(f"  identity OK ({'.'.join(got)})")


def gated_surface_check(failures, archives):
    """§6.5 window ratchet: a -D LIB_NO_BARE_EXPORTS=1 build of every
    gate-owning TU must export zero deprecated bare names. This is the whole
    point of the rename window -- one ungated .export quietly re-opens the
    #82/#83 collision class for composed consumers, and nothing else checks
    the gated configuration (the default build legitimately exports both
    spellings).

    SWEPT OVER ARMS, NOT TUs (issue #159). Through v0.14.0 this leg assembled
    each GATE_TU once, with `-I src` and no variant define -- the DEFAULT arm.
    But `precalc_manifest.s` is built eleven ways, `zp_aliases.s` six, and
    ELEVEN OF THE TWELVE shipped archives link a variant arm, so the gate's
    behaviour in the arm a real consumer links was unread. Driven red by
    planting, in src/precalc_manifest.s,

        .ifdef LIB_SHA384_ONLY
        .ifdef LIB_NO_BARE_EXPORTS
        LIB_PRECALC_adversarial_SIZE = 1
        .export LIB_PRECALC_adversarial_SIZE:abs
        .endif
        .endif

    which puts a deprecated bare name into precalc_manifest_sha384.o and hence
    into lib-p384-sha384, with `make check-archives` exiting 0.

    The arm roster is DERIVED from the Makefile's own per-object recipes (see
    parse_makefile_object_rules) and intersected with the parsed ar65 member
    lists, so it is the population that ships rather than a list maintained
    here. Restating it would reproduce the defect one level up: a hand-written
    roster is green about the arms it happens to name.

    Per-arm, the ungated-ownership sentinel is RELAXED to a per-TU one. Some
    arms legitimately own no bare name at all -- `zp_aliases_sha384.o` is the
    documented example (that archive exports only sha_*, none of which ever
    had a bare spelling) -- so requiring every arm to own one would fail a
    correct build. What is still asserted, and is what the sentinel was for,
    is that every roster TU owns at least one bare name in at least one arm,
    that every arm's two dumps were read, and that the ">=" half (survivors
    and their values) holds in every arm including the empty-owning ones.

    The honest limit of that relaxation: within THIS leg, an arm whose ungated
    export set had gone empty passes every assertion, because `owns`,
    `expected`, `dropped`, `gained` and `shifted` are then all empty sets.
    What rules that out is elsewhere -- MUST_EXPORT pins the bare
    LIB_PRECALC_* triples per archive and ZP_ALIAS_ARMS pins the exact
    per-arm alias set, both read from the built build/lib/*.a. That is a real
    cross-leg dependency, so it is written down rather than left implied."""
    import tempfile
    print("\n=== LIB_NO_BARE_EXPORTS gated surface (all shipped variant arms) ===")
    arms = {obj: rec for obj, rec in shipped_object_arms(archives).items()
            if rec[0] in GATE_TUS}
    if not arms:
        failures.append("gated surface: no shipped arm found for any GATE_TU -- "
                        "the sweep would be vacuous")
        print("  GATE FAIL: derived arm roster is empty")
        return
    missing_tus = sorted(set(GATE_TUS) - {rec[0] for rec in arms.values()})
    if missing_tus:
        failures.append(f"gated surface: {missing_tus} are in GATE_TUS but ship "
                        "in no archive -- their gated result binds nothing")
        print(f"  GATE FAIL: roster TUs shipping in no archive: {missing_tus}")
    bad = []
    owned = {}
    lost = {}
    gained = {}
    shifted = {}
    survivors = {}
    with tempfile.TemporaryDirectory() as td:
        for obj in sorted(arms):
            tu, defines, using = arms[obj]
            arm = _arm_label(obj, defines, using)
            dargs = []
            for d in defines:
                dargs += ["-D", d]
            # SENTINEL: assemble the arm UNGATED first. Without a populated
            # ungated dump the leg is an absence assertion over something it
            # never proved was there -- it would print "0 bare names" for an
            # arm that had been emptied, renamed, or had simply failed to
            # build in a way ca65 exited 0 on. Ownership itself is asserted
            # per TU below rather than per arm: an arm may legitimately own
            # none (zp_aliases_sha384), and failing that would redden a
            # correct build.
            uobj = Path(td) / (obj + "_ungated.o")
            rc, out = sh(["ca65", "--cpu", "6502", *dargs,
                          "-I", "src", "-o", str(uobj), f"src/{tu}.s"])
            urecs = od65_export_records(uobj) if not rc else None
            unames = set(urecs) if isinstance(urecs, dict) else urecs
            if unames is COUNT_MISMATCH:
                failures.append(f"gated surface [{arm}]: name extraction "
                                "disagrees with od65's declared export Count; "
                                "the file assembles, the reader is broken")
                print(f"  GATE FAIL [{arm}]: extraction dropped names vs Count")
                continue
            if unames is None:
                failures.append(f"gated surface [{arm}]: does not assemble ungated")
                print(f"  GATE FAIL [{arm}]: does not assemble ungated: "
                      f"{out.splitlines()[0] if out else ''}")
                continue
            owns = bare_gated(unames)
            owned[obj] = sorted(owns)

            gobj = Path(td) / (obj + "_gated.o")
            rc, out = sh(["ca65", "--cpu", "6502", "-D", "LIB_NO_BARE_EXPORTS=1",
                          *dargs, "-I", "src", "-o", str(gobj), f"src/{tu}.s"])
            if rc:
                failures.append(f"gated surface [{arm}]: does not assemble under the gate")
                print(f"  GATE FAIL [{arm}]: does not assemble: {out.splitlines()[0] if out else ''}")
                continue
            # Same trustworthy reader on BOTH sides. The gated dump used to go
            # through od65_names(), which has no Count cross-check -- so a
            # truncated gated dump under-reported, and every assertion below is
            # a set difference that a short read makes LOOK better. Asymmetric
            # extractors are the "diff whose readers break symmetrically and
            # agree" shape; here they would not even break symmetrically.
            grecs = od65_export_records(gobj)
            gnames = set(grecs) if isinstance(grecs, dict) else grecs
            if gnames is COUNT_MISMATCH:
                failures.append(f"gated surface [{arm}]: gated name extraction "
                                "disagrees with od65's declared export Count; "
                                "the file assembles, the reader is broken")
                print(f"  GATE FAIL [{arm}]: gated extraction dropped names vs Count")
                continue
            if gnames is None:
                failures.append(f"gated surface [{arm}]: gated dump is unreadable")
                print(f"  GATE FAIL [{arm}]: gated dump unreadable")
                continue

            leaked = bare_gated(gnames)
            if leaked:
                bad.append((arm, sorted(leaked)))

            # POSITIVE half (issue #158). The assertions above are all
            # absence-shaped: they say the gate removed what it must remove.
            # Nothing said it KEPT what it must keep -- and the prefixed
            # exports are the entire surface a composing consumer imports in
            # this mode, since LIB_NO_BARE_EXPORTS=1 is exactly what a
            # four-library link builds with. Moving a prefixed .export inside
            # the `.ifndef LIB_NO_BARE_EXPORTS` block (fifteen lines away in
            # lib_version.s) deleted LIB_NISTCURVES_VERSION_PATCH from every
            # gated build and BOTH gates stayed green; a consumer would have
            # met it as an ld65 unresolved external.
            #
            # The gate's whole contract, as one equation:
            #     gated exports == ungated exports - names the gate suppresses
            # "<=" is the leak check above; this is ">=". Neither direction
            # alone is the contract.
            # NOTE (review finding F4): `expected` is the roster's
            # COMPLEMENT, so every ungated export not in BARE_GATED is now
            # asserted to survive the gate -- including deprecated spellings
            # not yet on the roster, e.g. mul_8x8's `mul_8x8` (a back-compat
            # alias of ct_mul_8x8) and `sqtab_init` / `mul_tables_init`. When
            # those are gated at the next MAJOR, BARE_GATED must be updated in
            # the SAME commit as the source, or this leg reddens with a
            # message that misdescribes a correct change. Fail-closed, but the
            # diagnostic points the wrong way.
            expected = set(unames) - owns
            survivors[obj] = sorted(expected)
            dropped = expected - gnames
            if dropped:
                lost[arm] = sorted(dropped)
            extra = gnames - set(unames)
            if extra:
                gained[arm] = sorted(extra)

            # Values, not just names (review finding F3). A name-set equation
            # is satisfied by an equate that survives the gate holding a
            # DIFFERENT value -- and a composing consumer compiles against the
            # value. Planting
            #     .ifdef LIB_NO_BARE_EXPORTS / ABI_VERSION = 99 / .else / = 4
            # kept every name in place and passed every leg, while the gated
            # object really did export 99. The SPEC 7 counter that CLAUDE.md
            # calls load-bearing is exported from this very TU.
            for nm in sorted(expected & gnames):
                uv, gv = urecs.get(nm), grecs.get(nm)
                if uv != gv:
                    shifted.setdefault(arm, []).append(
                        f"{nm} {_vfmt(uv)} -> {_vfmt(gv)}")
    for arm, names in bad:
        failures.append(f"gated surface [{arm}]: exports bare {names} under the gate")
        print(f"  GATE FAIL [{arm}]: exports bare names under the gate: {names}")
    for arm, names in lost.items():
        failures.append(f"gated surface [{arm}]: LOSES {names} under the gate -- "
                        "the gate may only suppress deprecated bare names, and "
                        "these are the surface a composing consumer imports")
        print(f"  GATE FAIL [{arm}]: drops non-bare exports under the gate: {names}")
    for arm, names in gained.items():
        failures.append(f"gated surface [{arm}]: GAINS {names} under the gate -- "
                        "the gated build must be a subset of the ungated one")
        print(f"  GATE FAIL [{arm}]: exports names only under the gate: {names}")
    # Completion is keyed off `survivors`, not `owned`. `owned[obj]` is
    # recorded BEFORE the gated assemble, so every skip after that point
    # (gated assemble fails, COUNT_MISMATCH, unreadable dump) leaves `owned`
    # complete for an arm that was never examined under the gate. Keying the
    # banner off it printed "0 under the gate" for an arm whose gated build was
    # never read -- an absence assertion over a dump that does not exist, the
    # exact shape this leg's sentinel exists to prevent, one level up.
    # `survivors[obj]` is assigned only on the path that read both dumps, so it
    # is the honest completion record.
    for arm, entries in shifted.items():
        failures.append(f"gated surface [{arm}]: CHANGES exported values under "
                        f"the gate: {entries} -- the gate may only suppress "
                        "deprecated bare names, never restate a value")
        print(f"  GATE FAIL [{arm}]: exports different values under the gate: {entries}")
    # Per-TU ownership sentinel, aggregated over the TU's arms. Per-arm it
    # would be wrong (some arms legitimately own nothing); dropped entirely it
    # would let a roster entry that owns nothing anywhere sit here reporting a
    # vacuous zero, which is what it caught at issue #154.
    vacuous = []
    for tu in GATE_TUS:
        tu_arms = [o for o in arms if arms[o][0] == tu]
        if tu_arms and not any(owned.get(o) for o in tu_arms):
            vacuous.append(tu)
            failures.append(
                f"gated surface: {tu} owns no bare name in ANY shipped arm "
                f"({sorted(tu_arms)}) -- its gated result proves nothing; drop "
                "it from GATE_TUS or fix the TU")
            print(f"  GATE FAIL: {tu} exports no bare name UNGATED in any arm, "
                  "so '0 bare names under the gate' is vacuous for it")
    if (not bad and not lost and not gained and not shifted
            and len(survivors) == len(arms) and not vacuous and not missing_tus):
        total = sum(len(v) for v in owned.values())
        kept = sum(len(v) for v in survivors.values())
        print(f"  gated surface OK ({len(arms)} shipped arms of {len(GATE_TUS)} "
              f"TUs owning {total} bare names ungated, 0 under the gate; {kept} "
              "non-bare exports kept intact across the gate)")
        for obj in sorted(arms):
            tu, defines, using = arms[obj]
            d = " ".join(f"-D {x}" for x in defines) or "(default)"
            print(f"    {obj:36s} {d}")
            print(f"    {'':36s} suppresses {owned[obj]}")
            print(f"    {'':36s} keeps      {len(survivors[obj])} name(s)")


APP_OWNED_DEFINE_ARGS = ["-D", "SHARED_SQTAB_INIT", "-D", "SHARED_REU_MUL_INIT",
                         "-D", "SHARED_REU_MUL_FETCH", "-D", "SHARED_CT_MUL_8X8"]


def app_owned_reachability_check(failures):
    """Reachability of APP_OWNED x profile (issue #123). §6.3 was RETIRED at
    contract 1.0.0 and the citations here are history, not a live obligation --
    we keep the check because it caught a real unreachable combination. The full
    deferral define set must ASSEMBLE against both profile arms of
    mul_8x8.s -- the onchip arm shipped for two releases with same-TU
    references (og_common -> ct_mul_8x8 / smc_* / poly_prod) that the gate
    removed without importing, so APP_OWNED x onchip was unreachable and no
    CI target exercised the combination. The onchip deferring object must
    IMPORT the five-symbol §8.3 provider surface and re-export none of it."""
    import tempfile
    print("\n=== APP_OWNED x profile reachability (issue #123; was §6.3) ===")
    with tempfile.TemporaryDirectory() as td:
        for profile_args, label in ([], "dma"), (["-D", "FP_ONCHIP_MUL"], "onchip"):
            obj = Path(td) / f"m8_{label}.o"
            rc, out = sh(["ca65", "--cpu", "6502", *APP_OWNED_DEFINE_ARGS,
                          *profile_args, "-I", "src", "-o", str(obj),
                          "src/mul_8x8.s"])
            if rc:
                failures.append(f"app-owned x {label}: mul_8x8.s does not assemble under full deferral")
                print(f"  REACH FAIL [{label}]: {out.splitlines()[0] if out else 'assemble error'}")
                continue
            imports = od65_names(obj, "--dump-imports")
            exports = od65_names(obj, "--dump-exports")
            leaked = sorted(exports & CT_MUL_PROVIDER_SYMS)
            if leaked:
                failures.append(f"app-owned x {label}: deferring TU re-exports provider surface {leaked}")
                print(f"  REACH FAIL [{label}]: re-exported provider surface: {leaked}")
                continue
            if label == "onchip":
                missing = sorted(CT_MUL_PROVIDER_SYMS - imports)
                if missing:
                    failures.append(f"app-owned x onchip: og_common's provider-surface imports missing {missing}")
                    print(f"  REACH FAIL [onchip]: provider-surface imports missing: {missing}")
                    continue
            print(f"  reachability OK [{label}] (assembles; surface imported, not re-exported)")


# --- SPEC §6.1 packaging + §3 header-guard leg --------------------------------
#
# The header and example cfg are NOT contract-required: 1.0.0 briefly made
# §6.1 say "Every library MUST provide `make lib`, producing
# build/lib/<shortname>.a PLUS the consumer-facing .inc header and an example
# .cfg" -- and 1.1.1 withdrew it, as a tightening the text cut had carried
# unannounced. We ship both anyway (consumers were transcribing symbols out of
# API.md prose), so what binds is §3's header-import rule, which governs any
# header that exists. Presence alone is a weak pin, so this leg also drives the header the
# way a consumer does, against the SHIPPED copy under build/lib/ rather than
# the source, and asserts BOTH halves of the §3 rule that governs it:
#
#   "Guard the .import with .ifndef iff the defining TU guards the definition,
#    and pair every such guard with an .else branch asserting the override
#    against the library's exported value -- a bare guard alone converts a
#    compile error into silent divergence."
#
# Half one (the .ifndef): a `-D` of a guarded equate must ASSEMBLE against the
# header. Without the guard it is `Symbol already defined`, i.e. the header
# breaks exactly the consumers following the documented override path.
#
# Half two (the .else): a WRONG `-D` must FAIL AT LINK. This is the half that
# makes the leg capable of failing: drop any one `.else` branch from
# src/nistcurves.inc and that symbol's wrong-value row links clean and is
# reported here. Verified by doing it -- see the docstring below.
#
# Each symbol is driven at its REAL archive value (must link) and at that
# value XOR 1 (must not). XOR rather than +1 so the wrong value stays in range
# for the 16-bit maximum (LIB_NISTCURVES_SHA384_UPDATE_MAX = 65535) as well as
# for the zero-valued offsets.
HEADER_GUARDED_SYMS = [
    # §3 REU placement -- src/reu_config.s guards all five with .ifndef.
    "LIB_NISTCURVES_REU_BANK_MUL",
    "LIB_NISTCURVES_REU_BANK_COMB",
    "LIB_NISTCURVES_REU_OFFSET_COMB_P256",
    "LIB_NISTCURVES_REU_OFFSET_COMB_P384",
    "LIB_NISTCURVES_REU_SETTLE_ITER",
    # §5 aggregate manifest + §8.0 masks -- src/lib_manifest.s guards all seven.
    "LIB_NISTCURVES_REU_BANKS_USED",
    "LIB_NISTCURVES_ZP_USAGE_BYTES",
    "LIB_NISTCURVES_RESIDENT_BYTES",
    "LIB_NISTCURVES_COLD_BYTES",
    "LIB_NISTCURVES_SHARED_PRIMITIVES",
    "LIB_NISTCURVES_SHARED_CONSUMES",
]

# Symbols whose defining TU assigns UNCONDITIONALLY. §3 says leave those
# imports bare so a `-D` collides loudly; a guard there would mask a
# deliberate parse-time rejection. Pinned in the opposite direction: a `-D` of
# one of these must FAIL TO ASSEMBLE against the header.
# Each archive and the ca65 switch set it is built with, so the header can be
# driven the way that archive's consumer drives it.
HEADER_ARCHIVE_SWITCHES = {
    "nistcurves.a": [],
    "nistcurves-onchip.a": ["FP_ONCHIP_MUL"],
    "nistcurves-app-owned.a": ["SHARED_SQTAB_INIT", "SHARED_CT_MUL_8X8",
                               "SHARED_REU_MUL_INIT", "SHARED_REU_MUL_FETCH"],
    "nistcurves-p256-verify.a": ["LIB_P256_VERIFY_ONLY"],
    "nistcurves-p256-verify-onchip.a": ["LIB_P256_VERIFY_ONLY", "FP_ONCHIP_MUL"],
    "nistcurves-p384-verify.a": ["LIB_P384_VERIFY_ONLY"],
    "nistcurves-p384-verify-onchip.a": ["LIB_P384_VERIFY_ONLY", "FP_ONCHIP_MUL"],
    "nistcurves-p384-curve.a": ["LIB_P384_CURVE_ONLY"],
    "nistcurves-p384-curve-onchip.a": ["LIB_P384_CURVE_ONLY", "FP_ONCHIP_MUL"],
    "nistcurves-p256-comb.a": ["LIB_P256_COMB_ONLY"],
    "nistcurves-p256-comb-onchip.a": ["LIB_P256_COMB_ONLY", "FP_ONCHIP_MUL"],
    "nistcurves-p384-sha384.a": ["LIB_SHA384_ONLY"],
}

HEADER_BARE_SYMS = [
    "LIB_NISTCURVES_ABI_VERSION",                # src/lib_version.s:71
    "LIB_NISTCURVES_SHARED_REU_MUL_BANK",        # src/reu_config.s:205
    "LIB_NISTCURVES_PRECALC_sqtab_SIZE",         # src/precalc_table.inc:86
    "LIB_NISTCURVES_SHA384_UPDATE_MAX",          # src/lib_manifest.s (a fact,
                                                 # not a knob -- see there)
]

# A consumer TU: includes the shipped header, emits the 2-byte PRG load
# address the example cfg expects, and nothing else. Every import the header
# makes must resolve against the archive for this to link.
HEADER_STUB = """\
.include "nistcurves.inc"

.segment "LOADADDR"
    .import __LOADADDR__
    .word   __LOADADDR__

.segment "CODE"
entry:
    rts
"""


def _header_link(td, incdir, cfg, archive, defines):
    """Assemble HEADER_STUB (+ defines) against `incdir`, link vs `archive`.

    Returns (asm_rc, asm_out, link_rc, link_out); link_* are (None, "") when
    the assemble failed.
    """
    src = td / "hdr_consumer.s"
    src.write_text(HEADER_STUB)
    obj = td / "hdr_consumer.o"
    arc, aout = sh(["ca65", "--cpu", "6502", *defines, "-I", str(incdir),
                    "-o", str(obj), str(src)])
    if arc != 0:
        return arc, aout, None, ""
    lrc, lout = sh(["ld65", "-C", str(cfg), "-o", str(td / "hdr_consumer.prg"),
                    str(obj), str(archive)])
    return arc, aout, lrc, lout


def packaging_check(failures, archives):
    """SPEC §6.1 packaging artifacts + SPEC §3 header-import guard rule.

    NEGATIVE-TEST PROVENANCE. This leg was confirmed capable of failing by
    deleting the `.else` branch of the LIB_NISTCURVES_REU_BANK_COMB guard in
    src/nistcurves.inc (leaving the bare `.ifndef` guard), rebuilding, and
    re-running: the wrong-value row for that symbol linked clean and the leg
    reported

        GUARD FAIL [LIB_NISTCURVES_REU_BANK_COMB]: wrong -D value linked
        clean -- the .else assert is missing or does not compare against the
        archive

    A second confirmation removed the `.ifndef` entirely (bare `.import`),
    which trips the other direction: the matching-value row fails to assemble
    with `Symbol 'LIB_NISTCURVES_REU_BANK_COMB' is already defined`.
    """
    print("\n=== §6.1 consumer packaging + §3 header guards ===")

    src_inc = REPO / "src" / "nistcurves.inc"
    src_cfg = REPO / "cfg" / "nistcurves-example.cfg"
    shipped_inc = LIBDIR / "nistcurves.inc"
    shipped_cfg = LIBDIR / "cfg" / "nistcurves-example.cfg"
    archive = LIBDIR / "nistcurves.a"

    # (1) `make lib` produced all three artifacts, and the shipped header/cfg
    # are byte-identical to the in-tree sources (a stale copy in build/lib is
    # exactly the drift this pin exists to catch).
    ok = True
    for label, p in (("archive", archive), ("header", shipped_inc),
                     ("example cfg", shipped_cfg)):
        if not p.exists():
            failures.append(f"packaging: `make lib` did not produce the {label} ({p})")
            print(f"  PACKAGING FAIL: missing {label}: {p}")
            ok = False
    for label, s, d in (("header", src_inc, shipped_inc),
                        ("example cfg", src_cfg, shipped_cfg)):
        if s.exists() and d.exists() and s.read_bytes() != d.read_bytes():
            failures.append(f"packaging: shipped {label} differs from {s}")
            print(f"  PACKAGING FAIL: build/lib copy of the {label} is stale")
            ok = False
    if not ok:
        return
    print("  artifacts OK (.a + .inc + example .cfg, shipped copies match src/)")

    # (2) Every LIB_NISTCURVES_* segment the sources emit must be mapped by the
    # example cfg. A consumer copies that SEGMENTS block; an unmapped segment
    # is a hard ld65 error for them and a silently-rotted example for us.
    emitted = set()
    for s in sorted((REPO / "src").glob("*.s")):
        emitted |= set(re.findall(r'\.segment\s+"(LIB_NISTCURVES_[A-Z0-9_]+)"',
                                  s.read_text()))
    cfg_text = src_cfg.read_text()
    m = re.search(r"^SEGMENTS\s*\{(.*?)^\}", cfg_text, re.S | re.M)
    mapped = set(re.findall(r"^\s*(LIB_NISTCURVES_[A-Z0-9_]+)\s*:",
                            m.group(1) if m else "", re.M))
    unmapped = sorted(emitted - mapped)
    if unmapped:
        failures.append(f"packaging: example cfg does not map {unmapped}")
        print(f"  CFG FAIL: segments emitted by src/*.s but absent from the example cfg: {unmapped}")
    else:
        print(f"  cfg segment coverage OK ({len(emitted)} LIB_NISTCURVES_* segments mapped)")

    # (3) SPEC §4 load-bearing attributes must travel with the example cfg,
    # not just with src/c64.cfg -- the example is the file consumers copy.
    for seg, attr in (("LIB_NISTCURVES_SHA384_TABLES", r"align\s*=\s*\$100"),
                      ("LIB_NISTCURVES_TABLES", r"align\s*=\s*\$100"),
                      ("LIB_NISTCURVES_TABLES", r"type\s*=\s*rw"),
                      ("LIB_NISTCURVES_MUL_CODE", r"type\s*=\s*rw"),
                      ("LIB_NISTCURVES_P256_CODE", r"type\s*=\s*rw"),
                      ("LIB_NISTCURVES_P384_CODE", r"type\s*=\s*rw")):
        line = re.search(rf"^\s*{seg}\s*:(.*)$", cfg_text, re.M)
        if not line or not re.search(attr, line.group(1)):
            failures.append(f"packaging: example cfg {seg} is missing `{attr}`")
            print(f"  CFG FAIL: {seg} lacks the load-bearing attribute {attr}")
    print("  cfg §4 load-bearing attributes OK (align/rw declared where they matter)")

    # (4) + (5) drive the shipped header the way a consumer does.
    full_mods = archives.get("nistcurves.a", [])
    obj_paths = [BUILD / (mo + ".o") for mo in full_mods]

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)

        arc, aout, lrc, lout = _header_link(td, LIBDIR, src_cfg, archive, [])
        if arc != 0:
            failures.append("header: the shipped .inc does not assemble")
            print(f"  HEADER FAIL: plain include does not assemble:\n{aout}")
            return
        if lrc != 0:
            failures.append("header: a consumer including the shipped .inc does not link")
            print(f"  HEADER FAIL: plain include does not link vs nistcurves.a:\n{lout}")
            return
        print("  header OK (plain .include assembles and links against nistcurves.a)")

        # (3b) ... and against EVERY archive, with the variant switch set that
        # archive is built with. The header gates ~650 lines by those switches,
        # and linking only the full archive exercises none of that gating --
        # while API.md and CLAUDE.md both claimed every archive was covered.
        # A claim of mechanical verification the mechanism does not perform is
        # worse than no claim, so the mechanism now performs it.
        for aname, adefs in sorted(HEADER_ARCHIVE_SWITCHES.items()):
            apath = LIBDIR / aname
            if not apath.exists():
                failures.append(f"header: {aname} not built, cannot check header against it")
                print(f"  HEADER FAIL [{aname}]: archive missing")
                continue
            dargs = []
            for d in adefs:
                dargs += ["-D", d]
            arc, aout, lrc, lout = _header_link(td, LIBDIR, src_cfg, apath, dargs)
            if arc != 0:
                failures.append(f"header: does not assemble for {aname}'s switch set")
                print(f"  HEADER FAIL [{aname}]: assemble:\n{aout}")
            elif lrc != 0:
                failures.append(f"header: does not link against {aname}")
                print(f"  HEADER FAIL [{aname}]: link:\n{lout}")
            else:
                print(f"  header OK [{aname}]")

        # (4) Guarded symbols: right value assembles AND links; wrong value
        # assembles but MUST be rejected at link by the .else assert.
        for sym in HEADER_GUARDED_SYMS:
            real = od65_value(obj_paths, sym)
            if real is None:
                failures.append(f"header: guarded symbol {sym} is not exported by nistcurves.a")
                print(f"  GUARD FAIL [{sym}]: not exported by the archive")
                continue

            arc, aout, lrc, lout = _header_link(
                td, LIBDIR, src_cfg, archive, ["-D", f"{sym}={real}"])
            if arc != 0:
                failures.append(f"header: -D {sym}={real} does not assemble ({sym} import is not .ifndef-guarded)")
                print(f"  GUARD FAIL [{sym}]: documented override does not assemble "
                      f"-- expected the .ifndef guard, got:\n{aout.strip()}")
                continue
            if lrc != 0:
                failures.append(f"header: -D {sym}={real} (the archive's own value) fails to link")
                print(f"  GUARD FAIL [{sym}]: matching override rejected at link:\n{lout.strip()}")
                continue

            wrong = real ^ 1
            arc, aout, lrc, lout = _header_link(
                td, LIBDIR, src_cfg, archive, ["-D", f"{sym}={wrong}"])
            if arc != 0:
                failures.append(f"header: -D {sym}={wrong} does not assemble")
                print(f"  GUARD FAIL [{sym}]: wrong override does not assemble:\n{aout.strip()}")
                continue
            if lrc == 0:
                failures.append(f"header: -D {sym}={wrong} linked clean against an archive at {real} "
                                "-- the .else assert is missing or does not compare against the archive")
                print(f"  GUARD FAIL [{sym}]: wrong -D value linked clean -- the .else assert "
                      "is missing or does not compare against the archive")
                continue
            if "override disagrees" not in lout:
                failures.append(f"header: -D {sym}={wrong} failed at link, but not on the override assert")
                print(f"  GUARD FAIL [{sym}]: link failed for some other reason:\n{lout.strip()}")
                continue
            print(f"  guard OK [{sym}] = {real}: matching -D links, {wrong} trips the .else assert")

        # (5) Bare-import symbols: their defining TU assigns unconditionally,
        # so §3 says the -D must collide loudly rather than be absorbed.
        for sym in HEADER_BARE_SYMS:
            arc, aout, _, _ = _header_link(td, LIBDIR, src_cfg, archive,
                                           ["-D", f"{sym}=1"])
            if arc == 0:
                failures.append(f"header: -D {sym}=1 assembled -- a derived equate's import "
                                "must stay bare so the override collides")
                print(f"  BARE FAIL [{sym}]: -D absorbed by a guard; §3 requires a bare import here")
            elif "already defined" not in aout:
                failures.append(f"header: -D {sym}=1 failed to assemble for the wrong reason")
                print(f"  BARE FAIL [{sym}]: assemble failed, but not on redefinition:\n{aout.strip()}")
            else:
                print(f"  bare OK [{sym}]: -D collides loudly, as a derived equate must")


def gated_link_check(failures, archives):
    """§6.5 at the level a consumer meets it: an ld65 LINK of a GATED archive.

    Everything else about `LIB_NO_BARE_EXPORTS=1` is verified at the object
    level -- six TUs, and (before issue #159) one arm. But the mode a consumer
    composing several libraries MUST build in is
    `make lib-<variant> CONTRACT_DEFINES='-D LIB_NO_BARE_EXPORTS=1'` followed
    by a link, and through v0.14.0 no leg ever performed one: the §3 header
    leg resolves nistcurves.inc against the twelve archives UNGATED only.

    SCOPE, stated exactly, because the obvious overclaim is wrong. This leg
    proves the LIBRARY is self-consistent under the gate -- it does not prove
    a consumer's imports of nistcurves.inc resolve under it. ca65 drops an
    `.import` nothing references, so the HEADER_STUB object carries exactly
    one import (`__LOADADDR__`, checked with od65), and the header therefore
    contributes nothing to the link. A gated defect confined to the header --
    the header still declaring an import of a name the gate deletes -- stays
    invisible here. Closing that needs a stub that actually references the
    public surface (the SMOKE lists are the obvious source); it is not closed.

    The gap is not academic, because the object level cannot see it. Each
    object can be individually correct under the gate while the LINK fails:
    the gate deletes a bare `.export` in one TU, another TU still `.import`s
    that bare spelling, and every per-object assertion stays green because
    imports resolve at link, not at assemble. The consumer meets it as

        ld65: Error: Unresolved external 'zp_tmp1' referenced in ...

    Method: rebuild every member of every archive with that archive's own
    switch set plus the gate -- which is exactly what CONTRACT_DEFINES
    forwarding does -- and link the shipped header against them. The UNGATED
    rebuild is linked too, from the same code path, as the control: without it
    a failure could be blamed on this leg's rebuild rather than on the gate,
    and the ungated leg's own green would prove nothing about the gated one.

    Each distinct member object is assembled ONCE per direction and reused
    across the archives that share it (275 member slots collapse to 72 real
    objects), which is what keeps the leg at a few seconds.

    SENTINELS, because "the gated archive links" is a success-shaped claim
    that an empty or unbuilt archive also satisfies:
      * the ungated rebuild must export at least one bare name (otherwise
        there was nothing for the gate to suppress and the pair is vacuous);
      * the gated rebuild must export none (otherwise the gate did not run at
        all and the link result says nothing about the gated mode);
      * both links must actually be performed, and the completion banner is
        keyed off the archives that got that far.
    """
    import tempfile
    print("\n=== §6.5 gated LINK (every archive rebuilt under the gate) ===")
    arms = shipped_object_arms(archives)
    src_cfg = REPO / "cfg" / "nistcurves-example.cfg"
    # HEADER_ARCHIVE_SWITCHES is a hand-maintained roster, and it is the
    # population BOTH this leg and the §3 header leg (3b) iterate. Nothing
    # reconciled it against the archives the Makefile actually builds, so a
    # thirteenth archive would be skipped by both while each printed a clean
    # per-entry OK -- the roster-that-never-grew shape, the same one
    # gate_tus_derivation_check and zp_roster_reconciliation_check exist to
    # close for their own rosters. Reconciled here because this leg's result
    # is meaningless over an incomplete population.
    # MEMBER-LIST RECONCILIATION against an INDEPENDENT source. Everything in
    # this file that says "the archive contains X" comes from regexing the
    # Makefile, and that parse's failure mode is a SHORTER list, silently --
    # a shorter list is a smaller population, and a smaller population is what
    # every leg here reports as a clean count. Two shapes have already done
    # it: an unexpandable token dropping out, and a second `ar65 a` line being
    # ignored. So compare against `ar65 t` on the archive make actually built,
    # which is downstream of make's own expansion and of ar65 itself. Both
    # directions: a member we invented is as wrong as one we lost.
    for aname in sorted(archives):
        apath = LIBDIR / aname
        if not apath.exists():
            failures.append(f"gated link [{aname}]: archive not built, so the "
                            "parsed member list cannot be reconciled against it")
            print(f"  GATED LINK FAIL [{aname}]: archive missing, member list unverified")
            continue
        rc, out = sh(["ar65", "t", str(apath)])
        if rc:
            failures.append(f"gated link [{aname}]: `ar65 t` failed, so the "
                            f"parsed member list is unverified: {out.strip()}")
            print(f"  GATED LINK FAIL [{aname}]: ar65 t failed")
            continue
        real = {Path(ln.strip()).stem for ln in out.splitlines() if ln.strip().endswith(".o")}
        if not real:
            failures.append(f"gated link [{aname}]: `ar65 t` listed no members, "
                            "so the reconciliation would be vacuous")
            print(f"  GATED LINK FAIL [{aname}]: ar65 t listed nothing")
            continue
        parsed = set(archives[aname])
        lost, invented = sorted(real - parsed), sorted(parsed - real)
        if lost or invented:
            failures.append(
                f"gated link [{aname}]: the member list parsed from the Makefile "
                f"disagrees with `ar65 t` on the built archive -- missing from "
                f"the parse {lost}, parsed but not in the archive {invented}; "
                "every leg keyed off this population was measuring a different "
                "archive from the one that ships")
            print(f"  GATED LINK FAIL [{aname}]: parsed member list != ar65 t "
                  f"(parse is missing {lost}, invented {invented})")
    uncovered = sorted(set(archives) - set(HEADER_ARCHIVE_SWITCHES))
    phantom = sorted(set(HEADER_ARCHIVE_SWITCHES) - set(archives))
    if uncovered:
        failures.append(f"gated link: {uncovered} are built by the Makefile but "
                        "absent from HEADER_ARCHIVE_SWITCHES -- this leg and the "
                        "§3 header leg both skip them silently")
        print(f"  GATED LINK FAIL: archives with no switch set on record: {uncovered}")
    if phantom:
        failures.append(f"gated link: {phantom} are in HEADER_ARCHIVE_SWITCHES "
                        "but built by no ar65 recipe -- a roster entry that "
                        "binds nothing")
        print(f"  GATED LINK FAIL: phantom archives in the switch roster: {phantom}")
    # ARM-DERIVATION PIN. Everything above -- and the whole arm sweep in
    # gated_surface_check -- rests on this file's reading of the Makefile
    # being the same as make's. Both rebuild from source and compare only to
    # themselves, so a misread switch set is self-consistent and invisible:
    # the arm is assembled with the wrong -D, swept, and reported OK. (That
    # was live: the four APP_OWNED switches reach mul_8x8_appowned.o through
    # a $(APP_OWNED_DEFINES) variable, and reading it wrong swept the
    # app-owned arm as the default arm.) So compare the ungated rebuild of
    # each arm against the object `make` actually produced. The comparand is
    # genuinely independent: build/<obj>.o came out of make's own recipe, not
    # out of the regex being checked.
    #
    # NAMES ARE NOT ENOUGH, and the earlier version of this comment claiming
    # "different -D, different export set" was false. Enumerated against
    # wrong-switch candidates, 16 (object, wrong-set) pairs are name-identical:
    # all twelve lib_manifest arms collapse to two export-NAME signatures,
    # while lib_manifest_sha384 misparsed as the default arm differs in six §5
    # VALUES and each *_onchip arm losing FP_ONCHIP_MUL differs in four. That
    # TU exists precisely to emit different numbers per variant, so values are
    # the discriminator. precalc_manifest_p256verify == p384verify and
    # zp_aliases_p256verify == p384curve == p384verify by name as well.
    # So compare export names AND VALUES and the import set. What this pin
    # discriminates, stated honestly: any misparse that changes an export
    # name, an exported constant's value, or an import -- which covers every
    # degrade-to-default among the GATE_TUs, and the lib_manifest arms that
    # names alone could not separate.
    drift, unbuilt = [], []
    for obj, (src, defines, _using) in sorted(arms.items()):
        real = BUILD / f"{obj}.o"
        if not real.exists():
            unbuilt.append(obj)
            continue
        dargs = []
        for d in defines:
            dargs += ["-D", d]
        with tempfile.TemporaryDirectory() as ptd:
            mine = Path(ptd) / f"{obj}.o"
            rc, out = sh(["ca65", "--cpu", "6502", *dargs, "-I", "src",
                          "-o", str(mine), f"src/{src}.s"])
            if rc:
                drift.append(f"{obj} (rebuild with the parsed -D set fails: "
                             f"{out.splitlines()[0] if out else ''})")
                continue
            a, b = od65_export_records(mine), od65_export_records(real)
            ai, bi = od65_names(mine, "--dump-imports"), od65_names(real, "--dump-imports")
        if not isinstance(a, dict) or not isinstance(b, dict):
            drift.append(f"{obj} (export dump unreadable or short on one side)")
            continue
        # Only the first few differences: a misparse typically hits every arm
        # at once, and the full symmetric difference over 28 arms is thousands
        # of characters that bury the object names -- the part you act on.
        diffs = []
        for nm in sorted(set(a) ^ set(b)):
            diffs.append(f"{nm} {'only in the rebuild' if nm in a else 'only in build/'}")
        for nm in sorted(set(a) & set(b)):
            if a[nm] != b[nm]:
                diffs.append(f"{nm} = {_vfmt(a[nm])} rebuilt, "
                             f"{_vfmt(b[nm])} in build/{obj}.o")
        if ai != bi:
            diffs.append(f"imports differ: {sorted(ai ^ bi)[:4]}")
        if diffs:
            shown = "; ".join(diffs[:3]) + (f"; +{len(diffs) - 3} more"
                                            if len(diffs) > 3 else "")
            drift.append(f"{obj} parsed as {list(defines) or '(default)'}: "
                         f"disagrees with build/{obj}.o ({shown})")
    if unbuilt:
        failures.append(f"gated link: {unbuilt} are archive members but were "
                        "never built, so the arm-derivation pin cannot compare "
                        "this parser's reading against make's")
        print(f"  GATED LINK FAIL: unbuilt members {unbuilt}")
    if drift:
        head = drift[:5] + ([f"...and {len(drift) - 5} more arms"]
                            if len(drift) > 5 else [])
        failures.append(f"gated link: the Makefile switch sets this file parsed "
                        f"do not reproduce the built objects ({len(drift)} of "
                        f"{len(arms)} arms): {head}")
        print(f"  GATED LINK FAIL: arm derivation disagrees with the build "
              f"({len(drift)} of {len(arms)} arms):")
        for d in head:
            print(f"      {d}")
    elif not unbuilt:
        print(f"  arm derivation OK ({len(arms)} shipped objects reproduced "
              "from the parsed -D sets, exports match build/*.o)")
    done = []
    with tempfile.TemporaryDirectory() as topdir:
        topdir = Path(topdir)
        built = {}       # (mod, gated) -> Path or None
        barenames = {}   # (mod, gated) -> set or None (unreadable)

        def member(mod, gated):
            key = (mod, gated)
            if key in built:
                return built[key]
            src, defines, _ = arms.get(mod, (mod, (), []))
            dargs = []
            for d in defines:
                dargs += ["-D", d]
            if gated:
                dargs += ["-D", "LIB_NO_BARE_EXPORTS=1"]
            o = topdir / f"{'g' if gated else 'u'}_{mod}.o"
            rc, out = sh(["ca65", "--cpu", "6502", *dargs, "-I", "src",
                          "-o", str(o), f"src/{src}.s"])
            built[key] = None if rc else o
            names = od65_export_names(o) if not rc else None
            barenames[key] = bare_gated(names) if isinstance(names, set) else None
            return built[key]

        for aname in sorted(HEADER_ARCHIVE_SWITCHES):
            mods = archives.get(aname)
            if not mods:
                failures.append(f"gated link [{aname}]: no ar65 recipe parsed -- "
                                "nothing to rebuild under the gate")
                print(f"  GATED LINK FAIL [{aname}]: no member list")
                continue
            switches = []
            for d in HEADER_ARCHIVE_SWITCHES[aname]:
                switches += ["-D", d]
            td = topdir
            results = {}
            broke = False
            for gated in (False, True):
                objs = []
                for mod in mods:
                    o = member(mod, gated)
                    if o is None:
                        failures.append(
                            f"gated link [{aname}]: {mod}.o does not assemble "
                            f"{'under the gate' if gated else 'ungated'}")
                        print(f"  GATED LINK FAIL [{aname}]: {mod}.o assemble "
                              f"({'gated' if gated else 'ungated'})")
                        broke = True
                        break
                    objs.append(o)
                if broke:
                    break
                bare, unread = set(), []
                for mod in mods:
                    b = barenames[(mod, gated)]
                    if b is None:
                        unread.append(mod)
                    else:
                        bare |= b
                if unread:
                    failures.append(f"gated link [{aname}]: unreadable rebuilt "
                                    f"objects {sorted(unread)} -- the bare-name "
                                    "sentinel would be an absence over an unread dump")
                    print(f"  GATED LINK FAIL [{aname}]: unreadable objects {sorted(unread)}")
                    broke = True
                    break
                # The consumer TU is the shipped header, assembled with this
                # archive's switch set (plus the gate). It is linked ALONGSIDE
                # every member object rather than against an ar65 archive, and
                # that is load-bearing: ca65 drops an `.import` that nothing
                # references, so the header stub's object carries exactly one
                # import (__LOADADDR__) and a link against an archive pulls
                # almost no member at all. Passing the objects explicitly links
                # the whole library, which is what makes an intra-library
                # reference to a name the gate deleted show up as ld65's
                # `Unresolved external` -- the failure this leg exists for, and
                # the one no per-object assertion can see.
                dargs = list(switches)
                if gated:
                    dargs += ["-D", "LIB_NO_BARE_EXPORTS=1"]
                hs = td / f"{'g' if gated else 'u'}_hdr.s"
                hs.write_text(HEADER_STUB)
                ho = td / f"{'g' if gated else 'u'}_hdr.o"
                arc, aout = sh(["ca65", "--cpu", "6502", *dargs, "-I", str(LIBDIR),
                                "-o", str(ho), str(hs)])
                if arc != 0:
                    results[gated] = (bare, arc, aout, None, "", set())
                    continue
                lrc, lout = sh(["ld65", "-C", str(src_cfg), "-o",
                                str(td / f"{'g' if gated else 'u'}.prg"),
                                str(ho), *[str(o) for o in objs]])
                unres = set(re.findall(r"Unresolved external '([^']+)'", lout))
                results[gated] = (bare, arc, aout, lrc, lout, unres)
            if broke:
                continue

            ubare, uarc, uaout, ulrc, ulout, uunres = results[False]
            gbare, garc, gaout, glrc, glout, gunres = results[True]
            if not ubare:
                failures.append(
                    f"gated link [{aname}]: the UNGATED rebuild exports no bare "
                    "name, so the gated link proves nothing about the gate")
                print(f"  GATED LINK FAIL [{aname}]: nothing for the gate to suppress")
                continue
            if gbare:
                failures.append(
                    f"gated link [{aname}]: the GATED rebuild still exports bare "
                    f"{sorted(gbare)} -- the archive a consumer builds with "
                    "CONTRACT_DEFINES='-D LIB_NO_BARE_EXPORTS=1' is not gated")
                print(f"  GATED LINK FAIL [{aname}]: gated archive exports bare {sorted(gbare)}")
                continue
            if uarc != 0:
                failures.append(
                    f"gated link [{aname}]: the UNGATED control header does not "
                    "assemble -- this leg's rebuild is broken, so its gated result "
                    "is not attributable to the gate")
                print(f"  GATED LINK FAIL [{aname}]: ungated control assemble:\n{uaout.strip()}")
                continue
            if garc != 0:
                failures.append(f"gated link [{aname}]: the header does not assemble "
                                "with the gate defined")
                print(f"  GATED LINK FAIL [{aname}]: gated header assemble:\n{gaout.strip()}")
                continue
            # The sharp assertion, and the one that does not depend on the
            # documented-gap allowlist: the gate may suppress deprecated bare
            # exports, so it may never leave a reference UNRESOLVED that resolved
            # without it. Comparing the two sets rather than demanding a clean
            # gated link is what would keep a genuinely documented external
            # from reading as a gate defect.
            #
            # NOTE: every KNOWN_EXTERNAL entry is `set()` today, and every
            # archive's gated link here resolves closed -- app-owned
            # included, because in the DMA profile the `.import
            # poly_prod_lo/hi` is unreferenced and ca65 drops it. So the
            # `beyond` branch below is an empty-population absence with no
            # negative test. It is fail-closed, but `new_unres` is what
            # actually carries this leg; do not read the allowlist as
            # load-bearing.
            new_unres = sorted(gunres - uunres)
            if new_unres:
                failures.append(
                    f"gated link [{aname}]: -D LIB_NO_BARE_EXPORTS=1 leaves "
                    f"{new_unres} unresolved at ld65 while the ungated build of the "
                    "same objects resolves them -- a consumer composing libraries "
                    "cannot link this archive")
                print(f"  GATED LINK FAIL [{aname}]: gate creates unresolved externals: {new_unres}")
                continue
            stale = sorted(uunres - gunres)
            if stale:
                failures.append(
                    f"gated link [{aname}]: {stale} are unresolved WITHOUT the gate "
                    "but resolve with it -- the gated build must be a subset")
                print(f"  GATED LINK FAIL [{aname}]: gate resolves {stale} that the "
                      "ungated build does not")
                continue
            beyond = sorted(gunres - KNOWN_EXTERNAL.get(aname, set()))
            if beyond:
                failures.append(
                    f"gated link [{aname}]: gated link unresolved beyond the "
                    f"documented gaps: {beyond}")
                print(f"  GATED LINK FAIL [{aname}]: unresolved beyond allowlist: {beyond}")
                continue
            if glrc != 0 and not gunres:
                failures.append(
                    f"gated link [{aname}]: the gated link failed for a non-symbol "
                    f"reason:\n{glout.strip()}")
                print(f"  GATED LINK FAIL [{aname}]: gated link failed, no unresolved "
                      f"externals reported:\n{glout.strip()}")
                continue
            done.append((aname, len(ubare)))
    if len(done) == len(HEADER_ARCHIVE_SWITCHES):
        total = sum(n for _, n in done)
        print(f"  gated link OK ({len(done)} archives rebuilt with "
              f"-D LIB_NO_BARE_EXPORTS=1, {total} bare names suppressed across "
              "them, each links against the shipped header)")


def gate_tus_derivation_check(failures):
    """GATE_TUS is a roster. Derive the same set from the sources and compare.

    The gated-surface leg's pass condition is literally "0 bare names", and a
    count of zero passes when the input is empty: nothing distinguishes "looked
    and found none" from "looked at nothing". This repo has already produced
    two independent ways that leg could report zero falsely -- an extraction
    dropping exactly the bare LIB_PRECALC_* names, and BARE_GATED listing none
    of them. A roster that never grew is the third, and it is upstream of the
    sentinel: if GATE_TUS omits a TU, the leg never looks at it and still
    prints a clean zero.

    So derive: assemble every src/*.s twice, once ungated and once with
    LIB_NO_BARE_EXPORTS, and any TU whose export set SHRINKS owns a displaceable
    name by construction. That set must equal GATE_TUS exactly. A TU that
    starts owning one is then covered automatically, and one that stops is
    flagged rather than sitting in the roster proving nothing.

    ARMS AS WELL AS SOURCES (issue #159). Ownership is arm-dependent: a TU can
    export a displaceable name only under `-D LIB_SHA384_ONLY` and none in the
    default arm, and a default-arm-only derivation would then miss it and let
    the gated-surface leg skip it. So the population is every src/*.s in the
    default arm PLUS every (source, -D set) pair the Makefile actually ships,
    derived by parse_makefile_object_rules() rather than restated here."""
    import tempfile
    print("\n=== GATE_TUS derived from source (roster vs reality, all arms) ===")
    srcs = sorted((REPO / "src").glob("*.s"))
    if not srcs:
        failures.append("gate-tus: no sources found -- derivation is vacuous")
        print("  DERIVE FAIL: no src/*.s")
        return
    # (source stem, defines tuple) -> label. Default arm for every source, plus
    # each shipped variant arm.
    probes = {(s.stem, ()): s.stem for s in srcs}
    for obj, (tu, defines, using) in shipped_object_arms(
            parse_makefile_archives()).items():
        probes.setdefault((tu, defines), obj)
    derived, unreadable = set(), []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for (tu, defines), label in sorted(probes.items()):
            src = REPO / "src" / f"{tu}.s"
            dargs = []
            for d in defines:
                dargs += ["-D", d]
            ung, gat = td / f"{label}_u.o", td / f"{label}_g.o"
            r1, _ = sh(["ca65", "--cpu", "6502", "-I", "src", *dargs,
                        "-o", str(ung), str(src)])
            r2, _ = sh(["ca65", "--cpu", "6502", "-I", "src", *dargs, "-D",
                        "LIB_NO_BARE_EXPORTS=1", "-o", str(gat), str(src)])
            if r1 or r2:
                unreadable.append(label)
                continue
            a, b = od65_export_names(ung), od65_export_names(gat)
            if a is None or b is None or a is COUNT_MISMATCH or b is COUNT_MISMATCH:
                unreadable.append(label)
                continue
            if a - b:
                derived.add(tu)
    if unreadable:
        failures.append(f"gate-tus: could not derive from {sorted(unreadable)} -- "
                        "an undecided arm is not a clean one")
        print(f"  DERIVE FAIL: undecidable {sorted(unreadable)}")
        return
    roster = set(GATE_TUS)
    missing, extra = sorted(derived - roster), sorted(roster - derived)
    if missing:
        failures.append(f"gate-tus: {missing} own a displaceable name but are "
                        f"not in GATE_TUS -- the gated-surface leg never looks "
                        f"at them and still prints a clean zero")
        print(f"  DERIVE FAIL: unlisted owners {missing}")
    if extra:
        failures.append(f"gate-tus: {extra} are in GATE_TUS but own no "
                        f"displaceable name; their gated result proves nothing")
        print(f"  DERIVE FAIL: roster entries proving nothing {extra}")
    if not (missing or extra):
        print(f"  GATE_TUS OK ({len(derived)} TUs derived from {len(probes)} "
              f"source arms, roster matches exactly)")


def zp_roster_reconciliation_check(failures):
    """The ZP legs iterate over hand-maintained rosters. Reconcile them against
    the Makefile, or a seventh variant is silently unaudited by all four.

    ZP_ARM_OBJECTS, ZP_ARM_DEFINES and ZP_ALIAS_ARMS are each iterated over
    themselves, and nothing cross-checks them against the archives that
    actually exist. Adding a variant to the Makefile and to none of them leaves
    every ZP leg quietly not covering it: the half-updated case raises
    KeyError, the not-updated-at-all case says nothing.

    Same mechanism as BARE_GATED, which listed none of the 18 bare
    LIB_PRECALC_* names the §8.4 macro emits and so reported "0 bare names" for
    a TU it had never examined, since issue #113. A roster and a predicate look
    equally reasonable in review; only one survives its subject growing."""
    print("\n=== ZP roster reconciliation (rosters vs the real archive set) ===")
    archives = set(parse_makefile_archives())
    if not archives:
        failures.append("zp rosters: parsed no archives, so this reconciliation "
                        "is vacuous rather than passing")
        print("  ROSTER FAIL: no archives parsed")
        return
    covered = {a for arms in ZP_ARM_OBJECTS.values() for a in arms}
    missing = sorted(archives - covered)
    phantom = sorted(covered - archives)
    keys = set(ZP_ARM_OBJECTS) | set(ZP_ARM_DEFINES) | set(ZP_ALIAS_ARMS)
    ragged = sorted(k for k in keys
                    if not (k in ZP_ARM_OBJECTS and k in ZP_ARM_DEFINES
                            and k in ZP_ALIAS_ARMS))
    if missing:
        failures.append(f"zp rosters: {missing} exist as archives but no ZP arm "
                        f"covers them -- every ZP leg silently skips them")
        print(f"  ROSTER FAIL: uncovered archives {missing}")
    if phantom:
        failures.append(f"zp rosters: {phantom} named by an arm but built by no "
                        f"recipe")
        print(f"  ROSTER FAIL: phantom archives {phantom}")
    if ragged:
        failures.append(f"zp rosters: {ragged} present in some of the three "
                        f"rosters and not others")
        print(f"  ROSTER FAIL: ragged arms {ragged}")
    if not (missing or phantom or ragged):
        print(f"  rosters OK ({len(keys)} arms cover all {len(archives)} "
              f"archives, all three rosters agree)")


def footprint_basis_check(failures):
    """The §5 measurement basis is od65 segment sums. Pin that it equals a real
    link, because if it stops doing so the footprint leg understates SILENTLY.

    Since issue #161 this leg is what makes a sum-based measurand legitimate at
    all. §5 says the basis is "the placed span ... not the sum of member object
    sizes"; measured_code_rodata() IS such a sum, and equals the placed span
    only while no segment takes fragments from two objects with alignment
    between them. Nothing in ca65 or ld65 enforces that -- this leg does, by
    linking for real and asserting `od65 sums == placed sizes` per segment.

    c64-ChaCha20-Poly1305 found all five of their RESIDENT_BYTES under-reporting
    a real link by 39-295 B, in §5's dangerous direction, from exactly this
    basis: Sigma of what each MEMBER contributes excludes the fill ld65 inserts
    when it PLACES them, and `od65 basis + fill = real link` held exactly across
    ten of their rows.

    Two kinds of fill, and they are handled differently:

      WITHIN a segment -- if ld65 aligns each contributing object's fragment.
        UNBOUNDED in the number of contributing objects. This is what bit CCP,
        whose fill exceeded 255 and so cannot be a single inter-segment gap. It
        is inside the segment, so it IS part of §5's measurand, and it is the
        `od65 sums == placed sizes` identity below that catches it.
      BETWEEN segments -- up to 255 bytes before each page-aligned segment.
        NOT part of the measurand and no longer charged (issue #161): it is
        `(-previous_end) mod alignment`, fixed by the consumer's own placement
        and order, derivable only from the consumer's link map. Still measured
        here, as a bounded CHANGE DETECTOR rather than a budget line -- a gap
        exceeding INTER_SEGMENT_FILL_BOUND would mean the placement is no
        longer one page-aligned boundary per segment, i.e. that the reasoning
        above stopped describing the artifact. Be honest about its strength,
        because it is deliberately weak: while each aligned segment sits in one
        MEMORY region behind one $100 boundary, its gap is
        `(-previous_end) mod $100` and CANNOT exceed the bound, so the
        comparison reddens only on a cfg-level change (alignment raised past
        $100, or the segment moved region). It is a printed number to diff
        across commits, not a guard.

        Do NOT "strengthen" it by asserting the two segments are page-aligned
        in the map -- that assertion cannot fail, and issue #161 tried it and
        removed it again. Both are already asserted at LINK time by the
        library's own source, so the reference link dies before the map is
        parsed: src/sha384.s (`lo_2_tbl`/`hi_2_tbl`… `must be page-aligned
        (abs,x rotate LUT)`) covers LIB_NISTCURVES_SHA384_TABLES, and
        src/data_mul_stage.s:117 (`reu_mul stage_lo must be page-aligned (SPEC
        §8.2)`) covers LIB_NISTCURVES_TABLES. Deleting `align = $100` from
        src/c64.cfg was measured: this leg reports
        `BASIS FAIL: link error` / `ld65: Error: src/sha384.s(1063): lo_2_tbl
        must be page-aligned (abs,x rotate LUT)`, i.e. the failure is real but
        arrives through the link step, one leg earlier.

    We are clean today: no src file contains a source-level `.align`, and each
    aligned segment takes contributions from one object, so od65 sums equal
    placed sizes exactly. Measured over all 20 segments of a full link, delta
    +0 on every one.

    That is a property, not a guarantee. The precise condition, measured during
    issue #161's review because the looser statement that used to sit here was
    wrong: fill becomes INVISIBLE only when the `.align` sits at a FRAGMENT
    HEAD, so ld65 rather than ca65 inserts it. An `.align` mid-file is resolved
    locally by ca65 into object bytes, so the od65 sum and the placed span grow
    together and this leg correctly stays green. "Two objects contribute" is
    neither necessary nor sufficient. A re-runner who mutates the wrong
    position -- or picks an alignment the fragment head already satisfies, e.g.
    `.align 16` at an already-16-aligned offset -- will conclude this leg is
    broken when it is not. So this links for real, reads the map, and asserts
    the identity."""
    import tempfile
    print("\n=== §5 footprint basis (od65 sums == real placed sizes) ===")
    # Assemble from source into a scratch dir rather than reading build/*.o:
    # other legs in this file wipe the tree as a side effect, and a leg that
    # silently measures whatever objects happen to survive is the ambient-state
    # version of the vacuity problem. Deriving the module list from the
    # Makefile also means a new src file cannot quietly escape the check.
    mk = (REPO / "Makefile").read_text()
    m = re.search(r"^MODULES\s*=\s*((?:.*\\\n)*.*)$", mk, re.M)
    if not m:
        failures.append("footprint basis: cannot parse MODULES from the Makefile")
        print("  BASIS FAIL: MODULES unparsed")
        return
    modules = m.group(1).replace("\\\n", " ").split()
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        objs = []
        for mod in modules:
            src = REPO / "src" / f"{mod}.s"
            obj = td / f"{mod}.o"
            rc, out = sh(["ca65", "--cpu", "6502", "-I", "src", "-o", str(obj), str(src)])
            if rc:
                failures.append(f"footprint basis: {mod}.s does not assemble")
                print(f"  BASIS FAIL: {mod}.s\n{out[:200]}")
                return
            objs.append(str(obj))
        mp = td / "l.map"
        rc, out = sh(["ld65", "-o", str(td / "o.prg"), "-C", "src/c64.cfg",
                      "-m", str(mp), *objs])
        if rc or not mp.exists():
            failures.append("footprint basis: reference link failed")
            print(f"  BASIS FAIL: link error\n{out[:300]}")
            return
        sums = {}
        for o in objs:
            for n, sz in _SEG_RE.findall(sh(["od65", "--dump-segments", o])[1]):
                if int(sz):
                    sums[n] = sums.get(n, 0) + int(sz)
        mapping_lines = mp.read_text().splitlines()
        placed = {}
        for line in mapping_lines:
            m = re.match(r"(LIB_\S+)\s+[0-9A-F]{6}\s+[0-9A-F]{6}\s+([0-9A-F]{6})",
                         line.strip())
            if m:
                placed[m.group(1)] = int(m.group(2), 16)
    if not placed:
        failures.append("footprint basis: parsed no segments from the map -- "
                        "the check is vacuous, not passing")
        print("  BASIS FAIL: empty map parse")
        return

    # Second half: a bounded change detector on the inter-segment gaps. Those
    # gaps are NOT charged (issue #161) -- they are the consumer's to compute --
    # but their staying under one page per aligned footprint segment is the
    # observable form of "the only fill outside a segment is a single
    # page-alignment boundary". If that stops holding, the placement changed
    # shape and this leg's reasoning no longer describes the artifact, so it
    # fails rather than passing silently. Measured, not argued.
    starts = {}
    for line in mapping_lines:
        m = re.match(r"(LIB_\S+)\s+([0-9A-F]{6})\s+([0-9A-F]{6})\s+([0-9A-F]{6})",
                     line.strip())
        if m:
            starts[m.group(1)] = (int(m.group(2), 16), int(m.group(3), 16))
    real_fill = 0
    for seg in FOOTPRINT_ALIGNED & set(starts):
        if seg not in FOOTPRINT_SEGMENTS:
            continue
        st = starts[seg][0]
        prev_end = max((e for n, (b, e) in starts.items()
                        if e < st and n != seg), default=None)
        if prev_end is not None:
            real_fill += st - prev_end - 1
    bound = INTER_SEGMENT_FILL_BOUND * len(
        [x for x in FOOTPRINT_ALIGNED if x in FOOTPRINT_SEGMENTS and x in starts])
    if real_fill > bound:
        failures.append(
            f"footprint basis: inter-segment fill measures {real_fill} B, over "
            f"the {bound} B bound (one page per aligned footprint segment) -- "
            f"the placement is no longer one alignment boundary per segment, so "
            f"re-derive what the §5 measurand covers before trusting it")
        print(f"  BASIS FAIL: inter-segment fill {real_fill} > bound {bound}")
    else:
        # NOT a pass/fail result -- review finding F4. This number is reported,
        # not checked: nothing pins it and the comparison against `bound` cannot
        # redden (the gap is `(-previous_end) mod $100`, so it cannot exceed
        # 255 by construction). Printing it as "OK" made it read as a passing
        # check to anyone scanning output, which is the failure mode this file
        # exists to prevent. Pinning the value exactly was considered and
        # rejected: any code growth shifts segment offsets, so an exact pin
        # would redden on ordinary commits and be updated reflexively, which is
        # a worse kind of dishonest green. Read it as a value to eyeball across
        # commits, and see issue #159 for the coverage this leg genuinely lacks.
        print(f"  inter-segment fill (reported, not checked): {real_fill} B "
              f"-- consumer-side placement, not charged to the §5 measurand")
    bad = [(k, sums.get(k, 0), v) for k, v in sorted(placed.items())
           if sums.get(k, 0) != v]
    if bad:
        for k, a, b in bad:
            failures.append(
                f"footprint basis: {k} od65 sum {a} != placed {b} (+{b - a} of "
                f"WITHIN-segment fill). measured_code_rodata() is a sum of "
                f"member object sizes and §5's measurand is the placed span; "
                f"this identity is the only thing making them equal, so every "
                f"§5 figure is now low by that fill")
            print(f"  BASIS FAIL [{k}]: od65 {a} vs placed {b} (+{b - a})")
    else:
        print(f"  basis OK ({len(placed)} segments, od65 sums == placed sizes: "
              f"the sum-based §5 measurand equals the placed span)")


def sibling_sqtab_collision_check(failures):
    """§6.1 + §8.1: the MANDATORY boot call must not drag a bare sqtab name in.

    The sibling arm above probes one symbol family (`mul_dma_*`) reached through
    a §8.2 output equate. That left this repo's other §6.1 instance unguarded,
    and it was a live defect for the whole of issue #155: `mul_8x8.o` exported
    the displaceable bare `sqtab_lo`/`sqtab_hi` beside `sqtab_init`, and API.md
    step 2 makes `jsr sqtab_init` mandatory for any multiply. So EVERY
    conforming consumer pulled that member and both names, and any sibling
    library deriving the same two canonical names from the same
    LIB_SHARED_SQTAB_BASE collided -- with no consumer definition involved.

    The probe calls `sqtab_init`, deliberately. A probe calling only `fp_mul`
    passes today and proves nothing: in the default profile that link never
    builds the multiply table, so it is a configuration no consumer ships --
    the "fixture encodes the defect it should catch" shape. #155's first fix
    passed exactly that fixture while still colliding for every real consumer.

    Runs over EVERY built archive, not a sample: the same issue's first fix was
    green in the default profile and broken in all five onchip archives, which
    a three-archive sample would have missed.

    Second obligation, same leg (the drift the split introduced): `sqtab_lo`
    used to be one symbol serving as both the equate the body indexes and the
    name the archive exports. Since #155 they are two definitions that happen
    to agree -- `mul_8x8.s` derives its own from `sqtab_base.inc`, and
    `sqtab_aliases.s` derives and exports the exported pair. A `-D` cannot
    split them (CONTRACT_DEFINES reaches both TUs) but a source edit to one
    file silently can, and #154's "values are derived, never restated" is the
    standing warning. So every archive that exports the pair is link-resolved
    and compared against the base parsed out of src/sqtab_base.inc."""
    import tempfile
    print("\n=== §6.1 sibling bare-name collision + §8.1 value pin (sqtab_*) ===")

    inc = (REPO / "src" / "sqtab_base.inc").read_text()
    m = re.search(r"LIB_SHARED_SQTAB_BASE\s*=\s*\$([0-9a-fA-F]+)", inc)
    if not m:
        failures.append("sqtab collision: cannot parse the default base out of "
                        "src/sqtab_base.inc -- the value pin below would be "
                        "comparing against nothing")
        print("  SQTAB FAIL: base unparsed from sqtab_base.inc")
        return
    base = int(m.group(1), 16)

    sibling = ('; stand-in for a sibling §8.1 adopter deriving the same two names\n'
               '.export sqtab_lo, sqtab_hi\n'
               'sqtab_lo = $a000\n'
               'sqtab_hi = $a200\n')
    # The DOCUMENTED boot call (API.md step 2), not a bare field op.
    consumer = ('.import sqtab_init\n'
                '.segment "CODE"\n'
                'entry:\n\tjsr sqtab_init\n\trts\n')
    # Value pin: import the exported name and read what it resolves to.
    valprobe = ('.import sqtab_lo\n'
                '.segment "CODE"\n'
                'entry:\n\tlda sqtab_lo\n\trts\n')

    archives = sorted(LIBDIR.glob("*.a"))
    if not archives:
        failures.append("sqtab collision: no archives built -- leg is vacuous")
        print("  SQTAB FAIL: no archives found")
        return

    checked = pinned = 0
    for archive in archives:
        name = archive.name
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "cfg").write_text(CONSUMER_CFG)
            (td / "s.s").write_text(sibling)
            (td / "c.s").write_text(consumer)
            (td / "v.s").write_text(valprobe)
            bad = False
            for f in ("s", "c", "v"):
                rc, _ = sh(["ca65", "--cpu", "6502", "-o", str(td / f"{f}.o"),
                            str(td / f"{f}.s")])
                if rc:
                    failures.append(f"sqtab collision: probe {f}.s does not "
                                    f"assemble ({name})")
                    print(f"  SQTAB FAIL [{name}]: probe {f}.s assemble error")
                    bad = True
            if bad:
                continue

            _, out = sh(["ld65", "-C", str(td / "cfg"), "-o", str(td / "o.prg"),
                         str(td / "c.o"), str(td / "s.o"), str(archive)])
            if "Duplicate external identifier" in out:
                dup = sorted(set(re.findall(
                    r"Duplicate external identifier: '([^']+)'", out)))
                failures.append(
                    f"sqtab collision: {name} forces bare {dup} on a consumer "
                    f"performing the documented sqtab_init boot call "
                    f"(§6.1 member isolation)")
                print(f"  SQTAB FAIL [{name}]: duplicate {dup}")
                continue
            checked += 1

            # Value pin, on archives that export the pair at all. app-owned
            # gates the export out under SHARED_SQTAB_INIT, so an unresolved
            # external there is the CORRECT result, not a failure.
            mp = td / "v.map"
            _, vout = sh(["ld65", "-C", str(td / "cfg"), "-o", str(td / "v.prg"),
                          "-m", str(mp), str(td / "v.o"), str(archive)])
            if "Unresolved external" in vout or "unresolved external" in vout:
                print(f"  sqtab OK [{name}] (no collision; exports no bare "
                      "sqtab_lo, so nothing to pin)")
                continue
            if not mp.exists():
                failures.append(f"sqtab collision: {name} value probe produced "
                                "no map, so the pin below examined nothing")
                print(f"  SQTAB FAIL [{name}]: no map from the value probe")
                continue
            vm = re.search(r"^sqtab_lo\s+([0-9A-F]{6})", mp.read_text(), re.M)
            if not vm:
                failures.append(f"sqtab collision: {name} links sqtab_lo but it "
                                "is absent from the map -- pin is vacuous")
                print(f"  SQTAB FAIL [{name}]: sqtab_lo not in map")
                continue
            got = int(vm.group(1), 16)
            if got != base:
                failures.append(
                    f"sqtab collision: {name} exports sqtab_lo = ${got:04x} but "
                    f"src/sqtab_base.inc says ${base:04x} -- the alias TU and "
                    "mul_8x8.s have drifted (values are derived, never restated)")
                print(f"  SQTAB FAIL [{name}]: sqtab_lo ${got:04x} != base ${base:04x}")
                continue
            pinned += 1
            print(f"  sqtab OK [{name}] (boot call pulls no bare name; "
                  f"sqtab_lo = ${got:04x} matches sqtab_base.inc)")

    if checked == 0:
        failures.append("sqtab collision: no archive completed the probe -- "
                        "the leg passed without examining anything")
        print("  SQTAB FAIL: nothing examined")
    else:
        print(f"  sqtab summary: {checked} archive(s) collision-free, "
              f"{pinned} value-pinned against sqtab_base.inc")


def sibling_bare_collision_check(failures):
    """§6.1: importing a §8.2 output equate must not drag a bare `mul_` name in.

    `LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO`/`_HI` are output equates a consumer
    is told to import to verify that two co-linked §8.2 libraries agree on the
    landing page. They are NOT prefixed counterparts of anything displaceable --
    they are different names that happen to hold the same address -- so 1.2.1's
    carve-out does not cover them, and while they shared a TU with the bare
    `mul_dma_lo`/`_hi` aliases, importing one pulled the member and its bare
    names with it.

    Against c64-x25519, which exports `mul_dma_lo`, `mul_dma_hi` and
    `mul_dma_carry` from its own src/mul_stage.s, that is:

        ld65: Error: Duplicate external identifier: 'mul_dma_hi'

    Same failure class and symbol family as the c64-https v0.12.0 outage §6.1
    exists for. The aliases now live alone in src/mul_aliases.s.

    The probe stands in for that composed link: a consumer importing ONLY the
    §8.2 output equate, a sibling exporting the bare pair, and our archive.

    Negative-tested: putting the aliases back into src/data_mul_stage.s
    reproduces the duplicate-external on every archive below."""
    import tempfile
    print("\n=== §6.1 sibling bare-name collision (mul_dma_*) ===")
    sibling = ('; stand-in for c64-x25519 src/mul_stage.s\n'
               '.export mul_dma_lo, mul_dma_hi\n'
               '.segment "SIB"\n'
               'mul_dma_lo:\n\t.res 256, 0\n'
               'mul_dma_hi:\n\t.res 256, 0\n')
    consumer = ('.import LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO\n'
                '.segment "CODE"\n'
                'entry:\n'
                '\tlda #<LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO\n'
                '\trts\n')
    cfg = CONSUMER_CFG.replace(
        "SEGMENTS {",
        "SEGMENTS {\n    SIB: load = MAIN, type = rw, align = $100, optional = yes;")
    for name in ("nistcurves.a", "nistcurves-onchip.a", "nistcurves-p256-verify.a"):
        archive = LIBDIR / name
        if not archive.exists():
            failures.append(f"sibling collision: {name} not built")
            print(f"  SIBLING FAIL [{name}]: archive missing")
            continue
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "cfg").write_text(cfg)
            (td / "s.s").write_text(sibling)
            (td / "c.s").write_text(consumer)
            rc1, _ = sh(["ca65", "--cpu", "6502", "-o", str(td / "s.o"), str(td / "s.s")])
            rc2, _ = sh(["ca65", "--cpu", "6502", "-o", str(td / "c.o"), str(td / "c.s")])
            if rc1 or rc2:
                failures.append(f"sibling collision: probe does not assemble ({name})")
                print(f"  SIBLING FAIL [{name}]: probe assemble error")
                continue
            _, out = sh(["ld65", "-C", str(td / "cfg"), "-o", str(td / "o.prg"),
                         str(td / "c.o"), str(td / "s.o"), str(archive)])
        if "Duplicate external identifier" in out:
            dup = sorted(set(re.findall(
                r"Duplicate external identifier: '([^']+)'", out)))
            failures.append(
                f"sibling collision: {name} forces bare {dup} on a consumer that "
                f"imported only a §8.2 output equate (§6.1 member isolation)")
            print(f"  SIBLING FAIL [{name}]: duplicate {dup}")
        else:
            print(f"  sibling OK [{name}] (§8.2 output equate pulls no bare name)")


def od65_extraction_canary(failures):
    r"""Pin the assumption every other leg here rests on: that we see every name
    od65 prints.

    od65 emits the field as `printf("Name:%*s\"%s\"", 24 - Len, "", Name)`.
    The padding is therefore `|24 - Len|`, NOT a fixed column: it shrinks to
    zero at Len == 24 and grows again above it, because a negative `%*s` width
    left-justifies rather than truncating. Measured here across name lengths 4
    to 47, every one matching `|24 - Len|`.

    At Len == 24 exactly, the padding is zero and the line is emitted as
    `Name:"LIB_NISTCURVES_P256_CODE"` with no space at all. Anything that
    splits on whitespace -- `awk '/Name:/{print $2}'`, or a regex with
    `Name:\s+"` -- then yields an empty field and drops the symbol SILENTLY.

    The mechanism matters because a fixed-column model licenses two false
    inferences. It suggests the quote sits at a stable offset, so a `cut -c` or
    column-based extraction would be safe -- it is not, the quote column moves
    with every name. And it suggests LONG names are the hazard, so one checks
    the 47-character prefixed names and misses the 24-character bare ones,
    which are the only ones that actually break.

    This is not hypothetical here and it is not harmless. Seven names in this
    tree are exactly 24 characters, and they are precisely the ones the two
    load-bearing legs read:

        LIB_NISTCURVES_MAIN_CODE   segments -> the footprint measurement
        LIB_NISTCURVES_P256_CODE   segments -> the footprint measurement
        LIB_NISTCURVES_P384_CODE   segments -> the footprint measurement
        LIB_PRECALC_reu_mul_SIZE   exports  -> the gated-surface count
        LIB_PRECALC_sqtab_REGION   exports  -> the gated-surface count
        LIB_PRECALC_sqtab_SHARED   exports  -> the gated-surface count
        bench_fp_mod_mul_n_tramp   exports  -> no leg (main.o, never archived)

    Both failures would be in the passing direction. Dropping the three code
    segments understates `measured`, so the footprint leg would certify figures
    that are too low -- the exact unsafe direction §5 exists to prevent, in the
    check written to prevent it. Dropping the three bare names would let a leg
    whose pass condition is "zero bare names" report success on an object
    exporting three, with the prefixed counterparts still visible so the dump
    looks plausible.

    Our extractors use `\s*` (zero-or-more) and are verified immune. This leg
    exercises the ones that feed a comparison -- od65_names, _SEG_RE,
    od65_value, od65_export_names and od65_zp_exports. It does NOT prove every
    reader in the file, and it asserts only that no-space names ARE extracted:
    an extractor dropping every SPACED name would pass it. Stated rather than
    papered over. It works by: it finds the no-space names by substring,
    which cannot tokenise and so cannot be fooled, and asserts our real
    extractors return each one.

    Reported by c64-ChaCha20-Poly1305 via the contract session as needing
    40-plus-character names, which is why they could not reproduce it -- a
    47-character name is fine, only 24 is not."""
    import glob
    print("\n=== od65 extraction canary (name length 24 emits no space) ===")
    seen = 0
    dropped_any = False
    for obj in sorted(glob.glob(str(BUILD / "*.o"))):
        objp = Path(obj)
        for mode in ("--dump-exports", "--dump-imports"):
            raw = sh(["od65", mode, obj])[1]
            # Substring, never tokenised: immune to the padding by construction.
            nospace = set(re.findall(r'Name:"([^"]+)"', raw))
            if not nospace:
                continue
            seen += len(nospace)
            got = od65_names(objp, mode)
            missed = sorted(nospace - got)
            if missed:
                dropped_any = True
                failures.append(f"od65 canary: {objp.name} {mode} -- extractor "
                                f"drops no-space name(s) {missed}")
                print(f"  CANARY FAIL [{objp.name} {mode}]: dropped {missed}")
        raw = sh(["od65", "--dump-segments", obj])[1]
        nospace = set(re.findall(r'Name:"([^"]+)"', raw))
        if nospace:
            seen += len(nospace)
            got = {n for n, _ in _SEG_RE.findall(raw)}
            missed = sorted(nospace - got)
            if missed:
                dropped_any = True
                failures.append(f"od65 canary: {objp.name} --dump-segments -- "
                                f"_SEG_RE drops no-space name(s) {missed}")
                print(f"  CANARY FAIL [{objp.name} segments]: dropped {missed}")
    # Every OTHER extraction path, exercised against the same known-hard input.
    # Reading a regex and concluding it is safe is the standard this file has
    # been bitten by; a comparison check in particular does not fail loudly when
    # its extractor breaks SYMMETRICALLY -- it agrees, wrongly, and in a ratchet
    # it then bakes the omission into the recorded baseline. So every helper
    # that feeds a comparison is called for real on a 24-character name.
    probe_obj = BUILD / "precalc_manifest.o"
    if probe_obj.exists():
        HARD = "LIB_PRECALC_sqtab_REGION"          # exactly 24 characters
        assert len(HARD) == 24, "probe symbol is no longer the hard case"
        if od65_value([probe_obj], HARD) is None:
            failures.append("od65 canary: od65_value() cannot read the "
                            f"24-character {HARD} -- every §5 value pin and the "
                            "manifest comparison runs through it")
            print(f"  CANARY FAIL [od65_value]: {HARD} unreadable")
        else:
            print(f"  canary OK [od65_value] ({HARD})")
        zpo = BUILD / "zp_config.o"
        zp = od65_zp_exports(zpo) if zpo.exists() else None
        if zp is None:
            failures.append("od65 canary: od65_zp_exports() could not read "
                            "zp_config.o, so the ZP audits' reader is unexercised")
            print("  CANARY FAIL [od65_zp_exports]: unreadable")
        else:
            print(f"  canary OK [od65_zp_exports] ({len(zp)} slots read)")
        exp = od65_export_names(probe_obj)
        if exp is None or HARD not in exp:
            failures.append("od65 canary: od65_export_names() drops the "
                            f"24-character {HARD} -- the gated-surface and "
                            "zp-alias audits run through it")
            print(f"  CANARY FAIL [od65_export_names]: {HARD} missing")
        else:
            print(f"  canary OK [od65_export_names] ({HARD})")
    else:
        failures.append("od65 canary: build/precalc_manifest.o absent, so the "
                        "helper probes did not run")
        print("  CANARY FAIL: probe object missing, helper paths unexercised")

    if seen == 0:
        # Not a pass. If nothing in the tree is 24 characters long any more, the
        # canary is no longer testing anything and should be told so rather
        # than printing green -- that is the vacuous-evidence failure this file
        # has been bitten by twice.
        failures.append("od65 canary: no no-space names found at all -- the "
                        "canary is now vacuous; re-check whether od65's padding "
                        "changed before trusting any other leg's extraction")
        print("  CANARY FAIL: nothing to test -- leg has gone vacuous")
    elif not dropped_any:
        print(f"  canary OK ({seen} no-space name occurrences, all extracted)")


def app_owned_buffer_ownership_check(failures):
    """Issue #149: resolving the §8.2 settle state must not drag an APP_OWNED
    buffer definition into the link.

    ld65 pulls whole archive members. Through v0.12.0 the §8.2 DMA-completion
    state (nistcurves_reu_wait_cnt / _dma_timeout) shared a translation unit
    with the multiply-row landing buffers (nistcurves_mul_dma_lo / _hi), which
    a consumer taking the §8.0/§8.3 APP_OWNED route defines itself. Any
    reference to the settle state therefore pulled data_shared.o in and ld65
    refused the link:

        ld65: Error: Duplicate external identifier: 'nistcurves_mul_dma_hi'

    c64-https hit this on all three of its shipped configurations and could not
    take v0.12.0 at all. The failure is invisible to this library's own build:
    nothing here defines those buffers twice.

    The probe stands in for that consumer -- an object that defines and exports
    the two buffers and references the settle state -- and asserts the link
    still succeeds.

    Negative-tested at introduction: reverting the src/data_reu_wait.s split
    makes every archive below report Duplicate external identifier."""
    import tempfile
    print("\n=== §8.0 APP_OWNED buffer ownership (issue #149) ===")
    # The probe must do what a real APP_OWNED consumer does: own the buffers
    # AND call a field operation. An earlier version referenced only the §8.2
    # settle state, which made it blind to the defect it exists to catch --
    # the operand cache (nistcurves_mul_cached_a / _src2_buf) stayed in the
    # buffers' TU, and fp256.o / fp384.o / mul_8x8.o import it, so any consumer
    # calling fp_mul still pulled the member and still collided. A probe that
    # links nothing proves nothing.
    consumer = (
        '; Stands in for a consumer that owns the multiply-row buffers itself\n'
        '; and also calls into the library, which is the only shape that has a\n'
        '; reason to exist.\n'
        '.export nistcurves_mul_dma_lo, nistcurves_mul_dma_hi\n'
        '.import nistcurves_reu_dma_timeout, nistcurves_reu_wait_cnt\n'
        '.import fp_mul\n'
        '.segment "CODE"\n'
        'entry:\n'
        '\tlda nistcurves_reu_dma_timeout\n'
        '\tlda nistcurves_reu_wait_cnt\n'
        '\tjsr fp_mul\n'
        '\trts\n'
        '.segment "APP_TABLES"\n'
        'nistcurves_mul_dma_lo:\n\t.res 256, 0\n'
        'nistcurves_mul_dma_hi:\n\t.res 256, 0\n'
    )
    cfg = CONSUMER_CFG.replace(
        "SEGMENTS {",
        "SEGMENTS {\n    APP_TABLES:                     load = MAIN, type = rw,  align = $100, optional = yes;",
    )
    for name in ("nistcurves-app-owned.a", "nistcurves-p256-verify-onchip.a",
                 "nistcurves-p256-comb-onchip.a"):
        archive = Path("build/lib") / name
        if not archive.exists():
            failures.append(f"app-owned buffers: {name} not built")
            print(f"  OWNERSHIP FAIL [{name}]: archive missing")
            continue
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "cfg").write_text(cfg)
            (td / "c.s").write_text(consumer)
            rc, out = sh(["ca65", "--cpu", "6502", "-o", str(td / "c.o"),
                          str(td / "c.s")])
            if rc:
                failures.append(f"app-owned buffers: probe does not assemble ({name})")
                print(f"  OWNERSHIP FAIL [{name}]: probe assemble error")
                continue
            rc, out = sh(["ld65", "-C", str(td / "cfg"), "-o", str(td / "o.prg"),
                          str(td / "c.o"), str(archive)])
        if "Duplicate external identifier" in out:
            dup = sorted(set(re.findall(
                r"Duplicate external identifier: '([^']+)'", out)))
            failures.append(
                f"app-owned buffers: {name} forces its own definition of {dup} "
                f"on a consumer that owns them (issue #149)")
            print(f"  OWNERSHIP FAIL [{name}]: duplicate {dup}")
            continue
        # Unresolved externals are expected and fine here: the probe links only
        # the members ld65 pulls, and the documented APP_OWNED gaps stay open.
        print(f"  ownership OK [{name}] (settle state resolves without "
              f"duplicating the APP_OWNED buffers)")


def defines_staleness_check(failures):
    """Knob-staleness guard. §6.3 was RETIRED at contract 1.0.0; what survives
    is §6.2's define-scoping rule, and the artifact-flipped property below is
    now ours to keep rather than something the contract asks for.

    §6.3 looks-reachable rule, staleness shape (SPEC v0.10.5): a make
    re-invocation with a changed CONTRACT_*DEFINES value must rebuild --
    without the Makefile's knob stamp, make reuses every stale object and
    exits 0 with an artifact other than the one requested (shape-3 silent
    no-op, measured live during the issue #123 repro). Drives the REAL make
    flow six ways -- three per knob, CONTRACT_DEFINES then
    CONTRACT_ZP_DEFINES -- and reads the built object's exported surface each
    time, which is SPEC v0.11.1's "assert the artifact flipped, not that
    something rebuilt". Runs LAST: a knob change wipes build/*.o by design;
    the final leg restores the default configuration."""
    print("\n=== knob-staleness guard (defines change must rebuild; was §6.3) ===")

    # --- Linked-artifact leg (issue #144) ------------------------------------
    # Every other leg in this function reads a built OBJECT's exported surface.
    # Objects are the artifact for `make lib-*`, but for the PRG the link is a
    # separate step, and it was being SKIPPED: the stamp deleted build/*.o but
    # not build/*.prg, objects reassembled in well under a second, and GNU make
    # 3.81 compares mtimes at whole-second granularity -- so make judged the
    # existing PRG up to date and ld65 never ran. Measured before the fix:
    # three consecutive knob values, one link, one PRG hash, exit 0 each time.
    #
    # That is the SPEC v0.11.1 §6.3 property this guard exists to provide
    # ("assert the artifact FLIPPED, not that something rebuilt") failing in
    # the half of the pipeline no leg inspected. The two knobs the other legs
    # drive (CONTRACT_ZP_DEFINES, the sqtab base) cannot exhibit it: for both,
    # the object IS the evidence. So this leg deliberately picks a knob whose
    # failure path is longest -- downstream of the link.
    #
    # Negative-tested by reverting the Makefile fix (dropping *.prg from the
    # stamp's rm list): this leg goes red on the second build while every
    # object-level leg above stays green.
    def prg_sha():
        prg = BUILD / "nist-curves.prg"
        if not prg.exists():
            return None
        return hashlib.sha256(prg.read_bytes()).hexdigest()

    art_legs = [
        (["make", "-C", str(REPO)], "default"),
        (["make", "-C", str(REPO),
          "CONTRACT_DEFINES=-D LIB_NISTCURVES_REU_SETTLE_ITER=4"], "ITER=4"),
        (["make", "-C", str(REPO)], "revert to default"),
    ]
    art_hashes = []
    for cmd, label in art_legs:
        rc, _ = sh(cmd)
        h = prg_sha()
        art_hashes.append(h)
        if rc or h is None:
            failures.append(
                f"knob-staleness(artifact): {label}: build failed (rc={rc})")
            print(f"  ARTIFACT FAIL [{label}]: rc={rc}")
    if len(art_hashes) == 3 and all(art_hashes):
        if art_hashes[0] == art_hashes[1]:
            failures.append(
                "knob-staleness(artifact): a changed knob left the LINKED PRG "
                f"identical ({art_hashes[0][:16]}...) -- the link was skipped, "
                "so the build carries the previous knob's artifact (issue #144)")
            print("  ARTIFACT FAIL: changed knob did not flip the PRG "
                  f"({art_hashes[0][:16]}...)")
        elif art_hashes[0] != art_hashes[2]:
            failures.append(
                "knob-staleness(artifact): reverting the knob did not restore "
                f"the default PRG ({art_hashes[2][:16]}... != "
                f"{art_hashes[0][:16]}...)")
            print("  ARTIFACT FAIL: revert did not restore the default PRG")
        else:
            print(f"  artifact leg OK (PRG flips {art_hashes[0][:12]}... -> "
                  f"{art_hashes[1][:12]}... -> back)")


    def fp_src1_value():
        return od65_value([BUILD / "zp_config.o"], "fp_src1")

    # SPEC v0.11.1 states the two properties an invalidation guard must have:
    # unchanged knobs must not rebuild (the mtime leg at the bottom), and the
    # check must assert the ARTIFACT FLIPPED rather than that something
    # rebuilt -- a check with only change-rebuilds legs passes on a guard that
    # has degraded to an unconditional rebuild. Every leg here reads the built
    # object's exported surface, so both properties are covered.
    #
    # CONTRACT_DEFINES leg first: the stamp flattens BOTH knobs
    # (Makefile CURRENT_KNOBS), and through v0.11.2 this check exercised only
    # the ZP half -- so a regression dropping $(CONTRACT_DEFINES) from the
    # stamp passed. Negative-tested by making exactly that edit: with only the
    # ZP legs the check still reported OK; with this leg it fails on the
    # unchanged bare-export surface. Runs before the ZP legs because a knob
    # change wipes build/*.o, and the ZP legs' final default-build leg is what
    # leaves zp_config.o current for the incrementality assertion.
    def bare_version_exported():
        return "LIB_VERSION_MAJOR" in od65_names(BUILD / "lib_version.o",
                                                 "--dump-exports")

    defines_legs = [
        (["make", "-C", str(REPO), "build/lib_version.o"], True,
         "default build (bare §1 aliases exported)"),
        (["make", "-C", str(REPO), "build/lib_version.o",
          "CONTRACT_DEFINES=-D LIB_NO_BARE_EXPORTS=1"], False,
         "changed CONTRACT_DEFINES must take effect (stale reuse would keep the bare exports)"),
        (["make", "-C", str(REPO), "build/lib_version.o"], True,
         "revert to default"),
    ]
    for cmd, want, label in defines_legs:
        rc, out = sh(cmd)
        got = bare_version_exported()
        if rc or got != want:
            failures.append(
                f"knob-staleness: {label}: bare LIB_VERSION_MAJOR "
                f"{'exported' if got else 'absent'}, want "
                f"{'exported' if want else 'absent'} (rc={rc})")
            print(f"  STALENESS FAIL [{label}]: bare LIB_VERSION_MAJOR "
                  f"{'exported' if got else 'absent'}, expected "
                  f"{'exported' if want else 'absent'}")
            return

    legs = [
        (["make", "-C", str(REPO), "build/zp_config.o"], 0x22, "default build"),
        (["make", "-C", str(REPO), "build/zp_config.o",
          "CONTRACT_ZP_DEFINES=-D fp_src1=0x50"],
         0x50, "changed knob must take effect (stale-reuse would keep 0x22)"),
        (["make", "-C", str(REPO), "build/zp_config.o"], 0x22, "revert to default"),
    ]
    for cmd, want, label in legs:
        rc, out = sh(cmd)
        got = fp_src1_value()
        if rc or got != want:
            failures.append(f"knob-staleness: {label}: fp_src1={got if got is not None else '?'}, want {hex(want)} (rc={rc})")
            print(f"  STALENESS FAIL [{label}]: fp_src1 = {hex(got) if got is not None else '?'}, expected {hex(want)}")
            return
    # incremental sanity: an unchanged-knob re-run must NOT rebuild
    before = (BUILD / "zp_config.o").stat().st_mtime_ns
    sh(["make", "-C", str(REPO), "build/zp_config.o"])
    after = (BUILD / "zp_config.o").stat().st_mtime_ns
    if before != after:
        failures.append("knob-staleness: unchanged knobs re-ran the assembler (stamp churns)")
        print("  STALENESS FAIL: unchanged knobs rebuilt the object -- stamp not stable")
        return
    print("  staleness guard OK (both knobs flip the artifact; revert restores; "
          "no-change is incremental)")

    # --- §6.2 CONTRACT_ZP_DEFINES scoping across the #154 TU split -----------
    # zp_config.s DEFINES the slots and takes the ZP overrides; zp_aliases.s
    # IMPORTS them and must not (`-D` of an imported name is a hard ca65
    # error). That asymmetry is only safe if the alias still MOVES with the
    # slot -- if it did not, an overriding consumer would get an archive whose
    # members disagree about an address, which links cleanly and corrupts at
    # runtime. Nothing else in this file drives a real ZP override through the
    # Makefile's per-recipe flag wiring and out the other side of a link, so
    # this leg is what proves the wiring rather than the source intent.
    # Drive EVERY arm, not just the default pair. The first version of this leg
    # built only build/zp_config.o and build/zp_aliases.o, so ten of the twelve
    # recipes were never given an override -- and two real mis-wirings stayed
    # green: adding CONTRACT_ZP_DEFINES to a zp_aliases_* recipe (which makes
    # the documented override fail to assemble, since that TU .importzp's the
    # slot) and removing it from a zp_config_* recipe (which ships an archive
    # whose members disagree about an address, links cleanly, fails at runtime
    # -- §6.2's named silent failure). A leg that proves 2 of 12 recipes is
    # evidence about 2 of 12 recipes.
    print("\n=== §6.2 ZP override reaches slot AND alias together (issue #154) ===")
    for arm, (alias_obj, bare) in sorted(ZP_ALIAS_ARMS.items()):
        if "zp_ptr2" not in bare:
            print(f"  override SKIP [{arm}]: arm exports no bare zp_ptr2")
            continue
        _zp_override_probe(failures, arm, alias_obj)
    print("  (each arm driven with a real -D through make, both spellings read "
          "from an ld65 map)")


def _zp_override_probe(failures, arm, alias_obj):
    import tempfile
    for knob, want in ((["CONTRACT_ZP_DEFINES=-D nistcurves_zp_ptr2=0x60"], 0x60),
                       ([], 0xfd)):
        rc, out = sh(["make", "-C", str(REPO), f"build/{arm}.o",
                      f"build/{alias_obj}.o", *knob])
        if rc:
            failures.append(f"zp-override {arm}: build failed with {knob or ['(default)']}")
            print(f"  OVERRIDE FAIL [{arm}]: make failed for {knob or ['(default)']}:\n{out}")
            return
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "cfg").write_text(CONSUMER_CFG)
            (td / "p.s").write_text(
                ".importzp zp_ptr2\n.importzp nistcurves_zp_ptr2\n"
                '.segment "CODE"\nentry:\n\tlda zp_ptr2\n'
                "\tlda nistcurves_zp_ptr2\n\trts\n")
            rc, out = sh(["ca65", "--cpu", "6502", "-o", str(td / "p.o"),
                          str(td / "p.s")])
            if rc:
                failures.append("zp-override: probe will not assemble")
                print(f"  OVERRIDE FAIL: probe will not assemble:\n{out}")
                return
            rc, out = sh(["ld65", "-C", str(td / "cfg"), "-Ln", str(td / "lbl"),
                          "-o", str(td / "o.prg"), str(td / "p.o"),
                          str(BUILD / f"{arm}.o"), str(BUILD / f"{alias_obj}.o")])
            if rc:
                failures.append(f"zp-override: link failed at {hex(want)}")
                print(f"  OVERRIDE FAIL: link failed:\n{out}")
                return
            lbl = {s: int(a, 16) for a, s in re.findall(
                r"^al\s+([0-9A-Fa-f]+)\s+\.(\S+)",
                (td / "lbl").read_text(), re.M)}
        got = (lbl.get("nistcurves_zp_ptr2"), lbl.get("zp_ptr2"))
        if got != (want, want):
            failures.append(
                f"zp-override {arm} {knob or 'default'}: nistcurves_zp_ptr2="
                f"{got[0]!r}, zp_ptr2={got[1]!r}, want both {hex(want)}")
            print(f"  OVERRIDE FAIL: canonical={got[0]!r} alias={got[1]!r}, "
                  f"want both {hex(want)} -- the two spellings have drifted; "
                  "check CONTRACT_ZP_DEFINES reaches zp_config.o (and NOT "
                  "zp_aliases.o)")
            return
        label = knob[0].split("=", 1)[1] if knob else "default"
        print(f"  override OK [{arm}/{label}]: nistcurves_zp_ptr2 and zp_ptr2 "
              f"both link at ${want:02x}")


def main():
    archives = parse_makefile_archives()
    failures = []

    # (c) src/c64.cfg placement invariant -- see cfg_bss_before_emitting.
    m, offenders = cfg_bss_before_emitting()
    print("\n=== src/c64.cfg placement ===")
    if m is None:
        failures.append("c64.cfg: could not parse SEGMENTS block")
        print("  PARSE FAIL: SEGMENTS block not found")
    elif offenders:
        for bss, after in offenders:
            failures.append(f"c64.cfg: {bss} is type=bss ahead of file-emitting {after}")
            print(f"  CFG FAIL: {bss} is `type = bss` and precedes {after}, which emits bytes")
            print("            -> image ends up shorter than its span; everything after loads low")
    else:
        print("  placement OK (no bss segment precedes a file-emitting one)")

    version_identity_check(failures)
    zp_alias_audit(failures)
    zp_alias_link_identity(failures)
    gated_surface_check(failures, archives)
    app_owned_reachability_check(failures)
    packaging_check(failures, archives)
    gated_link_check(failures, archives)

    for name in sorted(KNOWN_EXTERNAL):
        allow = KNOWN_EXTERNAL[name]
        archive_path = LIBDIR / name
        print(f"=== {name} ===")
        if name not in archives:
            failures.append(f"{name}: not found in Makefile ar65 recipes")
            print("  MAKEFILE: no ar65 recipe parsed for this archive")
            continue
        if not archive_path.exists():
            failures.append(f"{name}: archive not built ({archive_path})")
            print(f"  MISSING: {archive_path} -- run `make {name.replace('.a','').replace('nistcurves','lib').replace('lib-','lib-')}` first")
            continue

        # (a) closure sweep over the object set.
        mods = archives[name]
        imports, exports = set(), set()
        for mod in mods:
            o = BUILD / (mod + ".o")
            imports |= od65_names(o, "--dump-imports")
            exports |= od65_names(o, "--dump-exports")
        unresolved = imports - exports
        unexpected = sorted(unresolved - allow)
        stale = sorted(allow - unresolved)
        if unexpected:
            failures.append(f"{name}: unexpected unresolved externals {unexpected}")
            print(f"  CLOSURE FAIL: new unresolved (not on allowlist): {unexpected}")
        if stale:
            failures.append(f"{name}: allowlisted externals now resolved {stale} -- shrink allowlist + update docs")
            print(f"  CLOSURE FAIL: allowlist entries now resolved: {stale}")
        if not unexpected and not stale:
            gap = sorted(allow) if allow else "(none)"
            print(f"  closure OK: documented gaps = {gap}")

        # (a2) SPEC §8.2 provider presence/absence pins (issue #81).
        missing = sorted(MUST_EXPORT.get(name, set()) - exports)
        leaked = sorted(MUST_NOT_EXPORT.get(name, set()) & exports)
        if missing:
            failures.append(f"{name}: required exports missing {missing}")
            print(f"  EXPORT FAIL: required symbols not exported: {missing}")
        if leaked:
            failures.append(f"{name}: forbidden exports present {leaked}")
            print(f"  EXPORT FAIL: symbols must not ship in this archive: {leaked}")
        if not missing and not leaked:
            print("  provider pins OK (reu_mul_init presence/absence matches contract)")

        # (a3) manifest VALUE pins. Symbol presence alone cannot catch a
        # regression that ships the right equate carrying the wrong number --
        # exactly how issue #88 slipped in, where the sha384 archive exported
        # a well-formed manifest describing a different library.
        obj_paths = [BUILD / (m + ".o") for m in mods]
        for sym, want in sorted(MANIFEST_VALUES.get(name, {}).items()):
            got = od65_value(obj_paths, sym)
            if got is None:
                failures.append(f"{name}: manifest equate {sym} not found")
                print(f"  VALUE FAIL: {sym} not exported")
            elif got != want:
                failures.append(f"{name}: {sym} = {got}, contract says {want}")
                print(f"  VALUE FAIL: {sym} = {got}, expected {want}")
        if MANIFEST_VALUES.get(name):
            print("  manifest value pins OK (§5 equates match the pinned table)")

        # (a4) §5 footprint MEASUREMENT (issue #142). The pins above compare
        # the manifest against MANIFEST_VALUES -- a hard-coded copy of the same
        # numbers in this file. Both sides are the table, so the leg reports
        # agreement while checking nothing about the archive, and a figure that
        # has drifted from the bytes it describes passes. That is the shape
        # that left 43 of 45 §5 values wrong before issue #90, sitting inside
        # the gate that exists to prevent a recurrence.
        #
        # This measures instead, and checks the one property §5 states
        # normatively: "Footprint equates MUST be safe-direction: round up,
        # never down", with RESIDENT and COLD a pair a consumer budgets
        # together. So the invariant is
        #
        #     RESIDENT_BYTES + COLD_BYTES  >=  measured code+rodata
        #
        # An understating figure makes a consumer's §5 fit check pass while the
        # library overruns their region, which is the direction that corrupts.
        measured, unknown = measured_code_rodata(mods)
        if unknown:
            # A new segment must not silently escape the accounting: whoever
            # adds one decides whether it is footprint, here, on purpose.
            failures.append(f"{name}: unclassified segment(s) {sorted(unknown)} "
                            f"-- add them to FOOTPRINT_SEGMENTS or the exclusions")
            print(f"  FOOTPRINT FAIL: unclassified segment(s) {sorted(unknown)}")
        else:
            declared = 0
            have_both = True
            for sym in ("LIB_NISTCURVES_RESIDENT_BYTES", "LIB_NISTCURVES_COLD_BYTES"):
                v = od65_value(obj_paths, sym)
                if v is None:
                    have_both = False
                else:
                    declared += v
            if not have_both:
                failures.append(f"{name}: §5 footprint equates missing")
                print("  FOOTPRINT FAIL: RESIDENT/COLD not both exported")
            resident = od65_value(obj_paths, "LIB_NISTCURVES_RESIDENT_BYTES")
            cold = od65_value(obj_paths, "LIB_NISTCURVES_COLD_BYTES")
            if resident is not None and cold is not None and resident < measured - cold:
                # RESIDENT alone is what a consumer sizing a resident-only
                # region binds to; pinning only the sum leaves it unchecked.
                failures.append(
                    f"{name}: §5 RESIDENT_BYTES understates -- {resident} declared, "
                    f"but measured {measured} minus COLD {cold} needs {measured - cold}")
                print(f"  FOOTPRINT FAIL: RESIDENT {resident} < measured-minus-COLD {measured - cold}")
            elif declared < measured:
                failures.append(
                    f"{name}: §5 footprint understates -- RESIDENT+COLD = {declared} "
                    f"but the archive's code+rodata measures {measured} "
                    f"(short by {measured - declared}; §5 requires safe-direction)")
                print(f"  FOOTPRINT FAIL: declared {declared} < measured {measured}")
            else:
                slack = declared - measured
                pct = (slack / measured * 100) if measured else 0.0
                print(f"  footprint OK (RESIDENT+COLD {declared} >= measured "
                      f"{measured}, +{slack} B / {pct:.1f}%)")

        # (b) dummy-link smoke tests.
        for label, imps, expect_link in SMOKE.get(name, []):
            ok, unres, raw = link_test(archive_path, imps)
            if expect_link:
                if ok:
                    print(f"  link OK   [{label}]")
                else:
                    failures.append(f"{name}: '{label}' should link but failed: {sorted(unres)}")
                    print(f"  LINK FAIL [{label}] expected clean, got unresolved {sorted(unres)}")
            else:
                if ok:
                    failures.append(f"{name}: '{label}' should FAIL to link (documented gap) but linked clean -- update docs")
                    print(f"  LINK FAIL [{label}] expected documented-broken, but it linked")
                elif not unres:
                    failures.append(f"{name}: '{label}' failed for a non-symbol reason:\n{raw}")
                    print(f"  LINK FAIL [{label}] failed but not on unresolved symbols")
                elif not unres <= allow:
                    extra = sorted(unres - allow)
                    failures.append(f"{name}: '{label}' unresolved beyond allowlist: {extra}")
                    print(f"  LINK FAIL [{label}] unresolved beyond allowlist: {extra}")
                else:
                    print(f"  link gap OK [{label}] unresolved (documented): {sorted(unres)}")
        print()

    # Runs last by design: its knob-change legs wipe build/*.o via the
    # Makefile stamp, and the final default-build leg restores only the
    # object it exercises.
    gate_tus_derivation_check(failures)
    zp_roster_reconciliation_check(failures)
    footprint_basis_check(failures)
    sibling_bare_collision_check(failures)
    sibling_sqtab_collision_check(failures)
    od65_extraction_canary(failures)
    app_owned_buffer_ownership_check(failures)
    defines_staleness_check(failures)

    if failures:
        print("ARCHIVE CONTRACT RATCHET: FAIL")
        for f in failures:
            print("  - " + f)
        return 1
    print("ARCHIVE CONTRACT RATCHET: PASS -- reality matches API.md §8.4.1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
