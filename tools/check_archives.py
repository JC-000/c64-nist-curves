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
    "nistcurves-onchip.a": set(),
    "nistcurves-p256-verify-onchip.a": set(),
    "nistcurves-p384-verify-onchip.a": set(),
    "nistcurves-p384-curve-onchip.a": set(),
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
PRECALC_COMB_SYMS = _precalc_syms("lim_lee_comb_p256", "lim_lee_comb_p384")
PRECALC_SHA384_K_SYMS = _precalc_syms("sha384_k")

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
    "ec_scalar_ptr", "zp_ptr2",
}
# Used only by points256_comb.o / points384_comb.o (zp_ptr1 for the anchor
# copy in ec_precompute_*, zp_tmp1/zp_tmp2 in sm384w_calc_reu_offset), so
# these ship in the two full archives and nowhere else.
ZP_COMB_SYMS = {"zp_tmp1", "zp_tmp2", "zp_ptr1"}
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
        "LIB_NISTCURVES_RESIDENT_BYTES": 9000,
        "LIB_NISTCURVES_COLD_BYTES": 0,
    },
    "nistcurves.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 27,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x07,
        "LIB_NISTCURVES_RESIDENT_BYTES": 27000,
        "LIB_NISTCURVES_COLD_BYTES": 1840,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 27,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x04,
        "LIB_NISTCURVES_RESIDENT_BYTES": 27000,
        "LIB_NISTCURVES_COLD_BYTES": 1650,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p256-verify.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x03,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8700,
        "LIB_NISTCURVES_COLD_BYTES": 430,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p256-verify-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8700,
        "LIB_NISTCURVES_COLD_BYTES": 240,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p384-verify.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x03,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8300,
        "LIB_NISTCURVES_COLD_BYTES": 430,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p384-verify-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 15,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_RESIDENT_BYTES": 8300,
        "LIB_NISTCURVES_COLD_BYTES": 240,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p384-curve.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 23,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x03,
        "LIB_NISTCURVES_RESIDENT_BYTES": 17400,
        "LIB_NISTCURVES_COLD_BYTES": 430,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-p384-curve-onchip.a": {
        "LIB_NISTCURVES_ZP_USAGE_BYTES": 23,
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_RESIDENT_BYTES": 17400,
        "LIB_NISTCURVES_COLD_BYTES": 240,
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
                     | PRECALC_FULL | PRECALC_REU_MUL_SYMS | ZP_DEFAULT_SYMS),
    "nistcurves-p256-verify.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                                 | PRECALC_VERIFY | PRECALC_REU_MUL_SYMS
                                 | ZP_VERIFY_SYMS),
    "nistcurves-p384-verify.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                                 | PRECALC_VERIFY | PRECALC_REU_MUL_SYMS
                                 | ZP_VERIFY_SYMS),
    "nistcurves-p384-curve.a": (REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS
                                | PRECALC_CURVE | PRECALC_REU_MUL_SYMS
                                | ZP_VERIFY_SYMS | ZP_SHA384_SYMS),
    "nistcurves-p384-sha384.a": MANIFEST_SYMS | PRECALC_SHA384_K_SYMS | ZP_SHA384_SYMS,
    "nistcurves-onchip.a": MANIFEST_SYMS | PRECALC_FULL | ZP_DEFAULT_SYMS,
    "nistcurves-p256-verify-onchip.a": MANIFEST_SYMS | PRECALC_VERIFY | ZP_VERIFY_SYMS,
    "nistcurves-p384-verify-onchip.a": MANIFEST_SYMS | PRECALC_VERIFY | ZP_VERIFY_SYMS,
    "nistcurves-p384-curve-onchip.a": (MANIFEST_SYMS | PRECALC_CURVE
                                       | ZP_VERIFY_SYMS | ZP_SHA384_SYMS),
}
MUST_NOT_EXPORT = {
    "nistcurves.a": set() | TESTVEC_SYMS,
    "nistcurves-p256-verify.a": (PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                 | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS),
    "nistcurves-p384-verify.a": (PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                 | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS),
    "nistcurves-p384-curve.a": PRECALC_COMB_SYMS | ZP_COMB_SYMS | TESTVEC_SYMS,
    "nistcurves-p384-sha384.a": REU_MUL_PROVIDER_SYMS | PRECALC_NON_SHA_SYMS | ZP_NON_SHA_SYMS | TESTVEC_SYMS,
    "nistcurves-onchip.a": REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS | TESTVEC_SYMS,
    "nistcurves-p256-verify-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                        | PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                        | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS),
    "nistcurves-p384-verify-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                        | PRECALC_COMB_SYMS | PRECALC_SHA384_K_SYMS
                                        | ZP_COMB_SYMS | ZP_SHA384_SYMS | TESTVEC_SYMS),
    "nistcurves-p384-curve-onchip.a": (REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS
                                       | PRECALC_COMB_SYMS | ZP_COMB_SYMS | TESTVEC_SYMS),
}

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


def parse_makefile_archives():
    """Map archive filename -> [object module names], from the ar65 recipes.

    Parses the Make variable assignments (LIB_*_OBJS, BUILD_DIR) with line
    continuations, then the `ar65 a $(LIB_DIR)/<name>.a <tokens>` lines, and
    expands $(VAR) / $(BUILD_DIR) references down to build/<mod>.o paths.
    """
    text = MAKEFILE.read_text()
    joined = re.sub(r"\\\n\s*", " ", text)  # fold backslash continuations

    vars_ = {}
    for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", joined, re.M):
        vars_[m.group(1)] = m.group(2).strip()

    def expand(s, depth=0):
        if depth > 20:
            raise RuntimeError(f"variable expansion too deep: {s!r}")
        out = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]",
                     lambda mm: expand(vars_.get(mm.group(1), ""), depth + 1), s)
        return out

    # Each archive rule is `$(LIB_DIR)/<name>.a: <prereqs>` followed by an
    # `ar65 a $@ <tokens>` recipe line ($@ = the archive path). Capture the
    # target name from the rule head and the object tokens from the recipe.
    archives = {}
    rule = re.compile(
        r"^\$[({]LIB_DIR[)}]/(?P<name>\S+\.a):[^\n]*\n"
        r"(?:\t[^\n]*\n)*?"
        r"\tar65 a \$@ (?P<tokens>[^\n]*)$",
        re.M,
    )
    for m in rule.finditer(joined):
        name, tokens = m.group("name"), expand(m.group("tokens"))
        mods = [Path(t).stem for t in tokens.split() if t.endswith(".o")]
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
            print("  manifest value pins OK (§5 equates match the archive's real content)")

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

    if failures:
        print("ARCHIVE CONTRACT RATCHET: FAIL")
        for f in failures:
            print("  - " + f)
        return 1
    print("ARCHIVE CONTRACT RATCHET: PASS -- reality matches API.md §8.4.1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
