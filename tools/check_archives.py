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
    # poly_prod_lo/hi ARE unresolved since issue #123 moved the §8.3 product
    # cells inside the deferral gate (they are the canonical body's output
    # interface -- the provider that owns the body owns the cells it writes,
    # and both fleet providers export them): fp256.o/fp384.o read them as
    # diagonal-squaring scratch, and the app's §8.3 provider supplies them.
    "nistcurves-app-owned.a": {"poly_prod_lo", "poly_prod_hi"},
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


# Segments the cfg page-aligns. ld65 inserts 0-255 bytes of padding ahead of
# each when it places them, and a per-object size sum cannot see that padding --
# so the placed span a consumer must budget is larger than the sum. Charged at
# the worst case, because the actual amount depends on the consumer's own
# preceding code, which we cannot know and must not assume is favourable.
FOOTPRINT_ALIGNED = {"LIB_NISTCURVES_SHA384_TABLES", "LIB_NISTCURVES_TABLES"}
ALIGN_WORST_CASE = 255


def measured_code_rodata(mods):
    """Placed code+rodata bytes an archive's members demand, worst case.

    Returns (total, unknown_segment_names). Zero-length segments are ignored --
    ca65 emits placeholders for the default names in every object. Missing
    objects are a hard failure, not a skip: a partially-built tree would
    otherwise measure low and pass.
    """
    total = 0
    unknown = set()
    aligned_present = set()
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
                if seg in FOOTPRINT_ALIGNED:
                    aligned_present.add(seg)
            elif seg not in FOOTPRINT_EXCLUDED:
                unknown.add(seg)
    total += ALIGN_WORST_CASE * len(aligned_present)
    return total, unknown


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
GATE_TUS = ["zp_aliases", "data_shared", "mul_8x8", "lib_version",
            "precalc_manifest"]


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
        return None
    m = re.search(r"Exports:\s*\n\s*Count:\s*(\d+)", out)
    if not m:
        return None
    names = set(re.findall(r'Name:\s*"([^"]+)"', out))
    if len(names) != int(m.group(1)):
        return None
    return names


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


def gated_surface_check(failures):
    """§6.5 window ratchet: a -D LIB_NO_BARE_EXPORTS=1 build of every
    gate-owning TU must export zero deprecated bare names. This is the whole
    point of the rename window -- one ungated .export quietly re-opens the
    #82/#83 collision class for composed consumers, and nothing else checks
    the gated configuration (the default build legitimately exports both
    spellings)."""
    import tempfile
    print("\n=== LIB_NO_BARE_EXPORTS gated surface ===")
    bad = []
    owned = {}
    with tempfile.TemporaryDirectory() as td:
        for tu in GATE_TUS:
            # SENTINEL: assemble the TU UNGATED first and require it to export
            # at least one bare name. Without this the leg is an absence
            # assertion over a dump it never proved was populated -- it would
            # print "0 bare names" for a TU that had been emptied, renamed,
            # or had simply failed to build in a way ca65 exited 0 on. It also
            # keeps GATE_TUS honest: a TU that stops owning a bare name (as
            # zp_config did at issue #154) must be removed from the list
            # rather than left behind as a permanently-green entry.
            uobj = Path(td) / (tu + "_ungated.o")
            rc, out = sh(["ca65", "--cpu", "6502",
                          "-I", "src", "-o", str(uobj), f"src/{tu}.s"])
            unames = od65_export_names(uobj) if not rc else None
            if unames is None:
                failures.append(f"gated surface: {tu}.s does not assemble ungated")
                print(f"  GATE FAIL: {tu}.s does not assemble ungated: "
                      f"{out.splitlines()[0] if out else ''}")
                continue
            owns = bare_gated(unames)
            if not owns:
                failures.append(
                    f"gated surface: {tu}.o owns no bare name ungated -- its "
                    "gated result proves nothing; drop it from GATE_TUS or "
                    "fix the TU")
                print(f"  GATE FAIL: {tu}.o exports no bare name UNGATED, so "
                      "'0 bare names under the gate' is vacuous for it")
                continue
            owned[tu] = sorted(owns)

            obj = Path(td) / (tu + ".o")
            rc, out = sh(["ca65", "--cpu", "6502", "-D", "LIB_NO_BARE_EXPORTS=1",
                          "-I", "src", "-o", str(obj), f"src/{tu}.s"])
            if rc:
                failures.append(f"gated surface: {tu}.s does not assemble under the gate")
                print(f"  GATE FAIL: {tu}.s does not assemble: {out.splitlines()[0] if out else ''}")
                continue
            leaked = bare_gated(od65_names(obj, "--dump-exports"))
            if leaked:
                bad.append((tu, sorted(leaked)))
    for tu, names in bad:
        failures.append(f"gated surface: {tu}.o exports bare {names}")
        print(f"  GATE FAIL: {tu}.o exports bare names under the gate: {names}")
    if not bad and len(owned) == len(GATE_TUS):
        total = sum(len(v) for v in owned.values())
        print(f"  gated surface OK ({len(GATE_TUS)} TUs owning {total} bare "
              "names ungated, 0 under the gate)")
        for tu in GATE_TUS:
            print(f"    {tu:20s} suppresses {owned[tu]}")


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


def footprint_basis_check(failures):
    """The §5 measurement basis is od65 segment sums. Pin that it equals a real
    link, because if it stops doing so the footprint leg understates SILENTLY.

    c64-ChaCha20-Poly1305 found all five of their RESIDENT_BYTES under-reporting
    a real link by 39-295 B, in §5's dangerous direction, from exactly this
    basis: Sigma of what each MEMBER contributes excludes the fill ld65 inserts
    when it PLACES them, and `od65 basis + fill = real link` held exactly across
    ten of their rows.

    Two kinds of fill, and only one of them is bounded by what we charge:

      BETWEEN segments -- up to 255 bytes before each page-aligned segment.
        Bounded, and measured_code_rodata() charges ALIGN_WORST_CASE per
        aligned footprint segment for it.
      WITHIN a segment -- if ld65 aligns each object's fragment. UNBOUNDED in
        the number of contributing objects, and NOT charged. This is what bit
        CCP, whose fill exceeded 255 and so cannot be a single inter-segment
        gap.

    We are clean today: no src file contains a source-level `.align`, and each
    aligned segment takes contributions from one object, so od65 sums equal
    placed sizes exactly. Measured over all 20 segments of a full link, delta
    +0 on every one.

    That is a property, not a guarantee -- adding one `.align` to a segment two
    objects contribute to would introduce within-segment fill and make every
    footprint figure quietly low again. So this links for real, reads the map,
    and asserts the identity."""
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

    # Second half: the charge must BOUND the real inter-segment fill, measured
    # rather than argued. measured_code_rodata() adds ALIGN_WORST_CASE per
    # aligned footprint segment on the reasoning that fill before a
    # page-aligned segment cannot exceed 255. That reasoning is sound but it is
    # reasoning; this measures the gap ld65 actually left.
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
    charged = ALIGN_WORST_CASE * len(
        [x for x in FOOTPRINT_ALIGNED if x in FOOTPRINT_SEGMENTS and x in starts])
    if real_fill > charged:
        failures.append(
            f"footprint basis: inter-segment fill measures {real_fill} B but "
            f"only {charged} B is charged -- every §5 figure is low by the "
            f"difference")
        print(f"  BASIS FAIL: fill {real_fill} > charged {charged}")
    else:
        print(f"  fill charge OK (measured {real_fill} B inter-segment, "
              f"{charged} B charged)")
    bad = [(k, sums.get(k, 0), v) for k, v in sorted(placed.items())
           if sums.get(k, 0) != v]
    if bad:
        for k, a, b in bad:
            failures.append(f"footprint basis: {k} od65 sum {a} != placed {b} "
                            f"(+{b - a} of fill the §5 measurement does not see)")
            print(f"  BASIS FAIL [{k}]: od65 {a} vs placed {b} (+{b - a})")
    else:
        print(f"  basis OK ({len(placed)} segments, od65 sums == placed sizes, "
              f"so the only fill is inter-segment and is charged)")


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
    exists so they stay that way: it finds the no-space names by substring,
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
    gated_surface_check(failures)
    app_owned_reachability_check(failures)
    packaging_check(failures, archives)

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
    footprint_basis_check(failures)
    sibling_bare_collision_check(failures)
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
