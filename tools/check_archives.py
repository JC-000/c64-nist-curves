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

# §8.4 reu_mul precalc row, BOTH the prefixed and the deprecated bare
# triple. Gated out under FP_ONCHIP_MUL (issue #78) -- the profile never
# builds or reads an REU multiply table, so an onchip archive that
# advertised the row would be describing a table it does not have. This
# mirrors the REU_MUL_PROVIDER_SYMS direction below at the manifest layer.
def _precalc_syms(*names):
    """Both the prefixed and the deprecated bare triple, for each table."""
    return {
        f"LIB{p}_PRECALC_{n}_{f}"
        for n in names
        for p in ("", "_NISTCURVES")
        for f in ("SIZE", "REGION", "SHARED")
    }


PRECALC_REU_MUL_SYMS = _precalc_syms("reu_mul")

# The lib-p384-sha384 archive contains no field, point, or multiply code,
# so sha384_k is the only precalc table it actually has (issue #88). It
# previously shipped the default-profile manifest pair and enumerated all
# five, describing four tables it does not carry — and, because the §8.0
# cross-adopter audit greps exactly these symbols, advertising itself as an
# sqtab provider to any sibling library that genuinely ships one.
PRECALC_NON_SHA_SYMS = _precalc_syms(
    "sqtab", "reu_mul", "lim_lee_comb_p256", "lim_lee_comb_p384"
)
PRECALC_SHA384_K_SYMS = _precalc_syms("sha384_k")

# --- §5 manifest VALUE pins (issue #88) --------------------------------------
# Each archive's §5 equates must describe THAT archive, not the library as a
# whole. Only values that are contractually load-bearing are pinned here:
#
#   REU_BANKS_USED     over-claiming makes a consumer reserve banks it could
#                      have used for something else
#   SHARED_PRIMITIVES  over-claiming trips a co-linked sibling's §8.0
#                      disjointness assert on a valid composition
#   SHARED_CONSUMES    over-claiming makes the v0.5.0 coverage assert demand a
#                      provider the link has no use for
#
# RESIDENT_BYTES / COLD_BYTES are deliberately NOT pinned for the curve
# archives: they still carry whole-library figures (1.5x-3x overstated for the
# minimal variants) pending the per-variant re-derivation. The sha384 archive
# IS pinned, since issue #88 re-derived it from a measured ld65 map.
MANIFEST_VALUES = {
    "nistcurves-p384-sha384.a": {
        "LIB_NISTCURVES_REU_BANKS_USED": 0x00,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0000,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0000,
        "LIB_NISTCURVES_RESIDENT_BYTES": 9000,
        "LIB_NISTCURVES_COLD_BYTES": 0,
    },
    "nistcurves.a": {
        "LIB_NISTCURVES_REU_BANKS_USED": 0x07,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0007,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0007,
    },
    "nistcurves-onchip.a": {
        "LIB_NISTCURVES_REU_BANKS_USED": 0x04,
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p256-verify-onchip.a": {
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p384-verify-onchip.a": {
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
    "nistcurves-p384-curve-onchip.a": {
        "LIB_NISTCURVES_SHARED_PRIMITIVES": 0x0005,
        "LIB_NISTCURVES_SHARED_CONSUMES": 0x0005,
    },
}

MUST_EXPORT = {
    "nistcurves.a": REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS,
    "nistcurves-p256-verify.a": REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS,
    "nistcurves-p384-verify.a": REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS,
    "nistcurves-p384-curve.a": REU_MUL_PROVIDER_SYMS | MANIFEST_SYMS,
    "nistcurves-p384-sha384.a": MANIFEST_SYMS | PRECALC_SHA384_K_SYMS,
    "nistcurves-onchip.a": MANIFEST_SYMS,
    "nistcurves-p256-verify-onchip.a": MANIFEST_SYMS,
    "nistcurves-p384-verify-onchip.a": MANIFEST_SYMS,
    "nistcurves-p384-curve-onchip.a": MANIFEST_SYMS,
}
MUST_NOT_EXPORT = {
    "nistcurves.a": set(),
    "nistcurves-p256-verify.a": set(),
    "nistcurves-p384-verify.a": set(),
    "nistcurves-p384-curve.a": set(),
    "nistcurves-p384-sha384.a": REU_MUL_PROVIDER_SYMS | PRECALC_NON_SHA_SYMS,
    "nistcurves-onchip.a": REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS,
    "nistcurves-p256-verify-onchip.a": REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS,
    "nistcurves-p384-verify-onchip.a": REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS,
    "nistcurves-p384-curve-onchip.a": REU_MUL_PROVIDER_SYMS | PRECALC_REU_MUL_SYMS,
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


def main():
    archives = parse_makefile_archives()
    failures = []

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
