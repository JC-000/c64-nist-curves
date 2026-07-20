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
    ],
    "nistcurves-p256-verify.a": [
        ("variable-base building blocks",
         ["ec_scalar_mul_var", "ec_jacobian_to_affine", "fp_mod_inv", "fp_mod_mul"], True),
        ("packaged ecdsa_verify_256 (nocomb variant)", ["ecdsa_verify_256"], True),
    ],
    "nistcurves-p384-verify.a": [
        ("variable-base building blocks",
         ["ec_scalar_mul_var_384", "ec_jacobian_to_affine_384",
          "fp_mod_inv_384", "fp_mod_mul_384"], True),
        ("packaged ecdsa_verify_384 (nocomb variant)", ["ecdsa_verify_384"], True),
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
