# c64-nist-curves v0.12.0 — REU DMA settle (SPEC §8.2), adversarial test suite, and two machine-locking hangs fixed

**Released:** 2026-08-30
**Tarball:** `c64-nist-curves-v0.12.0.tar.gz` (265,893 bytes)
**SHA256:** `bf6921d516a233d0063cba9e74912c14acf4ec553ec0397c9ece0a66ae659185`

MINOR release. Four new exported symbols (all additive),
`LIB_NISTCURVES_ABI_VERSION` stays **2**, and the PRG grows 3 bytes
(37480 → 37483; `18701274…` → `e070a554…`, ending the v0.10.0–v0.11.2
byte-identity chain). Conformance baseline moves to **SPEC v0.15.0**.

Two independent lines of work land together: adopting the upstream
§8.2 REU-DMA clause, and an adversarial audit that found — and this
release fixes — a public-API input that locks the machine.

## 1. SPEC v0.13.0 §8.2: DMA completion confirm + post-execute settle

On a U64 Elite running firmware 3.15 at 48 MHz, the REU's post-transfer
restore outlasts the turbo CPU, so the REU register write that follows
an execute is lost or misapplied — a wrong multiply row, wrong field
products, and silent wrong crypto with no error path. Measured upstream
([c64-lib-contract#144](https://github.com/JC-000/c64-lib-contract/issues/144)):
every REU-backed handshake in a sibling consumer failed its AEAD, while
the same build passed at 1 MHz and on firmware 3.14d. Every adopter,
this library included, had assumed the REU's DMA line halting the CPU
was the whole story.

All **thirteen** `sta reu_command` execute sites now confirm `$DF00`
bit 6 (end-of-block) and observe a post-execute settle before the next
REU register access, in two forms chosen by how soon that access comes:

| Sites | Form | Cost |
|---|---|---|
| 6 hot `fp_mul` / `fp_sqr` row fetches (both curves) | inline `REU_DMA_CONFIRM` (`bit reu_status / bvs`, `src/reu_dma_done.inc`), entering the bounded spin only if bit 6 is clear | 7 cycles/row, A/X/Y preserved |
| 2 `reu_mul_init` stashes, 4 comb stash/fetch routines, exported `reu_fetch_mul_row` | `jsr nistcurves_reu_dma_wait`: bounded 16-bit spin, then `LIB_NISTCURVES_REU_SETTLE_ITER` × 9-cycle settle | ~106 cycles (default 8), 2.16× the measured floor |

At the six hot sites the settle obligation is met **structurally** — the
next REU register write is a full accumulate body away — and SPEC
v0.14.1 asks that such a settle be *asserted* rather than described,
because it is a constraint held only by unrelated instructions, the
natural optimisation shortens exactly that path, and no emulator
reproduces the failure. Each site therefore carries
`REU_SETTLE_ASSERT_BYTES`, an assemble-time check that its straight-line
byte distance to the next REU register write is ≥ the 49-cycle floor
(bytes are a conservative cycle floor on any 6502 path). Negative-tested
by inflating the floor with `-D`: the diagonal-squaring sites trip
first, at 60–70 B, `fp_mul` at 100–120, `fp_sqr` at 120–140.

**64 MHz is explicitly unbracketed** in the contract — no C64 Ultimate
was reachable. For the two tightest sites the hand-counted minimum path
is 86 cycles (55 + 15 + 16), which clears a time-anchored ~65-cycle
64 MHz floor; the seven `jsr` sites are covered by the knob instead.

**The §8.2 hardware row has since been measured**, on an Ultimate 64
Elite (`601A96`, fw 3.15 + local patch, **core 1.4F** read live per run,
REU 512 KB) at 48 MHz and 16 MHz, both verified in-band:
**22 of 22 cells, ~2100 fetches, zero wrong bytes** — a bare-metal probe
reading the landing buffer +4 cycles after the execute (0/200), a stash
ladder with the settle poked from 12 to 106 cycles (0/1000), and an
**unmitigated control** built from the pre-fix tag and verified
unmitigated from its own bytes — zero occurrences of `bit $DF00` in the
image — which also passed (0/1000). Full row:
[c64-lib-contract#144](https://github.com/JC-000/c64-lib-contract/issues/144#issuecomment-5468958751).

**That result does not relax anything in this release, and the settle
ships exactly as described above.** It says the hazard is not observable
*on core 1.4F*; c64-x25519's core-1.4E pair — the same build failing
unmitigated and passing mitigated, same device, same day — is untouched,
as are 1.4E devices, real 17xx REUs and other REU implementations. The
likely cause is an FPGA core change (GideonZ/1541ultimate `59594060`,
*"no initial delay on U64/U64E2, because of Turbo Mode"*), but its fix is
gated on a generic never set true in that repository, so that remains
consistent-with rather than proof. What is still owed on issue #130 is
**only the 64 MHz bracket**, which needs a C64 Ultimate.

## 2. Adversarial test suite (hazmat-oracle audit)

A `cryptography.hazmat`-oracle audit ran 483 adversarial cases against
the library — ECDSA verify with `r`/`s`/`h` at 0, `n`, `n±1`, above `n`,
malleated `s`, off-curve / non-canonical / infinity `Q`, `u1 = 0`,
`R = ∞`, the cofactor fallback; field values at `p−1`, `p`, `p+1`,
`2ⁿ−1` and Solinas worst cases; point degeneracies and comb/variable-base
agreement; SHA-384 boundary and chained-update splits. **No wrong-accept
and no wrong-result was found.** The cases are now permanent
entrypoints:

- `tools/test_ecdsa_adversarial.py` (92 cases, both curves)
- `tools/test_prims_adversarial.py` (290 cases + 34 informational rows)
- `tools/audit_common.py` — one-boot machine wrapper, per-case timeout
  so a hang becomes a row instead of a wedged run, and transport
  recovery after a hang

What the audit found was in the *tests*, and those are fixed here too:
the issue-#66 Q-validation group was **vacuous** (mutation-proved: with
the range gate NOP-ed out the group still passed 4/4, and the mutant
then accepted a signature it must reject), and `test_fp_cmp` /
`test_fp_is_zero` on both curves incremented their pass counters without
reading anything back — 52 cases that could not fail. The Q-gate check
is rewritten as the one construction that only passes with the gate
present, the flag tests now assert C and Z from the `jsr()` register
dict, CAVP SigVer reason codes are asserted rather than printed, and
`--full` requests all 15 vectors instead of 20 of 15.

## 3. Fixed: `fp_mod_inv` and `ec_jacobian_to_affine` could lock the machine

**Impact: a consumer calling documented public entry points could hang
the C64, requiring a power cycle. Not reachable through
`ecdsa_verify_256` / `ecdsa_verify_384`.**

`fp_mod_inv` / `fp_mod_inv_384` never terminated when the input was
`0` **or equal to the modulus** — the binary extended GCD's halve branch
is taken forever and `v` is never reduced. `ec_jacobian_to_affine` /
`_384` then inverted `Z` with no zero test, and `Z = 0` is *the
library's own point-at-infinity encoding*: `ec_scalar_mul` for
`k ∈ {0, n}`, `ec_scalar_mul_var` for `k ≡ 0 (mod n)`, and
`ec_point_add(P, −P)` all emit it. So converting a legitimate library
output to affine locked the machine.

Both are now guarded at the entry:

- `fp_mod_inv[_384]`: input ≡ 0 modulo the modulus in `fp_misc` — the
  all-zero value **or** the modulus itself, so mod-`p` and mod-`n` are
  both covered — returns **C = 1** with the result zeroed. Every normal
  exit now returns **C = 0** (previously the carry was whatever the
  internal comparison left).
- `ec_jacobian_to_affine[_384]`: `Z ≡ 0` returns **C = 1** with the
  affine `x`/`y` outputs zeroed.

Cost is a two-scan prologue that leaves at the first non-zero or
mismatching byte: **22 cycles** on the fast path, ~350 worst case,
against ~750 kcy for the inversion itself. The routine is variable-time
by construction and takes public verify operands only (this library
provides no signing path), so the guard does not change its
constant-time posture.

The six hang cases run on every invocation of
`tools/test_prims_adversarial.py` under a 90-second per-case timeout,
and the guards were mutation-tested: flipping the guard's `sec` to `clc`
makes the no-inverse rows fail on C, and NOP-ing its branch re-exposes
the original hang, which the timeout catches.

## Also in this release

- **Docs:** `fp_cmp`'s "Z=1 if equal" comment was false (the final `dey`
  clears Z; C is the result, and no caller uses Z). API.md §5.2 now
  documents the canonical-input precondition of `fp_mod_add` /
  `fp_mod_sub` (inputs ≥ p produce non-canonical output) and
  `fp_mod_mul_n`'s load-bearing "at least one operand < n".
- **Docs:** the §8.1 sqtab override examples are shown `0x`-form. An
  unquoted `$8800` is a shell positional expansion and make eats `$`
  too — and the §8.1 asserts pass on the resulting `0`, placing a 1 KB
  table over zero page with no diagnostic from make, ca65 or ld65.
- Conformance baseline **SPEC v0.11.1 → v0.15.0**, verified
  clause-by-clause: v0.12.0 / v0.12.1 / v0.14.0 are §13 network-ABI
  releases this library does not adopt; v0.14.2 is doc-only; v0.15.0's
  §8.4 bare-`LIB_PRECALC_*` carve-out scopes to libraries with no
  released consumers, so this library keeps emitting the gated triple.

## New exported symbols (additive; ABI stays 2)

| Symbol | Where | What |
|---|---|---|
| `LIB_NISTCURVES_REU_SETTLE_ITER` | `src/reu_config.s`, `:abs` | Settle iterations (default 8, range 1–255), overridable via `CONTRACT_DEFINES='-D LIB_NISTCURVES_REU_SETTLE_ITER=<n>'`. Exported as the value the code reads, so a consumer can assert what the archive settles for. Raise it if you claim conformance at 64 MHz. |
| `nistcurves_reu_dma_wait` | `src/mul_8x8.s` | The bounded confirm + settle routine (library-private plumbing, not part of the §8.2 provider surface). |
| `nistcurves_reu_dma_timeout` | `src/data_shared.s`, 1 B | Sticky: set to 1 if any bounded spin on `$DF00` bit 6 ever expires. The primitive has no error channel, so this is how a bounded-spin failure surfaces. Consumers whose linker config makes the BSS segment `bss`-typed must zero it before init. |
| `nistcurves_reu_wait_cnt` | `src/data_shared.s`, 2 B | Spin/settle scratch counter. |

## Footprint deltas (§6.6, code + rodata, measured with od65 over extracted members)

Both endpoints measured, not inferred: v0.11.2's figures come from a
fresh worktree at that tag, built and measured the same way.

| Archive | v0.11.2 | v0.12.0 | Δ |
|---|---|---|---|
| `nistcurves.a` | 25,457 | 25,681 | +224 |
| `nistcurves-onchip.a` | 25,354 | 25,524 | +170 |
| `nistcurves-app-owned.a` | 25,028 | 25,243 | +215 |
| `nistcurves-p256-verify.a` | 8,945 | 9,075 | +130 |
| `nistcurves-p256-verify-onchip.a` | 8,862 | 8,962 | +100 |
| `nistcurves-p384-verify.a` | 8,605 | 8,735 | +130 |
| `nistcurves-p384-verify-onchip.a` | 8,522 | 8,622 | +100 |
| `nistcurves-p384-curve.a` | 14,583 | 14,713 | +130 |
| `nistcurves-p384-curve-onchip.a` | 14,500 | 14,600 | +100 |
| `nistcurves-p256-comb.a` | 10,036 | 10,172 | +136 |
| `nistcurves-p256-comb-onchip.a` | 9,953 | 10,059 | +106 |
| `nistcurves-p384-sha384.a` | 5,929 | 5,929 | 0 |

The onchip archives grow too (+100 to +170) even though they issue no
REU DMA: their share is the `fp_mod_inv` and `ec_jacobian_to_affine`
guards, which are profile-independent. The DMA-profile archives carry
those plus the §8.2 confirm code.

**No `LIB_NISTCURVES_*_BYTES` equate changed** — every archive still fits
its §5 pin, ratcheted by `make check-archives`. Margins narrowed, and the
tightest is worth stating: `nistcurves-p256-verify.a` is now 8,637
resident (9,075 total − 438 cold) against a `RESIDENT_BYTES` pin of
8,700 — **63 bytes of headroom**. The next change to the P-256 verify
path should re-measure rather than assume.

The SHA-384 archive is untouched: it contains no REU DMA and no
inversion.

## Upgrading from v0.11.2

Drop-in. No symbol was removed or renamed, no archive member moved, and
`LIB_NISTCURVES_ABI_VERSION` stays 2 — an existing `.import` set links
unchanged.

Two things a consumer may want to do deliberately:

1. **If you run REU-backed builds on turbo hardware**, this is the
   release to pin: the pre-v0.12.0 code path produces silently wrong
   field products on U64E firmware 3.15 at 48 MHz. Sibling
   `c64-x25519` v0.12.0 carries the matching fix for the shared
   primitive; pin both.
2. **If you call `fp_mod_inv[_384]` or `ec_jacobian_to_affine[_384]`
   directly**, you can now branch on carry (`C = 1` → no inverse /
   point at infinity, output zeroed) instead of guaranteeing a non-zero
   input yourself. Existing code that ignores the carry behaves exactly
   as before for every input that previously returned.

## Verification

- `make check-archives` PASS (12 archives; §1 identity at 0.12.0;
  footprint pins unchanged). `make check-docs` PASS.
- VICE oracle suites on the release tree: `test_prims_adversarial
  --strict` 290/0/0, `test_ecdsa_adversarial` 92/0,
  `test_ecdsa_verify` 43/43, `test_fp256` 479/479, `test_fp384`
  481/481, `test_points256` 41/41, `test_points384` 41/41.
- Independent verification (separate agent, separate worktree): the
  suite is genuinely red before the fix (exactly six hang rows, each a
  caught 90 s timeout with recovered transport) and green after, and
  both mutations of the guard make the green rows fail.
- PRG `e070a554…`, 37,483 B; `__MAIN_LAST__` `$9A6A`, sqtab window
  guard intact.
- Tarball reproducible across two independent `make dist` runs, and
  builds standalone from the extracted archive.
- Worktree-rebuild byte-identity at the tag.
- **Hardware**: 22/22 cells on a U64 Elite at core 1.4F (see §1) —
  including an unmitigated control that also passed, which is why this
  release's claim is scoped to that core rather than to "the REU".
- Consumer overrides (`CONTRACT_DEFINES`) verified to assemble **and** to
  change the linked artifact: a `check-archives` leg now hashes the PRG
  across a knob change and back, negative-tested by reverting the fix.
