# c64-nist-curves v0.7.0 — Release Notes

Released 2026-07-25. Compared to v0.6.0 (2026-07-20).

This is a MINOR release. v0.7.0 closes the last unvalidated-input gap
in the packaged ECDSA verifiers: `ecdsa_verify_256` and
`ecdsa_verify_384` now validate the public key Q at entry (FIPS 186-5
§3.3), so the ABI's "C=1 on malformed inputs" promise holds for the
Qx/Qy fields, not just r/s.

No public entry points were removed or renamed; `LIB_ABI_VERSION`
remains `0`. The standalone PRG grows **+512 bytes (37171 → 37683 B)**
— the first PRG change since v0.4.0.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md)
`## [0.7.0]`; this file is the concise release summary.

## What's new

### ECDSA verify public-key validation gate (issue #66)

Both packaged verifiers now run, as step 3b before the mod-n switch:

- **range check** — `Qx, Qy ∈ [0, p−1]`; non-canonical encodings
  (`Qx ≥ p` or `Qy ≥ p`) are rejected, and
- **on-curve check** — `Qy² ≡ Qx³ − 3·Qx + b (mod p)`.

Failures return C=1 (INVALID) before any scalar multiplication runs.
Previously a malformed Q flowed into the `u2·Q` ladder and produced an
unspecified accept/reject on garbage curve arithmetic; invalid-curve
inputs are now cut off at the front door.

Cost: 2 `fp_cmp` + 3 mod-p multiplies + 4 mod-p add/subs per verify —
noise against the multi-second scalar-mul phase at any clock speed. No
new RAM: the gate reuses the `ecdsa_w` / `ecdsa_u1` scratch slots,
which are dead at step 3b. Both the comb-fast default and the
`-D ECDSA_NO_COMB` archive variants carry the gate (it sits in common
code before the step-7 `.ifdef`).

Test coverage: 8 new negative-Q cases per suite (non-canonical `x+p`
encoding, off-curve bit-flip, random `Qx ≥ p` / `Qy ≥ p`, both curves)
— `tools/test_ecdsa_verify.py` is now 43 tests on the default PRG and
43 on the nocomb variant, all oracle-gated.

### Documentation: `fp_mod_mul_n[_384]` precondition widened (issue #65)

The routine headers in `src/mod256.s` / `src/mod384.s` claimed both
operands must be in `[0, n−1]`. The invariant the bit-serial reduction
actually needs is weaker — at least one operand `< n` — and the ECDSA
verify `u1 = h·w` step relies on the weaker form: it passes the
UNREDUCED digest `h`, and for P-256 the `h ≥ n` region is
adversarially reachable with ~2³² hash grinding. The headers now state
the real precondition, name the relying caller, and warn future
editors not to optimize on a both-reduced assumption. Comment-only.

## Artifact

| | |
|---|---|
| Tarball | `c64-nist-curves-v0.7.0.tar.gz` |
| Size | TBD bytes |
| SHA256 | `TBD` |

Reproducible via `make dist VERSION=v0.7.0` at tag `v0.7.0`
(byte-identical re-runs verified).

## Upgrade notes / compatibility

- **Relink to pick up the gate.** All archives containing
  `ecdsa256.o` / `ecdsa384.o` (full, curve, verify, and their -onchip
  variants) grow by the gate code; symbols, ZP, segments, and §5
  manifest equates are unchanged (`RESIDENT_BYTES` / `COLD_BYTES` are
  approximate and were not re-baselined for +512 B).
- **Behavioural change (intended):** verify calls with `Qx ≥ p`,
  `Qy ≥ p`, or an off-curve (Qx, Qy) now return C=1 deterministically
  before scalar multiplication. Consumers passing valid public keys
  see no change in results or (measurably) in timing.
- Direct consumers of the LE primitives (`ec_scalar_mul_var` etc.) are
  unaffected — the gate lives in the BE packaged verifiers only, and
  point-format preconditions on the raw primitives are unchanged.
- The verifiers remain NOT constant-time (public verify inputs only);
  do not repurpose for signing.
