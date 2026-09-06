# c64-nist-curves v0.13.0 — ECDSA verify no longer fails open on a collapsed comb table; SPEC v1.2.1 realignment

**Released:** 2026-09-06
**Tarball:** `c64-nist-curves-v0.13.0.tar.gz`
**Checksum:** published as the `c64-nist-curves-v0.13.0.tar.gz.sha256` release
asset and in the GitHub Release body. It is deliberately **not** repeated here:
these notes ship *inside* the tarball, so any hash they claimed would be
computed over a document that does not yet contain the claim and could never be
correct — which is exactly how v0.12.0 shipped a stale one (issue #147).
`make check-release-notes` now keeps that claim out.

MINOR release. **`LIB_NISTCURVES_ABI_VERSION` moves 2 → 3** — consumers with an
ABI gate must update it. Conformance baseline moves from SPEC v0.15.0 to
**v1.2.1**, across a contract that was cut by seven eighths in between.

---

## 1. Security: ECDSA verify failed open on a collapsed comb table (issue #148)

Reported by c64-https against v0.12.0, and it affected every release with the
Lim-Lee comb.

The comb reads its anchor table straight out of the REU and validated nothing.
If a fetched slot drove the accumulator to the point at infinity, `u1·G`
collapsed, `ecdsa_verify_*` took `ec_point_add_jj`'s P1-infinity branch,
`R := u2·Q`, and the check no longer involved `G` or the message at all. That
is the textbook `u1·G = O` forgery: anyone holding the public key `Q` picks any
`w`, sets `r = x(w·Q) mod n` and `s = r·w⁻¹`, and **any** message verifies. No
private key needed.

**Both curves were affected.** The report covered P-256; `points384_comb.s` had
the identical shape.

### What changed

`ec_scalar_mul` and `ec_scalar_mul_384` now check a **post-condition**: having
seeded from at least one anchor slot, the result must not be the point at
infinity. It is checked once, on `Z`, and returns **C=1 with the output
zeroed** when it fails. Every normal path returns **C=0**.
`ecdsa_verify_256` / `_384` reject on C=1.

### Why a post-condition and not a per-slot check

The first attempt tested each fetched `Y` for zero bytes — the shape the report
suggested — and adversarial review broke it. The collapse condition is
`Y ≡ 0 (mod p)`, not "Y is zero bytes", and `Y = p` is representable and is
never reduced between the DMA and the seed, so the byte test missed the forgery
by exactly one value. Two further routes also walked past it: a slot equal to
the negation of the accumulator collapses through `ec_point_add`'s `H = 0`
branch with every fetched `Y` non-zero, and a timed-out DMA leaves the previous
slot in place. Checking the *result* covers what checking the slots could not,
and costs one 32/48-byte scan per call instead of one per comb column.

### Scope — stated narrowly, because the useful version is narrow

This closes **collapse-to-infinity that persists to the last column**. That is
the shape *accidental* corruption produces — an REU too small for the
configured bank, a precompute that never ran, another tenant part-way through
bank 2 — and for those it is the difference between failing open and failing
closed.

It is **not** a defence against an adversary who can write the comb bank, and
no post-condition on the result could be:

- a mid-evaluation collapse is *erased* by the next non-zero column, because
  `ec_point_add`'s P1-infinity branch re-seeds `R` with `Z = 1`;
- an attacker who chooses the planted point needs no collapse at all. Given
  `Q`, planting the single slot `T[1] = R' − (r·h⁻¹)·Q` with `r = x(R') mod n`
  and `s = h` reaches `R'` through entirely well-formed arithmetic, `Z ≠ 0`
  throughout.

Anyone able to write REU bank 2 can also write the code that reads it, so that
is outside the library's threat model. Closing it needs table *integrity* — a
tag checked at use, or recomputation — not a check on the result. **Do not
restate this guard as "verify fails closed on a corrupt table."** It fails
closed on a *collapsed* one.

### No false positives

`Y = 0` cannot occur in a healthy table: every `T[j]` is a non-empty subset sum
of `{2^{32p}·G}`, so a non-zero multiple of `G` on a prime-order curve. On a
healthy table the guard fires only for a scalar that is a non-zero multiple of
`n`, which has no usable result either. The verifiers cannot reach even that —
they pass `u1 = h·w mod n < n`. **`u1 = 0` still returns the infinity encoding
with C=0**, which valid signatures depend on. The `ECDSA_NO_COMB` archive
variants route `u1·G` through the variable-base ladder and never reach this
path.

### Action for consumers

- Update any `.assert LIB_NISTCURVES_ABI_VERSION = 2` gate to `= 3`.
- Callers using `ec_scalar_mul[_384]` directly should branch on the carry.
  Callers of `ecdsa_verify_*` need no change — the rejection is internal.
- **C=0 does not imply an affine-convertible point**: `k = 0` returns C=0 with
  the infinity encoding, so `ec_jacobian_to_affine`'s own issue-#132 carry is
  still required.

---

## 2. v0.12.0 could not be linked by an APP_OWNED consumer at all (issue #149)

`c64-https` could not adopt v0.12.0 on **any** of its three shipped
configurations. Not a subtle failure — no PRG at all:

```
ld65: Error: Duplicate external identifier: 'nistcurves_mul_dma_hi'
```

ld65 links whole archive members. v0.12.0's §8.2 DMA-completion state shared a
translation unit with the multiply-row landing buffers, which a consumer taking
the §8.0/§8.3 APP_OWNED route defines and places itself. Referencing the settle
state — which `mul_8x8*.o` does at every profile — pulled the member in, and the
consumer had no remedy: dropping their own definition surrenders the placement
control APP_OWNED exists to give them, and editing an archive member is banned
by §6.1.

Fixed by separating three concerns that were one file: `src/data_reu_wait.s`
(the settle state), `src/data_mul_stage.s` (the APP_OWNED-displaceable staging
buffers, alone), and `src/data_shared.s` (the library-private operand cache).

**The first fix was half a fix**, and this is worth recording: splitting only
the settle state left the operand cache in the buffers' TU, and
`fp256.o`/`fp384.o`/`mul_8x8.o` all import it — so a consumer that owned the
buffers *and* called any field operation still hit the identical error. The
`check-archives` probe referenced only the settle state, so it stood in for a
consumer that links nothing and reported OK. The probe now calls `fp_mul`.

**This is now normative upstream** as SPEC 1.2.0 §6.1 *member isolation*, from
our contract issue #179, refined by 1.2.1's counterpart carve-out. The contract
records this library as conformant on the day the clause landed.

---

## 3. SPEC v1.2.1 realignment

The contract was cut from 40,737 words to ~5,300 at 1.0.0. Sections §9, §12,
§13, §14, §15 and sub-clauses §6.3, §6.6, §6.7 are retired; surviving sections
kept their numbers, so citations still resolve, and citations to retired ones
resolve permanently at `git show v0.17.1:SPEC.md`.

A clause-by-clause re-audit — verified from built objects, not source comments
— closed six gaps:

| Clause | Was | Now |
|---|---|---|
| §8.2 base bank | `< $FE`, so `1 .shl 32` exported 0 and a consumer's collision assert passed **falsely** | `< 31`, on both spellings of the knob |
| §3 bank mask | `LIB_NISTCURVES_REU_BANKS_USED` was a per-variant literal that ignored bank overrides — same false pass, one level up | computed from the values the code reads, via `src/reu_banks.inc` |
| §8.1 init | §8.1 ownership claimed in every non-SHA archive, but only `sqtab_init` exported | `mul_tables_init` exported — a deferring sibling got an unresolved external before |
| §8.2 staging | knobs not honoured; §8.2's Fetch clause named an address this library did not define | `LIB_SHARED_REU_MUL_STAGE_LO`/`_HI` move the buffers the code reads, prefixed outputs published |
| §8.4 | 3072 B of SHA-384 rotate LUTs unenumerated | `sha384_rotr_lut` row added |
| §5 | `sha384_update`'s 64 KB ceiling was prose-only | `LIB_NISTCURVES_SHA384_UPDATE_MAX` |

### §5 footprint figures were wrong in six of twelve archives

`make check-archives`'s "manifest value pins" compared each manifest against a
hard-coded copy of the same numbers inside the checker. Both sides were the
table, so the leg reported that the equates "match the archive's real content"
while checking nothing about the archive (issue #142).

Replacing it with a real measurement failed **six of twelve archives
immediately**, all understating, all in the direction where a consumer's §5 fit
check passes while the library overruns their region — `p384-verify-onchip` by
72 bytes. The leg now sums each archive's code+rodata from its built members,
charges worst-case page-alignment padding, pins `RESIDENT_BYTES` on its own as
well as the pair, and fails on an unrecognised segment rather than silently
omitting it. All twelve now carry 0.4–2.1% headroom.

**Consumers should re-read the §8.4.1 table** — every `RESIDENT_BYTES` moved.

### Consumer header and example cfg

`make lib` and every `make lib-*` target now also ship `nistcurves.inc` and
`cfg/nistcurves-example.cfg`. **Not contract-required** — SPEC 1.0.0 briefly
demanded them and 1.1.1 withdrew that — but consumers were otherwise
transcribing imports and a `SEGMENTS{}` block out of prose in API.md.

§3's header-import rule binds any header that exists, so every guarded
`.import` carries an `.else` asserting your `-D` against the archive's own
exported value; a bare guard would turn a compile error into silent divergence.
`check-archives` drives all twelve archives with their own switch sets, and
every guarded symbol at both the right value and a wrong one.

---

## 4. Also fixed

- **`make CONTRACT_DEFINES=<changed>` reassembled but skipped `ld65`** (issue
  #144), leaving the PRG carrying the *previous* knob's value at exit 0.
  Verified against the reporter's repro plus the archive case they had not been
  able to check.
- **The release-notes hash could never be correct** (issue #147). `make dist`
  now writes a `<tarball>.sha256` sidecar; the notes no longer claim a hash;
  v0.12.0's notes gain an erratum recording that the copy at that *tag* carries
  the stale pre-#145 pair while the published tarball is correct.

---

## 5. Size and compatibility

PRG **37483 → 37739 B**. About 64 bytes of code, rounded up by the page-aligned
table segment. Slack under the `__MAIN_LAST__ <= sqtab_lo` link guard is now
**150 bytes**, down from 406 — anything that grows MAIN much further needs the
buffers moved rather than the guard relaxed.

No symbol was removed or renamed. Additions: `mul_tables_init`,
`LIB_NISTCURVES_SHARED_REU_MUL_STAGE_LO`/`_HI`,
`LIB_NISTCURVES_SHA384_UPDATE_MAX`, and the `sha384_rotr_lut` §8.4 triples.

## 6. Known and disclosed

- §8.1 says `sqtab_lo`/`sqtab_hi` MUST NOT be exported; the default archive
  still exports them, gated under `LIB_NO_BARE_EXPORTS` and now also suppressed
  in the `SHARED_SQTAB_INIT` deferral arm. A §6.5 deprecation window is a
  schedule, not conformance — they go at the next MAJOR.
- **`zp_config.o` does not satisfy §6.1 member isolation**, and this is the
  one known non-conformance in the release. Its deprecated bare `zp_tmp1` /
  `zp_tmp2` / `zp_ptr1` / `zp_ptr2` aliases share a translation unit with the
  sixteen importable `fp_*` / `ec_*` / `sha_*` slots, so a consumer importing
  `fp_src1` pulls the member and its bare names collide with a sibling library
  exporting the same four.

  Raised as contract#188 and **ruled at SPEC v1.2.2**: §2's dedicated
  `src/zp_config.s` governs *claimed slots*, and a deprecated bare alias is not
  one — §2's registry requires every exported slot name to carry a registered
  prefix, which no bare `zp_` name does. So §2 never required the alias to live
  there, and it may be exported from a separate **archived** TU. Upstream
  measured the fleet before ruling: of five adopters only this one is affected.

  Deliberately **not** in this release. The move is a file split across the six
  variant gates, it changes no name, value or archive and is therefore not a
  §6.5 event, and it has no ABI consequence — so there is no reason to hold a
  security fix and a consumer's total link failure behind it. Tracked as #154.

  **Composing consumers are already covered**: `-D LIB_NO_BARE_EXPORTS=1`
  suppresses all four, which is what a consumer linking two libraries does
  anyway.
- `reu_fetch_mul_row`'s documented `A = a` entry convention is implemented by
  neither §8.2 provider in the fleet — both read a library-private byte and the
  two bytes have different names, so cross-adopter fetch deferral is nominal
  rather than real. Raised as contract#182 rather than changed one-sidedly,
  which would move which side is wrong instead of fixing the pairing. Now
  tracked here as **#153**: upstream ruled there is no ordering against
  c64-x25519 — each provider fixing itself completely makes deferral work
  whichever lands first — and that the entry shim and a caller audit must land
  together, since a shim alone turns a stale-row read into a garbage-row read.
