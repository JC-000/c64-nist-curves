# c64-nist-curves public API

This document is the integration reference for developers embedding the
`c64-nist-curves` math library into another Commodore 64 program. It lists the
public entry points, their calling convention, the memory the library occupies,
and the initialization sequence that must run before any field or point
operation is called.

For architectural detail and benchmark numbers, see `CLAUDE.md` and `README.md`.

## 1. Overview

`c64-nist-curves` provides NIST P-256 and P-384 arithmetic tuned for a stock
Commodore 64 plus a RAM Expansion Unit (REU):

- 32-byte / 48-byte field arithmetic (add, sub, mul, sqr, inv, modular variants)
- Jacobian point doubling and mixed Jacobian/affine point addition
- Fixed-base scalar multiplication `k * G` via an 8-way width-1 Lim-Lee comb
  over a REU-resident 256-entry precompute table (Wave 7a; h=4 landed in Wave 5)
- Variable-base scalar multiplication `k * P` (`ec_scalar_mul_var[_384]`,
  ECDSA-verify building block; non-constant-time)
- Jacobian-to-affine conversion for result export
- Packaged ECDSA verify (`ecdsa_verify_256` / `ecdsa_verify_384`) with a
  big-endian wire-format ABI suitable for TLS-style callers
- SHA-384 streaming hash (FIPS 180-4 §6.4) and a one-shot
  `ecdsa_verify_with_message_384` hash-then-verify wrapper

Target platform: 6502 @ 1 MHz with a 1764 / 1750 / compatible REU.
Exception: the `FP_ONCHIP_MUL` turbo-profile archives (§8.4.2) compute
multiply rows on-chip — the `*-verify-onchip` archives issue no REU DMA
at all and run on REU-less machines (and accelerated hosts above the
~22 MHz / ~33 MHz crossovers, where they are the faster choice;
crossovers measured on C64 Ultimate fw 1.1.0 and shift per
device/firmware generation — see §8.4.2).
Source is ca65/ld65 assembly for the cc65 toolchain; build via `make clean && make`. See README.md for toolchain install notes.

Byte-order conventions:

- **Field elements, curve parameters, Jacobian / affine coordinates:**
  little-endian (byte 0 is the LSB). This matches the natural 6502 carry chain.
- **Scalars (private keys, nonces):** big-endian (byte 0 is the MSB), matching
  the wire format used by ECDSA / RFC 6979 / SP 800-186.

Unless a routine is explicitly documented as `_384`, the name refers to the
P-256 variant. Every public P-256 routine has a corresponding `_384`
counterpart with the same contract except the operand width.

## 2. Memory footprint

The library currently assumes the fixed load layout below. Relocating the data
buffers requires re-placing the `LIB_NISTCURVES_*` data segments (declared
across `src/data_shared.s`, `src/data_p256.s`, `src/data_p256_invref.s`,
`src/data_p256_limlee.s`, `src/data_p384.s`, `src/data_p384_limlee.s`,
`src/data_sha.s`) in the consumer's ld65 config; relocating the zero-page
slots can be done either by editing `src/zp_config.s` or, without modifying
the library source, by pre-defining the ZP symbol in the consumer's build
(every equate in `zp_config.s` is wrapped in `.ifndef NAME ... .endif`, so a
host-supplied definition wins).

The table below is **anchored to symbols**; the addresses shown are from the
current `master` build (v0.7.0, PRG 37683 B) and drift as code size changes.
`build/labels.txt` is the authoritative address source for any given build —
regenerate it with `make` and plan your memory map from the symbols there.

| Region | Address range (current build) | Purpose |
|---|---|---|
| PRG code + RODATA | `$0801`-`$7AFF` (approx.) | BASIC stub, boot code, math routines, curve constants; ends with the RODATA reduction helper tables (`lo_7_tbl` `$7900`, `hi_7_tbl` `$7A00`). |
| `mul_dma_lo` (page-aligned) | `$7B00`-`$7BFF` | REU DMA target: low bytes of the current multiply row. |
| `mul_dma_hi` (page-aligned) | `$7C00`-`$7CFF` | REU DMA target: high bytes of the current multiply row. |
| Shared multiply scratch | `$7D00`-`$7D23` | `mul_cached_a`, `mul_src2_buf` (`data_shared.s`). |
| P-256 field / point / ECDSA buffers | `$7D24`-`$8243` | `fp_wide` (`$7D24`), `fp_r0`, `fp_inv_*`, `ec_p1/p2/p3` (`ec_p1` `$7E04`), `ec_t1..6`, `ec_jj_tmp`, `ec_affine_x/y`, `ecdsa_*`, `fp_rev_buf` (`data_p256.s`). `fp_tmp2..4` are harness-only staging in `data_test.s`; `fp_r1..3` / `fp_inv_iter` / `fp_red_tmp` were deleted (issue #54). |
| Fermat-reference scratch | `$8244`-`$8263` | `fp_tmp1` (`data_p256_invref.s`); rides with `inv256.o` — full archive + standalone PRG only. |
| Lim-Lee anchors + working scalar (P-256) | `$8264`-`$84C5` | `ec_aff2g_256_x/y`, `ec_anchor1..8_x/y` (8 * 64 bytes, `ec_anchor1_x` `$82A4`), `cm_k` (32, `$84A4`), comb walker state (`data_p256_limlee.s`). |
| P-384 field / point / ECDSA buffers | `$84C7`-`$8E32` | `mul_src2_buf_384`, `fp384_wide` (`$84FB`), `fp384_tmp1..4`, `fp384_r0`, `fp384_inv_*`, `ec384_p1/p2/p3`, `ec384_t1..6`, `ec384_jj_tmp`, `ec384_affine_x/y` (`ec384_affine_y` `$8ACB`), `ecdsa384_*`, `fp_rev_buf_384` (`data_p384.s`). |
| Lim-Lee anchors + working scalar (P-384) | `$8E33`-`$9162` | `ec_anchor1..8_384_x/y` (8 * 96 bytes, `ec_anchor1_384_x` `$8E33`), `cm_k_384` (48, ends `$9162`) (`data_p384_limlee.s`). |
| SHA-384 streaming state + buffers | `$9163`-`$9573` | `sha_state` (64, `$9163`) + `sha_w` (640) + `sha_abcdefgh` (64) + `sha_t` (16) + `sha_scratch` (64) + `sha_block_buf` (128) + `sha_block_len` (1) + `sha_total_len` (16) + `sha384_digest` (48) ≈ 1041 B (`data_sha.s`). K[80] round constants (640 B) live in RODATA inside `src/sha384.s`. |
| Test-harness staging buffers | `$9574`-`$9B66` | `ecdsa_inputs_*`, `ecdsa_result_*`, `sha384_msg_buf` (1024), `fp_tmp2..4` (`data_test.s`). Standalone PRG only — excluded from every consumer archive. |
| Quarter-square multiply tables | `$9C00`-`$9FFF` (1 KB) | `sqtab_lo` / `sqtab_hi`. Built once by `sqtab_init`. Moved from `$7800` on 2026-05-17 to clear the linker-managed `mul_dma_*` page-aligned slots as code grew (see CLAUDE.md "Known issues"); base overridable via `LIB_SHARED_SQTAB_BASE` (§8.6.1). |
| Zero-page | 8-27 bytes depending on archive, see `zp_config.s` | `LIB_NISTCURVES_ZP_USAGE_BYTES = 27` for the full archive (8-23 for the minimal archives — §8.4 has the complete per-archive table); every slot is `.ifndef`-guarded so a consumer pre-definition wins. |
| REU bank 0-1 | `$00_0000`-`$01_FFFF` | 128 KB full 8x8 -> 16 multiply table, built once by `reu_mul_init`. |
| REU bank 2, offset `$0000`-`$3FFF` | 16 KB | P-256 Lim-Lee comb precompute (256 entries x 64 bytes, X + Y only). Wave 7a h=8. |
| REU bank 2, offset `$4000`-`$9F9F` | 24 KB | P-384 Lim-Lee comb precompute (256 entries x 96 bytes). Wave 7a h=8. |

Run `build/labels.txt` through your own tooling for exact symbol addresses in
any given build. The address ranges above are from the v0.7.0 build and will
drift slightly as code size changes; the symbol names are stable.

## 3. Initialization sequence (required)

The host program must perform the following calls, in order, before any field
or point routine is used. All of them are defined in `mul_8x8.s` /
`reu_mul_init.s` / `points256_comb.s` / `points384_comb.s` and are public
labels. (`reu_mul_init` moved from the never-archived `main.s` into its own
object by issue #81, so every default-profile archive now ships it —
archive consumers link this whole sequence with no extra objects.)

1. **Bank out BASIC ROM** (optional but recommended) so `$A000`-`$BFFF` is RAM.
   `proc_port` ($01, the 6510 CPU I/O port) is hardware-fixed but is not a
   library-claimed symbol (issue #90) — define it yourself, same as
   `src/main.s` does, guarded so a pre-existing definition wins:

   ```asm
   .ifndef proc_port
     proc_port = $01
   .endif
   lda proc_port
   and #$fe
   sta proc_port
   ```

2. **`jsr sqtab_init`** — builds the quarter-square lookup tables at
   `$9C00`-`$9FFF`. Required for any multiply.

3. **`jsr reu_mul_init`** — fills REU banks 0-1 with the full 128 KB 8x8 -> 16
   multiply table and pre-configures the REU DMA registers. Required for any
   multiply **in the default (DMA-table) profile**; consumers linking a
   `FP_ONCHIP_MUL` turbo-profile archive (§8.4.2) skip this step entirely —
   their multiply rows are generated on-chip and only `sqtab_init` is needed.
   Takes ~7 seconds on a real C64 (~4 s of prior baseline plus
   ~2.8 s added by the constant-time `mul_8x8` port of issue #14; the boot
   cost is a one-time tax, no runtime call path is affected).

4. **`jsr ec_precompute_256`** — builds the 16 KB Lim-Lee anchor / comb table in
   REU bank 2 at offset `$0000` (256 entries * 64 bytes, h=8). Required before
   `ec_scalar_mul`. Only needed if you will call P-256 scalar multiply; field
   arithmetic and point double / add do not depend on it. Boot cost at 1 MHz
   is **~17 minutes** (measured ~1038 Mcyc, default profile — issue #121; the
   "~25 seconds" this step quoted through v0.11.0 was ~40× low). See §8.5 for
   the per-profile table and turbo scaling.

5. **`jsr ec_precompute_384`** — analogous P-384 precompute at REU bank 2
   offset `$4000` (24 KB, 256 entries * 96 bytes, h=8). Required before
   `ec_scalar_mul_384`. Boot cost at 1 MHz is **~34 minutes** (measured
   ~2108 Mcyc, default profile — issue #121). See §8.5.

If your host program only uses one curve, you may omit that curve's
`ec_precompute_*` call. In the default profile, `sqtab_init` and
`reu_mul_init` are mandatory for both curves. In the `FP_ONCHIP_MUL`
turbo profile (§8.4.2) only `sqtab_init` is mandatory — the
`*-verify-onchip` archives additionally exclude the comb, so they need
no `ec_precompute_*` and issue no REU DMA at all.

### Test-harness sentinel (optional)

`main.s`'s `start` routine writes `$42` to `$02A7` as the final step of
initialization. The Python test harness polls this byte to detect "ready"
without racing the KERNAL `READY.` prompt. Consumer programs do not need to
emit this sentinel, but repurposing `$02A7` is safe only after the harness has
observed it.

## 4. Calling convention

Every public routine follows the same contract:

### Inputs: zero-page pointers

- `fp_src1` (2 bytes, LE) — pointer to operand 1
- `fp_src2` (2 bytes, LE) — pointer to operand 2 (unused for unary ops)
- `fp_dst`  (2 bytes, LE) — pointer to destination buffer
- `fp_misc` (2 bytes, LE) — pointer to modulus for `fp_mod_*` routines; set by
  `ec_set_modp` / `ec_set_modn` (and `_384` variants). Scalar multiply uses
  `ec_scalar_ptr` (1 byte; high byte lives in `ec_scalar_ptr+1`) to point at
  the big-endian scalar.

Pointers are written with `lda #<label / sta fp_src1 / lda #>label / sta fp_src1+1`.

### Operand widths

| Object | P-256 | P-384 |
|---|---|---|
| Field element | 32 bytes (LE) | 48 bytes (LE) |
| Double-width product | 64 bytes (`fp_wide`) | 96 bytes (`fp384_wide`) |
| Jacobian point | 96 bytes (X@0, Y@32, Z@64) | 144 bytes (X@0, Y@48, Z@96) |
| Affine point | 64 bytes (X then Y) | 96 bytes (X then Y) |
| Scalar (BE) | 32 bytes | 48 bytes |

Scalars must be zero-padded up to the curve's full field width.

### Outputs

- Field ops: result at `(fp_dst)`. `fp_mod_mul` / `fp_mod_sqr` / `fp_mod_inv`
  additionally land their result in `fp_r0` (P-256) or `fp384_r0` (P-384).
  The `ec_mulp` / `ec_sqrp` wrappers copy `fp_r0` into `(fp_dst)` for you.
- Point ops: result in `ec_p3` (P-256) or `ec384_p3` (P-384).
- `ec_jacobian_to_affine` writes the affine result to `ec_affine_x/y` (P-256)
  or `ec384_affine_x/y` (P-384).
- `fp_add` / `fp_sub` (and their `_384` variants) store the carry-out or
  borrow-out byte in `fp_carry` (1 = carry/borrow occurred, 0 = clean).

### Clobbers

All public routines clobber `A`, `X`, `Y`. They also clobber the shared
scratch buffers listed in `src/data_p256.s` / `src/data_p384.s` (`fp_wide`,
`fp_r0`, `fp_inv_*`, `ec_t1..6`, `ec_jj_tmp`, and their `_384`
counterparts), plus `mul_cached_a` / `mul_src2_buf` / `mul_dma_lo` /
`mul_dma_hi`.

### Re-entrancy: **NOT re-entrant**

The field-multiply state (`mul_cached_a`, `mul_src2_buf`, `mul_dma_lo`,
`mul_dma_hi`) and the ZP pointers (`fp_src1/2/dst/misc`) are globally shared
between every P-256 and P-384 routine. Sequential calls across the two
curves are fine, but the host must never interleave library calls —
in particular, it must not invoke any field or point routine from an IRQ
handler while the mainline is already inside one. Mask IRQs around crypto
work or keep all library calls on a single thread of control. See the
re-entrancy comment block in `src/data_shared.s` (above `mul_cached_a`)
for the canonical statement.

### Persistent REU DMA descriptor state

As a micro-optimization, `reu_mul_init` (and the point-level DMA
restore hooks `.sm_reu_restore` / `.sm384w_restore_reu`) leave the
REU descriptor registers in a specific state that `fp_mul` / `fp_sqr`
rely on across all subsequent calls:

| Register | Address | Value |
|---|---|---|
| C64 base low / high | `$DF02` / `$DF03` | `<mul_dma_lo` / `>mul_dma_lo` |
| REU offset low | `$DF04` | `$00` |
| Transfer length | `$DF07` / `$DF08` | `$00` / `$02` (512 bytes) |
| Address control | `$DF0A` | `$00` (both increment) |

The inner loop only rewrites `reu_reu_hi` (`$DF05`), `reu_reu_bank`
(`$DF06`), and `reu_command` (`$DF01`) per row. **Host programs that
issue their own REU DMA must either (a) leave these invariant registers
untouched, or (b) restore them before the next call into any library
routine that may invoke `fp_mul` / `fp_sqr` / any field op that
multiplies.** Interleaving host REU traffic with library multiplies
without honouring this contract will produce silent wrong answers.

**DMA completion confirm + post-execute settle (c64-lib-contract SPEC
v0.13.0 §8.2, issue #130).** After every REU execute, and before the
next REU register access, the library (a) reads `$DF00` and confirms
bit 6 (end-of-block), spinning bounded if it is not set, and (b) leaves
a post-execute settle. This is not optional hardening: on U64E fw 3.15
at 48 MHz the REU's post-transfer restore outlasts a turbo CPU, and a
register write that follows the execute immediately is lost or
misapplied — wrong row, wrong products, silent wrong crypto
([c64-lib-contract#144](https://github.com/JC-000/c64-lib-contract/issues/144)).
The six `fp_mul` / `fp_sqr` row fetches use an inline 7-cycle confirm
(the settle is structural there — the next REU write is a full
accumulate body away); the table build, the comb DMA routines and
`reu_fetch_mul_row` call `nistcurves_reu_dma_wait`, whose settle length
is `LIB_NISTCURVES_REU_SETTLE_ITER` (default 8 → ~107 cycles, 2.2× the
measured ≥ 49-cycle floor at 48 MHz; see §8.6.1 to raise it). If a
bounded spin ever expires, the sticky byte `nistcurves_reu_dma_timeout`
is set to 1 and execution proceeds; a host that wants fail-closed
behaviour tests it after `reu_mul_init`. **Host programs that issue
their own REU DMA between library calls should apply the same clause to
their own execute sites** — the library's confirm covers only the
transfers it issues. 64 MHz (C64 Ultimate) is unbracketed as of SPEC
v0.13.0; raise the knob there until a FAIL/PASS bracket exists.

## 5. Public API reference

All symbols below are defined as globally-addressable labels in the file
listed in the "Source" column. `_384` variants take 48-byte operands
and use the P-384 modulus / buffers; in every other respect they behave
identically to the P-256 version.

### 5.1 Raw field arithmetic (`fp256.s`, `fp384.s`)

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `fp_copy` / `fp_copy_384` | fp256/fp384 | `fp_src1`, `fp_dst` | `(fp_dst)` := `(fp_src1)` | Clobbers A, Y. |
| `fp_zero` / `fp_zero_384` | fp256/fp384 | `fp_dst` | `(fp_dst)` := 0 | Clobbers A, Y. |
| `fp_cmp` / `fp_cmp_384` | fp256/fp384 | `fp_src1`, `fp_src2` | Carry set if src1 >= src2, Z set if equal | No memory output. |
| `fp_add` / `fp_add_384` | fp256/fp384 | `fp_src1`, `fp_src2`, `fp_dst` | `(fp_dst)` := src1 + src2; `fp_carry` = carry-out | Non-reducing. |
| `fp_sub` / `fp_sub_384` | fp256/fp384 | `fp_src1`, `fp_src2`, `fp_dst` | `(fp_dst)` := src1 - src2; `fp_carry` = borrow-out | Non-reducing. |
| `fp_is_zero` / `fp_is_zero_384` | fp256/fp384 | `fp_src1` | Z flag set iff `(fp_src1)` == 0 | |
| `fp_rshift1` / `fp_rshift1_384` | fp256/fp384 | `fp_src1` | `(fp_src1)` := src1 >> 1 (in place) | |
| `fp_mul` / `fp_mul_384` | fp256/fp384 | `fp_src1`, `fp_src2` | `fp_wide` / `fp384_wide` := src1 * src2 (double-width) | Uses REU DMA multiply table. |
| `fp_sqr` / `fp_sqr_384` | fp256/fp384 | `fp_src1` | `fp_wide` / `fp384_wide` := src1^2 | Deferred-doubling squaring. |

### 5.2 Modular field arithmetic (`mod256.s`, `mod384.s`)

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `fp_mod_add` / `fp_mod_add_384` | mod256/mod384 | `fp_src1`, `fp_src2`, `fp_dst`, `fp_misc` | `(fp_dst)` := (src1 + src2) mod (fp_misc) | Works for any modulus passed via `fp_misc`. |
| `fp_mod_sub` / `fp_mod_sub_384` | mod256/mod384 | `fp_src1`, `fp_src2`, `fp_dst`, `fp_misc` | `(fp_dst)` := (src1 - src2) mod (fp_misc) | |
| `fp_mod_reduce256` | mod256 | `fp_wide` | `fp_r0` := `fp_wide` mod p256 | Solinas fast reduction. Hard-wired to the P-256 prime. |
| `fp_mod_reduce384` | mod384 | `fp384_wide` | `fp384_r0` := `fp384_wide` mod p384 | Solinas fast reduction. Hard-wired to the P-384 prime. |
| `fp_mod_mul` / `fp_mod_mul_384` | mod256/mod384 | `fp_src1`, `fp_src2` | `fp_r0` / `fp384_r0` := (src1 * src2) mod p | Hard-wired to the curve prime via `fp_mod_reduce*`. |
| `fp_mod_sqr` / `fp_mod_sqr_384` | mod256/mod384 | `fp_src1` | `fp_r0` / `fp384_r0` := src1^2 mod p | |
| `fp_mod_inv` / `fp_mod_inv_384` | mod256/mod384 | `fp_src1`, `fp_misc` | `fp_r0` / `fp384_r0` := src1^(-1) mod `(fp_misc)` | Binary extended GCD; accepts any prime modulus (p or n). Saves and restores `fp_dst`. |
| `ec_set_modp` / `ec_set_modp_384` | mod256/mod384 | — | `fp_misc` := address of curve prime p | Convenience setter. |
| `ec_set_modn` / `ec_set_modn_384` | mod256/mod384 | — | `fp_misc` := address of curve group order n | Convenience setter. |
| `ec_mulp` / `ec_mulp_384` | mod256/mod384 | `fp_src1`, `fp_src2`, `fp_dst` | `(fp_dst)` := (src1 * src2) mod p | Wrapper: `ec_set_modp` + `fp_mod_mul` + copy `fp_r0` to `(fp_dst)`. Preserves `fp_src1`. |
| `ec_sqrp` / `ec_sqrp_384` | mod256/mod384 | `fp_src1`, `fp_dst` | `(fp_dst)` := src1^2 mod p | Wrapper as above using `fp_mod_sqr`. |

### 5.3 Point operations (`points256_core.s` / `points256_comb.s`, `points384_core.s` / `points384_comb.s`)

The `_core` modules carry the verify-path primitives (present in every
curve archive); the `_comb` modules carry the Lim-Lee fixed-base comb
(excluded from the `*-verify` archives — see §8.4).

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `ec_point_double` / `ec_point_double_384` | points256_core/points384_core | `ec_p1` / `ec384_p1` (Jacobian) | `ec_p3` / `ec384_p3` (Jacobian) | Handles Z=0 (infinity) input. Uses curve-specific `a = -3` formula. |
| `ec_point_add` / `ec_point_add_384` | points256_core/points384_core | `ec_p1` / `ec384_p1` (Jacobian), `ec_p2` / `ec384_p2` (affine X in first half, Y in second half; Z ignored) | `ec_p3` / `ec384_p3` (Jacobian) | Mixed Jacobian+affine addition (7M + 4S). Handles both-infinity / same-point cases. The Lim-Lee comb evaluate loop uses this primitive. |
| `ec_point_add_jj` / `ec_point_add_jj_384` | points256_core/points384_core | `ec_p1` / `ec384_p1` (full Jacobian), `ec_p2` / `ec384_p2` (full Jacobian) | `ec_p3` / `ec384_p3` (Jacobian) | Full Jacobian+Jacobian addition (Bernstein-Lange add-2007-bl, 11M + 5S). Reads Z2 from `ec_p2+64` (or `ec384_p2+96`) — caller must populate it. Handles P1∞, P2∞, both∞, same projective point (tail-calls `ec_point_double`), and P1=-P2 natively. Used by `ecdsa_verify_256/384` at the `u1*G + u2*Q` join. |
| `ec_scalar_mul` | points256_comb | `ec_scalar_ptr` (ZP pointer to 32-byte BE scalar) | `ec_p3` (Jacobian) | Computes `k * G` for fixed generator G using an 8-way Lim-Lee comb over the 256-entry P-256 precompute table (Wave 7a h=8). **Requires `ec_precompute_256`.** Base-point only. |
| `ec_scalar_mul_384` | points384_comb | `ec_scalar_ptr` (ZP pointer to 48-byte BE scalar) | `ec384_p3` (Jacobian) | P-384 analogue (Wave 7a h=8). **Requires `ec_precompute_384`.** |
| `ec_jacobian_to_affine` | points256_core | `ec_p3` | `ec_affine_x`, `ec_affine_y` | Sets `fp_misc` to p256 internally. |
| `ec_jacobian_to_affine_384` | points384_core | `ec384_p3` | `ec384_affine_x`, `ec384_affine_y` | P-384 analogue. |
| `ec_precompute_256` | points256_comb | — | REU bank 2 @ `$0000`..`$3FFF`, `ec_anchor1..8_x/y` | Builds the 16 KB h=8 Lim-Lee comb table. Run once at boot (~17 min at 1 MHz, default profile — §8.5, issue #121). |
| `ec_precompute_384` | points384_comb | — | REU bank 2 @ `$4000`..`$9F9F`, `ec_anchor1..8_384_x/y` | P-384 analogue, 24 KB table (~34 min at 1 MHz, default profile — §8.5). |

### 5.4 Hash functions (`sha384.s`)

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `sha384_init` | sha384 | — | resets `sha_state` to the SHA-384 IV; clears `sha_block_len`, `sha_total_len` | Must be called before the first `sha384_update` of a new stream and after every `sha384_final`. |
| `sha384_update` | sha384 | `sha_src` (ZP, 2 B LE pointer), `sha_len` (ZP, 2 B LE byte count) | absorbs `sha_len` bytes from `sha_src`; may trigger zero or more 1024-bit compressions as the 128 B `sha_block_buf` fills | 16-bit `sha_len` caps a single call at 64 KB. May be called repeatedly to stream longer messages. |
| `sha384_final` | sha384 | — | writes 48 BE bytes to `sha384_digest` | Pads per FIPS 180-4 §5.1.2 and runs the final compression(s). After this call, `sha384_init` must precede any further hashing. |

Streaming pattern: `sha384_init` once, `sha384_update` one or more times
(set `sha_src` and `sha_len` before each call), `sha384_final` once,
then read 48 BE bytes from `sha384_digest`. The module is
self-contained: it does not touch the REU, the multiply scratch, or any
of the field/point ZP slots, but it is **not re-entrant** (per the
library-wide contract in §4) and a single SHA stream cannot be
interleaved with itself or with other library calls.

### 5.5 ECDSA verify (`ecdsa256.s`, `ecdsa384.s`)

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `ecdsa_verify_256` | ecdsa256 | A (lo) / X (hi) = pointer to 160 B BE struct `r(32) | s(32) | h(32) | Qx(32) | Qy(32)` | C=0 valid, C=1 invalid/malformed | Non-constant-time (public inputs). Validates r, s ∈ [1, n-1] AND the public key Q (issue #66): range check Qx, Qy ∈ [0, p-1] plus on-curve check Qy² ≡ Qx³ − 3·Qx + b (mod p); non-canonical (Qx or Qy ≥ p) or off-curve Q returns C=1 before any scalar mul. Internally byte-reverses to LE via `fp_reverse32`, then composes `ec_scalar_mul`, `ec_scalar_mul_var`, `ec_point_add`, `fp_mod_inv`, `fp_mod_mul_n`. |
| `ecdsa_verify_384` | ecdsa384 | A (lo) / X (hi) = pointer to 240 B BE struct `r(48) | s(48) | h(48) | Qx(48) | Qy(48)` | C=0 valid, C=1 invalid/malformed | P-384 analogue using `fp_reverse48`. Same non-constant-time caveat; same full input validation incl. the Q range + on-curve gate (issue #66). |
| `ecdsa_verify_with_message_384` | ecdsa384 | A (lo) / X (hi) = pointer to same 240 B BE struct (h slot is overwritten); `sha_src` / `sha_len` (ZP) point at the message | C=0 valid, C=1 invalid/malformed | One-shot wrapper: runs `sha384_init / sha384_update / sha384_final`, splices `sha384_digest` into struct[96..143], then tail-calls `ecdsa_verify_384`. |

The verify ABI is big-endian throughout because that is the wire
format for X.509 / ASN.1 signatures and the SHA-2 digest spec.
Internally the routines translate to the library's native
little-endian layout. They are NOT constant-time and must NOT be
repurposed for ECDSA signing; the library does not provide a
constant-time verify because it is unnecessary for TLS.

`ecdsa_verify_with_message_384` issues exactly one `sha384_update` call.
For TLS-style transcripts spanning multiple buffers, callers should
drive `sha384_init / sha384_update (n times) / sha384_final` directly
and then `jsr ecdsa_verify_384` with the digest already stored at
struct[96..143]. No P-256 / SHA-384 wrapper is provided: TLS 1.3
cipher-suite pairings are `secp256r1+SHA-256` and `secp384r1+SHA-384`,
and only SHA-384 is implemented here.

`fp_reverse32` and `fp_reverse48` are exported for callers who want to
drive the LE primitives directly from BE wire-format inputs without
going through the packaged verifier.

## 6. Example usage

### 6.1 Modular multiply: `r = a * b mod p256`

```asm
        .importzp fp_src1, fp_src2, fp_dst
        .import ec_mulp

.bss
; buf_a, buf_b, buf_r stand in for wherever your program keeps its
; 32-byte LE operands/result. Named with a prefix deliberately: a bare
; `a` cannot be a label in ca65 — it is the accumulator token for
; implied addressing, so `a: .res 32` fails with "Unexpected trailing
; garbage characters".
buf_a: .res 32
buf_b: .res 32
buf_r: .res 32

.code
        lda #<buf_a
        sta fp_src1
        lda #>buf_a
        sta fp_src1+1
        lda #<buf_b
        sta fp_src2
        lda #>buf_b
        sta fp_src2+1
        lda #<buf_r
        sta fp_dst
        lda #>buf_r
        sta fp_dst+1
        jsr ec_mulp         ; sets modulus to p256, multiplies, copies fp_r0 to buf_r
```

Use `ec_mulp_384` with 48-byte buffers for P-384.

### 6.2 Fixed-base scalar multiply: `Q = k * G` on P-256

```asm
        .importzp ec_scalar_ptr
        .import ec_scalar_mul, ec_jacobian_to_affine
        .import ec_affine_x, ec_affine_y

.bss
k: .res 32   ; a 32-byte big-endian scalar somewhere in RAM

.code
        lda #<k
        sta ec_scalar_ptr
        lda #>k
        sta ec_scalar_ptr+1

        jsr ec_scalar_mul           ; ec_p3 := k*G (Jacobian)

        jsr ec_jacobian_to_affine   ; ec_affine_x / ec_affine_y = Q.x / Q.y

        ; ec_affine_x and ec_affine_y are 32 bytes each, little-endian.
```

The same pattern works for P-384 with `ec_scalar_mul_384` /
`ec_jacobian_to_affine_384` and a 48-byte big-endian scalar. Both variants
require the relevant `ec_precompute_*` to have been called at boot.

### 6.3 ECDSA verify with message: P-384 hash-then-verify wrapper

```asm
        .importzp sha_src, sha_len
        .import ecdsa_verify_with_message_384

; message_len is a compile-time constant (your real message length, or
; computed by your build), NOT a RAM label like message_buf below --
; #<message_len / #>message_len only produce the right byte count if
; it's a constant. Taking the address of a label here instead would
; silently load the wrong sha_len with no assemble-time error.
message_len = 6

        ; Pre-pack r, s, Qx, Qy into a 240 B BE struct. The h slot is
        ; OVERWRITTEN by the wrapper -- callers may leave it zero.
        ; struct layout: r(48) | s(48) | h(48) | Qx(48) | Qy(48).
.bss
verify_struct:  .res 240
message_buf:    .res 1024       ; or wherever the message lives

.code
        ; ... pack r, s, Qx, Qy into verify_struct as 48 B BE each ...

        ; Point sha_src / sha_len at the contiguous message bytes.
        lda #<message_buf
        sta sha_src
        lda #>message_buf
        sta sha_src+1
        lda #<message_len       ; 16-bit byte count
        sta sha_len
        lda #>message_len
        sta sha_len+1

        ; Call the wrapper: A/X = struct pointer.
        lda #<verify_struct
        ldx #>verify_struct
        jsr ecdsa_verify_with_message_384
        bcc @valid              ; C=0 => signature valid
        ; C=1 => invalid / malformed
        jmp @reject
@valid:
        ; ...
        rts
@reject:
        ; ...
        rts
```

For transcripts spanning multiple buffers (TLS handshake hashing,
streamed file verification), drive `sha384_init / sha384_update /
sha384_final` manually, splice `sha384_digest` into `verify_struct+96`,
and `jsr ecdsa_verify_384` directly.

## 7. Limitations

- **Not re-entrant.** The library shares global scratch and ZP slots across
  all field and point routines; callers must serialize all library calls and
  never invoke them from an IRQ handler that can preempt mainline crypto work.
  See the comment block in `src/data_shared.s` and section 4 above.
- **Shared P-256 / P-384 scratch.** Sequential cross-curve calls are fine, but
  there is no support for running a P-256 multiply "in parallel" with a P-384
  multiply.
- **Data buffers live at fixed absolute addresses.** Relocating them requires
  re-placing the `LIB_NISTCURVES_*` data segments (declared across the
  `src/data_*.s` modules) in the consumer's ld65 config and re-linking. The
  code / ZP layout is somewhat more flexible: code is position-independent
  within the PRG and ZP slots can be renamed via `src/zp_config.s`.
- **Zero-page footprint ranges 8-27 bytes depending on archive**
  (`LIB_NISTCURVES_ZP_USAGE_BYTES`; 8 for `lib-p384-sha384`, 15 for the two
  `*-verify` archives, 23 for `lib-p384-curve`, 27 for the full archive —
  see §8.4 for the complete per-archive table). See `src/zp_config.s` for
  the complete, editable list of slots. `proc_port` ($01, the 6510 CPU I/O
  port) is hardware-fixed but is **not** a library-claimed slot (issue
  #90) — ROM banking around REU access is the consumer's own
  responsibility; see the §3 step 1 example.
- **Scalar multiplication is non-constant-time.** Both the fixed-base
  `ec_scalar_mul[_384]` (Lim-Lee comb, branches on comb index and infinity
  flag) and the variable-base `ec_scalar_mul_var[_384]` (double-and-add,
  branches on every scalar bit) leak the scalar via timing. Use only in
  public-input contexts — ECDSA verify is the intended caller. Do not
  use these routines for ECDH or ECDSA signing where the scalar is secret.
- **Scalars must be zero-padded** to 32 bytes for P-256 and 48 bytes for P-384,
  big-endian.
- **SHA-384 only.** No SHA-256, SHA-512, or other digest is implemented.
  A P-256 / SHA-256 ECDSA verify struct can still be built by computing
  the digest off-chip (or with a separate library) and passing it in the
  `h` slot of `ecdsa_verify_256`; the `ecdsa_verify_with_message_*`
  one-shot wrapper exists only for the P-384 / SHA-384 pairing.

## 8. Consumer integration

This library targets C64 programs assembled with `ca65` and linked with
`ld65` (the cc65 toolchain). Consumers on the legacy ACME assembler must
migrate their project to ca65 first — see the cc65 documentation at
https://cc65.github.io/ for the toolchain, and this repository's
`f95d7f5` commit ("Migrate assembler from ACME to ca65") for a worked
example of the migration patterns we applied to our own source.

### 8.1 Importing the library

Recommended import mechanism: **git submodule**, pinned to a specific
release tag.

```sh
git submodule add https://github.com/JC-000/c64-nist-curves \
    lib/c64-nist-curves
git -C lib/c64-nist-curves checkout v0.7.0
git commit -m "Import c64-nist-curves v0.7.0 as submodule"
```

Bumping to a later release:

```sh
git -C lib/c64-nist-curves fetch --tags
git -C lib/c64-nist-curves checkout v0.9.1    # or whichever tag
git add lib/c64-nist-curves
git commit -m "Bump c64-nist-curves to v0.9.1"
```

Consumers should pin to a specific tag rather than tracking `master`
or any wave branch — see §8.5 for the version-stability policy.

### 8.2 Building against the library

The recommended consumer build pattern (added in v0.2.x via c64-lib-contract
SPEC §6) is to fetch one of the pre-built archive files from the library's
`make lib-<variant>` targets and link directly. No source patching, no
per-file `ca65` invocation, no `sed`-staging:

```make
LIB             = lib/c64-nist-curves
LIB_ARCHIVE     = $(LIB)/build/lib/nistcurves-p384-verify.a    # pick a variant

$(LIB_ARCHIVE):
	$(MAKE) -C $(LIB) lib-p384-verify

consumer.prg: $(CONSUMER_OBJECTS) $(LIB_ARCHIVE) consumer.cfg
	ld65 -o consumer.prg -C consumer.cfg $(CONSUMER_OBJECTS) $(LIB_ARCHIVE)
```

See §8.4 for the full archive-variant inventory.

The library uses **library-prefixed segment names** (`LIB_NISTCURVES_*`,
SPEC §4) so the consumer's `ld65` config can place each tier wherever its
own memory map needs. The segments to define in the consumer's cfg:

| Segment                              | Type | Constraint                          |
|--------------------------------------|------|-------------------------------------|
| `LIB_NISTCURVES_MUL_CODE`            | rw   | -                                   |
| `LIB_NISTCURVES_P256_CODE`           | rw   | -                                   |
| `LIB_NISTCURVES_P384_CODE`           | rw   | -                                   |
| `LIB_NISTCURVES_SHA384_CODE`         | rw   | -                                   |
| `LIB_NISTCURVES_P256_RODATA`         | ro   | -                                   |
| `LIB_NISTCURVES_P384_RODATA`         | ro   | -                                   |
| `LIB_NISTCURVES_SHA384_RODATA`       | ro   | -                                   |
| `LIB_NISTCURVES_SHA384_TABLES`       | ro   | `align = $100` (rotr LUTs / K[80])  |
| `LIB_NISTCURVES_TABLES`              | rw   | `align = $100` (`mul_dma_lo/hi`)    |
| `LIB_NISTCURVES_BSS`                 | rw   | shared mul scratch                  |
| `LIB_NISTCURVES_P256_BSS`            | rw   | P-256 field/point/ECDSA buffers     |
| `LIB_NISTCURVES_P256_INVREF_BSS`     | rw   | `fp_tmp1` (Fermat-reference scratch)|
| `LIB_NISTCURVES_P256_LIMLEE_BSS`     | rw   | P-256 Lim-Lee anchors + working k   |
| `LIB_NISTCURVES_P384_BSS`            | bss  | `mul_src2_buf_384` (fp384 scratch)  |
| `LIB_NISTCURVES_P384_DATA_BSS`       | rw   | P-384 field/point/ECDSA buffers     |
| `LIB_NISTCURVES_P384_LIMLEE_BSS`     | rw   | P-384 Lim-Lee anchors + working k   |
| `LIB_NISTCURVES_SHA384_BSS`          | rw   | SHA-384 stream state + digest       |

Per-variant `_BSS` / `_LIMLEE_BSS` segments are declared `optional = yes`
in `src/c64.cfg`, so consumers that pick a minimal archive (e.g.
`lib-p256-verify`) will not see linker complaints about missing P-384
or SHA-384 segments — they simply remain empty. The lone non-optional
segments are the ones whose objects every archive ships (`LIB_NISTCURVES_BSS`,
`LIB_NISTCURVES_TABLES`).

The `LIB_NISTCURVES_TABLES` segment carries the only hard placement
constraint: the two pages `mul_dma_lo` and `mul_dma_hi` must remain
page-aligned (REU DMA target alignment + `lda abs,Y` no-page-penalty).
`align = $100` on the segment in your consumer's cfg satisfies this.
See `src/c64.cfg` for the canonical placement; the simplest path is to
start from a copy of `src/c64.cfg` and override segment placements as
the consumer's memory map requires.

### 8.3 Memory-layout constraints

The library owns specific absolute addresses in the C64 memory map and
in the REU banks. Consumer programs must accommodate these without
overlap:

Addresses below are from the current build (v0.7.0); `build/labels.txt`
is authoritative per §2 — the symbol names are the stable anchors.

| Resource | Library-owned | Consumer restriction |
|---|---|---|
| C64 page $7B (`mul_dma_lo`) | $7B00–$7BFF | Do not use; page-aligned DMA target |
| C64 page $7C (`mul_dma_hi`) | $7C00–$7CFF | Do not use |
| C64 pages ~$7B–$97 | mul scratch, field / point / ECDSA buffers, Lim-Lee anchors, SHA state | See §2 for the full map |
| C64 pages $9C–$9F | Quarter-square multiply tables (`sqtab_lo/hi`) | Do not use |
| C64 zero-page | 8-27 bytes depending on archive (`LIB_NISTCURVES_ZP_USAGE_BYTES`; see §8.4 for the full per-archive table); see `src/zp_config.s` | Edit `src/zp_config.s` to relocate if needed |
| REU bank 0 / bank 1 | Full 128 KB multiply table | Do not write; initialized by `reu_mul_init` (default profile only — the `FP_ONCHIP_MUL` archives, §8.4.2, never populate or read these banks) |
| REU bank 2, $0000–$3FFF | P-256 Lim-Lee anchors (16 KB, 256 × 64) | Do not write |
| REU bank 2, $4000–$9F9F | P-384 Lim-Lee anchors (24 KB, 256 × 96) | Do not write |
| REU bank 2, $9FA0–$FFFF | Unused (~24 KB free) | Safe for consumer use |
| REU banks 3+ (if present) | Unused by library | Safe for consumer use |

Relocating library-owned C64 data addresses means re-placing the
`LIB_NISTCURVES_*` data segments (declared across the `src/data_*.s`
modules) in the consumer's ld65 config. ZP slots can be relocated via `src/zp_config.s`, or
overridden from the consumer's own source without editing the library
(every slot in `zp_config.s` is `.ifndef`-guarded — pre-define the symbol
before the library assembles and the host choice wins). REU bank
assignments are currently hard-coded in the library source and would
require a deeper refactor to change.

Programs using only one curve may skip the other's `ec_precompute_*`
call (§8.5), recovering its 16–24 KB of REU bank 2 for consumer use.

### 8.4 Archive build targets

Per `c64-lib-contract` SPEC §6, the library publishes pre-built `ar65`
archives in `build/lib/`. Consumers fetch the archive matching their
use case and pass it to `ld65` directly; no source patching, no
intermediate `.o` shuffling.

**Member basenames are contract surface, and they change at the next
MAJOR.** SPEC §6.5 lists archive member basenames alongside symbol and
segment names as versioned surface. This library's members are still
unprefixed (`lib_version.o`, `lib_manifest_<variant>.o`,
`precalc_manifest_<variant>.o`, `zp_config_<variant>.o`, plus the
per-module objects), which is the flat namespace §6.5 defers to each
library's next MAJOR: at that bump they take the `nistcurves_` prefix
(`nistcurves_lib_version.o`). Members cannot dual-name, so this rides
MAJOR rather than the usual one-MINOR rename window. A consumer whose
build scripts name members — an `od65` post-check over an extracted
member, an `ar65 d` surgery step — should read them from `ar65 t` at
build time rather than hard-coding them across a MAJOR bump. (SPEC
v0.11.0's carve-out, which has new libraries born prefixed, does not
reach this library: it scopes to libraries with no released consumers.)

| Target                       | Archive                              | Use case                                                                                 |
|------------------------------|--------------------------------------|------------------------------------------------------------------------------------------|
| `make lib`                   | `nistcurves.a`                       | Whole library minus the standalone test PRG driver. Default for whole-library consumers. |
| `make lib-p256-verify`       | `nistcurves-p256-verify.a`           | P-256 ECDSA verify only (variable-base scalar mul). Excludes Lim-Lee fixed-base comb.    |
| `make lib-p256-comb`         | `nistcurves-p256-comb.a`             | P-256 ECDSA verify with the comb-fast `u1·G` (issue #117): the verify set plus the Lim-Lee fixed-base comb, no P-384 / SHA-384. |
| `make lib-p384-verify`       | `nistcurves-p384-verify.a`           | P-384 ECDSA verify only. Excludes Lim-Lee comb and the SHA-driving wrapper.              |
| `make lib-p384-sha384`       | `nistcurves-p384-sha384.a`           | SHA-384 streaming hash only. Self-contained: no REU, no multiply tables.                 |
| `make lib-p384-curve`        | `nistcurves-p384-curve.a`            | P-384 ECDSA verify + SHA-384 + `ecdsa_verify_with_message_384` one-shot wrapper.         |
| `make lib-onchip`            | `nistcurves-onchip.a`                | Full library, **turbo profile** (§8.4.2): on-chip multiply, no REU mul-table DMA.        |
| `make lib-p256-verify-onchip`| `nistcurves-p256-verify-onchip.a`    | P-256 verify, turbo profile. No REU DMA at all (no mul table, no comb).                  |
| `make lib-p256-comb-onchip`  | `nistcurves-p256-comb-onchip.a`      | P-256 comb verify, turbo profile: on-chip multiply, REU used for the comb anchor table only (bank 2). Fastest verify configuration at turbo (issue #117). |
| `make lib-p384-verify-onchip`| `nistcurves-p384-verify-onchip.a`    | P-384 verify, turbo profile. No REU DMA at all.                                          |
| `make lib-p384-curve-onchip` | `nistcurves-p384-curve-onchip.a`     | P-384 verify + SHA-384 + one-shot wrapper, turbo profile.                                |

Exclusion summary (per minimal archive):

- `lib-p256-verify` excludes: `main`, `inv256` + `data_p256_invref`
  (Fermat-inverse reference and its `fp_tmp1` scratch; the binary-GCD
  path in `mod256` is what production uses), `points256_comb`
  + `data_p256_limlee` (Lim-Lee anchors, `ec_scalar_mul`, and the comb
  scalar-walker state `ec_sc_byte`/`ec_sc_mask`), all P-384,
  all SHA-384, the test-driver staging buffers (`ecdsa_inputs_*`,
  `sha384_msg_buf`, `fp_tmp2..4`). Its `LIB_NISTCURVES_P256_BSS`
  extent is 1312 B as of issue #54 (was 1573 B in v0.3.0).
- `lib-p256-comb` / `lib-p256-comb-onchip` (issue #117) are the
  `lib-p256-verify[-onchip]` member set with the comb-fast `ecdsa256.o`
  in place of `ecdsa256_nocomb.o`, plus `points256_comb` +
  `data_p256_limlee`. Still excluded: `main`, `inv256` +
  `data_p256_invref`, all P-384, all SHA-384, the test-driver staging
  buffers. Boot obligation grows by `ec_precompute_256` (**~17 min at
  1 MHz** default profile / ~34 min onchip; scales with clock only in
  the onchip profile — §8.5, issue #121) and REU bank 2 gains the 16 KB
  P-256 anchor table —
  in **both** profiles (the onchip arm still DMA-fetches comb anchors;
  it is the multiply table it does without).
- `lib-p384-verify` excludes: `main`, all P-256, `points384_comb` +
  `data_p384_limlee`, `ecdsa384_msg` (one-shot wrapper — consumers
  driving streaming SHA themselves link this in via `lib-p384-curve`
  instead), all SHA-384, the test-driver staging buffers.
- `lib-p384-sha384` is the tightest archive: `sha384.o`, `data_sha.o`,
  `zp_config.o`, `lib_version.o`, plus the two SHA-only manifest objects
  `lib_manifest_sha384.o` / `precalc_manifest_sha384.o`. No `mul_8x8`,
  no REU, no `constants.o` — SHA-384 has no shared scratch with the
  field / point / ECDSA code paths. Because it carries no field layer at
  all, its §5 manifest is built with `-D LIB_SHA384_ONLY`, one of six
  variant gates that together make each archive's §5 manifest describe
  that archive rather than the whole library (issue #88 was the first,
  narrower fix, SHA-384 only; issue #90 extended it to the three
  verify/curve gates; issue #117 added `LIB_P256_COMB_ONLY`):

  | Archive | `-D` switch(es) | `ZP_USAGE_BYTES` | `REU_BANKS_USED` | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` | `RESIDENT_BYTES` | `COLD_BYTES` | precalc rows |
  |---|---|---:|---|---|---|---:|---:|---|
  | `nistcurves.a` | (default) | 27 | `$07` | `$0007` | `$0007` | 27000 | 1840 | sqtab, reu_mul, lim_lee_comb_p256, lim_lee_comb_p384, sha384_k (5) |
  | `nistcurves-onchip.a` | `FP_ONCHIP_MUL` | 27 | `$04` | `$0005` | `$0005` | 27000 | 1650 | sqtab, lim_lee_comb_p256, lim_lee_comb_p384, sha384_k (4) |
  | `nistcurves-p256-verify.a` | `LIB_P256_VERIFY_ONLY` | 15 | `$03` | `$0007` | `$0007` | 8700 | 430 | sqtab, reu_mul (2) |
  | `nistcurves-p256-verify-onchip.a` | `LIB_P256_VERIFY_ONLY` + `FP_ONCHIP_MUL` | 15 | `$00` | `$0005` | `$0005` | 8700 | 240 | sqtab (1) |
  | `nistcurves-p384-verify.a` | `LIB_P384_VERIFY_ONLY` | 15 | `$03` | `$0007` | `$0007` | 8300 | 430 | sqtab, reu_mul (2) |
  | `nistcurves-p384-verify-onchip.a` | `LIB_P384_VERIFY_ONLY` + `FP_ONCHIP_MUL` | 15 | `$00` | `$0005` | `$0005` | 8300 | 240 | sqtab (1) |
  | `nistcurves-p384-curve.a` | `LIB_P384_CURVE_ONLY` | 23 | `$03` | `$0007` | `$0007` | 17400 | 430 | sqtab, reu_mul, sha384_k (3) |
  | `nistcurves-p384-curve-onchip.a` | `LIB_P384_CURVE_ONLY` + `FP_ONCHIP_MUL` | 23 | `$00` | `$0005` | `$0005` | 17400 | 240 | sqtab, sha384_k (2) |
  | `nistcurves-p384-sha384.a` | `LIB_SHA384_ONLY` | 8 | `$00` | `$0000` | `$0000` | 9000 | 0 | sha384_k (1) |
  | `nistcurves-p256-comb.a` | `LIB_P256_COMB_ONLY` | 17 | `$07` | `$0007` | `$0007` | 9216 | 1050 | sqtab, reu_mul, lim_lee_comb_p256 (3) |
  | `nistcurves-p256-comb-onchip.a` | `LIB_P256_COMB_ONLY` + `FP_ONCHIP_MUL` | 17 | `$04` | `$0005` | `$0005` | 9216 | 870 | sqtab, lim_lee_comb_p256 (2) |

  **What the two byte figures cover.** Per SPEC §5, `RESIDENT_BYTES` and
  `COLD_BYTES` are **code + rodata only**. RW scratch (the `*_BSS`
  segments), the page-aligned 512 B REU DMA landing pages
  (`LIB_NISTCURVES_TABLES`), and the 1 KB `sqtab` table generated at
  runtime into `LIB_SHARED_SQTAB_BASE` are all excluded and must be
  budgeted separately — see the §8.3 memory map. Worked example for the
  archive most consumers link, measured with `od65 --dump-segments` over
  the extracted members of `build/lib/nistcurves-p256-verify.a`:
  `P256_CODE` 8348 + `MUL_CODE` 477 + `P256_RODATA` 192 = 9017 code +
  rodata (of which 438 B is the cold block itemized in
  `src/lib_manifest.s` — `sqtab_init` + `ct_mul_8x8` 223,
  `reu_fetch_mul_row` 23, `reu_mul_init` 192 — leaving 8579 resident
  against the 8700 equate, §6.6 safe direction; figures after the SPEC
  v0.13.0 §8.2 completion-confirm adoption, issue #130, which added 24 B
  to `fp256.o`, 42 B to `mul_8x8.o` and 6 B to `reu_mul_init.o`),
  **plus** 1351 B BSS
  (`data_p256.o` 1312 + `data_shared.o` 39) + 512 B DMA landing pages,
  and 1024 B of `sqtab` if no sibling library already owns it. Total RAM
  for that archive is therefore 10880 B, or 11904 B counting `sqtab` —
  not the 27000 the *whole-library*
  manifest reports: since v0.9.0 (issue #90) each archive links its own
  `lib_manifest_<variant>.o`, so read the row above for the archive you
  actually link rather than the default one.

  The two `nistcurves-p256-comb*` rows (issue #117) are the verify set
  plus the comb: ZP adds `nistcurves_zp_ptr1` (the `ec_precompute_256`
  anchor-copy pointer — not `zp_tmp1`/`zp_tmp2`, whose only archived
  user is the P-384 comb) for 17 B; REU keeps the comb bank `$02` in
  BOTH profiles because `ec_precompute_256` populates and the comb
  evaluate loop DMA-fetches the anchor table regardless of how multiply
  rows are produced; the precalc enumeration carries `lim_lee_comb_p256`
  but **not** the 24 KB `lim_lee_comb_p384` table the archive lacks
  (the row gates split per curve for exactly this archive).

  Before issue #90, six of the (then) nine rows were wrong: the three
  non-onchip verify/curve archives claimed `REU_BANKS_USED = $07`
  (inherited from the default-profile manifest) despite never shipping
  the Lim-Lee comb objects that are bank 2's only consumer — true value
  `$03` — and their three onchip counterparts claimed `$04` for the same
  reason despite issuing **no REU DMA at all** — true value `$00`, now
  correctly reported by the manifest itself rather than something a
  consumer had to override (see §8.4.2). The precalc-row enumeration had
  the identical defect: `nistcurves-p256-verify.a`, a P-256-only archive
  with zero P-384 code linked in, was advertising a 24 KB
  `lim_lee_comb_p384` REU table it does not contain (and, symmetrically,
  its own `lim_lee_comb_p256` table too — neither minimal verify archive
  ships the comb objects). `ZP_USAGE_BYTES` and `RESIDENT_BYTES`/
  `COLD_BYTES` had the same "one manifest object describes the whole
  library" defect shape #88 first fixed for SHA-384.
  `SHARED_PRIMITIVES`/`SHARED_CONSUMES` were the one pair already correct
  across all nine archives before this fix — the verify/curve archives
  genuinely do ship `mul_8x8.o` (owns sqtab + ct_mul_8x8) and, in the DMA
  profile, `reu_mul_init.o` (owns reu_mul), so no change was needed there.

  The zero-page claim narrows with the rest: `sha384.o` `.importzp`s
  exactly four slots — `sha_src`, `sha_len`, `sha_w_ptr`, `sha_w_ptr2`,
  8 bytes contiguous at `$04..$0b` — and no object in the archive
  references any other, not even `proc_port` (SHA issues no REU DMA, so
  it never banks ROM). `src/zp_config.s` narrows its `.exportzp` surface
  to match under the same switch, so the equate and the archive's real
  export set agree.

  This matters more than the byte count suggests. Zero page is the
  scarcest resource on a 6502: with BASIC and KERNAL live, genuinely
  free ZP on a C64 runs to the low tens of bytes. An archive claiming 32
  against a real need of 8 can push a consumer's collision check into
  rejecting an integration that would have fit comfortably — the same
  fail-closed shape as the `RESIDENT_BYTES` overstatement in issue #90.

  Both mask values are `$0000` rather than absent: the equates are still
  exported, declaring the §8.0 **non-consumer** state for all three
  primitives. A consumer co-linking this archive with a sibling that
  owns `sqtab` / `ct_mul_8x8` therefore passes both the disjointness and
  coverage asserts. Before issue #88 the archive inherited the
  default-profile `$0007/$0007` and failed the disjointness assert on
  that entirely valid link, having claimed to own three primitives whose
  bodies it does not contain.
- `lib-p384-curve` = `lib-p384-verify` ⊕ SHA-384 objects ⊕
  `ecdsa384_msg.o`. Suitable for the TLS 1.3 secp384r1+SHA-384
  cipher-suite use case where the consumer wants a single
  hash-then-verify entry point.

**Note:** the verify / curve archives — both the default-profile ones
and their `*-onchip` counterparts — ship the `-D ECDSA_NO_COMB`
variants of the packaged verifiers (issue #61), so `ecdsa_verify_256` /
`ecdsa_verify_384` / `ecdsa_verify_with_message_384` all link standalone
— `u1·G` runs on the variable-base ladder instead of the excluded comb.
See §8.4.1 for the contract and the performance trade-off.

**Note (issue #81):** every default-profile REU-consuming archive
(`nistcurves.a`, the two verify archives, `lib-p384-curve`) ships the
SPEC §8.2 provider object `reu_mul_init.o` (`reu_mul_init` /
`reu_mul_tables_init`, moved out of the never-archived `main.s`), so
the mandatory §3 boot call `jsr reu_mul_init` links from the archive
alone and the §8.0 ownership bit `$0002` the manifest claims is backed
by a shipped provider. `lib-p384-sha384` (no REU at all) and the
`*-onchip` archives (§8.4.2 — the profile never builds or reads the
REU multiply table) deliberately do not contain it. `make
check-archives` pins both directions.

The PR-#40 source-file split itself changed no bytes; the standalone
test PRG (`make` with no args, default target) has since moved with
normal code evolution — 37302 B at the split, 37171 B after the
issue #54 BSS trim, 37683 B as of v0.7.0's issue #66 verify gate.
Consumers that built their own integration scripts against the
pre-split layout (e.g. `tools/integration/build_nistcurves_p256.sh` in
`c64-https`) can collapse those scripts to a
`make lib-p256-verify && cp` pattern when they next refresh.

### 8.4.1 Packaged verifiers: comb vs no-comb variants

**Contract (issues #60/#61/#63):** every archive is link-complete —
each documented entry point links from its archive alone, with no
external symbol requirements. `make check-archives` pins this.

The packaged verifiers come in **two build variants** of the same
sources (`src/ecdsa256.s` / `src/ecdsa384.s`), differing only in how
`u1·G` is computed:

| Variant | `u1·G` path | Shipped in |
|---|---|---|
| comb (default) | h=8 Lim-Lee fixed-base comb (`ec_scalar_mul[_384]`) | `nistcurves.a` (full), `nistcurves-onchip.a`, `nistcurves-p256-comb.a`, `nistcurves-p256-comb-onchip.a` (issue #117), standalone PRG |
| `-D ECDSA_NO_COMB` | variable-base ladder seeded at `G` (`ec_scalar_mul_var[_384]`) | `nistcurves-p256-verify.a`, `nistcurves-p384-verify.a`, `nistcurves-p384-curve.a`, and their `*-onchip` counterparts (`nistcurves-p256-verify-onchip.a`, `nistcurves-p384-verify-onchip.a`, `nistcurves-p384-curve-onchip.a`) |

The no-comb variant exists so the trimmed verify archives need no
`points256_comb.o` / `points384_comb.o` (issue #60's gap, closed by
issue #61). Functional behaviour is identical — the full oracle ECDSA
suite passes against a no-comb build, including the `u1 ≡ 0 (mod n)`
infinity edge (both paths return the all-zero Jacobian encoding).

**Choosing a variant:**

- **Verify archives (no-comb).** No comb objects, no
  `ec_precompute_256/384` boot pass (~17 min / ~34 min at 1 MHz in the
  default profile — §8.5, issue #121), no
  REU bank-2 anchor residency (P-256 16 KB at `$0000..$3FFF`; P-384
  24 KB at `$4000..$9F9F`). **Trade-off:** `u1·G` runs a full
  variable-base double-and-add instead of the comb, so a verify costs
  roughly two variable-base scalar multiplies instead of one-plus-comb
  — up to ~2× slower per verify. Right choice for RAM/boot-constrained
  or occasional-verify consumers.
- **Comb archives.** Comb-accelerated `u1·G`; pay the boot pass
  + REU residency. Right choice for verify-throughput consumers.
  Note: adding the comb objects to a verify archive's link line does
  **not** restore comb speed — the archive's `ecdsa*_nocomb.o` has the
  variable-base path baked in. Comb-speed packaged P-256 verify means
  linking `nistcurves-p256-comb.a` / `nistcurves-p256-comb-onchip.a`
  (issue #117 — the minimal comb-fast set, no P-384/SHA members) or
  `nistcurves.a` / `nistcurves-onchip.a` (whole library). For P-384
  there is no minimal comb archive yet; comb-speed P-384 verify means
  the full archive (or composing your own object set from
  `build/ecdsa384.o` + comb objects).
- **Either variant, driving primitives directly.** The building blocks
  (`ec_scalar_mul_var`, `ec_point_add[_jj]`, `ec_jacobian_to_affine`,
  `fp_mod_inv`, `fp_mod_mul`, …) remain exported from all curve
  archives — the pre-#61 `c64-https` pattern keeps working unchanged.

**Ratchet:** `make check-archives` (`tools/check_archives.py`) — an
od65 import/export closure sweep plus `ld65` dummy-link smoke tests per
archive, checked against the documented expectations. Any drift (a new
unresolved symbol, or an expectation that flips) exits non-zero. Run it
after any change to the archive object sets or the ECDSA call graph.
To exercise the no-comb functional path end-to-end:
`make nocomb-prg`, then run `tools/test_ecdsa_verify.py` with
`C64_PRG_NAME=nist-curves-nocomb.prg C64_LABELS_NAME=labels_nocomb.txt
C64_SKIP_BUILD=1`.

### 8.4.2 FP_ONCHIP_MUL turbo profile (issue #69)

The REU's DMA transfer rate is anchored to the ~1 MHz C64 bus clock, so
on accelerated hosts (Ultimate 64 / C64 Ultimate turbo, SuperCPU-class)
the per-row multiply-table fetch inside `fp_mul` / `fp_sqr` becomes a
speed-invariant wall-clock floor: measured on a C64 Ultimate (fw 1.1.0),
`ecdsa_verify_256` carries a **22.2 s floor (87% of total wall at
64 MHz)** and `ecdsa_verify_384` a 51.7 s floor. These floor figures
are specific to that device and firmware: the per-row stall is a
firmware/generation-dependent wall-clock constant (~160 wall-ticks per
512 B row on C64U fw 1.1.0 vs ~189 on U64E fw 3.14; 532 cy on a real
1750 and under VICE — see issue #83 and c64-x25519
`docs/design/issue_72_onchip_mul.md`).

The **turbo profile** (`-D FP_ONCHIP_MUL`, shipped pre-built as the
`*-onchip.a` archives) replaces every REU row fetch with sparse on-chip
row generation: `gen_mul_row` / `gen_mul_row_384` (entry stubs in
`fp256.s` / `fp384.s`, shared loop `og_common` in `mul_8x8.s`) compute
— via the canonical §8.3 `ct_mul_8x8`, body unmodified — exactly the
`mul_dma_lo/hi` entries the inner loops will read for the current row.
Inner loops, SMC accumulators, and the sparse zero-byte fast path are
byte-identical to the default profile.

Measured on C64 Ultimate hardware (oracle-gated; issue #71 inline
quarter-square row generator, 2026-07-20):

| `ecdsa_verify_256` | 1 MHz (est.) | 16 MHz | 48 MHz | 64 MHz |
|---|---|---|---|---|
| default (DMA table) | ~5 min | 37.9 s | 28.2 s | 25.5 s |
| turbo (on-chip)     | ~12 min | 46.4 s | **15.8 s** | **11.8 s (2.16×)** |

Crossovers: **~22 MHz for P-256, ~33 MHz for P-384**. At stock 1 MHz
the DMA-table profile is ~2.5× faster (extrapolated from the measured
CPU-work fits) — the turbo profile is a complement, not a replacement.
P-384 @64 MHz: 62.0 s → 39.1 s (1.59×). Full A/B data:
`.research/issue71_shape2_2026_07_20/`.

**Measurement scope:** the A/B table, floors, and crossovers above
were measured on a C64 Ultimate fw 1.1.0 only; the "1 MHz (est.)"
column is a projection from the CPU-work fits, not a measurement.
Because the per-row DMA stall is a firmware/generation-dependent
wall-clock constant (~160 wall-ticks C64U fw 1.1.0 vs ~189 U64E
fw 3.14 per 512 B row; 532 cy on a real 1750 and under VICE), the
crossover points do not transfer across devices — a U64E baseline
measures a larger floor and a lower crossover — and neither Ultimate
generation reproduces real-1750 1 cy/byte DMA under turbo, so any
"real 1750 + accelerator" figure is likewise a projection. See
issue #83 and c64-x25519 `docs/design/issue_72_onchip_mul.md`.

**Contract deltas vs the default profile:**

- **REU banks (§5):** `LIB_NISTCURVES_REU_BANKS_USED = $04` (comb bank
  only) for the comb-carrying onchip archives — `nistcurves-onchip.a`
  (both combs) and `nistcurves-p256-comb-onchip.a` (P-256 comb, issue
  #117). The three onchip verify/curve archives (`*-verify-onchip.a`,
  `nistcurves-p384-curve-onchip.a`) correctly report `$00`: none of them ship the comb objects,
  so bank 2 is never referenced, and the onchip profile already drops
  banks 0/1. Before issue #90 all four onchip archives inherited the
  same `$04` from one shared manifest object, over-claiming REU for the
  three that in fact issue **no REU DMA at all** — the same REU-less
  claim this doc's own opening summary makes (§1) and `make
  onchip-nocomb-prg` + `C64_NO_REU=1` runtime-validates (35/35, CLAUDE.md
  "Key optimizations"), but which the manifest equate itself previously
  contradicted. The manifest now states it natively rather than
  requiring a consumer override. (Issue-#33 defensive REU register
  writes remain at entry points regardless; they are harmless
  expansion-I/O writes and claim no banks.)
- **Boot obligation:** onchip consumers need only `sqtab_init` — no
  §8.2 `reu_mul` provider, and (verify archives) no `ec_precompute_*`.
  Accordingly the onchip archives do not ship `reu_mul_init.o` (the
  §8.2 provider object every default-profile archive carries,
  issue #81) — `reu_mul_init` is deliberately unlinkable from them.
- **Resident/cold (§5):** the row generator (~250 B) becomes verify-hot
  and the REU row-fetch path drops out — a net delta inside the §5
  rounding, so `RESIDENT_BYTES` still shares one figure across both
  profiles for a given variant (27000 for the full archive; see §8.4 for
  the per-variant figures). `COLD_BYTES` does **not** share across
  profiles: every default/onchip pair differs by ~186-200 B, the
  boot-only `reu_mul_init` body present in every DMA-profile archive and
  absent from every onchip one (issues #78/#81) — 1840 vs. 1650 for the
  full archive, and a larger relative delta (26-35%) on the minimal
  archives, outside the SPEC §5 ±5% band either way (issue #90). Note the
  runtime-generated 1 KB `sqtab` RAM table is verify-hot under this
  profile but excluded from the equates (generated RW state, not
  code+rodata) — budget it separately at `LIB_SHARED_SQTAB_BASE`.
- **§8.0 mask / §8.0 precalc enumeration:** the onchip manifest omits
  the §8.2 `reu_mul` ownership bit (standalone onchip mask `$0005`) and
  the onchip archives do not enumerate the `reu_mul` precalc table —
  the profile has no REU multiply table to own (issue #78, matching
  c64-x25519 PR #73).
- **Not constant-time:** unchanged from the default verify path (public
  inputs only; do not repurpose for signing).

To exercise the profile end-to-end: `make onchip-prg`, then
`tools/test_ecdsa_verify.py` with `C64_PRG_NAME=nist-curves-onchip.prg
C64_LABELS_NAME=labels_onchip.txt C64_SKIP_BUILD=1` (add
`C64_INIT_TIMEOUT=1800` — the on-chip precompute boots ~3× slower under
VICE warp).

### 8.5 Initialization sequence

Follow the call sequence documented in §3 — any deviation (skipping
`sqtab_init`, calling `ec_scalar_mul` before `ec_precompute_256`, etc.)
will produce silent wrong answers or infinite loops.

Boot cost at 1 MHz (measured via the KERNAL jiffy clock under VICE,
NTSC, VIC blanked — issue #121; the table this section carried through
v0.11.0 quoted `ec_precompute_*` figures that were ~40× low, VICE
warp-mode *wall* seconds having been passed off as real-C64 time):

| Step | default (REU DMA) | `FP_ONCHIP_MUL` |
|---|---|---|
| `sqtab_init` | <1 s | <1 s |
| `reu_mul_init` | ~7 s (~4 s prior baseline + ~2.8 s from the constant-time `mul_8x8` port, issue #14) | — (not built) |
| `ec_precompute_256` | **~1038 Mcyc ≈ 17 min** | **~2061 Mcyc ≈ 34 min** |
| `ec_precompute_384` | **~2108 Mcyc ≈ 34 min** | **~4782 Mcyc ≈ 78 min** |

Turbo scaling differs by profile: the **onchip** precompute is pure CPU
work and scales with the host clock (P-256: ~45 s at 48 MHz / ~34 s at
64 MHz, consumer-measured on U64E), while the **default-profile**
precompute is dominated by wall-clock-anchored REU row fetches at turbo
(issue #83) and does not divide by the clock multiplier.

**Consumer sizing note (issue #121):** at stock 1 MHz the comb fill
costs on the order of several ECDSA verifies, so the comb archives pay
off only for sessions doing repeated verifies (or hosts that keep REU
bank 2 populated across runs); a single-verify session at 1 MHz is
better served by the `*-verify` archives' variable-base path. This is
the number that decides comb-vs-no-comb shippability — it was wrong by
the amortisation-flipping margin until this correction.

The `reu_mul_init` row applies to the default (DMA-table) profile only:
`FP_ONCHIP_MUL` turbo-profile consumers (§8.4.2) skip it — their boot
obligation is `sqtab_init` alone (plus `ec_precompute_*` if they link a
comb-carrying onchip archive and use fixed-base scalar_mul).

Programs using only one curve may omit the other's `ec_precompute_*`
call. Programs using neither curve's scalar_mul (e.g. only raw field
arithmetic or point double/add on caller-supplied points) may omit both
`ec_precompute_*` calls and save the whole precompute cost — **~3146
Mcyc ≈ 51 min at 1 MHz** in the default profile, ~6843 Mcyc ≈ 112 min
onchip (the two rows of the table above summed) — at the price of
losing `ec_scalar_mul` and `ec_scalar_mul_384`. (The "~100 s" this
sentence carried through v0.11.2 was one of the VICE warp-mode
wall-second figures issue #121 corrected; it was missed in that
sweep.)

### 8.6 Version compatibility checks

The library exports four integer constants for link-time version
checks, defined in `src/lib_version.s` (the fourth, `LIB_ABI_VERSION`,
landed in v0.3.0 per c64-lib-contract SPEC §1):

```asm
.import LIB_NISTCURVES_VERSION_MAJOR, LIB_NISTCURVES_VERSION_MINOR
.import LIB_NISTCURVES_VERSION_PATCH, LIB_NISTCURVES_ABI_VERSION

.assert (LIB_NISTCURVES_VERSION_MAJOR > 0) .or (LIB_NISTCURVES_VERSION_MINOR >= 10), lderror, "c64-nist-curves v0.10 or newer is required"
.assert LIB_NISTCURVES_ABI_VERSION = 2, lderror, "c64-nist-curves ABI v2 expected; rebuild consumer"
```

This uses `.assert`/`lderror` rather than `.if`/`.error`. `.if` requires
an assembly-time constant, and an `.import`ed symbol has no value until
link — the `.if` form does not silently pass or skip, it fails to
assemble outright with `Error: Constant expression expected`
(c64-lib-contract issue #73). `.assert ..., lderror, ...` defers
evaluation to ld65, the first stage that actually knows the imported
constant's value. The cost: the guard now fires at **link time** rather
than assemble time — one step later in the build — but it still fires
before anything runs, so a mismatched consumer is still caught before
producing a bad PRG, just via a `ld65` error instead of a `ca65` error.

`LIB_NISTCURVES_ABI_VERSION` is the load-bearing gate for consumers
pinning to a specific ABI generation — it changes only when public
exports are removed or renamed. Note it is **not** in lockstep with
`LIB_NISTCURVES_VERSION_MAJOR` pre-1.0: SPEC §7 describes breaking
changes riding MINOR bumps while the contract is in v0.x, so MAJOR
stays 0 across exactly the breakage this gate exists to catch. It is
instead an independent generation counter starting at 1 (this library
shipped 0 from v0.3.0 through v0.8.0 — an outlier against the other
contract adopters — and corrected to 1 at v0.9.0; see the versioning
note in `src/lib_version.s`). Watch `LIB_NISTCURVES_ABI_VERSION`
directly rather than inferring it from MAJOR.

**Bare vs prefixed forms.** The library-prefixed names above are
canonical as of c64-lib-contract v0.7.0. The library additionally exports
the unprefixed `LIB_VERSION_MAJOR` / `_MINOR` / `_PATCH` /
`LIB_ABI_VERSION` as aliases, so consumers written against v0.8.0 and
earlier keep working with no change. Those bare names are **deprecated
and removed at contract v1.0**: they are identical across every library
adopting the contract, so a consumer that links two sibling libraries and
imports both manifests gets

```text
ld65: Error: Duplicate external identifier: 'LIB_VERSION_MAJOR'
```

A consumer composing two or more contract libraries builds **all** of
them with

```sh
ca65 -D LIB_NO_BARE_EXPORTS=1 ...
```

which suppresses the bare forms library-wide, and imports the prefixed
names only. Beyond avoiding the collision, the prefixed form makes a
version guard name *which* library is out of date instead of reporting
one anonymous version. Single-library consumers need not define it.

The same `-D LIB_NO_BARE_EXPORTS=1` switch also suppresses the bare
`LIB_PRECALC_<name>_*` triples described in §8.6.1 — it is one build-wide
flag covering both symbol families.

The library is currently in the v0.x pre-stable series. Version policy:

- **PATCH** bumps (v0.7.0 → v0.7.1) ship bugfixes or performance
  improvements with no public API changes. Always safe to adopt;
  `LIB_ABI_VERSION` unchanged.
- **MINOR** bumps (v0.6.x → v0.7.0) may add public symbols (new entry
  points, new constants, new SPEC §3/§5/§8 manifest equates) but will
  not remove or rename existing ones. Additive changes; safe to adopt
  if your consumer's `.import` list is a subset of what the new
  version exports. `LIB_ABI_VERSION` unchanged.
- **MAJOR** bumps (v0.x → v1.0) are reserved for the first stability
  commitment. After v1.0.0, MAJOR bumps indicate breaking API changes
  and will be documented in CHANGELOG.md with migration notes.
  `LIB_ABI_VERSION` bumps in lockstep.

Consumers should pin to a specific tag rather than tracking the
mainline branch. The `src/lib_version.s` constants are the authoritative
source; the `VERSION` file at the repository root is a convenience
mirror for non-ca65 tooling (CI scripts, Makefile version variables).

### 8.6.1 SPEC §3 / §5 / §8 manifest equates (v0.3.0+)

c64-lib-contract adoption added a per-section override + introspection
surface a consumer can use at assemble time to (a) override placement
decisions and (b) detect cross-library conflicts when linking multiple
sibling crypto libraries into the same PRG.

**§3 REU placement** (consumer overrides via `ca65 -D`):

```sh
ca65 -D LIB_NISTCURVES_REU_BANK_MUL=$03 ...        # default $00
ca65 -D LIB_NISTCURVES_REU_BANK_COMB=$05 ...       # default $02
ca65 -D LIB_NISTCURVES_REU_OFFSET_COMB_P256=$0000  # default $0000
ca65 -D LIB_NISTCURVES_REU_OFFSET_COMB_P384=$4000  # default $4000
```

**§5 manifest equates** (consumer imports for cfg-side fit checks):

```asm
.import LIB_NISTCURVES_REU_BANKS_USED       ; bitmask, default $07 ($00-$07 depending on archive, §8.4)
.import LIB_NISTCURVES_ZP_USAGE_BYTES       ; default 27, 8-23 for the minimal archives (§8.4)
.import LIB_NISTCURVES_RESIDENT_BYTES       ; default 27000
.import LIB_NISTCURVES_COLD_BYTES           ; default 1840 (1650 under FP_ONCHIP_MUL; §8.4)
.import LIB_NISTCURVES_SHARED_PRIMITIVES    ; standalone default $0007
                                            ; (sqtab | reu_mul | ct_mul_8x8);
                                            ; conditional per SPEC §8.0 — each
                                            ; defined SHARED_* deferral switch
                                            ; drops its bit
```

**§8.1 shared `sqtab`** (cross-library shared primitive — consumer
provides one base address, all sqtab-consuming sibling libs agree):

```sh
ca65 -D LIB_SHARED_SQTAB_BASE=$8800   # any page-aligned address; $9c00 is the default
```

Page-aligned + `sqtab_hi = sqtab_lo + $0200` are
enforced by `.assert` in `src/mul_8x8.s`.

**§8.2 shared `reu_mul` placement** (contract v0.8.5 export discipline). The
consumer-*input* equates `LIB_SHARED_REU_MUL_BANK` / `_OFFSET` /
`_BANKS_USED` are **not exported** — they are unprefixed names every §8.2
consumer defines, so exporting them collides in any composed link. Override
them the same way as the sqtab base:

```sh
make lib CONTRACT_DEFINES='-D LIB_SHARED_REU_MUL_BANK=0x03'
```

What this library exports instead is the prefixed *output* counterparts, whose
values are **the values the REU access paths actually read** — so a consumer
can verify co-linked libraries agree on placement:

<!-- check-docs: external="LIB_X25519_SHARED_REU_MUL_BANK" -->
```asm
.import LIB_NISTCURVES_SHARED_REU_MUL_BANK
.import LIB_X25519_SHARED_REU_MUL_BANK
.assert LIB_NISTCURVES_SHARED_REU_MUL_BANK = LIB_X25519_SHARED_REU_MUL_BANK, lderror, "co-linked libraries disagree on reu_mul placement"
```

**§8.2 post-execute settle knob** (SPEC v0.13.0, issue #130).
`LIB_NISTCURVES_REU_SETTLE_ITER` (default 8; 1..255) sets how many
9-cycle iterations `nistcurves_reu_dma_wait` settles for after every REU
execute at a tight site, on top of the `$DF00` bit-6 confirm. The
default's ~107-cycle execute-to-next-write distance is 2.2× the measured
floor (≥ 49 cycles at 48 MHz, U64E fw 3.15). The floor is
**unbracketed at 64 MHz**; a consumer running a C64 Ultimate at that
clock raises the knob until a FAIL/PASS bracket exists (§13.6's ~63 µs
fence ≈ 450 iterations is the contract's safe over-estimate — cap at 255
and split across the boot cost if you need more):

```sh
make lib CONTRACT_DEFINES='-D LIB_NISTCURVES_REU_SETTLE_ITER=32'
```

The equate is exported `:abs` as the value the code reads, so a consumer
can `.import` it and `.assert` the archive settles for what it expects.
`nistcurves_reu_dma_timeout` (BSS, sticky) is 1 if any bounded spin
expired; see §4.

`lderror`, not `error`: the operands are imports and have no value until link
(§8.6's guard rule). `LIB_NISTCURVES_SHARED_REU_MUL_BANKS_USED` is derived from
the same code-read bank, so it can be composed straight into a §3 REU-region
collision `.assert`.

The "values the code reads" wording is load-bearing rather than pedantic. These
outputs alias `LIB_NISTCURVES_REU_BANK_MUL` — the symbol `fp256.s` / `fp384.s`
actually load into the REU bank register — not the `LIB_SHARED_REU_MUL_BANK`
knob, because **both spellings relocate the table**:

| override | code reads | exported output |
|---|---:|---:|
| *(none)* | `$00` | `$00` |
| `-D LIB_SHARED_REU_MUL_BANK=3` | `$03` | `$03` |
| `-D LIB_NISTCURVES_REU_BANK_MUL=5` | `$05` | `$05` |

Aliasing the knob would publish `$00` in the third row while the code read
`$05` — an export that certifies nothing, which is the exact defect contract
v0.8.5 cites from `c64-x25519`'s pre-#92 form. `LIB_NISTCURVES_SHARED_PRIMITIVES`
bit `$0001` (= `LIB_SHARED_PRIMITIVES_SQTAB`) signals to consumers that
this library claims ownership of the §8.1 primitive; consumers `.assert
(LIB_NISTCURVES_SHARED_PRIMITIVES & LIB_X_SHARED_PRIMITIVES) = 0` to
catch double-ownership at link time when also pulling in another
sqtab-consuming sibling (`c64-x25519`, `c64-ChaCha20-Poly1305`). See
c64-lib-contract SPEC §8.1 for the full placement contract.

> **Use `&`, not `.and`.** ca65's `.and` is the *boolean* operator; on
> integer masks it evaluates operands for truthiness, so two correctly
> **disjoint** masks like `$0005` and `$0002` yield true-and-true = true
> and the assert fires spuriously. The bitwise operator is `&`. (Fixed
> upstream in c64-lib-contract v0.4.2, issue #41; this page carried the
> `.and` spelling until issue #86.)

The mask is **conditional** (SPEC §8.0, v0.4.0): building with a
primitive's deferral switch defined (`-D SHARED_SQTAB_INIT`,
`-D SHARED_REU_MUL_INIT`, `-D SHARED_CT_MUL_8X8`) gates out this
library's copy AND drops the matching bit (`$0001` / `$0002` / `$0004`)
from `LIB_NISTCURVES_SHARED_PRIMITIVES`, so exactly one co-linked
sibling owns each shared primitive and the disjointness `.assert`
holds. Standalone default-profile builds (no switches) export `$0007`;
`FP_ONCHIP_MUL` builds additionally omit the §8.2 bit and export
`$0005` — the profile has no reu_mul table to own, which is a
deliberate omission rather than a `SHARED_REU_MUL_INIT` deferral
(§8.4.2, issue #78).

**Companion mask `LIB_NISTCURVES_SHARED_CONSUMES`** (SPEC §5 + §8.0,
required since contract v0.5.0; adopted here in issue #86). The
ownership mask alone is ambiguous when a bit is *clear*, because two
different build configurations clear it for opposite reasons:

| State | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` | What the consumer must do |
|---|---|---|---|
| **owner** | set | set | Nothing — this library provides the primitive. |
| **deferring consumer** | clear | set | Ensure exactly one *other* module in the link owns it, and that boot initializes it before first use. |
| **non-consumer** | clear | clear | Nothing — the primitive is absent from this build entirely. |

This library is the worked example the contract clause was written
against: our `-D SHARED_REU_MUL_INIT` build and our `-D FP_ONCHIP_MUL`
build both export `LIB_NISTCURVES_SHARED_PRIMITIVES = $0005`, but the
first *requires* a §8.2 provider elsewhere in the link and the second
requires none. The consumes mask separates them:

| Build configuration | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` |
|---|---|---|
| default, standalone | `$0007` | `$0007` |
| default + `-D SHARED_REU_MUL_INIT` | `$0005` | `$0007` |
| `-D FP_ONCHIP_MUL` | `$0005` | `$0005` |

The gating rule: **profile switches** (`FP_ONCHIP_MUL`) drop a bit from
*both* masks; **deferral switches** (`SHARED_*`) drop it from the
ownership mask *only*. The library pins the invariant itself at
assemble time in `src/lib_manifest.s`:

```asm
.import LIB_NISTCURVES_SHARED_PRIMITIVES, LIB_NISTCURVES_SHARED_CONSUMES
.assert (LIB_NISTCURVES_SHARED_PRIMITIVES & ~LIB_NISTCURVES_SHARED_CONSUMES) = 0, error, "a build cannot own a primitive it does not consume"
```

Consumers pair the existing disjointness check with a coverage check, so
every consumed primitive has exactly one owner somewhere in the link.
`LIB_X_SHARED_PRIMITIVES` / `LIB_X_SHARED_CONSUMES` stand for whichever
sibling library you're co-linking (e.g. `c64-x25519`) — its own manifest
equates, not this library's:

<!-- check-docs: external="LIB_X_SHARED_PRIMITIVES, LIB_X_SHARED_CONSUMES" -->
```asm
.import LIB_NISTCURVES_SHARED_PRIMITIVES, LIB_NISTCURVES_SHARED_CONSUMES
.import LIB_X_SHARED_PRIMITIVES, LIB_X_SHARED_CONSUMES
; no double ownership (v0.4.0)
.assert (LIB_NISTCURVES_SHARED_PRIMITIVES & LIB_X_SHARED_PRIMITIVES) = 0, error, "shared-primitive double-ownership"
; no consumed primitive without an owner (v0.5.0)
.assert ((LIB_NISTCURVES_SHARED_CONSUMES | LIB_X_SHARED_CONSUMES) & ~(LIB_NISTCURVES_SHARED_PRIMITIVES | LIB_X_SHARED_PRIMITIVES)) = 0, error, "consumed shared primitive with no owner in the link"
```

If the consumer application supplies a primitive from its own modules
(the original intent of the `SHARED_*` switches — every linked library
defers, the app provides), OR its own contribution into the owner union:

<!-- check-docs: external="LIB_X_SHARED_PRIMITIVES, LIB_X_SHARED_CONSUMES" -->
```asm
.import LIB_NISTCURVES_SHARED_PRIMITIVES, LIB_NISTCURVES_SHARED_CONSUMES
.import LIB_X_SHARED_PRIMITIVES, LIB_X_SHARED_CONSUMES
APP_OWNED = $0001   ; LIB_SHARED_PRIMITIVES_SQTAB per c64-lib-contract SPEC §8.0's
                    ; bit-allocation table ($0001 sqtab | $0002 reu_mul | $0004 ct_mul_8x8)
.assert ((LIB_NISTCURVES_SHARED_CONSUMES | LIB_X_SHARED_CONSUMES) & ~(LIB_NISTCURVES_SHARED_PRIMITIVES | LIB_X_SHARED_PRIMITIVES | APP_OWNED)) = 0, error, "consumed shared primitive with no owner in the link"
```

The bit value is spelled out literally rather than imported as
`LIB_SHARED_PRIMITIVES_SQTAB`: per c64-lib-contract SPEC v0.7.3, the §8.x
per-primitive bit constants (`LIB_SHARED_PRIMITIVES_SQTAB` / `_REU_MUL` /
`_CT_MUL_8X8`) MUST NOT be `.export`ed, precisely because they are
unprefixed and identically valued across every adopting library —
exporting them would reintroduce the same duplicate-identifier collision
in a two-library link that this whole section exists to avoid. This
library does not export them (conformant since c64-lib-contract issue
#86), so `.import LIB_SHARED_PRIMITIVES_SQTAB` here would fail to link
with an unresolved external. If a future SPEC revision assigns different
bit values, re-check this against the current §8.0 allocation table
rather than assuming `$0001` is permanent.

One subtlety worth stating explicitly, because it looks like an error:
the `FP_ONCHIP_MUL` build claims §8.3 `ct_mul_8x8` (`$0004`) in **both**
masks. The issue #71 row generator inlines its own quarter-square for
the per-product inner loop, but `og_common` still `jsr`s the canonical
`ct_mul_8x8` once per generated row for the `a*a` diagonal — a genuine
runtime call (this is precisely the call that made `-D
SHARED_CT_MUL_8X8` fail to assemble against the onchip TU until issue
#123 added the gated provider-surface imports). And per SPEC §8.0,
shipping a primitive's canonical body counts as consuming it in any
case — the body is present, callable, and available for a co-linked
sibling to defer to. Dropping the bit would break that sibling's
deferral.

Deferring builds (issue #123): under `-D SHARED_CT_MUL_8X8` this TU
imports the five-symbol §8.3 provider surface — `ct_mul_8x8`, the two
`smc_*_a_imm` SMC bake sites, and the `poly_prod_lo/hi` product cells —
instead of defining it, so APP_OWNED × onchip is reachable per §6.3.
The product cells travel with the body: a deferring build's runtime
callers must read the cells the *provider's* body writes. Consequence:
the app-owned archive carries `poly_prod_lo`/`poly_prod_hi` as
documented unresolved externals (the app's §8.3 provider exports them,
as both fleet providers already do); `make check-archives` pins the
surface exported from every owning archive, absent from the deferring
one, and assembles APP_OWNED × both profiles as a standing
reachability leg.

**§8.0 precalc-table manifest** (`src/precalc_manifest.s`): alongside
the equates above, every archive ships the SPEC §8.0 precalculated-table
enumeration — one `LIB_PRECALC_TABLE` macro invocation (macro defined in
`src/precalc_table.inc`, copied verbatim from c64-lib-contract) per
table of ≥ 256 B that is REU-resident, hot-loop-read, or page-aligned.
Default-profile archives enumerate five tables: `sqtab` (1 KB RAM),
`reu_mul` (128 KB REU), `lim_lee_comb_p256` (16 KB REU),
`lim_lee_comb_p384` (24 KB REU), `sha384_k` (640 B RODATA). The
`FP_ONCHIP_MUL` archives ship `precalc_manifest_onchip.o`, which gates
out the `reu_mul` row (the profile never builds that table — no
`*_PRECALC_reu_mul_*` exports at all; issue #78); see the Profiles
column in `docs/precalc-tables.md` for the per-profile enumeration.

Each invocation exports **two** equate triples since contract v0.7.0
(adopted here in issue #86):

| Form | Symbols | Status |
|---|---|---|
| prefixed | `LIB_NISTCURVES_PRECALC_<name>_{SIZE,REGION,SHARED}` | canonical |
| bare | `LIB_PRECALC_<name>_{SIZE,REGION,SHARED}` | deprecated, removed at contract v1.0 |

The bare triple is what collides when two adopters describe the same
shared table — measured upstream between `c64-x25519` v0.8.0 and
`c64-ChaCha20-Poly1305` v0.6.0 on `LIB_PRECALC_sqtab_*`, which is why
the prefix exists. A consumer composing two or more contract libraries
builds them all with `-D LIB_NO_BARE_EXPORTS=1` (the same flag that
governs the §8.6 version equates) and imports the prefixed forms, which
additionally lets it cross-check that two libraries *agree* on a shared
table's shape — a check the bare form could never express, since both
libraries emitted the same symbol name. Default single-library builds
keep emitting both.

Discover them with:

```sh
od65 --dump-exports build/precalc_manifest.o | grep _PRECALC_
```

Note both details of that command. Dump the **`.o`**, not the `.a` —
`od65` reads single ca65 object files only and reports `(no xo65 object
file)` on an archive while still exiting `0`, so a grep over its output
silently finds nothing. And grep on **`_PRECALC_`**, not `LIB_PRECALC_`,
so the pattern matches the prefixed and bare forms alike.

Also note the address-size limit on the assemble-time form: a consumer
can `.import` a `_SIZE` equate and `.assert` on it only for tables
≤ 65535 B, since ca65's `.import` has no 24-bit hint. Importing
`LIB_NISTCURVES_PRECALC_reu_mul_SIZE` (131072) raises `Range error`; use
the `od65` dump for that one. The producer-side `.export` is unaffected.

**§6.6 consumer footprint assert** (SPEC v0.10.0). The §5 figures are
per-archive (§6.4) and safe-direction (each ≥ the measured sum for that
archive), so a consumer can gate its build on them: `declared ≤ budget`
implies `actual ≤ budget`, and a library bump that outgrows the budget fails
the link with a named cause instead of an opaque segment overflow.

<!-- check-docs: external="__CRYPTO_HOT_SIZE__" -->
```asm
; consumer side -- one per linked archive, in the consumer's own build.
; __CRYPTO_HOT_SIZE__ is the consumer's own region size, published by
; `define = yes` on that area in the consumer's cfg.
.import LIB_NISTCURVES_RESIDENT_BYTES, LIB_NISTCURVES_COLD_BYTES
.import __CRYPTO_HOT_SIZE__
.assert LIB_NISTCURVES_RESIDENT_BYTES + LIB_NISTCURVES_COLD_BYTES <= __CRYPTO_HOT_SIZE__, lderror, "c64-nist-curves does not fit the CRYPTO_HOT region"
```

Consumers with split budgets assert `RESIDENT` and `COLD` separately against
the regions that hold them -- `COLD` is reclaimable-after-init and may
legitimately live in a different budget, which is why the pair is published
as two equates rather than one sum.

The doc-level twin (with the per-table classification rationale) is
`docs/precalc-tables.md`; the two forms must stay in lock-step.

### 8.7 Reference integrations

The `c64-https` and `c64-wireguard` projects are planned reference
integrations. Both have adopted ca65 sufficient to drive
the c64-lib-contract SPEC §6 archive-link pattern, and tracking issues
for the sqtab §8.1 placement contract are open in
[`c64-ChaCha20-Poly1305`](https://github.com/JC-000/c64-ChaCha20-Poly1305/issues/40)
(needed for `c64-wireguard` ingestion). `c64-x25519` shipped its §8.1
side concurrently with this library's v0.3.0 in
[c64-x25519 PR #56](https://github.com/JC-000/c64-x25519/pull/56);
once `c64-ChaCha20-Poly1305` lands its side, the
`c64-wireguard`-driven multi-sibling integration pattern (one consumer
linking against this library + `c64-x25519` + `c64-ChaCha20-Poly1305`,
all sharing one `sqtab` via `LIB_SHARED_SQTAB_BASE`) will be the
canonical worked example for §8.1 + §6 cross-library composition.

### 8.8 Releases

Tagged releases are published at
https://github.com/JC-000/c64-nist-curves/releases. Consumers
should pin to a specific `vMAJOR.MINOR.PATCH` tag (as shown in §8.1)
and consult `CHANGELOG.md` for the per-release notes before bumping.

## 9. References

- `CLAUDE.md` — architecture overview, re-entrancy contract, optimization
  history, and known issues.
- `README.md` — benchmark results and current performance numbers.
- `src/zp_config.s` — editable zero-page allocation.
- `src/data_shared.s`, `src/data_p256.s`, `src/data_p256_invref.s`,
  `src/data_p256_limlee.s`, `src/data_p384.s`, `src/data_p384_limlee.s`,
  `src/data_sha.s`, `src/data_test.s` — data-segment layout, including all
  shared scratch buffers (split from the former monolithic `data.s`).
- `docs/precalc-tables.md` — SPEC §8.0 precalculated-table enumeration
  (doc twin of `src/precalc_manifest.s`).
- `build/labels.txt` — authoritative VICE symbol table with current addresses.
