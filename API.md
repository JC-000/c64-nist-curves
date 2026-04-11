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
- Fixed-base scalar multiplication `k * G` via a 4-way width-1 Lim-Lee comb
  over a REU-resident precompute table
- Jacobian-to-affine conversion for result export

Target platform: 6502 @ 1 MHz with a 1764 / 1750 / compatible REU. Source is
ACME assembler syntax (`acme -f cbm`).

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
buffers requires editing the labels in `src/data.asm`; relocating the zero-page
slots only requires editing `src/zp_config.asm`.

| Region | Address range | Purpose |
|---|---|---|
| PRG code | `$0801`-`$57FF` (approx.) | BASIC stub, boot code, math routines. Current PRG size: 20055 bytes. |
| P-256 field buffers | `$4608`-`$49E9` | `fp_wide`, `fp_tmp1..4`, `fp_r0..3`, `fp_inv_*` (see `data.asm`). |
| P-256 point buffers | `$47CA`-`$49E9` | `ec_p1`, `ec_p2`, `ec_p3`, `ec_t1..6`, `ec_affine_x/y`. Overlap in table above reflects contiguous placement in `data.asm`. |
| `mul_cached_a` / `mul_src2_buf` / reduction scratch | `$49EA`-`$4AFF` (approx.) | Shared multiply scratch and Solinas accumulator. |
| `mul_dma_lo` (page-aligned) | `$4B00`-`$4BFF` | REU DMA target: low bytes of the current multiply row. |
| `mul_dma_hi` | `$4C00`-`$4CFF` | REU DMA target: high bytes of the current multiply row. |
| P-384 field + point buffers | `$4D21`-`$5365` | `fp384_wide`, `fp384_tmp1..4`, `fp384_r0..3`, `fp384_inv_*`, `ec384_p1/p2/p3`, `ec384_t1..6`, `ec384_affine_x/y`. |
| Lim-Lee anchors + working scalar (P-256) | `$5367`-`$5486` | `ec_anchor1..4_x/y`, `cm_k`. |
| Lim-Lee anchors + working scalar (P-384) | `$5487`-`$56F6` | `ec_anchor1..4_384_x/y`, `cm_k_384`. |
| Quarter-square multiply tables | `$7800`-`$7BFF` (1 KB) | `sqtab_lo` / `sqtab_hi`. Built once by `sqtab_init`. |
| Zero-page | ~16 bytes, see `zp_config.asm` | `$02`-`$03`, `$1A`-`$1D`, `$22`-`$2D`, `$3B`, `$FB`-`$FE` by default. |
| REU bank 0-1 | `$00_0000`-`$01_FFFF` | 128 KB full 8x8 -> 16 multiply table, built once by `reu_mul_init`. |
| REU bank 2, offset `$0000`-`$03FF` | 1 KB | P-256 Lim-Lee comb precompute (16 entries x 64 bytes, X + Y only). |
| REU bank 2, offset `$0400`-`$09FF` | 1.5 KB | P-384 Lim-Lee comb precompute (16 entries x 96 bytes). |

Run `build/labels.txt` through your own tooling for exact symbol addresses in
any given build. The address ranges above are derived from the current
`master`-equivalent build and will drift slightly as code size changes.

## 3. Initialization sequence (required)

The host program must perform the following calls, in order, before any field
or point routine is used. All of them are defined in `main.asm` / `points256.asm`
/ `points384.asm` and are public labels.

1. **Bank out BASIC ROM** (optional but recommended) so `$A000`-`$BFFF` is RAM:

   ```
   lda proc_port
   and #$fe
   sta proc_port
   ```

2. **`jsr sqtab_init`** — builds the quarter-square lookup tables at
   `$7800`-`$7BFF`. Required for any multiply.

3. **`jsr reu_mul_init`** — fills REU banks 0-1 with the full 128 KB 8x8 -> 16
   multiply table and pre-configures the REU DMA registers. Required for any
   multiply. Takes ~4 seconds on a real C64.

4. **`jsr ec_precompute_256`** — builds the 1 KB Lim-Lee anchor / comb table in
   REU bank 2 at offset `$0000`. Required before `ec_scalar_mul`. Only needed
   if you will call P-256 scalar multiply; field arithmetic and
   point double / add do not depend on it.

5. **`jsr ec_precompute_384`** — analogous P-384 precompute at REU bank 2
   offset `$0400`. Required before `ec_scalar_mul_384`.

If your host program only uses one curve, you may omit that curve's
`ec_precompute_*` call. `sqtab_init` and `reu_mul_init` are mandatory for both.

### Test-harness sentinel (optional)

`main.asm`'s `start` routine writes `$42` to `$02A7` as the final step of
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
scratch buffers listed in `src/data.asm` (`fp_wide`, `fp_tmp1..4`, `fp_r0..3`,
`fp_inv_*`, `ec_t1..6`, and their `_384` counterparts), plus
`mul_cached_a` / `mul_src2_buf` / `mul_dma_lo` / `mul_dma_hi` / `fp_red_tmp`.

### Re-entrancy: **NOT re-entrant**

The field-multiply state (`mul_cached_a`, `mul_src2_buf`, `mul_dma_lo`,
`mul_dma_hi`) and the ZP pointers (`fp_src1/2/dst/misc`) are globally shared
between every P-256 and P-384 routine. Sequential calls across the two
curves are fine, but the host must never interleave library calls —
in particular, it must not invoke any field or point routine from an IRQ
handler while the mainline is already inside one. Mask IRQs around crypto
work or keep all library calls on a single thread of control. See the
re-entrancy comment block at the top of `src/data.asm` for the canonical
statement.

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

## 5. Public API reference

All symbols below are defined as globally-addressable labels in the file
listed in the "Source" column. `_384` variants take 48-byte operands
and use the P-384 modulus / buffers; in every other respect they behave
identically to the P-256 version.

### 5.1 Raw field arithmetic (`fp256.asm`, `fp384.asm`)

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

### 5.2 Modular field arithmetic (`mod256.asm`, `mod384.asm`)

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

### 5.3 Point operations (`points256.asm`, `points384.asm`)

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `ec_point_double` / `ec_point_double_384` | points256/384 | `ec_p1` / `ec384_p1` (Jacobian) | `ec_p3` / `ec384_p3` (Jacobian) | Handles Z=0 (infinity) input. Uses curve-specific `a = -3` formula. |
| `ec_point_add` / `ec_point_add_384` | points256/384 | `ec_p1` / `ec384_p1` (Jacobian), `ec_p2` / `ec384_p2` (affine X in first half, Y in second half; Z ignored) | `ec_p3` / `ec384_p3` (Jacobian) | Mixed Jacobian+affine addition. Handles both-infinity / same-point cases. |
| `ec_scalar_mul` | points256 | `ec_scalar_ptr` (ZP pointer to 32-byte BE scalar) | `ec_p3` (Jacobian) | Computes `k * G` for fixed generator G using a 4-way Lim-Lee comb over the P-256 precompute table. **Requires `ec_precompute_256`.** Base-point only. |
| `ec_scalar_mul_384` | points384 | `ec_scalar_ptr` (ZP pointer to 48-byte BE scalar) | `ec384_p3` (Jacobian) | P-384 analogue. **Requires `ec_precompute_384`.** |
| `ec_jacobian_to_affine` | points256 | `ec_p3` | `ec_affine_x`, `ec_affine_y` | Sets `fp_misc` to p256 internally. |
| `ec_jacobian_to_affine_384` | points384 | `ec384_p3` | `ec384_affine_x`, `ec384_affine_y` | P-384 analogue. |
| `ec_precompute_256` | points256 | — | REU bank 2 @ `$0000`..`$03FF`, `ec_anchor1..4_x/y` | Builds the Lim-Lee comb table. Run once at boot. |
| `ec_precompute_384` | points384 | — | REU bank 2 @ `$0400`..`$09FF`, `ec_anchor1..4_384_x/y` | P-384 analogue. |

## 6. Example usage

### 6.1 Modular multiply: `r = a * b mod p256`

```asm
        ; Assume a, b, r are each 32-byte LE buffers in your program.
        lda #<a
        sta fp_src1
        lda #>a
        sta fp_src1+1
        lda #<b
        sta fp_src2
        lda #>b
        sta fp_src2+1
        lda #<r
        sta fp_dst
        lda #>r
        sta fp_dst+1
        jsr ec_mulp         ; sets modulus to p256, multiplies, copies fp_r0 to r
```

Use `ec_mulp_384` with 48-byte buffers for P-384.

### 6.2 Fixed-base scalar multiply: `Q = k * G` on P-256

```asm
        ; k is a 32-byte big-endian scalar somewhere in RAM.
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

## 7. Limitations

- **Not re-entrant.** The library shares global scratch and ZP slots across
  all field and point routines; callers must serialize all library calls and
  never invoke them from an IRQ handler that can preempt mainline crypto work.
  See the comment block in `src/data.asm` and section 4 above.
- **Shared P-256 / P-384 scratch.** Sequential cross-curve calls are fine, but
  there is no support for running a P-256 multiply "in parallel" with a P-384
  multiply.
- **Data buffers live at fixed absolute addresses.** Relocating them requires
  editing `src/data.asm` and re-assembling. The code / ZP layout is somewhat
  more flexible: code is position-independent within the PRG and ZP slots can
  be renamed via `src/zp_config.asm`.
- **Zero-page footprint is ~16 bytes.** See `src/zp_config.asm` for the
  complete, editable list of slots. The hardware-fixed `proc_port` at `$01`
  is the only slot that cannot be moved.
- **`ec_scalar_mul` is fixed-base only.** Only `k * G` (the curve generator)
  is supported; there is no variable-base scalar multiply currently. ECDH and
  ECDSA-verify are therefore not yet buildable on top of this library without
  adding one.
- **Scalars must be zero-padded** to 32 bytes for P-256 and 48 bytes for P-384,
  big-endian.
## 8. References

- `CLAUDE.md` — architecture overview, re-entrancy contract, optimization
  history, and known issues.
- `README.md` — benchmark results and current performance numbers.
- `src/zp_config.asm` — editable zero-page allocation.
- `src/data.asm` — data-segment layout, including all shared scratch buffers.
- `build/labels.txt` — authoritative VICE symbol table with current addresses.
