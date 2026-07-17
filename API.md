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
buffers requires editing the labels in `src/data.s`; relocating the zero-page
slots can be done either by editing `src/zp_config.s` or, without modifying
the library source, by pre-defining the ZP symbol in the consumer's build
(every equate in `zp_config.s` is wrapped in `.ifndef NAME ... .endif`, so a
host-supplied definition wins).

| Region | Address range | Purpose |
|---|---|---|
| PRG code | `$0801`-`$58FF` (approx.) | BASIC stub, boot code, math routines. PRG size varies per build — see `build/labels.txt` for the exact `__CODE_LAST__` symbol address in any given build. |
| P-256 field buffers | see `build/labels.txt` | `fp_wide`, `fp_r0`, `fp_inv_*` (`data_p256.s`); `fp_tmp1` rides in `data_p256_invref.s` (Fermat-reference scratch, full archive only). `fp_tmp2..4` are harness-only staging in `data_test.s`; `fp_r1..3` / `fp_inv_iter` / `fp_red_tmp` were deleted (issue #54). |
| P-256 point buffers | see `build/labels.txt` | `ec_p1`, `ec_p2`, `ec_p3`, `ec_t1..6`, `ec_jj_tmp`, `ec_affine_x/y` (`data_p256.s`). |
| `mul_cached_a` / `mul_src2_buf` / reduction scratch | `$49EA`-`$4AFF` (approx.) | Shared multiply scratch and Solinas accumulator. |
| `mul_dma_lo` (page-aligned) | `$4B00`-`$4BFF` | REU DMA target: low bytes of the current multiply row. |
| `mul_dma_hi` | `$4C00`-`$4CFF` | REU DMA target: high bytes of the current multiply row. |
| P-384 field + point buffers | `$4D21`-`$5365` | `fp384_wide`, `fp384_tmp1..4`, `fp384_r0..3`, `fp384_inv_*`, `ec384_p1/p2/p3`, `ec384_t1..6`, `ec384_affine_x/y`. |
| Lim-Lee anchors + working scalar (P-256) | approx. `$5367`-`$5586` | `ec_anchor1..8_x/y` (8 * 64 bytes), `cm_k` (32). Wave 7a h=8 doubled the anchor storage. |
| Lim-Lee anchors + working scalar (P-384) | approx. `$5587`-`$58F6` | `ec_anchor1..8_384_x/y` (8 * 96 bytes), `cm_k_384` (48). |
| Quarter-square multiply tables | `$9C00`-`$9FFF` (1 KB) | `sqtab_lo` / `sqtab_hi`. Built once by `sqtab_init`. Moved from `$7800` on 2026-05-17 to clear the linker-managed `mul_dma_*` page-aligned slots as code grew (see CLAUDE.md "Known issues"). |
| SHA-384 streaming state + buffers | varies (DATA segment) | `sha_state` (64) + `sha_w` (640) + `sha_abcdefgh` (64) + `sha_t` (16) + `sha_scratch` (64) + `sha_block_buf` (128) + `sha_block_len` (1) + `sha_total_len` (16) + `sha384_digest` (48) + `sha384_msg_buf` (1024 test scratch) ≈ 2065 B total. K[80] round constants (640 B) live in RODATA inside `src/sha384.s`. |
| Zero-page | ~20 bytes, see `zp_config.s` | `$02`-`$03`, `$04`-`$0B` (SHA), `$1A`-`$1D`, `$22`-`$2D`, `$3B`, `$FB`-`$FE` by default. |
| REU bank 0-1 | `$00_0000`-`$01_FFFF` | 128 KB full 8x8 -> 16 multiply table, built once by `reu_mul_init`. |
| REU bank 2, offset `$0000`-`$3FFF` | 16 KB | P-256 Lim-Lee comb precompute (256 entries x 64 bytes, X + Y only). Wave 7a h=8. |
| REU bank 2, offset `$4000`-`$9F9F` | 24 KB | P-384 Lim-Lee comb precompute (256 entries x 96 bytes). Wave 7a h=8. |

Run `build/labels.txt` through your own tooling for exact symbol addresses in
any given build. The address ranges above are derived from the current
`master`-equivalent build and will drift slightly as code size changes.

## 3. Initialization sequence (required)

The host program must perform the following calls, in order, before any field
or point routine is used. All of them are defined in `main.s` / `points256.s`
/ `points384.s` and are public labels.

1. **Bank out BASIC ROM** (optional but recommended) so `$A000`-`$BFFF` is RAM:

   ```
   lda proc_port
   and #$fe
   sta proc_port
   ```

2. **`jsr sqtab_init`** — builds the quarter-square lookup tables at
   `$9C00`-`$9FFF`. Required for any multiply.

3. **`jsr reu_mul_init`** — fills REU banks 0-1 with the full 128 KB 8x8 -> 16
   multiply table and pre-configures the REU DMA registers. Required for any
   multiply. Takes ~7 seconds on a real C64 (~4 s of prior baseline plus
   ~2.8 s added by the constant-time `mul_8x8` port of issue #14; the boot
   cost is a one-time tax, no runtime call path is affected).

4. **`jsr ec_precompute_256`** — builds the 16 KB Lim-Lee anchor / comb table in
   REU bank 2 at offset `$0000` (256 entries * 64 bytes, h=8). Required before
   `ec_scalar_mul`. Only needed if you will call P-256 scalar multiply; field
   arithmetic and point double / add do not depend on it. Boot cost on a real
   C64 is on the order of ~25 seconds (224 doubles + 762 mixed adds + 255 J->A
   conversions).

5. **`jsr ec_precompute_384`** — analogous P-384 precompute at REU bank 2
   offset `$4000` (24 KB, 256 entries * 96 bytes, h=8). Required before
   `ec_scalar_mul_384`. Boot cost is on the order of ~80 seconds (336 doubles
   + 762 mixed adds + 255 J->A conversions on 48-byte operands).

If your host program only uses one curve, you may omit that curve's
`ec_precompute_*` call. `sqtab_init` and `reu_mul_init` are mandatory for both.

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
re-entrancy comment block at the top of `src/data.s` for the canonical
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

### 5.3 Point operations (`points256.s`, `points384.s`)

| Name | Source | Inputs | Output | Notes |
|---|---|---|---|---|
| `ec_point_double` / `ec_point_double_384` | points256/384 | `ec_p1` / `ec384_p1` (Jacobian) | `ec_p3` / `ec384_p3` (Jacobian) | Handles Z=0 (infinity) input. Uses curve-specific `a = -3` formula. |
| `ec_point_add` / `ec_point_add_384` | points256/384 | `ec_p1` / `ec384_p1` (Jacobian), `ec_p2` / `ec384_p2` (affine X in first half, Y in second half; Z ignored) | `ec_p3` / `ec384_p3` (Jacobian) | Mixed Jacobian+affine addition (7M + 4S). Handles both-infinity / same-point cases. The Lim-Lee comb evaluate loop uses this primitive. |
| `ec_point_add_jj` / `ec_point_add_jj_384` | points256/384 | `ec_p1` / `ec384_p1` (full Jacobian), `ec_p2` / `ec384_p2` (full Jacobian) | `ec_p3` / `ec384_p3` (Jacobian) | Full Jacobian+Jacobian addition (Bernstein-Lange add-2007-bl, 11M + 5S). Reads Z2 from `ec_p2+64` (or `ec384_p2+96`) — caller must populate it. Handles P1∞, P2∞, both∞, same projective point (tail-calls `ec_point_double`), and P1=-P2 natively. Used by `ecdsa_verify_256/384` at the `u1*G + u2*Q` join. |
| `ec_scalar_mul` | points256 | `ec_scalar_ptr` (ZP pointer to 32-byte BE scalar) | `ec_p3` (Jacobian) | Computes `k * G` for fixed generator G using an 8-way Lim-Lee comb over the 256-entry P-256 precompute table (Wave 7a h=8). **Requires `ec_precompute_256`.** Base-point only. |
| `ec_scalar_mul_384` | points384 | `ec_scalar_ptr` (ZP pointer to 48-byte BE scalar) | `ec384_p3` (Jacobian) | P-384 analogue (Wave 7a h=8). **Requires `ec_precompute_384`.** |
| `ec_jacobian_to_affine` | points256 | `ec_p3` | `ec_affine_x`, `ec_affine_y` | Sets `fp_misc` to p256 internally. |
| `ec_jacobian_to_affine_384` | points384 | `ec384_p3` | `ec384_affine_x`, `ec384_affine_y` | P-384 analogue. |
| `ec_precompute_256` | points256 | — | REU bank 2 @ `$0000`..`$3FFF`, `ec_anchor1..8_x/y` | Builds the 16 KB h=8 Lim-Lee comb table. Run once at boot (~25 s on real C64). |
| `ec_precompute_384` | points384 | — | REU bank 2 @ `$4000`..`$9F9F`, `ec_anchor1..8_384_x/y` | P-384 analogue, 24 KB table (~80 s on real C64). |

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
| `ecdsa_verify_256` | ecdsa256 | A (lo) / X (hi) = pointer to 160 B BE struct `r(32) | s(32) | h(32) | Qx(32) | Qy(32)` | C=0 valid, C=1 invalid/malformed | Non-constant-time (public inputs). Internally byte-reverses to LE via `fp_reverse32`, then composes `ec_scalar_mul`, `ec_scalar_mul_var`, `ec_point_add`, `fp_mod_inv`, `fp_mod_mul_n`. |
| `ecdsa_verify_384` | ecdsa384 | A (lo) / X (hi) = pointer to 240 B BE struct `r(48) | s(48) | h(48) | Qx(48) | Qy(48)` | C=0 valid, C=1 invalid/malformed | P-384 analogue using `fp_reverse48`. Same non-constant-time caveat. |
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

### 6.3 ECDSA verify with message: P-384 hash-then-verify wrapper

```asm
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
```

For transcripts spanning multiple buffers (TLS handshake hashing,
streamed file verification), drive `sha384_init / sha384_update /
sha384_final` manually, splice `sha384_digest` into `verify_struct+96`,
and `jsr ecdsa_verify_384` directly.

## 7. Limitations

- **Not re-entrant.** The library shares global scratch and ZP slots across
  all field and point routines; callers must serialize all library calls and
  never invoke them from an IRQ handler that can preempt mainline crypto work.
  See the comment block in `src/data.s` and section 4 above.
- **Shared P-256 / P-384 scratch.** Sequential cross-curve calls are fine, but
  there is no support for running a P-256 multiply "in parallel" with a P-384
  multiply.
- **Data buffers live at fixed absolute addresses.** Relocating them requires
  editing `src/data.s` and re-assembling. The code / ZP layout is somewhat
  more flexible: code is position-independent within the PRG and ZP slots can
  be renamed via `src/zp_config.s`.
- **Zero-page footprint is ~16 bytes.** See `src/zp_config.s` for the
  complete, editable list of slots. The hardware-fixed `proc_port` at `$01`
  is the only slot that cannot be moved.
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

```
git submodule add https://github.com/JC-000/c64-nist-curves \
    lib/c64-nist-curves
git -C lib/c64-nist-curves checkout v0.4.0
git commit -m "Import c64-nist-curves v0.4.0 as submodule"
```

Bumping to a later release:

```
git -C lib/c64-nist-curves fetch --tags
git -C lib/c64-nist-curves checkout v0.4.1    # or whichever tag
git add lib/c64-nist-curves
git commit -m "Bump c64-nist-curves to v0.4.1"
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

| Resource | Library-owned | Consumer restriction |
|---|---|---|
| C64 page $4B (`mul_dma_lo`) | $4B00–$4BFF | Do not use; page-aligned DMA target |
| C64 page $4C (`mul_dma_hi`) | $4C00–$4CFF | Do not use |
| C64 pages ~$46–$58 | field / point buffers, Lim-Lee anchors | See §2 for the full map |
| C64 pages $9C–$9F | Quarter-square multiply tables (`sqtab_lo/hi`) | Do not use |
| C64 zero-page | ~16 slots; see `src/zp_config.s` | Edit `src/zp_config.s` to relocate if needed |
| REU bank 0 / bank 1 | Full 128 KB multiply table | Do not write; initialized by `reu_mul_init` |
| REU bank 2, $0000–$3FFF | P-256 Lim-Lee anchors (16 KB, 256 × 64) | Do not write |
| REU bank 2, $4000–$9F9F | P-384 Lim-Lee anchors (24 KB, 256 × 96) | Do not write |
| REU bank 2, $9FA0–$FFFF | Unused (~24 KB free) | Safe for consumer use |
| REU banks 3+ (if present) | Unused by library | Safe for consumer use |

Relocating library-owned C64 data addresses requires editing `src/data.s`
and reassembling. ZP slots can be relocated via `src/zp_config.s`, or
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

| Target                       | Archive                              | Use case                                                                                 |
|------------------------------|--------------------------------------|------------------------------------------------------------------------------------------|
| `make lib`                   | `nistcurves.a`                       | Whole library minus the standalone test PRG driver. Default for whole-library consumers. |
| `make lib-p256-verify`       | `nistcurves-p256-verify.a`           | P-256 ECDSA verify only (variable-base scalar mul). Excludes Lim-Lee fixed-base comb.    |
| `make lib-p384-verify`       | `nistcurves-p384-verify.a`           | P-384 ECDSA verify only. Excludes Lim-Lee comb and the SHA-driving wrapper.              |
| `make lib-p384-sha384`       | `nistcurves-p384-sha384.a`           | SHA-384 streaming hash only. Self-contained: no REU, no multiply tables.                 |
| `make lib-p384-curve`        | `nistcurves-p384-curve.a`            | P-384 ECDSA verify + SHA-384 + `ecdsa_verify_with_message_384` one-shot wrapper.         |

Exclusion summary (per minimal archive):

- `lib-p256-verify` excludes: `main`, `inv256` + `data_p256_invref`
  (Fermat-inverse reference and its `fp_tmp1` scratch; the binary-GCD
  path in `mod256` is what production uses), `points256_comb`
  + `data_p256_limlee` (Lim-Lee anchors, `ec_scalar_mul`, and the comb
  scalar-walker state `ec_sc_byte`/`ec_sc_mask`), all P-384,
  all SHA-384, the test-driver staging buffers (`ecdsa_inputs_*`,
  `sha384_msg_buf`, `fp_tmp2..4`). Its `LIB_NISTCURVES_P256_BSS`
  extent is 1312 B as of issue #54 (was 1573 B in v0.3.0).
- `lib-p384-verify` excludes: `main`, all P-256, `points384_comb` +
  `data_p384_limlee`, `ecdsa384_msg` (one-shot wrapper — consumers
  driving streaming SHA themselves link this in via `lib-p384-curve`
  instead), all SHA-384, the test-driver staging buffers.
- `lib-p384-sha384` is the tightest archive: just `sha384.o`,
  `data_sha.o`, `zp_config.o`, `lib_version.o`. No `mul_8x8`, no REU,
  no `constants.o` — SHA-384 has no shared scratch with the field /
  point / ECDSA code paths.
- `lib-p384-curve` = `lib-p384-verify` ⊕ SHA-384 objects ⊕
  `ecdsa384_msg.o`. Suitable for the TLS 1.3 secp384r1+SHA-384
  cipher-suite use case where the consumer wants a single
  hash-then-verify entry point.

**Important:** excluding the Lim-Lee comb means the *packaged* verifiers
`ecdsa_verify_256` / `ecdsa_verify_384` (and
`ecdsa_verify_with_message_384`) are **not** linkable from the verify /
curve archives on their own. See §8.4.1 for the full contract, the
supported variable-base building-block path, and the comb add-on recipe.

The standalone test PRG (`make` with no args, default target) continues
to be byte-identical to the pre-PR-#40 baseline (37302 bytes loaded at
$0801); only the source-file layout changed. Consumers that built
their own integration scripts against the pre-split layout (e.g.
`tools/integration/build_nistcurves_p256.sh` in `c64-https`) can
collapse those scripts to a `make lib-p256-verify && cp` pattern when
they next refresh.

### 8.4.1 Packaged verifiers are NOT linkable from the verify archives alone

**Contract (issue #60):** the trimmed verify archives ship the ECDSA
verify *building blocks*, not a link-complete packaged verifier. The
headline routines `ecdsa_verify_256` (`src/ecdsa256.s`) and
`ecdsa_verify_384` (`src/ecdsa384.s`) compute `u1·G` by calling the
h=8 Lim-Lee fixed-base comb (`ec_scalar_mul` / `ec_scalar_mul_384`),
which lives in `points256_comb.o` / `points384_comb.o` — objects the
verify archives **exclude by design**. Linking a consumer that imports
`ecdsa_verify_256` against `nistcurves-p256-verify.a` alone therefore
fails:

```
Unresolved external 'ec_scalar_mul' referenced in:
  src/ecdsa256.s(252)
```

This is pre-existing behaviour since PR #40 (the SPEC §6 archive split),
made explicit here rather than changed. It affects, per archive:

| Archive | Packaged entry point(s) NOT linkable standalone | Missing symbol(s) |
|---|---|---|
| `nistcurves-p256-verify.a` | `ecdsa_verify_256` | `ec_scalar_mul` |
| `nistcurves-p384-verify.a` | `ecdsa_verify_384` | `ec_scalar_mul_384` |
| `nistcurves-p384-curve.a` | `ecdsa_verify_384`, `ecdsa_verify_with_message_384` | `ec_scalar_mul_384` (+ test-buffer leak below) |
| `nistcurves.a` (full) | `ecdsa_verify_with_message_384` | `ecdsa_inputs_384`, `ecdsa_result_msg_384` |

`nistcurves-p384-sha384.a` is self-contained and has no such gap.

**Additional gap — `ecdsa_verify_with_message_384`:** the object
`ecdsa384_msg.o` also carries a *test-only* trampoline
(`ecdsa_verify_with_msg_384_tramp`) that references the test-driver
buffers `ecdsa_inputs_384` / `ecdsa_result_msg_384` (in `data_test.o`,
excluded from every archive). Because `ld65` pulls a whole object from
an archive when any of its symbols is referenced, importing
`ecdsa_verify_with_message_384` drags in that trampoline and leaves
those two buffers unresolved — so the wrapper is unlinkable even from
the full `nistcurves.a`. Provide your own definitions, or drive
`ecdsa_verify_384` with the digest pre-spliced into the struct (path 1
below). This leak is tracked in issue #63 (relocate the test-only
trampoline out of `ecdsa384_msg.o` into a test-only object so the
wrapper object stops importing the test buffers).

**What to do — two supported paths:**

1. **Variable-base building blocks (recommended today, the current
   `c64-https` pattern).** The verify archives fully support driving
   the low-level primitives directly: compute `u1·G` with
   `ec_scalar_mul_var` seeded at the base point `G`, `u2·Q` with
   `ec_scalar_mul_var`, join with `ec_point_add` / `ec_point_add_jj`,
   lift with `ec_jacobian_to_affine`, and reduce with `fp_mod_inv` /
   `fp_mod_mul` (all exported from the verify archive). This path needs
   no comb, so it skips the `ec_precompute_256` / `ec_precompute_384`
   boot pass (~25 s / ~80 s at 1 MHz; see §8.5) and the comb's REU
   bank-2 residency entirely.

2. **Add the comb objects (or link the full archive).** To use the
   packaged `ecdsa_verify_256` / `ecdsa_verify_384` as-is, add the comb
   objects to the link line:
   - P-256: `build/points256_comb.o build/data_p256_limlee.o`
   - P-384: `build/points384_comb.o build/data_p384_limlee.o`

   or simply link `nistcurves.a`. **Operational cost:** the comb's REU
   anchor table must be built once at boot by `ec_precompute_256` /
   `ec_precompute_384` (~25 s / ~80 s at 1 MHz, §8.5), and it occupies
   REU bank 2 for the program's lifetime (P-256 16 KB at
   `$0000..$3FFF`; P-384 24 KB at `$4000..$9F9F`). Verify-only consumers
   that cannot pay that boot time or REU residency should prefer path 1.

A future enhancement (issue #61, the option-1 fallback from #60) would
let `ecdsa_verify_256/384` route `u1·G` through `ec_scalar_mul_var`
when the comb is absent, so the verify archives link standalone; until
that lands, the contract above is the reality.

**Ratchet:** `make check-archives` (`tools/check_archives.py`) pins this
contract — an od65 import/export closure sweep plus `ld65` dummy-link
smoke tests per archive. It fails if a packaged verifier ever links
cleanly from a verify archive (gap closed — shrink the docs) or if a new
unresolved symbol appears (regression). Run it after any change to the
archive object sets or the ECDSA call graph.

### 8.5 Initialization sequence

Follow the call sequence documented in §3 — any deviation (skipping
`sqtab_init`, calling `ec_scalar_mul` before `ec_precompute_256`, etc.)
will produce silent wrong answers or infinite loops.

Boot cost on a stock C64, in warp mode:

| Step | Cost |
|---|---|
| `sqtab_init` | <1 s |
| `reu_mul_init` | ~7 s (~4 s of prior baseline + ~2.8 s from the constant-time `mul_8x8` port, issue #14) |
| `ec_precompute_256` | ~25 s |
| `ec_precompute_384` | ~80 s |
| **Total (both curves)** | **~113 s** |

Programs using only one curve may omit the other's `ec_precompute_*`
call. Programs using neither curve's scalar_mul (e.g. only raw field
arithmetic or point double/add on caller-supplied points) may omit both
`ec_precompute_*` calls and save the full ~100 s precompute cost, at
the price of losing `ec_scalar_mul` and `ec_scalar_mul_384`.

### 8.6 Version compatibility checks

The library exports four integer constants for assembly-time version
checks, defined in `src/lib_version.s` (the fourth, `LIB_ABI_VERSION`,
landed in v0.3.0 per c64-lib-contract SPEC §1):

```asm
.import LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH
.import LIB_ABI_VERSION

.if LIB_VERSION_MAJOR <> 0 .or LIB_VERSION_MINOR < 4
    .error "c64-nist-curves v0.4.0 or newer is required"
.endif

.if LIB_ABI_VERSION <> 0
    .error "c64-nist-curves ABI v0 expected; rebuild consumer"
.endif
```

`LIB_ABI_VERSION` bumps in lockstep with `LIB_VERSION_MAJOR` and is the
load-bearing gate for consumers pinning to a specific ABI generation —
it changes only when public exports are removed or renamed.

The library is currently in the v0.x pre-stable series. Version policy:

- **PATCH** bumps (v0.4.0 → v0.4.1) ship bugfixes or performance
  improvements with no public API changes. Always safe to adopt;
  `LIB_ABI_VERSION` unchanged.
- **MINOR** bumps (v0.3.x → v0.4.0) may add public symbols (new entry
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

**§3 REU placement** (consumer overrides via `ca65 --asm-define`):

```asm
ca65 --asm-define LIB_NISTCURVES_REU_BANK_MUL=$03 ...        # default $00
ca65 --asm-define LIB_NISTCURVES_REU_BANK_COMB=$05 ...       # default $02
ca65 --asm-define LIB_NISTCURVES_REU_OFFSET_COMB_P256=$0000  # default $0000
ca65 --asm-define LIB_NISTCURVES_REU_OFFSET_COMB_P384=$4000  # default $4000
```

**§5 manifest equates** (consumer imports for cfg-side fit checks):

```asm
.import LIB_NISTCURVES_REU_BANKS_USED       ; bitmask, default $07
.import LIB_NISTCURVES_ZP_USAGE_BYTES       ; default 31
.import LIB_NISTCURVES_RESIDENT_BYTES       ; default 27000
.import LIB_NISTCURVES_COLD_BYTES           ; default 2500
.import LIB_NISTCURVES_SHARED_PRIMITIVES    ; standalone default $0007
                                            ; (sqtab | reu_mul | ct_mul_8x8);
                                            ; conditional per SPEC §8.0 — each
                                            ; defined SHARED_* deferral switch
                                            ; drops its bit
```

**§8.1 shared `sqtab`** (cross-library shared primitive — consumer
provides one base address, all sqtab-consuming sibling libs agree):

```asm
ca65 --asm-define LIB_SHARED_SQTAB_BASE=$<page-aligned-addr>
```

Default `$9c00`. Page-aligned + `sqtab_hi = sqtab_lo + $0200` are
enforced by `.assert` in `src/mul_8x8.s`. `LIB_NISTCURVES_SHARED_PRIMITIVES`
bit `$0001` (= `LIB_SHARED_PRIMITIVES_SQTAB`) signals to consumers that
this library claims ownership of the §8.1 primitive; consumers `.assert
(LIB_NISTCURVES_SHARED_PRIMITIVES .and LIB_X_SHARED_PRIMITIVES) = 0` to
catch double-ownership at link time when also pulling in another
sqtab-consuming sibling (`c64-x25519`, `c64-ChaCha20-Poly1305`). See
c64-lib-contract SPEC §8.1 for the full placement contract.

The mask is **conditional** (SPEC §8.0, v0.4.0): building with a
primitive's deferral switch defined (`-D SHARED_SQTAB_INIT`,
`-D SHARED_REU_MUL_INIT`, `-D SHARED_CT_MUL_8X8`) gates out this
library's copy AND drops the matching bit (`$0001` / `$0002` / `$0004`)
from `LIB_NISTCURVES_SHARED_PRIMITIVES`, so exactly one co-linked
sibling owns each shared primitive and the disjointness `.assert`
holds. Standalone builds (no switches) export `$0007`.

### 8.7 Reference integrations

The `c64-https` and `c64-wireguard` projects are planned reference
integrations. As of v0.3.0, both have adopted ca65 sufficient to drive
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
- `src/data.s` — data-segment layout, including all shared scratch buffers.
- `build/labels.txt` — authoritative VICE symbol table with current addresses.
