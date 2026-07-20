.setcpu "6502"

; =============================================================================
; mul_8x8.s - Quarter-square 8x8->16 multiply + table init
;
; Quarter-square table: sqtab_lo/hi, 1024 bytes, derived from
;   LIB_SHARED_SQTAB_BASE per c64-lib-contract SPEC §8.1.
; Identity: a*b = floor((a+b)^2/4) - floor((a-b)^2/4)
;
; SPEC §8.1 placement contract: the consumer supplies the base via
;   `ca65 --asm-define LIB_SHARED_SQTAB_BASE=$<addr>` so multiple
;   sqtab-using libraries linked into the same PRG agree on one base.
;   The standalone library build defaults to $9c00 (page-aligned,
;   below BASIC ROM at $A000 which the library banks out anyway).
;   The .assert guards below catch misconfigurations at assemble
;   time -- the 2026-05-17 incident where code growth silently
;   overlapped the previous $7800 base and corrupted sqtab at boot
;   is now caught by the page-alignment assert + the consumer's
;   §5 cfg fit checks against `__DATA_SIZE__`.
;
; The mul_8x8 body still uses SMC patching on the `lda sqtab_lo,x` /
;   `lda sqtab_hi,x` opcode hi bytes (the page-delta `$0200` is folded
;   into the SMC math below). ld65 can't rewrite those embedded
;   constants at link time, so the equate-with-default shape (rather
;   than a linker-managed segment) is the only mechanism that works
;   with SMC dispatch -- ratified in SPEC §8.1's "Placement contract".
; =============================================================================

.importzp poly_i, poly_j, poly_carry, poly_tmp

; --- data imports (for reu_fetch_mul_row) ---
.import mul_cached_a

; --- constants imports (for reu_fetch_mul_row) ---
.import reu_reu_hi, reu_reu_bank, reu_command

; --- REU layout contract (SPEC §3) ---
.import LIB_NISTCURVES_REU_BANK_MUL

.segment "LIB_NISTCURVES_MUL_CODE"

; --- Quarter-square table base (SPEC §8.1) ---
; Consumer override via `ca65 --asm-define LIB_SHARED_SQTAB_BASE=$<addr>`.
; Default $9c00 was chosen on 2026-05-17 (see Known issues note) so the
; standalone library build links cleanly without an override.
.ifndef LIB_SHARED_SQTAB_BASE
        LIB_SHARED_SQTAB_BASE = $9c00
.endif

sqtab_lo        = LIB_SHARED_SQTAB_BASE             ; 512 B: lo bytes of floor(n^2/4)
sqtab_hi        = LIB_SHARED_SQTAB_BASE + $0200     ; 512 B: hi bytes of floor(n^2/4)

; SPEC §8.1 assemble-time guards:
;   - page-aligned base for cycle-stable `abs,x` indexing in CT mul_8x8
;   - exact $0200 lo->hi delta for the SMC dispatch below
.assert (LIB_SHARED_SQTAB_BASE & $00ff) = 0, error, "sqtab base must be page-aligned (SPEC §8.1)"
.assert sqtab_hi = sqtab_lo + $0200,        error, "sqtab_hi must follow sqtab_lo by $0200 (SPEC §8.1)"

.export sqtab_lo, sqtab_hi

; =============================================================================
; sqtab_init - Build quarter-square lookup table at sqtab_lo / sqtab_hi
;
; Computes floor(i^2/4) for i = 0..511 using recurrence i^2 = (i-1)^2 + 2i - 1
;
; Clobbers: A, X, Y
;
; SPEC §8.1 migration gate: when a consumer defines SHARED_SQTAB_INIT,
;   this body (and its scratch) is gated out so the consumer's canonical
;   `mul_tables_init` from a shared-primitives module owns the init.
;   Idempotent per SPEC §8.1.
; =============================================================================
.ifndef SHARED_SQTAB_INIT
.export sqtab_init
sqtab_init:
        lda #0
        sta sq_acc              ; accumulator = 0
        sta sq_acc+1
        sta sq_acc+2
        sta sq_i                ; index = 0
        sta sq_i+1

@loop:
        ; Compute f(i) = sq_acc >> 2 (divide by 4)
        lda sq_acc+2
        lsr
        sta sq_sh+2
        lda sq_acc+1
        ror
        sta sq_sh+1
        lda sq_acc
        ror
        sta sq_sh
        lsr sq_sh+2
        ror sq_sh+1
        ror sq_sh

        ; Store in table at index sq_i (0..511)
        ldx sq_i                ; low byte of index
        lda sq_i+1
        beq @pg0
        ; Page 1 (256..511)
        lda sq_sh
        sta sqtab_lo+256,x
        lda sq_sh+1
        sta sqtab_hi+256,x
        jmp @advance
@pg0:
        lda sq_sh
        sta sqtab_lo,x
        lda sq_sh+1
        sta sqtab_hi,x

@advance:
        ; sq_acc += 2*i + 1 (recurrence: (i+1)^2 = i^2 + 2i + 1)
        lda sq_i
        asl
        sta sq_ad
        lda sq_i+1
        rol
        sta sq_ad+1
        inc sq_ad
        bne :+
        inc sq_ad+1
:
        clc
        lda sq_acc
        adc sq_ad
        sta sq_acc
        lda sq_acc+1
        adc sq_ad+1
        sta sq_acc+1
        lda sq_acc+2
        adc #0
        sta sq_acc+2

        inc sq_i
        bne :+
        inc sq_i+1
:       lda sq_i+1
        cmp #2                  ; check if i reached 512 (0x200)
        beq @done
        jmp @loop
@done:  rts

; Temporaries for sqtab_init
sq_acc: .res 3, 0              ; 24-bit accumulator for i^2
sq_sh:  .res 3, 0              ; 24-bit shifted result (i^2 / 4)
sq_ad:  .res 2, 0              ; 16-bit addition term (2i+1)
sq_i:   .res 2, 0              ; 16-bit index counter (0..511)
.endif  ; .ifndef SHARED_SQTAB_INIT

; =============================================================================
; mul_8x8 / ct_mul_8x8 - Constant-time 8-bit x 8-bit -> 16-bit multiply
;
; SPEC §8.3 candidate (c64-lib-contract issue #14): the instruction
;   sequence below is the canonical `ct_mul_8x8` body from
;   c64-ChaCha20-Poly1305 v0.3.0 (src/lib/poly1305_lib.s), adopted
;   VERBATIM so the cross-adopter gate `tools/ct_mul_brute_check.py`
;   sees byte-identical opcodes (from `mul_8x8:` to `rts`) across
;   chacha / nist-curves / x25519. Do NOT locally edit the instruction
;   sequence -- any opcode change breaks the §8.3 byte-identity ratchet.
;   The previous register-entry adaptation (A=a, X=b with a tay/stx mul_b
;   preamble + Y-shuttle diff block) diverged in opcode bytes from chacha
;   on Axis A and has been replaced; `mul_8x8` is retained as a
;   back-compat alias of the canonical `ct_mul_8x8` entry.
;
; Entry: Y = b, and `a` SMC-baked into smc_sum_a_imm+1 / smc_diff_a_imm+1
;        by the caller. In c64-nist-curves the sole caller `reu_mul_init`
;        (src/main.s) bakes `a` once per outer-a iteration and varies b in
;        Y across the inner b-loop -- exactly chacha's amortized shape.
; Output: poly_prod_lo / poly_prod_hi = a * b (16-bit result).
;
; Uses identity: a*b = sqtab[a+b] - sqtab[|a-b|]
;
; CONSTANT-TIME PROPERTY (Issue #14): no data-dependent branches and no
;   data-dependent memory addresses. The |a-b| sign test is a branchless
;   sign-mask flip-and-negate; the sum-page dispatch is an SMC patch of
;   the two `lda abs,x` hi bytes (page-aligned base => fixed 4-cy `abs,x`
;   timing independent of the patched page). Total body is straight-line.
;
; In c64-nist-curves `mul_8x8` is called only by `reu_mul_init` at boot
;   (65 536 calls, once) to build the REU multiply table. No secret inputs
;   ever reach it, so it has zero CT exposure here; the canonical CT-clean
;   body is adopted regardless to satisfy §8.3 byte-identity. No runtime
;   (post-boot) path calls it, so all fp_mul / fp_sqr / point-op /
;   scalar-mul cycle counts are unaffected. Migrating to the SMC-baked
;   convention removes the prior register-entry per-call entry-stash
;   (~8 cy/call vs the canonical body), a small net boot-time win amortized
;   over the outer-a bake -- lost in the warp-mode init noise either way.
;
; SPEC §8.3 migration gate: when a consumer defines SHARED_CT_MUL_8X8,
;   this body (and its scratch) is gated out so the consumer's canonical
;   `ct_mul_8x8` from a shared-primitives module owns the multiply. Mirrors
;   the §8.1 SHARED_SQTAB_INIT pattern.
;
; Clobbers: A, X, Y; ct_diff_raw / ct_sign_mask (local scratch); the four
;   SMC patch sites (smc_sum_a_imm, smc_diff_a_imm, smc_lo_addr, smc_hi_addr).
; =============================================================================
.ifndef SHARED_CT_MUL_8X8
.export poly_prod_lo, poly_prod_hi
poly_prod_lo:   .byte 0
poly_prod_hi:   .byte 0

.export mul_8x8, ct_mul_8x8
; SMC immediate-bake sites: the caller writes `a` to smc_sum_a_imm+1 and
; smc_diff_a_imm+1 before the inner b-loop (see reu_mul_init in main.s).
.export smc_sum_a_imm, smc_diff_a_imm
mul_8x8:
        ; --- Compute sum = a + b and SMC-patch the two abs,x hi bytes ---
        tya                     ; A = b
        clc
smc_sum_a_imm:
        adc #$00                ; SMC imm = a; A = (a+b).lo, C = sum-page bit
        tax                     ; X = (a+b) & $FF
        lda #>sqtab_lo
        adc #0                  ; sum-page carry folded into hi byte
        sta smc_lo_addr+2       ; patch sqtab_lo abs,x hi byte
        adc #(>sqtab_hi - >sqtab_lo)   ; C=0 after prior adc #0, so += 2
        sta smc_hi_addr+2       ; patch sqtab_hi abs,x hi byte

        ; --- Branchless |a-b| -> Y (sign-mask flip-and-negate) ---
        tya                     ; A = b
        sec
smc_diff_a_imm:
        sbc #$00                ; SMC imm = a; A = b-a, C=1 iff b>=a
        sta ct_diff_raw
        lda #$00
        sbc #$00                ; C=1: $00; C=0: $FF (sign mask)
        sta ct_sign_mask
        eor ct_diff_raw         ; raw XOR mask
        sec
        sbc ct_sign_mask        ; + (-mask): +0 if b>=a, +1 if b<a
        tay                     ; Y = |a-b| (in [0,255])

        ; --- Table-lookup subtract: sqtab[a+b] - sqtab[|a-b|] ---
smc_lo_addr:
        lda sqtab_lo,x          ; hi byte SMC-patched above
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
smc_hi_addr:
        lda sqtab_hi,x          ; hi byte SMC-patched above
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts

ct_mul_8x8 = mul_8x8            ; §8.3 canonical name; mul_8x8 kept as alias

ct_diff_raw:    .byte 0
ct_sign_mask:   .byte 0
.endif  ; .ifndef SHARED_CT_MUL_8X8

; =============================================================================
; reu_fetch_mul_row - DMA a multiplication table row from REU to C64
;
; Input: mul_cached_a = multiplier value (0-255)
; Fetches 512 bytes: 256 lo bytes to mul_dma_lo, 256 hi bytes to mul_dma_hi
; Clobbers: A
; =============================================================================
.export reu_fetch_mul_row
reu_fetch_mul_row:
        lda mul_cached_a
        asl                    ; A = multiplier * 2, carry = bit 7
        sta reu_reu_hi
        lda #<LIB_NISTCURVES_REU_BANK_MUL
        adc #0                 ; bank = MUL_BASE + carry from shift
        sta reu_reu_bank
        lda #%10110001         ; execute + autoload + FETCH (REU->C64)
        sta reu_command
        rts

.ifdef FP_ONCHIP_MUL
; =============================================================================
; og_common - FP_ONCHIP_MUL shared row-generation loop (issue #69: REU DMA
;   stall is wall-clock-anchored and caps turbo scaling)
;
; Instead of DMA-fetching the full 512 B a-row, compute on-chip -- via
; ct_mul_8x8 -- exactly the mul_dma_lo/hi entries the fp_mul / fp_sqr
; inner loops will read for the current row:
;   - one product a*v per byte value v in the staged src buffer [0..X]
;     (zero bytes skipped: the inner loops' beq fast-path never reads
;     index 0)
;   - the diagonal entry at index mul_cached_a (a*a; the fp_sqr diagonal
;     pass reads it, and in fp_sqr mul_cached_a is itself a src byte)
; Entries at all other indices are left stale from previous rows; the
; consumers above never read them for the current row.
;
; Entry points live with their curve objects so no cross-curve import
; leaks into this object (archive linkability, SPEC §6 / check-archives):
; fp256.s `gen_mul_row` and fp384.s `gen_mul_row_384` are 6-instruction
; stubs that SMC-patch the og_src_ld operand to their own staged-src
; buffer (mul_src2_buf / mul_src2_buf_384) and jmp og_common. The
; placeholder operand $FFFF below is ALWAYS overwritten before the loop
; runs.
;
; Input:  X = last source-buffer index (31 for P-256, 47 for P-384)
;         og_src_ld+1/+2 = staged-src buffer address (patched by stub)
;         mul_cached_a = row multiplicand a
; Clobbers: A, X, Y, poly_prod_lo/hi, ct_mul_8x8 scratch + SMC sites.
;   All six call sites reload X and Y after the (former) fetch block, so
;   the wider clobber set vs the DMA path (A only) is safe.
; =============================================================================
.import mul_dma_lo, mul_dma_hi
.export og_common, og_src_ld
og_common:
        stx og_i
        lda mul_cached_a
        sta smc_sum_a_imm+1     ; bake a once per row (canonical SMC entry)
        sta smc_diff_a_imm+1
        tay
        jsr ct_mul_8x8          ; a*a for the fp_sqr diagonal read
        ldy mul_cached_a
        lda poly_prod_lo
        sta mul_dma_lo,y
        lda poly_prod_hi
        sta mul_dma_hi,y
og_loop:
        ldx og_i
og_src_ld:
        ldy $FFFF,x             ; operand SMC-patched by the entry stubs
        beq og_skip             ; index 0 never read (inner-loop beq fast-path)
        sty og_v
        jsr ct_mul_8x8
        ldy og_v
        lda poly_prod_lo
        sta mul_dma_lo,y
        lda poly_prod_hi
        sta mul_dma_hi,y
og_skip:
        dec og_i
        bpl og_loop
        rts

og_i:   .byte 0
og_v:   .byte 0
.endif  ; FP_ONCHIP_MUL
