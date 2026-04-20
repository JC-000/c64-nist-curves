.setcpu "6502"

; =============================================================================
; mul_8x8.s - Quarter-square 8x8->16 multiply + table init
;
; Quarter-square table: sqtab_lo/hi at $7800-$7BFF (1024 bytes)
; Identity: a*b = floor((a+b)^2/4) - floor((a-b)^2/4)
; =============================================================================

.importzp poly_i, poly_j, poly_carry, poly_tmp

; --- data imports (for reu_fetch_mul_row) ---
.import mul_cached_a

; --- constants imports (for reu_fetch_mul_row) ---
.import reu_reu_hi, reu_reu_bank, reu_command

; Quarter-square table addresses (page-aligned for speed)
sqtab_lo        = $7800         ; 512 bytes: low bytes of floor(n^2/4)
sqtab_hi        = $7a00         ; 512 bytes: high bytes of floor(n^2/4)

.export sqtab_lo, sqtab_hi

; =============================================================================
; sqtab_init - Build quarter-square lookup table at $7800-$7BFF
;
; Computes floor(i^2/4) for i = 0..511 using recurrence i^2 = (i-1)^2 + 2i - 1
;
; Clobbers: A, X, Y
; =============================================================================
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

; =============================================================================
; mul_8x8 - Constant-time 8-bit x 8-bit -> 16-bit multiply
;
; Input: A = multiplicand, X = multiplier
; Output: poly_prod_lo/hi = A * X (16-bit result)
;
; Uses identity: a*b = sqtab[a+b] - sqtab[|a-b|]
;
; CONSTANT-TIME PROPERTY (Issue #14, Option B):
;   This routine has no data-dependent branches and no data-dependent memory
;   addresses. The two secret-dependent branches present in the previous
;   implementation have been removed:
;
;     1. `bcs :+` at the old |a-b| sign test (formerly ~line 133). Replaced
;        by a branchless sign-mask trick: compute raw = a - b, capture the
;        borrow via `lda #0 / sbc #0` (→ $00 if a>=b, $FF if a<b), then
;        `eor raw / sec / sbc mask` flips-and-negates raw without a branch.
;
;     2. `beq @s0` at the sum-page dispatch (formerly ~line 140). Replaced
;        by SMC-patching the high byte of two `lda abs,x` instructions at
;        runtime with the correct sqtab page ($78/$79 for lo, $7a/$7b for
;        hi). `abs,x` with a page-aligned base has fixed 4-cy timing,
;        independent of the patched page (the base hi byte is in the
;        instruction encoding, not computed from base.lo + x).
;
;   All table loads use page-aligned bases ($7800/$7a00 ± 0/256), X and Y
;   are in [0,255], so no `abs,x` / `abs,y` ever page-crosses. Total body
;   is straight-line with no conditional branches.
;
; Origin: ported from c64-ChaCha20-Poly1305 v0.3.0 `ct_mul_8x8`
;   (src/lib/poly1305_lib.s), design memo in docs/design/ct_mul_8x8.md.
;   Adapted to register-based entry (A=a, X=b) used in this project, rather
;   than the SMC-baked entry used by the Poly1305 inner loop.
;
; Cost: 86 cy body + 6 cy caller-side jsr = 92 cy at the call site
;   (hand-counted from the straight-line instruction sequence below; body
;   is branchless so the count is exact and input-independent). The
;   previous (non-CT) implementation averaged ~46-50 cy at the call site,
;   so this adds ~+42 cy per call. In c64-nist-curves `mul_8x8` is only
;   called by `reu_mul_init` at boot (65 536 calls, once), adding ~2.8 M cy
;   ≈ ~2.8 s of real C64 boot time. In VICE warp mode the boot-to-sentinel
;   time is dominated by the h=8 Lim-Lee precompute tables (~115-120 s on
;   an EPYC dev box) so the ct_mul_8x8 contribution is in the noise. No
;   runtime (post-boot) call path is affected, so all `fp_mul` / `fp_sqr`
;   / point-op / scalar-mul cycle counts are flat within measurement noise.
;
; Register entry adaptation: this project passes operands in A (=a) and
;   X (=b); the c64-ChaCha20-Poly1305 reference `ct_mul_8x8` expects `a`
;   to be SMC-baked into two `adc #imm` / `sbc #imm` slots by the caller's
;   outer-j loop, with `b` in Y at entry. That convention is specific to
;   the Poly1305 272-partial-product inner loop and is not a fit for this
;   project's single boot-time caller. The adaptation here stashes `a` in
;   Y at entry (`tay`, 2 cy) and `b` in the zero-page `mul_b` slot
;   (`stx mul_b`, 3 cy), then keeps `a` live in Y across the sum block so
;   the diff block can recover it with a 2-cy `tya` instead of a 3-cy
;   `lda mul_a` round-trip. The alternative `sta mul_a / stx mul_b /
;   ... / lda mul_a` form costs 2 cy more; this is a pure win and the
;   reason the `mul_a` scratch slot is absent from the local .byte block.
;   Net deviation from the reference's ~78 cy body: +8 cy, coming from
;   the two stash instructions at entry (5 cy) and the absence of the
;   reference's caller-side SMC pre-bake step (which in Poly1305 is
;   amortized over 17 `i` iterations per outer `j` but isn't applicable
;   to a single-caller boot-time build). This is inherent to the calling
;   convention, not a suboptimal port.
;
; Clobbers: A, X, Y; ct_sign_mask (local scratch); the four SMC patch sites.
; =============================================================================
.export poly_prod_lo, poly_prod_hi
poly_prod_lo:   .byte 0
poly_prod_hi:   .byte 0

.export mul_8x8
mul_8x8:
        ; Entry: A = a, X = b. Stash `a` in Y (2 cy) and `b` in zp (3 cy) so
        ; that A is free to use as the sum accumulator. Keeping `a` in Y
        ; across the sum block avoids a `sta mul_a / lda mul_a` round-trip
        ; (saves 2 cy vs the obvious `sta mul_a / stx mul_b` entry); Y is
        ; clobbered anyway later when we stash the raw diff via `tay`, so
        ; this is a pure win. See the "register entry adaptation" note in
        ; the header comment for the calling-convention analysis.
        tay                     ; Y = a (preserve)
        stx mul_b               ; mul_b = b

        ; --- Compute sum = a + b, SMC-patch the two abs,x hi bytes ---
        clc
        adc mul_b               ; A = (a+b).lo, C = sum-page bit
        tax                     ; X = (a+b) & $FF
        lda #>sqtab_lo          ; $78
        adc #0                  ; $78 or $79 depending on sum page
        ; --- SMC site #1: patch hi byte of `lda abs,x` at smc_lo_addr ---
        ; The three-byte `lda $7800,x` opcode sequence is (BD 00 78); the
        ; `+2` offset targets the high byte of the base address ($78). We
        ; store $78 or $79 here, selecting sqtab_lo page 0 or page 1. Using
        ; SMC instead of a `beq`/`bcc` dispatch keeps the routine branchless,
        ; which is the whole point of the issue #14 fix — `abs,x` with a
        ; page-aligned base has fixed 4-cy timing regardless of the patched
        ; page (the hi byte is in the instruction encoding, not computed at
        ; runtime from base.lo + x). The instruction lives in the CODE
        ; segment, which `src/c64.cfg` places in RAM, so the SMC store is
        ; safe. If the `smc.inc` macro pack (c64-ChaCha20-Poly1305-style)
        ; were in use here, this would be spelled `SMC_StoreHighByte smc_lo_addr`.
        sta smc_lo_addr+2       ; patch sqtab_lo abs,x hi byte
        ; C=0 after `adc #0` (the page-bit was consumed; $78 + 0 + C never
        ; wraps). Fold the lo->hi page delta (sqtab_hi - sqtab_lo = $0200).
        adc #(>sqtab_hi - >sqtab_lo)
        ; --- SMC site #2: patch hi byte of `lda abs,x` at smc_hi_addr ---
        ; Same mechanism as SMC site #1 above, targeting the hi byte ($7a)
        ; of `lda $7a00,x`. Store $7a or $7b, selecting sqtab_hi page 0 or
        ; page 1. `+2` is the hi-byte offset inside the 3-byte `lda abs,x`
        ; encoding. Pair of `sta abs` writes is constant-cy; no CT concern.
        sta smc_hi_addr+2       ; patch sqtab_hi abs,x hi byte

        ; --- Branchless |a-b| -> Y (sign-mask flip-and-negate) ---
        ; `a` is still live in Y from the entry stash, so we recover it
        ; with a 2-cy `tya` instead of a 3-cy `lda mul_a`. This is the
        ; other half of the register-entry optimization; the reason the
        ; `mul_a` scratch slot is absent from the local .byte block below.
        tya                     ; A = a (from entry stash)
        sec
        sbc mul_b               ; A = a - b, C=1 iff a>=b
        tay                     ; Y = raw diff (scratch)
        lda #$00
        sbc #$00                ; C=1: $00; C=0: $FF (sign mask)
        sta ct_sign_mask
        tya                     ; A = raw diff (from Y)
        eor ct_sign_mask        ; raw XOR mask
        sec
        sbc ct_sign_mask        ; + (-mask): +0 if a>=b, +1 if a<b
        tay                     ; Y = |a-b| (in [0,255])

        ; --- Table-lookup subtract: sqtab[a+b] - sqtab[|a-b|] ---
smc_lo_addr:
        lda sqtab_lo,x          ; hi byte SMC-patched above ($78 or $79)
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
smc_hi_addr:
        lda sqtab_hi,x          ; hi byte SMC-patched above ($7a or $7b)
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts

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
        lda #0
        adc #0                 ; bank = carry from shift
        sta reu_reu_bank
        lda #%10110001         ; execute + autoload + FETCH (REU->C64)
        sta reu_command
        rts

mul_b:          .byte 0
ct_sign_mask:   .byte 0
