.setcpu "6502"

; ===========================================================================
; sha384.s -- SHA-384 streaming hash (FIPS 180-4 §6.4)
;
; SHA-384 is SHA-512 with a different IV and a truncated 384-bit output.
; This file implements the full SHA-512 compression and uses the SHA-384
; constants/IV.
;
; ABI (all entry points; A/X/Y are clobbered by every routine):
;
;   sha384_init           Reset running state. No args.
;
;   sha384_update         Absorb sha_len (16-bit ZP) bytes from sha_src
;                         (16-bit ZP pointer). May trigger zero or more
;                         compression calls as the 128-byte block buffer
;                         fills. Caller may call repeatedly.
;
;   sha384_final          Pad (FIPS 180-4 §5.1.2) and run final
;                         compression(s); write 48 BE bytes of digest to
;                         sha384_digest. After this call the running
;                         state must be reset with sha384_init before
;                         any further calls.
;
;   sha384_digest         48-byte BE output buffer (label).
;   sha384_msg_buf        1024-byte test scratch (label, owned by harness).
;
; Endianness contract (read carefully):
;   * On-chip 64-bit words (sha_state, sha_w, sha_abcdefgh, sha_t) are
;     LITTLE-ENDIAN-WITHIN-WORD: byte[0] = LSB, byte[7] = MSB. This
;     matches 6502 ADC carry propagation.
;   * Wire / spec format is BIG-ENDIAN-WITHIN-WORD. sha_block_buf holds
;     bytes verbatim from the input stream (wire order). On compression
;     start, each 8-byte chunk in sha_block_buf is byte-reversed into
;     the corresponding sha_w[t] slot.
;   * The 128-bit length tail in the final padding block is appended as
;     BE bytes in sha_block_buf[112..127] -- the same byte-reverse step
;     puts them in LE position in W[14], W[15].
;   * sha384_digest is BE: each H[i] (LE on-chip) is written back high
;     byte first.
;
; Dependencies: this module is self-contained -- no REU DMA, no shared
; field/multiply scratch. Re-entrancy concerns from the curve modules do
; not apply. The only ZP slots used (sha_src, sha_len) are dedicated.
; ===========================================================================

.segment "CODE"

.export sha384_init
.export sha384_update
.export sha384_final

.importzp sha_src, sha_len, sha_w_ptr, sha_w_ptr2
.import sha_state, sha_w, sha_abcdefgh, sha_t, sha_scratch
.import sha_block_buf, sha_block_len, sha_total_len
.import sha384_digest, sha384_msg_buf

; ---------------------------------------------------------------------------
; Scratch slot layout inside sha_scratch (8 x 8 = 64 bytes available):
;   sha_in        = sha_scratch +  0  ; rotate input
;   sha_out       = sha_scratch +  8  ; rotate output
;   sha_tmp1      = sha_scratch + 16  ; sigma accumulator
;   sha_tmp2      = sha_scratch + 24
;   sha_tmp3      = sha_scratch + 32
;   sha_tmp4      = sha_scratch + 40  ; round helper
;   sha_tmp5      = sha_scratch + 48
;   sha_tmp6      = sha_scratch + 56
; ---------------------------------------------------------------------------
sha_in   = sha_scratch +  0
sha_out  = sha_scratch +  8
sha_tmp1 = sha_scratch + 16
sha_tmp2 = sha_scratch + 24
sha_tmp3 = sha_scratch + 32
sha_tmp4 = sha_scratch + 40
sha_tmp5 = sha_scratch + 48
sha_tmp6 = sha_scratch + 56

; T1 / T2 inside sha_t (16 bytes total):
sha_T1 = sha_t + 0
sha_T2 = sha_t + 8

; abcdefgh letters (each 8 bytes):
sha_a = sha_abcdefgh +  0
sha_b = sha_abcdefgh +  8
sha_c = sha_abcdefgh + 16
sha_d = sha_abcdefgh + 24
sha_e = sha_abcdefgh + 32
sha_f = sha_abcdefgh + 40
sha_g = sha_abcdefgh + 48
sha_h = sha_abcdefgh + 56

; ---------------------------------------------------------------------------
; copy64  -- 8-byte unrolled copy
; ---------------------------------------------------------------------------
.macro copy64 dst, src
        .repeat 8, i
                lda src+i
                sta dst+i
        .endrepeat
.endmacro

; ---------------------------------------------------------------------------
; xor64  dst ^= src
; ---------------------------------------------------------------------------
.macro xor64 dst, src
        .repeat 8, i
                lda dst+i
                eor src+i
                sta dst+i
        .endrepeat
.endmacro

; ---------------------------------------------------------------------------
; add64  dst += src   (LE-within-word, mod 2^64)
; ---------------------------------------------------------------------------
.macro add64 dst, src
        clc
        .repeat 8, i
                lda dst+i
                adc src+i
                sta dst+i
        .endrepeat
.endmacro

; ---------------------------------------------------------------------------
; zero64  dst = 0
; ---------------------------------------------------------------------------
.macro zero64 dst
        lda #0
        .repeat 8, i
                sta dst+i
        .endrepeat
.endmacro

; ===========================================================================
; sha384_init -- reset running state to SHA-384 IV.
; ===========================================================================
sha384_init:
        ; Copy 64-byte IV (sha384_iv) to sha_state.
        ldx #64
@cp:
        lda sha384_iv-1, x
        sta sha_state-1, x
        dex
        bne @cp

        ; Zero sha_block_len.
        lda #0
        sta sha_block_len

        ; Zero sha_total_len (16 bytes).
        ldx #16
@zl:
        sta sha_total_len-1, x
        dex
        bne @zl

        rts

; ===========================================================================
; sha384_update -- absorb sha_len bytes from (sha_src) into the block
;                  buffer. May trigger one or more compressions.
;
; Entry:
;   sha_src (ZP, 2 B) -- pointer to first input byte
;   sha_len (ZP, 2 B) -- 16-bit byte count
;
; Implementation uses a simple byte-at-a-time append loop. Performance
; could be improved by bulk-copying full 128-byte chunks, but keeping
; the code small / obvious matches the project's "first cut should be
; correct" guidance.
; ===========================================================================
sha384_update:
        ; Quick exit if sha_len == 0.
        lda sha_len+0
        ora sha_len+1
        bne @loop
        rts

@loop:
        ; Fetch one byte from (sha_src), Y=0 (avoid Y-flag hazard).
        ldy #0
        lda (sha_src), y

        ; Append to sha_block_buf at position sha_block_len.
        ldx sha_block_len
        sta sha_block_buf, x

        ; sha_block_len += 1
        inx
        stx sha_block_len

        ; Increment sha_total_len by 8 bits (one byte). 128-bit add of #8.
        ;
        ; The previous loop form here used `iny / cpy #16 / bne` to walk the
        ; carry. CPY clobbers C between iterations, so any non-zero carry
        ; from byte N's `adc #0` was lost before byte N+1 ran. The bug
        ; manifested only for messages >= 8192 bytes (where byte 1 of the
        ; bit count carries into byte 2). Fix: fully unroll the 15-byte
        ; carry chain so no flag-clobbering loop control is involved.
        clc
        lda sha_total_len+0
        adc #8
        sta sha_total_len+0
        .repeat 15, i
                lda sha_total_len + 1 + i
                adc #0
                sta sha_total_len + 1 + i
        .endrepeat

        ; Advance sha_src by 1 (16-bit increment).
        inc sha_src+0
        bne :+
        inc sha_src+1
:
        ; Decrement sha_len by 1 (16-bit decrement).
        lda sha_len+0
        bne :+
                dec sha_len+1
:
        dec sha_len+0

        ; If block is full (sha_block_len == 128), compress.
        lda sha_block_len
        cmp #128
        bne @check_done
        jsr sha_compress
        lda #0
        sta sha_block_len

@check_done:
        ; Loop until sha_len == 0. The unrolled 128-bit carry chain pushed
        ; the loop body past 6502 short-branch range, so use a branch-around-JMP.
        lda sha_len+0
        ora sha_len+1
        beq @loop_done
        jmp @loop
@loop_done:
        rts

; ===========================================================================
; sha384_final -- pad and finalize, write 48 BE bytes to sha384_digest.
;
; Pad scheme (FIPS 180-4 §5.1.2):
;   1. Append 0x80.
;   2. Append zero bytes until block length mod 128 == 112 (= 896 bits).
;   3. Append 128-bit total *bit* length, big-endian.
;   If room after 0x80 is < 16 bytes, zero-fill the current block,
;   compress, then start a fresh zero block whose only non-zero data is
;   the length tail at offset [112..127].
; ===========================================================================
sha384_final:
        ; Append 0x80 to the buffer.
        ldx sha_block_len
        lda #$80
        sta sha_block_buf, x
        inx
        stx sha_block_len

        ; If sha_block_len > 112 we cannot fit the 16-byte length tail in
        ; the current block; flush it after zero-fill.
        lda sha_block_len
        cmp #113
        bcc @fill_then_tail   ; len < 113 -> tail fits in this block

        ; --- Need an extra block. Zero-fill current block to 128, compress.
@fill_to_128:
        lda #0
@fz1:
        ldx sha_block_len
        cpx #128
        beq @did_fill1
        sta sha_block_buf, x
        inc sha_block_len
        jmp @fz1
@did_fill1:
        jsr sha_compress

        ; Start fresh block: zero bytes 0..111. Then continue to tail write.
        lda #0
        ldx #112
@fz2:
        sta sha_block_buf-1, x
        dex
        bne @fz2
        sta sha_block_len     ; A is still 0
        jmp @write_tail

@fill_then_tail:
        ; Zero-fill from sha_block_len up to byte 112 (exclusive).
        lda #0
@fz3:
        ldx sha_block_len
        cpx #112
        beq @write_tail
        sta sha_block_buf, x
        inc sha_block_len
        jmp @fz3

@write_tail:
        ; Write 128-bit length BE into sha_block_buf[112..127].
        ; sha_total_len is LE-on-chip; reverse byte-by-byte: high byte first.
        ldx #0                ; cursor into sha_block_buf+112
        ldy #15               ; cursor into sha_total_len (high byte first)
@wt:
        lda sha_total_len, y
        sta sha_block_buf+112, x
        inx
        dey
        bpl @wt

        ; Compress the final block.
        jsr sha_compress

        ; --- Output digest: 6 words (48 bytes), each LE-on-chip -> BE on disk.
        ; Mirror each 8-byte word: digest[8*i + (7 - j)] = H[8*i + j].
        ; Implement as a flat 48-iteration loop indexed by Y = 0..47.
        ; For each Y: word_off = (Y / 8) * 8 = Y & $f8; in-word = Y & 7;
        ;             dst_off = word_off + (7 - in_word).
        ; Easier: use an 8-byte-mirror unrolled per-word body, called 6 times.
        ldx #0                ; word index 0..5
@dw_word:
        ; word_base = 8 * X
        txa
        asl a
        asl a
        asl a                 ; A = 8 * X
        tay                   ; Y = 8 * X (used as base for both src and dst)
        ; Mirror 8 bytes src[Y..Y+7] -> dst[Y..Y+7] reversed.
        .repeat 8, j
                lda sha_state + j, y
                sta sha384_digest + (7 - j), y
        .endrepeat
        inx
        cpx #6
        bne @dw_word
        rts

; ===========================================================================
; sha_compress -- run one block compression.
;
; Reads:  sha_block_buf (128 bytes, wire BE order)
; Reads/writes: sha_state (H[0..7] LE-on-chip)
; Clobbers: sha_w, sha_abcdefgh, sha_t, sha_scratch, A/X/Y, sha_w_ptr/ptr2
; ===========================================================================
sha_compress:
        ; ---- Step 1: copy block into W[0..15] with byte reverse per word.
        ; sha_block_buf is 128 bytes (no page-cross issue); use Y indexing.
        ldx #0                ; word counter t = 0..15
@wcopy_word:
        txa
        asl a
        asl a
        asl a                 ; A = 8*t  (max 8*15 = 120 -- fits in a byte)
        tay
        .repeat 8, j
                lda sha_block_buf + j, y
                sta sha_w + (7 - j), y
        .endrepeat
        inx
        cpx #16
        bne @wcopy_word

        ; ---- Step 2: expand W[16..79].
        ; Strategy: maintain sha_w_ptr = &W[t]. After processing one t,
        ; advance by +8. Initial value at t=16: sha_w + 128.
        lda #<(sha_w + 128)
        sta sha_w_ptr+0
        lda #>(sha_w + 128)
        sta sha_w_ptr+1
        lda #16
        sta sha_t_idx

@expand:
        ; sha_tmp1 = sigma1(W[t-2])  ; offset -16 from sha_w_ptr
        lda #<(0-16)
        ldx #>(0-16)
        jsr load_w_rel_to_in
        jsr sigma1_in_to_tmp1

        ; sha_tmp2 = sigma0(W[t-15]) ; offset -120 from sha_w_ptr
        lda #<(0-120)
        ldx #>(0-120)
        jsr load_w_rel_to_in
        jsr sigma0_in_to_tmp2

        ; sha_tmp1 += sha_tmp2
        add64 sha_tmp1, sha_tmp2

        ; sha_tmp1 += W[t-7]  ; offset -56
        lda #<(0-56)
        ldx #>(0-56)
        jsr load_w_rel_to_in
        add64 sha_tmp1, sha_in

        ; sha_tmp1 += W[t-16] ; offset -128
        lda #<(0-128)
        ldx #>(0-128)
        jsr load_w_rel_to_in
        add64 sha_tmp1, sha_in

        ; Store sha_tmp1 -> *(sha_w_ptr) = W[t]   (8 bytes via (zp),y)
        ldy #0
@store_w:
        lda sha_tmp1, y
        sta (sha_w_ptr), y
        iny
        cpy #8
        bne @store_w

        ; Advance sha_w_ptr by +8.
        clc
        lda sha_w_ptr+0
        adc #8
        sta sha_w_ptr+0
        bcc :+
                inc sha_w_ptr+1
:
        inc sha_t_idx
        lda sha_t_idx
        cmp #80
        beq @expand_done
        jmp @expand
@expand_done:

        ; ---- Step 3: copy H[0..7] into sha_a..sha_h.
        ldx #64
@cp_h:
        lda sha_state-1, x
        sta sha_abcdefgh-1, x
        dex
        bne @cp_h

        ; ---- Step 4: 80 rounds.
        ; Maintain sha_w_ptr = &W[t] and sha_w_ptr2 = &K[t]. Both advance
        ; by +8 per round.
        lda #<sha_w
        sta sha_w_ptr+0
        lda #>sha_w
        sta sha_w_ptr+1
        lda #<sha384_k
        sta sha_w_ptr2+0
        lda #>sha384_k
        sta sha_w_ptr2+1

        lda #0
        sta sha_t_idx
@rnd:
        jsr sha_round
        ; Advance both pointers by +8.
        clc
        lda sha_w_ptr+0
        adc #8
        sta sha_w_ptr+0
        bcc :+
                inc sha_w_ptr+1
:
        clc
        lda sha_w_ptr2+0
        adc #8
        sta sha_w_ptr2+0
        bcc :+
                inc sha_w_ptr2+1
:
        inc sha_t_idx
        lda sha_t_idx
        cmp #80
        bne @rnd

        ; ---- Step 5: H[i] += letter[i] for i = 0..7.
        add64 sha_state +  0, sha_a
        add64 sha_state +  8, sha_b
        add64 sha_state + 16, sha_c
        add64 sha_state + 24, sha_d
        add64 sha_state + 32, sha_e
        add64 sha_state + 40, sha_f
        add64 sha_state + 48, sha_g
        add64 sha_state + 56, sha_h
        rts

; ---------------------------------------------------------------------------
; load_w_rel_to_in -- copy 8 bytes from (sha_w_ptr + signed16(A,X)) into
;                     sha_in. The offset is added to sha_w_ptr into a
;                     temporary at sha_w_ptr2; sha_w_ptr is preserved.
;
; Entry:  A = low byte of signed offset, X = high byte
; Exit:   sha_in[0..7] = bytes at (sha_w_ptr + offset)
; Clobbers: A, X, Y, sha_w_ptr2
; ---------------------------------------------------------------------------
load_w_rel_to_in:
        clc
        adc sha_w_ptr+0
        sta sha_w_ptr2+0
        txa
        adc sha_w_ptr+1
        sta sha_w_ptr2+1
        ldy #0
@l:
        lda (sha_w_ptr2), y
        sta sha_in, y
        iny
        cpy #8
        bne @l
        rts

sha_t_idx:   .byte 0          ; current round / expansion index

; ---------------------------------------------------------------------------
; sha_round -- one round body.
;
; Uses sha_t_idx (0..79) to index K[t] and W[t].
;
;   T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
;   T2 = Sigma0(a) + Maj(a,b,c)
;   h = g; g = f; f = e
;   e = d + T1
;   d = c; c = b; b = a
;   a = T1 + T2
;
; All 64-bit ops, mod 2^64.
; ---------------------------------------------------------------------------
sha_round:
        ; ---- Compute Sigma1(e) -> sha_tmp4 ----
        copy64 sha_in, sha_e
        jsr Sigma1_in_to_tmp1   ; sha_tmp1 = Sigma1(e)
        copy64 sha_tmp4, sha_tmp1

        ; ---- Compute Ch(e,f,g) -> sha_tmp5 ----
        ;   Ch = (e & f) ^ ((~e) & g)
        ; sha_tmp5 = e & f
        .repeat 8, i
                lda sha_e + i
                and sha_f + i
                sta sha_tmp5 + i
        .endrepeat
        ; sha_tmp6 = (~e) & g
        .repeat 8, i
                lda sha_e + i
                eor #$ff
                and sha_g + i
                sta sha_tmp6 + i
        .endrepeat
        ; sha_tmp5 ^= sha_tmp6
        xor64 sha_tmp5, sha_tmp6

        ; ---- T1 = h ----
        copy64 sha_T1, sha_h
        ; T1 += Sigma1(e)
        add64 sha_T1, sha_tmp4
        ; T1 += Ch(e,f,g)
        add64 sha_T1, sha_tmp5

        ; T1 += K[t]   (K[t] = *(sha_w_ptr2))   --   unrolled to preserve C
        clc
        .repeat 8, i
                ldy #i
                lda (sha_w_ptr2), y
                adc sha_T1 + i
                sta sha_T1 + i
        .endrepeat

        ; T1 += W[t]   (W[t] = *(sha_w_ptr))     --   unrolled to preserve C
        clc
        .repeat 8, i
                ldy #i
                lda (sha_w_ptr), y
                adc sha_T1 + i
                sta sha_T1 + i
        .endrepeat

        ; ---- T2 = Sigma0(a) + Maj(a,b,c) ----
        copy64 sha_in, sha_a
        jsr Sigma0_in_to_tmp1   ; sha_tmp1 = Sigma0(a)
        copy64 sha_T2, sha_tmp1

        ; Maj(a,b,c) = (a&b) ^ (a&c) ^ (b&c)
        ; sha_tmp4 = a & b
        .repeat 8, i
                lda sha_a + i
                and sha_b + i
                sta sha_tmp4 + i
        .endrepeat
        ; sha_tmp5 = a & c
        .repeat 8, i
                lda sha_a + i
                and sha_c + i
                sta sha_tmp5 + i
        .endrepeat
        ; sha_tmp6 = b & c
        .repeat 8, i
                lda sha_b + i
                and sha_c + i
                sta sha_tmp6 + i
        .endrepeat
        xor64 sha_tmp4, sha_tmp5
        xor64 sha_tmp4, sha_tmp6
        add64 sha_T2, sha_tmp4

        ; ---- shift abcdefgh ----
        ; h = g
        copy64 sha_h, sha_g
        ; g = f
        copy64 sha_g, sha_f
        ; f = e
        copy64 sha_f, sha_e
        ; e = d + T1
        copy64 sha_e, sha_d
        add64 sha_e, sha_T1
        ; d = c
        copy64 sha_d, sha_c
        ; c = b
        copy64 sha_c, sha_b
        ; b = a
        copy64 sha_b, sha_a
        ; a = T1 + T2
        copy64 sha_a, sha_T1
        add64 sha_a, sha_T2

        rts

; ===========================================================================
; sigma / Sigma helper subroutines.
; All take input in sha_in (8 bytes LE) and write output to sha_tmp1.
; They use sha_tmp2, sha_tmp3 and sha_out as scratch.
; ===========================================================================

; sigma0(x) = ROTR(x,1) ^ ROTR(x,8) ^ SHR(x,7)
sigma0_in_to_tmp2:
        ; intermediate result lives in sha_tmp2 to keep sha_tmp1 free for caller
        jsr rotr_1
        copy64 sha_tmp2, sha_out
        jsr rotr_8
        xor64 sha_tmp2, sha_out
        jsr shr_7
        xor64 sha_tmp2, sha_out
        rts

; sigma1(x) = ROTR(x,19) ^ ROTR(x,61) ^ SHR(x,6)  -> sha_tmp1
sigma1_in_to_tmp1:
        jsr rotr_19
        copy64 sha_tmp1, sha_out
        jsr rotr_61
        xor64 sha_tmp1, sha_out
        jsr shr_6
        xor64 sha_tmp1, sha_out
        rts

; Sigma0(x) = ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39)  -> sha_tmp1
Sigma0_in_to_tmp1:
        jsr rotr_28
        copy64 sha_tmp1, sha_out
        jsr rotr_34
        xor64 sha_tmp1, sha_out
        jsr rotr_39
        xor64 sha_tmp1, sha_out
        rts

; Sigma1(x) = ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41)  -> sha_tmp1
Sigma1_in_to_tmp1:
        jsr rotr_14
        copy64 sha_tmp1, sha_out
        jsr rotr_18
        xor64 sha_tmp1, sha_out
        jsr rotr_41
        xor64 sha_tmp1, sha_out
        rts

; ===========================================================================
; ROTR / SHR helpers: input in sha_in, output in sha_out.
;
; Strategy: each rotation is q*8 + r bits. We do a byte rotation by q (a
; renumbering of source bytes) into sha_out, then bit-rotate sha_out in
; place by r bits. SHR variants do the same byte step but zero-fill on the
; high end during the bit-shift.
;
; Macros below emit the byte-rotation as 8 LDA/STA pairs, and call shared
; bit-shift subroutines for the in-place tail shift.
; ===========================================================================

; byte_rotr_q  -- emit 8 LDA/STA pairs to right-rotate sha_in by q bytes
;                 into sha_out. For ROTR-by-byte, new[i] = old[(i+q) mod 8].
.macro byte_rotr_q q
        .repeat 8, i
                lda sha_in + ((i + q) .mod 8)
                sta sha_out + i
        .endrepeat
.endmacro

; byte_shr_q  -- emit a byte-shift-right by q bytes into sha_out.
;                For SHR-by-byte (zero fill at MSB end):
;                  new[i] = old[i+q] for i < 8-q, else 0.
.macro byte_shr_q q
        .repeat 8, i
                .if i + q < 8
                        lda sha_in + (i + q)
                        sta sha_out + i
                .else
                        lda #0
                        sta sha_out + i
                .endif
        .endrepeat
.endmacro

; ---------------------------------------------------------------------------
; bit_rotr1 -- in-place ROTR-by-1 of sha_out (8 bytes).
;
; Right-shift the 64-bit value with bit 0 of byte[0] wrapping into bit 7
; of byte[7]. Standard idiom: chain LSR/ROR from MSB down to LSB; the
; final carry holds the wrap bit.
; ---------------------------------------------------------------------------
bit_rotr1:
        lsr sha_out + 7
        ror sha_out + 6
        ror sha_out + 5
        ror sha_out + 4
        ror sha_out + 3
        ror sha_out + 2
        ror sha_out + 1
        ror sha_out + 0
        bcc :+
                lda sha_out + 7
                ora #$80
                sta sha_out + 7
:
        rts

; ---------------------------------------------------------------------------
; bit_shr1 -- in-place SHR-by-1 of sha_out (8 bytes), zero fill at MSB.
; ---------------------------------------------------------------------------
bit_shr1:
        lsr sha_out + 7
        ror sha_out + 6
        ror sha_out + 5
        ror sha_out + 4
        ror sha_out + 3
        ror sha_out + 2
        ror sha_out + 1
        ror sha_out + 0
        rts

; ---------------------------------------------------------------------------
; bit_rotr_n / bit_shr_n -- repeated calls to the 1-bit primitives.
;
; Each helper bit-shifts sha_out in place by n bits (n in 1..7).
; ---------------------------------------------------------------------------
bit_rotr_2:
        jsr bit_rotr1
        jmp bit_rotr1

bit_rotr_3:
        jsr bit_rotr1
        jsr bit_rotr1
        jmp bit_rotr1

bit_rotr_4:
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jmp bit_rotr1

bit_rotr_5:
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jmp bit_rotr1

bit_rotr_6:
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jmp bit_rotr1

bit_rotr_7:
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jsr bit_rotr1
        jmp bit_rotr1

bit_shr_6:
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jmp bit_shr1

bit_shr_7:
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jsr bit_shr1
        jmp bit_shr1

; ---------------------------------------------------------------------------
; The named ROTR_n / SHR_n entry points.
;
; ROTR(x, n) = byte-rotate by floor(n/8), then bit-rotate by (n mod 8).
;
;   n =  1: q=0, r=1
;   n =  6: q=0, r=6
;   n =  7: q=0, r=7
;   n =  8: q=1, r=0
;   n = 14: q=1, r=6
;   n = 18: q=2, r=2
;   n = 19: q=2, r=3
;   n = 28: q=3, r=4
;   n = 34: q=4, r=2
;   n = 39: q=4, r=7
;   n = 41: q=5, r=1
;   n = 61: q=7, r=5
; ---------------------------------------------------------------------------

rotr_1:
        byte_rotr_q 0
        jmp bit_rotr1

rotr_8:
        byte_rotr_q 1
        rts

rotr_14:
        byte_rotr_q 1
        jmp bit_rotr_6

rotr_18:
        byte_rotr_q 2
        jmp bit_rotr_2

rotr_19:
        byte_rotr_q 2
        jmp bit_rotr_3

rotr_28:
        byte_rotr_q 3
        jmp bit_rotr_4

rotr_34:
        byte_rotr_q 4
        jmp bit_rotr_2

rotr_39:
        byte_rotr_q 4
        jmp bit_rotr_7

rotr_41:
        byte_rotr_q 5
        jmp bit_rotr1

rotr_61:
        byte_rotr_q 7
        jmp bit_rotr_5

; SHR variants (zero fill at MSB).
shr_6:
        byte_shr_q 0
        jmp bit_shr_6

shr_7:
        byte_shr_q 0
        jmp bit_shr_7

; ===========================================================================
; SHA-384 IV (FIPS 180-4 §5.3.4) and K[80] table (FIPS 180-4 §4.2.3).
;
; All 64-bit constants are stored LE-within-word: byte 0 = LSB, byte 7 = MSB.
; The .byte rows below list bytes LSB-first; the trailing comment shows the
; canonical big-endian hex form for cross-reference with the spec.
; ===========================================================================

.segment "RODATA"

sha384_iv:
        .byte $d8, $9e, $05, $c1, $5d, $9d, $bb, $cb   ; H0 = cbbb9d5dc1059ed8
        .byte $07, $d5, $7c, $36, $2a, $29, $9a, $62   ; H1 = 629a292a367cd507
        .byte $17, $dd, $70, $30, $5a, $01, $59, $91   ; H2 = 9159015a3070dd17
        .byte $39, $59, $0e, $f7, $d8, $ec, $2f, $15   ; H3 = 152fecd8f70e5939
        .byte $31, $0b, $c0, $ff, $67, $26, $33, $67   ; H4 = 67332667ffc00b31
        .byte $11, $15, $58, $68, $87, $4a, $b4, $8e   ; H5 = 8eb44a8768581511
        .byte $a7, $8f, $f9, $64, $0d, $2e, $0c, $db   ; H6 = db0c2e0d64f98fa7
        .byte $a4, $4f, $fa, $be, $1d, $48, $b5, $47   ; H7 = 47b5481dbefa4fa4

sha384_k:
        ; Round constants K[0..79] for SHA-512 (also used by SHA-384).
        ; Each row: 8 bytes LE-within-word; comment shows BE hex form.
        .byte $22, $ae, $28, $d7, $98, $2f, $8a, $42   ; 428a2f98d728ae22
        .byte $cd, $65, $ef, $23, $91, $44, $37, $71   ; 7137449123ef65cd
        .byte $2f, $3b, $4d, $ec, $cf, $fb, $c0, $b5   ; b5c0fbcfec4d3b2f
        .byte $bc, $db, $89, $81, $a5, $db, $b5, $e9   ; e9b5dba58189dbbc
        .byte $38, $b5, $48, $f3, $5b, $c2, $56, $39   ; 3956c25bf348b538
        .byte $19, $d0, $05, $b6, $f1, $11, $f1, $59   ; 59f111f1b605d019
        .byte $9b, $4f, $19, $af, $a4, $82, $3f, $92   ; 923f82a4af194f9b
        .byte $18, $81, $6d, $da, $d5, $5e, $1c, $ab   ; ab1c5ed5da6d8118
        .byte $42, $02, $03, $a3, $98, $aa, $07, $d8   ; d807aa98a3030242
        .byte $be, $6f, $70, $45, $01, $5b, $83, $12   ; 12835b0145706fbe
        .byte $8c, $b2, $e4, $4e, $be, $85, $31, $24   ; 243185be4ee4b28c
        .byte $e2, $b4, $ff, $d5, $c3, $7d, $0c, $55   ; 550c7dc3d5ffb4e2
        .byte $6f, $89, $7b, $f2, $74, $5d, $be, $72   ; 72be5d74f27b896f
        .byte $b1, $96, $16, $3b, $fe, $b1, $de, $80   ; 80deb1fe3b1696b1
        .byte $35, $12, $c7, $25, $a7, $06, $dc, $9b   ; 9bdc06a725c71235
        .byte $94, $26, $69, $cf, $74, $f1, $9b, $c1   ; c19bf174cf692694
        .byte $d2, $4a, $f1, $9e, $c1, $69, $9b, $e4   ; e49b69c19ef14ad2
        .byte $e3, $25, $4f, $38, $86, $47, $be, $ef   ; efbe4786384f25e3
        .byte $b5, $d5, $8c, $8b, $c6, $9d, $c1, $0f   ; 0fc19dc68b8cd5b5
        .byte $65, $9c, $ac, $77, $cc, $a1, $0c, $24   ; 240ca1cc77ac9c65
        .byte $75, $02, $2b, $59, $6f, $2c, $e9, $2d   ; 2de92c6f592b0275
        .byte $83, $e4, $a6, $6e, $aa, $84, $74, $4a   ; 4a7484aa6ea6e483
        .byte $d4, $fb, $41, $bd, $dc, $a9, $b0, $5c   ; 5cb0a9dcbd41fbd4
        .byte $b5, $53, $11, $83, $da, $88, $f9, $76   ; 76f988da831153b5
        .byte $ab, $df, $66, $ee, $52, $51, $3e, $98   ; 983e5152ee66dfab
        .byte $10, $32, $b4, $2d, $6d, $c6, $31, $a8   ; a831c66d2db43210
        .byte $3f, $21, $fb, $98, $c8, $27, $03, $b0   ; b00327c898fb213f
        .byte $e4, $0e, $ef, $be, $c7, $7f, $59, $bf   ; bf597fc7beef0ee4
        .byte $c2, $8f, $a8, $3d, $f3, $0b, $e0, $c6   ; c6e00bf33da88fc2
        .byte $25, $a7, $0a, $93, $47, $91, $a7, $d5   ; d5a79147930aa725
        .byte $6f, $82, $03, $e0, $51, $63, $ca, $06   ; 06ca6351e003826f
        .byte $70, $6e, $0e, $0a, $67, $29, $29, $14   ; 142929670a0e6e70
        .byte $fc, $2f, $d2, $46, $85, $0a, $b7, $27   ; 27b70a8546d22ffc
        .byte $26, $c9, $26, $5c, $38, $21, $1b, $2e   ; 2e1b21385c26c926
        .byte $ed, $2a, $c4, $5a, $fc, $6d, $2c, $4d   ; 4d2c6dfc5ac42aed
        .byte $df, $b3, $95, $9d, $13, $0d, $38, $53   ; 53380d139d95b3df
        .byte $de, $63, $af, $8b, $54, $73, $0a, $65   ; 650a73548baf63de
        .byte $a8, $b2, $77, $3c, $bb, $0a, $6a, $76   ; 766a0abb3c77b2a8
        .byte $e6, $ae, $ed, $47, $2e, $c9, $c2, $81   ; 81c2c92e47edaee6
        .byte $3b, $35, $82, $14, $85, $2c, $72, $92   ; 92722c851482353b
        .byte $64, $03, $f1, $4c, $a1, $e8, $bf, $a2   ; a2bfe8a14cf10364
        .byte $01, $30, $42, $bc, $4b, $66, $1a, $a8   ; a81a664bbc423001
        .byte $91, $97, $f8, $d0, $70, $8b, $4b, $c2   ; c24b8b70d0f89791
        .byte $30, $be, $54, $06, $a3, $51, $6c, $c7   ; c76c51a30654be30
        .byte $18, $52, $ef, $d6, $19, $e8, $92, $d1   ; d192e819d6ef5218
        .byte $10, $a9, $65, $55, $24, $06, $99, $d6   ; d69906245565a910
        .byte $2a, $20, $71, $57, $85, $35, $0e, $f4   ; f40e35855771202a
        .byte $b8, $d1, $bb, $32, $70, $a0, $6a, $10   ; 106aa07032bbd1b8
        .byte $c8, $d0, $d2, $b8, $16, $c1, $a4, $19   ; 19a4c116b8d2d0c8
        .byte $53, $ab, $41, $51, $08, $6c, $37, $1e   ; 1e376c085141ab53
        .byte $99, $eb, $8e, $df, $4c, $77, $48, $27   ; 2748774cdf8eeb99
        .byte $a8, $48, $9b, $e1, $b5, $bc, $b0, $34   ; 34b0bcb5e19b48a8
        .byte $63, $5a, $c9, $c5, $b3, $0c, $1c, $39   ; 391c0cb3c5c95a63
        .byte $cb, $8a, $41, $e3, $4a, $aa, $d8, $4e   ; 4ed8aa4ae3418acb
        .byte $73, $e3, $63, $77, $4f, $ca, $9c, $5b   ; 5b9cca4f7763e373
        .byte $a3, $b8, $b2, $d6, $f3, $6f, $2e, $68   ; 682e6ff3d6b2b8a3
        .byte $fc, $b2, $ef, $5d, $ee, $82, $8f, $74   ; 748f82ee5defb2fc
        .byte $60, $2f, $17, $43, $6f, $63, $a5, $78   ; 78a5636f43172f60
        .byte $72, $ab, $f0, $a1, $14, $78, $c8, $84   ; 84c87814a1f0ab72
        .byte $ec, $39, $64, $1a, $08, $02, $c7, $8c   ; 8cc702081a6439ec
        .byte $28, $1e, $63, $23, $fa, $ff, $be, $90   ; 90befffa23631e28
        .byte $e9, $bd, $82, $de, $eb, $6c, $50, $a4   ; a4506cebde82bde9
        .byte $15, $79, $c6, $b2, $f7, $a3, $f9, $be   ; bef9a3f7b2c67915
        .byte $2b, $53, $72, $e3, $f2, $78, $71, $c6   ; c67178f2e372532b
        .byte $9c, $61, $26, $ea, $ce, $3e, $27, $ca   ; ca273eceea26619c
        .byte $07, $c2, $c0, $21, $c7, $b8, $86, $d1   ; d186b8c721c0c207
        .byte $1e, $eb, $e0, $cd, $d6, $7d, $da, $ea   ; eada7dd6cde0eb1e
        .byte $78, $d1, $6e, $ee, $7f, $4f, $7d, $f5   ; f57d4f7fee6ed178
        .byte $ba, $6f, $17, $72, $aa, $67, $f0, $06   ; 06f067aa72176fba
        .byte $a6, $98, $c8, $a2, $c5, $7d, $63, $0a   ; 0a637dc5a2c898a6
        .byte $ae, $0d, $f9, $be, $04, $98, $3f, $11   ; 113f9804bef90dae
        .byte $1b, $47, $1c, $13, $35, $0b, $71, $1b   ; 1b710b35131c471b
        .byte $84, $7d, $04, $23, $f5, $77, $db, $28   ; 28db77f523047d84
        .byte $93, $24, $c7, $40, $7b, $ab, $ca, $32   ; 32caab7b40c72493
        .byte $bc, $be, $c9, $15, $0a, $be, $9e, $3c   ; 3c9ebe0a15c9bebc
        .byte $4c, $0d, $10, $9c, $c4, $67, $1d, $43   ; 431d67c49c100d4c
        .byte $b6, $42, $3e, $cb, $be, $d4, $c5, $4c   ; 4cc5d4becb3e42b6
        .byte $2a, $7e, $65, $fc, $9c, $29, $7f, $59   ; 597f299cfc657e2a
        .byte $ec, $fa, $d6, $3a, $ab, $6f, $cb, $5f   ; 5fcb6fab3ad6faec
        .byte $17, $58, $47, $4a, $8c, $19, $44, $6c   ; 6c44198c4a475817
