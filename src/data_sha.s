.setcpu "6502"

; =============================================================================
; data_sha.s - SHA-384 streaming hash state (FIPS 180-4 §6.4).
;
; Split from the monolithic data.s as part of #40 (SPEC §6 minimal-archive
; build targets). Self-contained: SHA-384 has no shared scratch with the
; field / point / ECDSA code paths, so this can stand alone in the
; lib-p384-sha384 archive.
;
; Storage convention: each 64-bit word is held LITTLE-ENDIAN-WITHIN-WORD,
; matching 6502 ADC carry propagation. Wire SHA-512 byte order is BE-within-
; word; the byte-reverse happens at the boundary between sha_block_buf
; (wire order, BE) and sha_w (on-chip order, LE). The final digest is
; written BE in sha384_digest to match the FIPS spec output format.
; All buffers are owned exclusively by sha384.s.
; =============================================================================

.segment "LIB_NISTCURVES_SHA384_BSS"

.export sha_state
sha_state:        .res 64, 0     ; H[0..7], 8 bytes each LE-within-word
.export sha_w
sha_w:            .res 640, 0    ; W[0..79] message schedule, 8 B each LE
.export sha_abcdefgh
sha_abcdefgh:     .res 64, 0     ; working a..h, 8 B each LE
.export sha_t
sha_t:            .res 16, 0     ; T1 (8 B) + T2 (8 B), LE
.export sha_scratch
sha_scratch:      .res 64, 0     ; 8x 8-byte scratch slots for round helpers
.export sha_block_buf
sha_block_buf:    .res 128, 0    ; current 1024-bit block (wire order)
.export sha_block_len
sha_block_len:    .byte 0        ; bytes used in sha_block_buf, 0..127
.export sha_total_len
sha_total_len:    .res 16, 0     ; 128-bit total bit count, LE on-chip
.export sha384_digest
sha384_digest:    .res 48, 0     ; final BE digest output
