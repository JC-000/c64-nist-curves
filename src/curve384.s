.setcpu "6502"

; =============================================================================
; curve384.s - P-384 curve parameters and NIST test vectors
; All field elements stored LITTLE-ENDIAN (byte 0 = LSB)
; =============================================================================

.segment "LIB_NISTCURVES_P384_RODATA"

; =============================================================================
; P-384 Curve Parameters (little-endian)
; p = 2^384 - 2^128 - 2^96 + 2^32 - 1
; =============================================================================

; Coefficient a = p - 3 (mod p)
.export ec_a384
ec_a384:
        .byte $FC, $FF, $FF, $FF, $00, $00, $00, $00
        .byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        .byte $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        .byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        .byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        .byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF

; Coefficient b
.export ec_b384
ec_b384:
        .byte $EF, $2A, $EC, $D3, $ED, $C8, $85, $2A
        .byte $9D, $D1, $2E, $8A, $8D, $39, $56, $C6
        .byte $5A, $87, $13, $50, $8F, $08, $14, $03
        .byte $12, $41, $81, $FE, $6E, $9C, $1D, $18
        .byte $19, $2D, $F8, $E3, $6B, $05, $8E, $98
        .byte $E4, $E7, $3E, $E2, $A7, $2F, $31, $B3

; Generator x coordinate
.export ec_gx384
ec_gx384:
        .byte $B7, $0A, $76, $72, $38, $5E, $54, $3A
        .byte $6C, $29, $55, $BF, $5D, $F2, $02, $55
        .byte $38, $2A, $54, $82, $E0, $41, $F7, $59
        .byte $98, $9B, $A7, $8B, $62, $3B, $1D, $6E
        .byte $74, $AD, $20, $F3, $1E, $C7, $B1, $8E
        .byte $37, $05, $8B, $BE, $22, $CA, $87, $AA

; Generator y coordinate
.export ec_gy384
ec_gy384:
        .byte $5F, $0E, $EA, $90, $7C, $1D, $43, $7A
        .byte $9D, $81, $7E, $1D, $CE, $B1, $60, $0A
        .byte $C0, $B8, $F0, $B5, $13, $31, $DA, $E9
        .byte $7C, $14, $9A, $28, $BD, $1D, $F4, $F8
        .byte $29, $DC, $92, $92, $BF, $98, $9E, $5D
        .byte $6F, $2C, $26, $96, $4A, $DE, $17, $36

