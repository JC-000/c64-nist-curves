.setcpu "6502"

; =============================================================================
; curve384.s - P-384 curve parameters and NIST test vectors
; All field elements stored LITTLE-ENDIAN (byte 0 = LSB)
; =============================================================================

.segment "RODATA"

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

; =============================================================================
; NIST P-384 Test Vector: 2*G (derived from generator doubling)
; All values in LITTLE-ENDIAN byte order
; =============================================================================

; 2*G x-coordinate
.export ecdsa_test_2gx_384
ecdsa_test_2gx_384:
        .byte $61, $DF, $95, $52, $C7, $A9, $96, $5B
        .byte $F8, $64, $0E, $BE, $6E, $E8, $E0, $4F
        .byte $9E, $6E, $B9, $9F, $D1, $07, $D2, $51
        .byte $D6, $34, $F4, $A6, $59, $59, $02, $89
        .byte $F0, $97, $5B, $C5, $45, $00, $26, $69
        .byte $D9, $D2, $A3, $7B, $05, $99, $D9, $08

; 2*G y-coordinate
.export ecdsa_test_2gy_384
ecdsa_test_2gy_384:
        .byte $80, $0E, $94, $0A, $70, $1E, $50, $61
        .byte $2D, $E2, $39, $4D, $E9, $43, $FD, $5F
        .byte $25, $B4, $6A, $25, $5F, $50, $4E, $90
        .byte $3E, $C4, $6C, $BC, $75, $D8, $75, $B2
        .byte $74, $BA, $6D, $FD, $DF, $E8, $BF, $B7
        .byte $ED, $3C, $1B, $5B, $FA, $F1, $80, $8E
