.setcpu "6502"

.segment "LIB_NISTCURVES_P256_RODATA"

; Exports
.export ec_a256, ec_b256, ec_gx256, ec_gy256

; Coefficient a = p - 3
ec_a256:
        .byte $FC, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        .byte $FF, $FF, $FF, $FF, $00, $00, $00, $00
        .byte $00, $00, $00, $00, $00, $00, $00, $00
        .byte $01, $00, $00, $00, $FF, $FF, $FF, $FF

; Coefficient b
ec_b256:
        .byte $4B, $60, $D2, $27, $3E, $3C, $CE, $3B
        .byte $F6, $B0, $53, $CC, $B0, $06, $1D, $65
        .byte $BC, $86, $98, $76, $55, $BD, $EB, $B3
        .byte $E7, $93, $3A, $AA, $D8, $35, $C6, $5A

; Generator x coordinate
ec_gx256:
        .byte $96, $C2, $98, $D8, $45, $39, $A1, $F4
        .byte $A0, $33, $EB, $2D, $81, $7D, $03, $77
        .byte $F2, $40, $A4, $63, $E5, $E6, $BC, $F8
        .byte $47, $42, $2C, $E1, $F2, $D1, $17, $6B

; Generator y coordinate
ec_gy256:
        .byte $F5, $51, $BF, $37, $68, $40, $B6, $CB
        .byte $CE, $5E, $31, $6B, $57, $33, $CE, $2B
        .byte $16, $9E, $0F, $7C, $4A, $EB, $E7, $8E
        .byte $9B, $7F, $1A, $FE, $E2, $42, $E3, $4F

