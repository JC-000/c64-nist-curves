.setcpu "6502"

.segment "RODATA"

; Exports
.export ec_a256, ec_b256, ec_gx256, ec_gy256
.export ecdsa_test_privkey, ecdsa_test_k, ecdsa_test_hash
.export ecdsa_test_r, ecdsa_test_s
.export ecdsa_test_pubx, ecdsa_test_puby
.export ecdsa_test_2gx, ecdsa_test_2gy

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

; RFC 6979 A.2.5 Test Vectors (P-256/SHA-256, msg="sample")

; Private key
ecdsa_test_privkey:
        .byte $21, $67, $0F, $12, $2B, $62, $8A, $7B
        .byte $12, $9B, $E8, $36, $DB, $C3, $50, $4E
        .byte $93, $D6, $B1, $67, $57, $21, $5C, $6B
        .byte $16, $75, $BA, $45, $D8, $A9, $AF, $C9

; Nonce k
ecdsa_test_k:
        .byte $60, $AD, $8A, $3D, $49, $29, $61, $4D
        .byte $F2, $B0, $82, $33, $87, $AA, $17, $3B
        .byte $4C, $DD, $55, $83, $39, $38, $65, $08
        .byte $90, $BE, $1A, $D0, $7D, $C5, $E3, $A6

; SHA-256("sample")
ecdsa_test_hash:
        .byte $BF, $D1, $AD, $62, $8A, $3D, $11, $62
        .byte $15, $89, $E9, $68, $02, $1D, $83, $1A
        .byte $C7, $1F, $F4, $94, $D6, $E1, $AD, $E2
        .byte $C1, $6E, $9B, $AA, $E1, $DB, $2B, $AF

; Signature r
ecdsa_test_r:
        .byte $16, $37, $AF, $4E, $A8, $0E, $4D, $C3
        .byte $91, $F9, $AA, $56, $7B, $87, $2C, $9D
        .byte $D6, $81, $5E, $D4, $9C, $DD, $40, $11
        .byte $FD, $A8, $B6, $AC, $2A, $8B, $D4, $EF

; Signature s
ecdsa_test_s:
        .byte $A8, $CD, $3A, $84, $2F, $AB, $C4, $4D
        .byte $06, $F4, $AF, $B9, $DB, $00, $E9, $F3
        .byte $65, $9F, $E2, $B6, $A1, $C7, $36, $D4
        .byte $41, $7C, $65, $2D, $94, $1C, $CB, $F7

; Public key x
ecdsa_test_pubx:
        .byte $B6, $9F, $F2, $60, $2E, $62, $69, $E6
        .byte $6C, $FA, $61, $3B, $92, $B8, $49, $C0
        .byte $68, $6D, $35, $C6, $74, $EB, $61, $C9
        .byte $31, $9D, $5A, $25, $BA, $D4, $FE, $60

; Public key y
ecdsa_test_puby:
        .byte $99, $22, $46, $D4, $94, $C2, $A3, $77
        .byte $51, $9F, $7E, $2D, $0C, $B2, $F1, $F2
        .byte $64, $BC, $28, $56, $E9, $E9, $1A, $A4
        .byte $99, $BC, $B8, $08, $10, $FE, $03, $79

; Known intermediate: 2*G x-coordinate
ecdsa_test_2gx:
        .byte $78, $99, $66, $47, $FC, $48, $0B, $A6
        .byte $35, $1B, $F2, $77, $E2, $69, $89, $C0
        .byte $C3, $1A, $B5, $04, $03, $38, $52, $8A
        .byte $7E, $4F, $03, $8D, $18, $7B, $F2, $7C

; Known intermediate: 2*G y-coordinate
ecdsa_test_2gy:
        .byte $D1, $73, $78, $22, $9D, $B7, $04, $9E
        .byte $29, $82, $E9, $3C, $E6, $AD, $7D, $BA
        .byte $DB, $30, $74, $9F, $C6, $9A, $3D, $29
        .byte $40, $D0, $8E, $DB, $10, $55, $77, $07
