; =============================================================================
; constants.asm - System equates, hardware addresses
; For P-256 and P-384 NIST curve optimization
;
; Zero-page allocation lives in zp_config.asm (consumer-tunable). Hardware
; addresses below are fixed by the C64 platform and must not be changed.
; =============================================================================

; --- Zero-page allocation (consumer-tunable) ---
!source "zp_config.asm"

; --- Kernal routines ---
chrout          = $ffd2         ; output character
getin           = $ffe4         ; get character from keyboard

; --- Hardware registers ---
vic_ctrl1       = $d011         ; VIC-II control register 1 (DEN=bit4)
vic_border      = $d020         ; border color
vic_bg          = $d021         ; background color
cia1_ta_lo      = $dc04         ; CIA #1 timer A low byte
cia1_ta_hi      = $dc05         ; CIA #1 timer A high byte
cia1_cra        = $dc0e         ; CIA #1 control register A

; --- System addresses ---
screen_ram      = $0400         ; screen memory (40x25)
color_ram       = $d800         ; color memory
cassette_buf    = $0334         ; cassette buffer (safe scratch area)
jiffy_clock     = $00a0         ; 3-byte jiffy clock (MSB)

; --- REU (Ram Expansion Unit) registers ---
reu_status      = $df00         ; status register
reu_command     = $df01         ; command register
reu_c64_lo      = $df02         ; C64 base address low
reu_c64_hi      = $df03         ; C64 base address high
reu_reu_lo      = $df04         ; REU base address low
reu_reu_hi      = $df05         ; REU base address high
reu_reu_bank    = $df06         ; REU bank
reu_len_lo      = $df07         ; transfer length low
reu_len_hi      = $df08         ; transfer length high
reu_addr_ctrl   = $df0a         ; address control

; --- Field element sizes ---
FP256_SIZE      = 32            ; P-256 field element size in bytes
FP384_SIZE      = 48            ; P-384 field element size in bytes
