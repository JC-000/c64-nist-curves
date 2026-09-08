# check_doc_snippets negative-test fixture (issue #142)

Block 1 -- assembles clean, imports a real export.

```asm
.import fp_mul
.segment "CODE"
entry:
        jsr fp_mul
        rts
```

Block 2 -- does not assemble (bad mnemonic).

```asm
.segment "CODE"
        frobnicate #1
```

Block 3 -- assembles, imports a symbol the library does not export.

```asm
.import totally_not_a_library_symbol_142
.segment "CODE"
        jsr totally_not_a_library_symbol_142
```

Block 4 -- untagged fence (must FAIL).

```
.segment "CODE"
        rts
```

Block 5 -- malformed check-docs marker (must FAIL).

<!-- check-docs: skipp reason="typo in the marker keyword" -->
```asm
.segment "CODE"
        rts
```

Block 6 -- explicit skip with a reason (must be listed, not failed).

<!-- check-docs: skip reason="deliberate opt-out, exercised by the fixture" -->
```asm
this is not assembly at all
```

Block 7 -- consumer-owned external declared (must PASS).

<!-- check-docs: external="app_owned_symbol_142" -->
```asm
.import app_owned_symbol_142
.segment "CODE"
        jsr app_owned_symbol_142
```

Block 8 -- stale `.import` line that ca65 drops, naming a dead symbol
(must FAIL via the text-scan half of imports_of).

```asm
.import dead_symbol_142
.segment "CODE"
        rts
```
