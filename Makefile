ACME = acme
CA65 = ca65
LD65 = ld65

SRC_DIR = src
BUILD_DIR = build

PRG = $(BUILD_DIR)/nist-curves.prg
LABELS = $(BUILD_DIR)/labels.txt
LABELS_RAW = $(BUILD_DIR)/labels_raw.txt
DBG = $(BUILD_DIR)/nist-curves.dbg
CFG = $(SRC_DIR)/c64.cfg

# Source modules (order matters for linking — matches original !source chain).
# data.s was split per-curve / per-feature for issue #40 / SPEC §6 so the
# minimal-archive build targets below can exclude buffers their use case
# doesn't touch (Lim-Lee anchors, the other curve's state, SHA buffers,
# test-driver scratch).
MODULES = main constants zp_config lib_version reu_config lib_manifest \
          precalc_manifest mul_8x8 \
          fp256 mod256 curve256 points256_core points256_comb inv256 ecdsa256 \
          fp384 mod384 curve384 points384_core points384_comb ecdsa384 ecdsa384_msg \
          sha384 \
          data_shared data_p256 data_p256_invref data_p256_limlee \
          data_p384 data_p384_limlee data_sha data_test

CA65_SRCS = $(addprefix $(SRC_DIR)/,$(addsuffix .s,$(MODULES)))
OBJECTS   = $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(MODULES)))
ASM_SRCS  = $(wildcard $(SRC_DIR)/*.asm)

LIB_DIR = $(BUILD_DIR)/lib

.PHONY: all clean build-acme bench-u64 dist \
        lib lib-p256-verify lib-p384-verify lib-p384-sha384 lib-p384-curve \
        check-archives

all: $(PRG)

# --- ca65 + ld65 multi-object build (default) ---
# -g on ca65 embeds source-line debug info in each .o; --dbgfile on ld65
# aggregates that into a single VICE/c64-debugger-loadable debug file.
# The .prg is byte-identical with or without -g; debug data lives in .o
# metadata only and the .dbg is a separate output.
$(PRG): $(OBJECTS) $(CFG) | $(BUILD_DIR)
	$(LD65) -o $(PRG) -C $(CFG) -Ln $(LABELS_RAW) --dbgfile $(DBG) $(OBJECTS)
	sed 's/^al \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{4\}\) /al C:\2 /' $(LABELS_RAW) > $(LABELS)

# Pattern rule: assemble each .s to .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -I $(SRC_DIR) -o $@ $<

# No-comb ECDSA verify variants (issue #61): same sources, -D ECDSA_NO_COMB.
# u1*G routes through ec_scalar_mul_var seeded at G, dropping the link
# dependency on points256_comb.o / points384_comb.o. Consumed by the verify
# archives and the nocomb test PRG below; the default build never uses them.
$(BUILD_DIR)/ecdsa256_nocomb.o: $(SRC_DIR)/ecdsa256.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -D ECDSA_NO_COMB -I $(SRC_DIR) -o $@ $<
$(BUILD_DIR)/ecdsa384_nocomb.o: $(SRC_DIR)/ecdsa384.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -D ECDSA_NO_COMB -I $(SRC_DIR) -o $@ $<

# Nocomb test PRG (issue #61): the standalone test PRG with the two nocomb
# verify objects substituted, so the full oracle test suite can exercise the
# fallback u1*G path end-to-end:
#   make nocomb-prg
#   C64_PRG_NAME=nist-curves-nocomb.prg C64_LABELS_NAME=labels_nocomb.txt \
#     C64_SKIP_BUILD=1 python3 tools/test_ecdsa_verify.py
# Everything else (boot init, trampolines, comb precompute) is unchanged; the
# comb tables still populate at boot but the verify routines never call them.
PRG_NOCOMB = $(BUILD_DIR)/nist-curves-nocomb.prg
NOCOMB_OBJECTS = $(subst $(BUILD_DIR)/ecdsa256.o,$(BUILD_DIR)/ecdsa256_nocomb.o,$(subst $(BUILD_DIR)/ecdsa384.o,$(BUILD_DIR)/ecdsa384_nocomb.o,$(OBJECTS)))

.PHONY: nocomb-prg
nocomb-prg: $(PRG_NOCOMB)

$(PRG_NOCOMB): $(NOCOMB_OBJECTS) $(CFG) | $(BUILD_DIR)
	$(LD65) -o $@ -C $(CFG) -Ln $(BUILD_DIR)/labels_nocomb_raw.txt $(NOCOMB_OBJECTS)
	sed 's/^al \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{4\}\) /al C:\2 /' $(BUILD_DIR)/labels_nocomb_raw.txt > $(BUILD_DIR)/labels_nocomb.txt

# On-chip-mul turbo-profile variant (issue #69): -D FP_ONCHIP_MUL replaces
# the REU DMA row fetch in fp_mul/fp_sqr (both curves) with sparse on-chip
# row generation via ct_mul_8x8 (gen_mul_row / gen_mul_row_384 in mul_8x8.s).
# Trades CPU cycles (which scale with turbo clock) for zero wall-clock-
# anchored DMA stall. Test with:
#   make onchip-prg
#   C64_PRG_NAME=nist-curves-onchip.prg C64_LABELS_NAME=labels_onchip.txt \
#     C64_SKIP_BUILD=1 python3 tools/test_ecdsa_verify.py
# Boot init (REU mul-table population, comb precompute) is unchanged; the
# mul table still populates at boot but fp_mul/fp_sqr never DMA from it.
$(BUILD_DIR)/fp256_onchip.o: $(SRC_DIR)/fp256.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -D FP_ONCHIP_MUL -I $(SRC_DIR) -o $@ $<
$(BUILD_DIR)/fp384_onchip.o: $(SRC_DIR)/fp384.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -D FP_ONCHIP_MUL -I $(SRC_DIR) -o $@ $<
$(BUILD_DIR)/mul_8x8_onchip.o: $(SRC_DIR)/mul_8x8.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -D FP_ONCHIP_MUL -I $(SRC_DIR) -o $@ $<

PRG_ONCHIP = $(BUILD_DIR)/nist-curves-onchip.prg
ONCHIP_OBJECTS = $(subst $(BUILD_DIR)/lib_manifest.o,$(BUILD_DIR)/lib_manifest_onchip.o,$(subst $(BUILD_DIR)/fp256.o,$(BUILD_DIR)/fp256_onchip.o,$(subst $(BUILD_DIR)/fp384.o,$(BUILD_DIR)/fp384_onchip.o,$(subst $(BUILD_DIR)/mul_8x8.o,$(BUILD_DIR)/mul_8x8_onchip.o,$(OBJECTS)))))

.PHONY: onchip-prg
onchip-prg: $(PRG_ONCHIP)

# Onchip + no-comb test PRG (issue #71): both -D flags — the zero-REU
# configuration. fp_mul/fp_sqr compute rows on-chip AND u1*G routes through
# the variable-base ladder, so the verify path issues no REU DMA at all.
# Validate on a stock (REU-less) machine with:
#   make onchip-nocomb-prg
#   C64_PRG_NAME=nist-curves-onchip-nocomb.prg \
#   C64_LABELS_NAME=labels_onchip_nocomb.txt \
#   C64_SKIP_BUILD=1 C64_INIT_TIMEOUT=1800 C64_NO_REU=1 \
#     python3 tools/test_ecdsa_verify.py
# Boot still runs reu_mul_init + ec_precompute_* (writes vanish into open
# bus without an REU; comb tables are never read by the nocomb verifiers).
PRG_ONCHIP_NOCOMB = $(BUILD_DIR)/nist-curves-onchip-nocomb.prg
ONCHIP_NOCOMB_OBJECTS = $(subst $(BUILD_DIR)/ecdsa256.o,$(BUILD_DIR)/ecdsa256_nocomb.o,$(subst $(BUILD_DIR)/ecdsa384.o,$(BUILD_DIR)/ecdsa384_nocomb.o,$(ONCHIP_OBJECTS)))

.PHONY: onchip-nocomb-prg
onchip-nocomb-prg: $(PRG_ONCHIP_NOCOMB)

$(PRG_ONCHIP_NOCOMB): $(ONCHIP_NOCOMB_OBJECTS) $(CFG) | $(BUILD_DIR)
	$(LD65) -o $@ -C $(CFG) -Ln $(BUILD_DIR)/labels_onchip_nocomb_raw.txt $(ONCHIP_NOCOMB_OBJECTS)
	sed 's/^al \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{4\}\) /al C:\2 /' $(BUILD_DIR)/labels_onchip_nocomb_raw.txt > $(BUILD_DIR)/labels_onchip_nocomb.txt

$(PRG_ONCHIP): $(ONCHIP_OBJECTS) $(CFG) | $(BUILD_DIR)
	$(LD65) -o $@ -C $(CFG) -Ln $(BUILD_DIR)/labels_onchip_raw.txt $(ONCHIP_OBJECTS)
	sed 's/^al \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{4\}\) /al C:\2 /' $(BUILD_DIR)/labels_onchip_raw.txt > $(BUILD_DIR)/labels_onchip.txt

# --- ACME build (legacy, for side-by-side testing) ---
build-acme: $(ASM_SRCS) | $(BUILD_DIR)
	cd $(SRC_DIR) && $(ACME) -f cbm -o ../$(PRG) --vicelabels ../$(LABELS) main.asm

# --- U64E ECDSA / scalar_mul_var bench (requires live Ultimate 64 hardware) ---
# The `bench_*_tramp` wrappers in src/main.s emit $BFFF markers for the
# optional --debug-stream cross-check. Set U64_HOST=<ip> and optionally
# U64_PASSWORD=<pw>. Set BENCH_DEBUG_STREAM=1 to turn on the bus-trace
# cross-check (requires stream destination configured on the U64E).
bench-u64: $(PRG)
	python3 tools/bench_ecdsa_u64.py

# --- Library archives (c64-lib-contract SPEC §6) -----------------------------
#
# Consumers fetch one of these `.a` files and link directly; no source patching
# or sed staging required (the pre-PR-#40 approach in c64-https). Each archive
# contains exactly the symbols a specific consumer use-case needs:
#
#   nistcurves.a               -- full library minus the test PRG driver.
#                                 Reasonable default for whole-library
#                                 consumers.
#   nistcurves-p256-verify.a   -- P-256 ECDSA verify only. Excludes the
#                                 Lim-Lee fixed-base comb (points256_comb,
#                                 data_p256_limlee), all P-384, all SHA-384,
#                                 inv256.o + data_p256_invref.o (Fermat-based
#                                 modular inverse reference and its scratch --
#                                 production uses the binary-GCD path in
#                                 mod256.o), and the test driver.
#                                 Ships ecdsa256_nocomb.o (issue #61): the
#                                 packaged ecdsa_verify_256 links standalone,
#                                 with u1*G via the variable-base ladder
#                                 seeded at G (slower than the comb; comb-
#                                 speed verify needs nistcurves.a). See
#                                 API.md §8.4.1.
#   nistcurves-p384-verify.a   -- P-384 ECDSA verify only. Mirror of p256-
#                                 verify for the P-384 side. Excludes the
#                                 hash-then-verify wrapper ecdsa384_msg.o
#                                 (consumers drive streaming SHA themselves).
#                                 Ships ecdsa384_nocomb.o (issue #61):
#                                 ecdsa_verify_384 links standalone; u1*G via
#                                 variable-base ladder. See API.md §8.4.1.
#   nistcurves-p384-sha384.a   -- SHA-384 streaming hash only. Self-contained
#                                 (no REU, no multiply tables); minimal
#                                 dependency set.
#   nistcurves-p384-curve.a    -- P-384 ECDSA verify + SHA-384 +
#                                 ecdsa_verify_with_message_384 one-shot
#                                 wrapper. Suitable for the TLS 1.3
#                                 secp384r1+SHA-384 cipher-suite path.
#                                 Ships ecdsa384_nocomb.o (issue #61): both
#                                 ecdsa_verify_384 and the one-shot
#                                 ecdsa_verify_with_message_384 link
#                                 standalone; u1*G via variable-base ladder.
#                                 See API.md §8.4.1.
#
# Object-set composition is computed below as Make variables so the inventory
# stays self-describing. `make check-archives` ratchets this contract (the
# documented gaps above must match reality exactly -- tools/check_archives.py).

# Shared objects every archive includes: version + manifest + zp config.
# Consumers .import LIB_VERSION_* (semver), LIB_NISTCURVES_REU_BANKS_USED /
# ZP_USAGE_BYTES / RESIDENT_BYTES / COLD_BYTES (manifest, SPEC §5), and need
# our ZP slots reserved when they don't pre-define them. The library's own
# REU bank/offset equates (LIB_NISTCURVES_REU_BANK_*, SPEC §3) live in
# reu_config.o and are pulled in by LIB_MUL_OBJS below.
LIB_CORE_OBJS = $(BUILD_DIR)/lib_version.o $(BUILD_DIR)/lib_manifest.o \
                $(BUILD_DIR)/precalc_manifest.o \
                $(BUILD_DIR)/zp_config.o

# Field / multiply machinery (shared by every curve-using archive).
LIB_MUL_OBJS  = $(BUILD_DIR)/constants.o $(BUILD_DIR)/reu_config.o \
                $(BUILD_DIR)/mul_8x8.o $(BUILD_DIR)/data_shared.o

# Per-curve verify object sets (core point ops only -- no comb).
# The verify ARCHIVES take the ecdsa*_nocomb.o variants (-D ECDSA_NO_COMB,
# issue #61): u1*G routes through the variable-base ladder seeded at G, so
# the packaged verifiers link standalone without the comb objects. The full
# archive and the standalone PRG keep the comb-calling ecdsa*.o variants.
LIB_P256_VERIFY_BASE_OBJS = $(BUILD_DIR)/fp256.o $(BUILD_DIR)/mod256.o \
                      $(BUILD_DIR)/curve256.o $(BUILD_DIR)/points256_core.o \
                      $(BUILD_DIR)/data_p256.o
LIB_P256_VERIFY_OBJS = $(LIB_P256_VERIFY_BASE_OBJS) $(BUILD_DIR)/ecdsa256_nocomb.o
LIB_P384_VERIFY_BASE_OBJS = $(BUILD_DIR)/fp384.o $(BUILD_DIR)/mod384.o \
                      $(BUILD_DIR)/curve384.o $(BUILD_DIR)/points384_core.o \
                      $(BUILD_DIR)/data_p384.o
LIB_P384_VERIFY_OBJS = $(LIB_P384_VERIFY_BASE_OBJS) $(BUILD_DIR)/ecdsa384_nocomb.o

# SHA-384 object set: self-contained.
LIB_SHA384_OBJS      = $(BUILD_DIR)/sha384.o $(BUILD_DIR)/data_sha.o

# Lim-Lee fixed-base comb objects (only the full / curve archives need them).
LIB_P256_COMB_OBJS = $(BUILD_DIR)/points256_comb.o \
                    $(BUILD_DIR)/data_p256_limlee.o
LIB_P384_COMB_OBJS = $(BUILD_DIR)/points384_comb.o \
                    $(BUILD_DIR)/data_p384_limlee.o

# The full archive bundles every shipping object. The test-driver translation
# units (main.o + data_test.o) are deliberately excluded -- consumers provide
# their own main and never use ecdsa_inputs_* / sha384_msg_buf. inv256.o
# stays in `lib.a` for whole-library consumers that may want the Fermat
# inverse reference path; it is excluded from minimal archives.
LIB_FULL_OBJS = $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) \
                $(LIB_P256_VERIFY_BASE_OBJS) $(BUILD_DIR)/ecdsa256.o \
                $(LIB_P256_COMB_OBJS) \
                $(LIB_P384_VERIFY_BASE_OBJS) $(BUILD_DIR)/ecdsa384.o \
                $(LIB_P384_COMB_OBJS) \
                $(LIB_SHA384_OBJS) \
                $(BUILD_DIR)/inv256.o $(BUILD_DIR)/data_p256_invref.o \
                $(BUILD_DIR)/ecdsa384_msg.o

# --- FP_ONCHIP_MUL turbo-profile archives (issue #69) ------------------------
# Same archives with the on-chip-multiply field layer substituted: fp_mul /
# fp_sqr (both curves) compute rows via ct_mul_8x8 instead of REU DMA row
# fetches. Above ~30 MHz (P-256) / ~55 MHz (P-384) this is faster (the DMA
# stall is wall-clock-anchored); at stock 1 MHz the DMA-table profile wins
# ~2x. Verify-onchip archives issue no REU DMA at all (comb also excluded);
# consumer boot obligation shrinks to sqtab_init only (no SPEC §8.2 reu_mul
# provider needed). Manifest equates are profile-aware via
# lib_manifest_onchip.o (REU banks $04, resident/cold shift).
$(BUILD_DIR)/lib_manifest_onchip.o: $(SRC_DIR)/lib_manifest.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -g -D FP_ONCHIP_MUL -I $(SRC_DIR) -o $@ $<

LIB_CORE_ONCHIP_OBJS = $(BUILD_DIR)/lib_version.o \
                $(BUILD_DIR)/lib_manifest_onchip.o \
                $(BUILD_DIR)/precalc_manifest.o \
                $(BUILD_DIR)/zp_config.o
LIB_MUL_ONCHIP_OBJS = $(BUILD_DIR)/constants.o $(BUILD_DIR)/reu_config.o \
                $(BUILD_DIR)/mul_8x8_onchip.o $(BUILD_DIR)/data_shared.o
LIB_P256_VERIFY_ONCHIP_OBJS = $(BUILD_DIR)/fp256_onchip.o $(BUILD_DIR)/mod256.o \
                $(BUILD_DIR)/curve256.o $(BUILD_DIR)/points256_core.o \
                $(BUILD_DIR)/data_p256.o $(BUILD_DIR)/ecdsa256_nocomb.o
LIB_P384_VERIFY_ONCHIP_OBJS = $(BUILD_DIR)/fp384_onchip.o $(BUILD_DIR)/mod384.o \
                $(BUILD_DIR)/curve384.o $(BUILD_DIR)/points384_core.o \
                $(BUILD_DIR)/data_p384.o $(BUILD_DIR)/ecdsa384_nocomb.o
LIB_FULL_ONCHIP_OBJS = $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) \
                $(BUILD_DIR)/fp256_onchip.o $(BUILD_DIR)/mod256.o \
                $(BUILD_DIR)/curve256.o $(BUILD_DIR)/points256_core.o \
                $(BUILD_DIR)/data_p256.o $(BUILD_DIR)/ecdsa256.o \
                $(LIB_P256_COMB_OBJS) \
                $(BUILD_DIR)/fp384_onchip.o $(BUILD_DIR)/mod384.o \
                $(BUILD_DIR)/curve384.o $(BUILD_DIR)/points384_core.o \
                $(BUILD_DIR)/data_p384.o $(BUILD_DIR)/ecdsa384.o \
                $(LIB_P384_COMB_OBJS) \
                $(LIB_SHA384_OBJS) \
                $(BUILD_DIR)/inv256.o $(BUILD_DIR)/data_p256_invref.o \
                $(BUILD_DIR)/ecdsa384_msg.o

lib:             $(LIB_DIR)/nistcurves.a
lib-p256-verify: $(LIB_DIR)/nistcurves-p256-verify.a
lib-p384-verify: $(LIB_DIR)/nistcurves-p384-verify.a
lib-p384-sha384: $(LIB_DIR)/nistcurves-p384-sha384.a
lib-p384-curve:  $(LIB_DIR)/nistcurves-p384-curve.a
lib-onchip:              $(LIB_DIR)/nistcurves-onchip.a
lib-p256-verify-onchip:  $(LIB_DIR)/nistcurves-p256-verify-onchip.a
lib-p384-verify-onchip:  $(LIB_DIR)/nistcurves-p384-verify-onchip.a
lib-p384-curve-onchip:   $(LIB_DIR)/nistcurves-p384-curve-onchip.a

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

# ar65 a <archive> <objs>... creates / appends; we rm -f first so each rebuild
# starts from an empty archive (ar65 has no replace-all flag).
$(LIB_DIR)/nistcurves.a: $(LIB_FULL_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_FULL_OBJS)

$(LIB_DIR)/nistcurves-p256-verify.a: $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) $(LIB_P256_VERIFY_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) $(LIB_P256_VERIFY_OBJS)

$(LIB_DIR)/nistcurves-p384-verify.a: $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) $(LIB_P384_VERIFY_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) $(LIB_P384_VERIFY_OBJS)

# SHA-384 is self-contained: no REU, no multiply tables. Drop the entire
# LIB_MUL_OBJS set to keep the archive minimal.
$(LIB_DIR)/nistcurves-p384-sha384.a: $(LIB_CORE_OBJS) $(LIB_SHA384_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_OBJS) $(LIB_SHA384_OBJS)

$(LIB_DIR)/nistcurves-p384-curve.a: $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) $(LIB_P384_VERIFY_OBJS) $(LIB_SHA384_OBJS) $(BUILD_DIR)/ecdsa384_msg.o | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_OBJS) $(LIB_MUL_OBJS) $(LIB_P384_VERIFY_OBJS) $(LIB_SHA384_OBJS) $(BUILD_DIR)/ecdsa384_msg.o

$(LIB_DIR)/nistcurves-onchip.a: $(LIB_FULL_ONCHIP_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_FULL_ONCHIP_OBJS)

$(LIB_DIR)/nistcurves-p256-verify-onchip.a: $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) $(LIB_P256_VERIFY_ONCHIP_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) $(LIB_P256_VERIFY_ONCHIP_OBJS)

$(LIB_DIR)/nistcurves-p384-verify-onchip.a: $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) $(LIB_P384_VERIFY_ONCHIP_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) $(LIB_P384_VERIFY_ONCHIP_OBJS)

$(LIB_DIR)/nistcurves-p384-curve-onchip.a: $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) $(LIB_P384_VERIFY_ONCHIP_OBJS) $(LIB_SHA384_OBJS) $(BUILD_DIR)/ecdsa384_msg.o | $(LIB_DIR)
	rm -f $@
	ar65 a $@ $(LIB_CORE_ONCHIP_OBJS) $(LIB_MUL_ONCHIP_OBJS) $(LIB_P384_VERIFY_ONCHIP_OBJS) $(LIB_SHA384_OBJS) $(BUILD_DIR)/ecdsa384_msg.o

# --- Archive linkability contract ratchet (issue #60) ------------------------
# Builds all five archives, then runs tools/check_archives.py, which pins the
# documented per-archive symbol contract (API.md §8.4.1): the trimmed verify
# archives deliberately exclude the Lim-Lee comb, so the packaged verifiers
# ecdsa_verify_256 / ecdsa_verify_384 are NOT linkable from those archives
# alone. The ratchet fails if reality drifts looser OR tighter than the docs.
check-archives: lib lib-p256-verify lib-p384-verify lib-p384-sha384 lib-p384-curve lib-onchip lib-p256-verify-onchip lib-p384-verify-onchip lib-p384-curve-onchip
	python3 tools/check_archives.py

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/nist-curves.prg $(BUILD_DIR)/labels.txt $(BUILD_DIR)/labels_raw.txt $(BUILD_DIR)/nist-curves.dbg
	rm -rf $(LIB_DIR)

# --- Reproducible release tarball --------------------------------------------
#
# `make dist VERSION=v0.2.0` builds c64-nist-curves-<VERSION>.tar.gz from the
# named git tag, with the canonical v0.2.0+ vendoring file set, and prints
# byte size + SHA256. Deterministic: same VERSION always produces a
# byte-identical tarball (git archive is content-deterministic; gzip -n
# drops the gzip timestamp). The recorded SHA256 in
# docs/RELEASE_NOTES_<VERSION>.md must match this script's output for
# that VERSION.
#
# Used at release time to produce the artifact uploaded to the GitHub
# Release page. See tools/build_release.sh for the full recipe.
dist:
	@if [ -z "$(VERSION)" ]; then \
	  echo "usage: make dist VERSION=v0.2.0" >&2; \
	  exit 1; \
	fi
	@tools/build_release.sh $(VERSION)
