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
        lib lib-p256-verify lib-p384-verify lib-p384-sha384 lib-p384-curve

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
#   nistcurves-p384-verify.a   -- P-384 ECDSA verify only. Mirror of p256-
#                                 verify for the P-384 side. Excludes the
#                                 hash-then-verify wrapper ecdsa384_msg.o
#                                 (consumers drive streaming SHA themselves).
#   nistcurves-p384-sha384.a   -- SHA-384 streaming hash only. Self-contained
#                                 (no REU, no multiply tables); minimal
#                                 dependency set.
#   nistcurves-p384-curve.a    -- P-384 ECDSA verify + SHA-384 +
#                                 ecdsa_verify_with_message_384 one-shot
#                                 wrapper. Suitable for the TLS 1.3
#                                 secp384r1+SHA-384 cipher-suite path.
#
# Object-set composition is computed below as Make variables so the inventory
# stays self-describing.

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
LIB_P256_VERIFY_OBJS = $(BUILD_DIR)/fp256.o $(BUILD_DIR)/mod256.o \
                      $(BUILD_DIR)/curve256.o $(BUILD_DIR)/points256_core.o \
                      $(BUILD_DIR)/ecdsa256.o $(BUILD_DIR)/data_p256.o
LIB_P384_VERIFY_OBJS = $(BUILD_DIR)/fp384.o $(BUILD_DIR)/mod384.o \
                      $(BUILD_DIR)/curve384.o $(BUILD_DIR)/points384_core.o \
                      $(BUILD_DIR)/ecdsa384.o $(BUILD_DIR)/data_p384.o

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
                $(LIB_P256_VERIFY_OBJS) $(LIB_P256_COMB_OBJS) \
                $(LIB_P384_VERIFY_OBJS) $(LIB_P384_COMB_OBJS) \
                $(LIB_SHA384_OBJS) \
                $(BUILD_DIR)/inv256.o $(BUILD_DIR)/data_p256_invref.o \
                $(BUILD_DIR)/ecdsa384_msg.o

lib:             $(LIB_DIR)/nistcurves.a
lib-p256-verify: $(LIB_DIR)/nistcurves-p256-verify.a
lib-p384-verify: $(LIB_DIR)/nistcurves-p384-verify.a
lib-p384-sha384: $(LIB_DIR)/nistcurves-p384-sha384.a
lib-p384-curve:  $(LIB_DIR)/nistcurves-p384-curve.a

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
