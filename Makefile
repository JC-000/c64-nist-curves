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

# Source modules (order matters for linking — matches original !source chain)
MODULES = main constants zp_config lib_version reu_config mul_8x8 \
          fp256 mod256 curve256 points256 inv256 ecdsa256 \
          fp384 mod384 curve384 points384 ecdsa384 \
          sha384 \
          data

CA65_SRCS = $(addprefix $(SRC_DIR)/,$(addsuffix .s,$(MODULES)))
OBJECTS   = $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(MODULES)))
ASM_SRCS  = $(wildcard $(SRC_DIR)/*.asm)

.PHONY: all clean build-acme bench-u64 dist

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

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/nist-curves.prg $(BUILD_DIR)/labels.txt $(BUILD_DIR)/labels_raw.txt $(BUILD_DIR)/nist-curves.dbg

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
