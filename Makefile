ACME = acme
CA65 = ca65
LD65 = ld65

SRC_DIR = src
BUILD_DIR = build

PRG = $(BUILD_DIR)/nist-curves.prg
LABELS = $(BUILD_DIR)/labels.txt
LABELS_RAW = $(BUILD_DIR)/labels_raw.txt
CFG = $(SRC_DIR)/c64.cfg

# Source modules (order matters for linking — matches original !source chain)
MODULES = main constants zp_config lib_version mul_8x8 \
          fp256 mod256 curve256 points256 inv256 ecdsa256 \
          fp384 mod384 curve384 points384 ecdsa384 \
          data

CA65_SRCS = $(addprefix $(SRC_DIR)/,$(addsuffix .s,$(MODULES)))
OBJECTS   = $(addprefix $(BUILD_DIR)/,$(addsuffix .o,$(MODULES)))
ASM_SRCS  = $(wildcard $(SRC_DIR)/*.asm)

.PHONY: all clean build-acme bench-u64

all: $(PRG)

# --- ca65 + ld65 multi-object build (default) ---
$(PRG): $(OBJECTS) $(CFG) | $(BUILD_DIR)
	$(LD65) -o $(PRG) -C $(CFG) -Ln $(LABELS_RAW) $(OBJECTS)
	sed 's/^al \([0-9a-fA-F]\{2\}\)\([0-9a-fA-F]\{4\}\) /al C:\2 /' $(LABELS_RAW) > $(LABELS)

# Pattern rule: assemble each .s to .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s | $(BUILD_DIR)
	$(CA65) --cpu 6502 -I $(SRC_DIR) -o $@ $<

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
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/nist-curves.prg $(BUILD_DIR)/labels.txt $(BUILD_DIR)/labels_raw.txt
