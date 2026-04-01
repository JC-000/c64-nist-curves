ACME = acme

SRC_DIR = src
BUILD_DIR = build

PRG = $(BUILD_DIR)/nist-curves.prg
LABELS = $(BUILD_DIR)/labels.txt

ASM_SRCS = $(wildcard $(SRC_DIR)/*.asm)

.PHONY: all clean

all: $(PRG)

$(PRG): $(ASM_SRCS) | $(BUILD_DIR)
	cd $(SRC_DIR) && $(ACME) -f cbm -o ../$(PRG) --vicelabels ../$(LABELS) main.asm

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -f $(BUILD_DIR)/nist-curves.prg $(BUILD_DIR)/labels.txt
