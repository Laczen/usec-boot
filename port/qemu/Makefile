# Toolchain
CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump
SIZE = arm-none-eabi-size

# Build configuration
BUILD_DIR = build
TARGET = $(BUILD_DIR)/firmware.elf

# Cortex-M3 flags
ARCH_FLAGS = -mcpu=cortex-m3 -mthumb -mfloat-abi=soft
OPT_FLAGS = -Os -ffunction-sections -fdata-sections
WARN_FLAGS = -Wall -Wextra
INCLUDES = -I. -I../../ext/monocypher -I../../src

CFLAGS = $(ARCH_FLAGS) $(OPT_FLAGS) $(WARN_FLAGS) $(INCLUDES)
LDFLAGS = $(ARCH_FLAGS) -Wl,--gc-sections -Wl,--print-memory-usage
LDFLAGS += -Tlinker.ld -Wl,-Map=$(BUILD_DIR)/firmware.map

# Monocypher configuration
MONOCYPHER_DEFINES = -DX25519_NO_UNROLLING

# Root public key generation
ROOTPKEY_SCRIPT = ../../scripts/usectool.py
ROOTPKEY_INPUT = "genrootpkinclude keys/root_pubkey.pem --output root_pkey.h"
ROOTPKEY_HEADER = root_pkey.h

# Source files
LOCAL_SRCS = $(wildcard *.c)
MONOCYPHER_SRCS = $(wildcard ../../ext/monocypher/*.c)
SRC_SRCS = $(wildcard ../../src/*.c)

# Object files
OBJ = $(addprefix $(BUILD_DIR)/, $(LOCAL_SRCS:.c=.o)) \
      $(addprefix $(BUILD_DIR)/monocypher/, $(notdir $(MONOCYPHER_SRCS:.c=.o))) \
      $(addprefix $(BUILD_DIR)/src/, $(notdir $(SRC_SRCS:.c=.o)))
OBJ := $(sort $(OBJ))

# Default target
all: $(TARGET)

# Create build directory structure
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/monocypher $(BUILD_DIR)/src

# Generate root public key header
$(ROOTPKEY_HEADER): $(ROOTPKEY_SCRIPT) $(ROOTPKEY_INPUT)
	@echo "Generating root public key header"
	python3 $(ROOTPKEY_SCRIPT) $(ROOTPKEY_INPUT) > $@

# Compilation rules
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR) $(ROOTPKEY_HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/monocypher/%.o: ../../ext/monocypher/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(MONOCYPHER_DEFINES) -c $< -o $@

$(BUILD_DIR)/src/%.o: ../../src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link executable
$(TARGET): $(OBJ) linker.ld
	$(CC) $(LDFLAGS) $(OBJ) -o $@
	@echo "Build complete:"
	@$(SIZE) $@

# Create binary for flashing
$(BUILD_DIR)/firmware.bin: $(TARGET)
	$(OBJCOPY) -O binary $< $@

# QEMU emulation
qemu: $(BUILD_DIR)/firmware.bin
	@echo "Starting QEMU..."
	qemu-system-arm -M lm3s6965evb \
		-device loader,file=$(BUILD_DIR)/firmware.bin,addr=0x00000000 \
		-device loader,file=../../scripts/signed_image.bin,addr=0x00010000 \
		-nographic -monitor telnet:127.0.0.1:1234,server,nowait

# Analysis targets
size: $(TARGET)
	@$(SIZE) $<

disasm: $(TARGET)
	$(OBJDUMP) -S $< > $(BUILD_DIR)/firmware.disasm

# Cleanup
clean:
	rm -rf $(BUILD_DIR) $(ROOTPKEY_HEADER)

.PHONY: all clean qemu size disasm