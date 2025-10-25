# Toolchain
CC = arm-none-eabi-gcc
OBJCOPY = arm-none-eabi-objcopy
OBJDUMP = arm-none-eabi-objdump
SIZE = arm-none-eabi-size

# Cortex-M3 flags
ARCH_FLAGS = -mcpu=cortex-m3 -mthumb -mfloat-abi=soft
OPT_FLAGS = -Os -ffunction-sections
WARN_FLAGS = -Wall -Wextra
DEFINES = -DX25519_NO_UNROLLING
INCLUDES = -I. -I../../ext/monocypher -I../../src

CFLAGS = $(ARCH_FLAGS) $(OPT_FLAGS) $(WARN_FLAGS) $(DEFINES) $(INCLUDES)
LDFLAGS = $(ARCH_FLAGS) -Wl,--gc-sections -Wl,--print-memory-usage
LDFLAGS += -Tlinker.ld -Wl,-Map=$(BUILD_DIR)/firmware.map

# Build directory
BUILD_DIR = build

# Source files
LOCAL_SRCS = startup.c $(wildcard *.c)
MONOCYPHER_SRCS = $(wildcard ../../ext/monocypher/*.c)
SRC_SRCS = $(wildcard ../../src/*.c)

# Combine all sources
SRC = $(LOCAL_SRCS) $(MONOCYPHER_SRCS) $(SRC_SRCS)

# Object files in build directory
OBJ = $(addprefix $(BUILD_DIR)/, $(LOCAL_SRCS:.c=.o)) \
      $(addprefix $(BUILD_DIR)/monocypher/, $(notdir $(MONOCYPHER_SRCS:.c=.o))) \
      $(addprefix $(BUILD_DIR)/src/, $(notdir $(SRC_SRCS:.c=.o)))

# Remove duplicates from OBJ
OBJ := $(sort $(OBJ))

# Target executable
TARGET = $(BUILD_DIR)/firmware.elf

# Default target
all: $(BUILD_DIR) $(TARGET)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/monocypher
	@mkdir -p $(BUILD_DIR)/src
LOCAL_SRCS = startup.c $(wildcard *.c)
MONOCYPHER_SRCS = $(wildcard ../../ext/monocypher/*.c)
SRC_SRCS = $(wildcard ../../src/*.c)

# Combine all sources
SRC = $(LOCAL_SRCS) $(MONOCYPHER_SRCS) $(SRC_SRCS)

# Object files in build directory
OBJ = $(addprefix $(BUILD_DIR)/, $(LOCAL_SRCS:.c=.o)) \
      $(addprefix $(BUILD_DIR)/monocypher/, $(notdir $(MONOCYPHER_SRCS:.c=.o))) \
      $(addprefix $(BUILD_DIR)/src/, $(notdir $(SRC_SRCS:.c=.o)))

# Remove duplicates from OBJ
OBJ := $(sort $(OBJ))

# Target executable
TARGET = $(BUILD_DIR)/firmware.elf

# Default target
all: $(BUILD_DIR) $(TARGET)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/monocypher
	@mkdir -p $(BUILD_DIR)/src

# Compilation rules
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)

# Compilation rules
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/monocypher/%.o: ../../ext/monocypher/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/src/%.o: ../../src/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link
$(TARGET): $(OBJ) linker.ld
	$(CC) $(LDFLAGS) $(OBJ) -o $(TARGET)
	@echo "Build complete:"
	@$(SIZE) $(TARGET)

# Binary for flashing
$(BUILD_DIR)/firmware.bin: $(TARGET)
	$(OBJCOPY) -O binary $(TARGET) $(BUILD_DIR)/firmware.bin

# QEMU target
qemu: $(BUILD_DIR)/firmware.bin
	@echo "Starting QEMU..."
	qemu-system-arm -M lm3s6965evb -kernel $(BUILD_DIR)/firmware.bin -nographic -monitor telnet:127.0.0.1:1234,server,nowait

# Generate size information
size: $(TARGET)
	$(SIZE) $(TARGET)

# Debug info
disasm: $(TARGET)
	$(OBJDUMP) -S $(TARGET) > $(BUILD_DIR)/firmware.disasm

# Clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean qemu disasm