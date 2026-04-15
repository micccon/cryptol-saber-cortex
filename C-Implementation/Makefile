CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11

# Include project headers from C-Implementation/include.
INCLUDES = -Iinclude
# Place all built test binaries under build/.
BUILD_DIR = build

# List each test by the basename of its file in tests/.
# Example: tests/randombytes_test.c -> randombytes_test
TEST_NAMES = randombytes_test poly_test

# Sources linked into every test binary.
COMMON_TEST_SRCS = \
	src/helpers.c

# Per-test extra sources. Add a new <testname>_SRCS block when a test needs
# implementation files beyond COMMON_TEST_SRCS.
randombytes_test_SRCS = \
	src/randombytes.c \
	third_party/AES/WjCryptLib_Aes.c

poly_test_SRCS = \
	src/poly.c

TEST_BINS = $(addprefix $(BUILD_DIR)/,$(TEST_NAMES))

.PHONY: all clean test run $(addprefix test-,$(TEST_NAMES)) $(addprefix run-,$(TEST_NAMES))

# Default target: build all registered tests.
all: test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# For each test name, generate:
#   build/<testname>        - the compiled test binary
#   test-<testname>         - build only that test
#   run-<testname>          - build and run only that test
define make_test_rules
$(BUILD_DIR)/$(1): tests/$(1).c $(COMMON_TEST_SRCS) $$($(1)_SRCS) | $(BUILD_DIR)
	$$(CC) $$(CFLAGS) $$(INCLUDES) tests/$(1).c $$(COMMON_TEST_SRCS) $$($(1)_SRCS) -o $(BUILD_DIR)/$(1)

test-$(1): $(BUILD_DIR)/$(1)

run-$(1): $(BUILD_DIR)/$(1)
	./$(BUILD_DIR)/$(1)
endef

$(foreach test,$(TEST_NAMES),$(eval $(call make_test_rules,$(test))))

# Build every test listed in TEST_NAMES.
test: $(addprefix test-,$(TEST_NAMES))

# Build and run every test listed in TEST_NAMES.
run: $(addprefix run-,$(TEST_NAMES))

# Remove all generated test binaries.
clean:
	rm -rf $(BUILD_DIR)
