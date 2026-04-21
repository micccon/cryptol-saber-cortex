CC ?= cc
CFLAGS ?= -Wall -Wextra -Wpedantic -Wno-newline-eof -std=c23
INCLUDES = -Iinclude

BUILD_DIR = build

# Unit test names — each maps to tests/<name>.c
TEST_NAMES = randombytes_test poly_test pack_unpack_test arithmetic_test pke_test kem_test

# Sources linked into every test binary.
COMMON_TEST_SRCS = \
	src/helpers.c

# Full KEM source set, shared by kem_test and the KAT harness.
FULL_KEM_SRCS = \
	src/kem.c \
	src/indcpa.c \
	src/arithmetic.c \
	src/poly.c \
	src/pack_unpack.c \
	src/randombytes.c \
	third_party/fips202.c \
	third_party/AES/WjCryptLib_Aes.c

# Per-test extra sources. Add a new <testname>_SRCS block when a test needs
# implementation files beyond COMMON_TEST_SRCS.
randombytes_test_SRCS = \
	src/randombytes.c \
	third_party/AES/WjCryptLib_Aes.c

pack_unpack_test_SRCS = \
	src/pack_unpack.c

poly_test_SRCS = \
	src/poly.c

arithmetic_test_SRCS = \
	src/arithmetic.c \
	src/poly.c \
	src/pack_unpack.c \
	third_party/fips202.c

pke_test_SRCS = \
	src/indcpa.c \
	src/arithmetic.c \
	src/poly.c \
	src/pack_unpack.c \
	src/randombytes.c \
	third_party/fips202.c \
	third_party/AES/WjCryptLib_Aes.c

kem_test_SRCS = $(FULL_KEM_SRCS)

.PHONY: all test run clean \
        test-kats run-kats \
        $(addprefix test-,$(TEST_NAMES)) \
        $(addprefix run-,$(TEST_NAMES))

# Default target: build everything.
all: test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# For each test name, generate:
#   build/<testname>   - the compiled test binary
#   test-<testname>    - build only that test
#   run-<testname>     - build and run only that test
define make_test_rules
$(BUILD_DIR)/$(1): tests/$(1).c $(COMMON_TEST_SRCS) $$($(1)_SRCS) | $(BUILD_DIR)
	$$(CC) $$(CFLAGS) $$(INCLUDES) tests/$(1).c $$(COMMON_TEST_SRCS) $$($(1)_SRCS) -o $(BUILD_DIR)/$(1)

test-$(1): $(BUILD_DIR)/$(1)

run-$(1): $(BUILD_DIR)/$(1)
	./$(BUILD_DIR)/$(1)
endef

$(foreach test,$(TEST_NAMES),$(eval $(call make_test_rules,$(test))))

$(BUILD_DIR)/kats_test: KATs/kats.c KATs/kats.h $(COMMON_TEST_SRCS) $(FULL_KEM_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) KATs/kats.c $(COMMON_TEST_SRCS) $(FULL_KEM_SRCS) -o $(BUILD_DIR)/kats_test

test-kats: $(BUILD_DIR)/kats_test

run-kats: $(BUILD_DIR)/kats_test
	./$(BUILD_DIR)/kats_test

# Build all tests without running them.
test: $(addprefix test-,$(TEST_NAMES)) test-kats

# Build and run all tests.
run: $(addprefix run-,$(TEST_NAMES)) run-kats

# Remove all generated binaries.
clean:
	rm -rf $(BUILD_DIR)
