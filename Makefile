# c-serve: an HTTP/1.1 server and client over TLS (mbedtls), in C11.
# `make` builds the library, `make test` runs the suites, `make check` is
# the gate before a commit. Nothing is installed: a host compiles src/
# into itself (ctui-wm does, as a submodule).

CC ?= cc
OPT ?= -O2
# -ffunction-sections -fdata-sections: a host's --gc-sections drops what
# it never calls (a server that makes no requests links no client)
CFLAGS = -Wall -Wextra -Wno-format-truncation $(WARN) -std=c11 -Isrc -g $(OPT) \
	-ffunction-sections -fdata-sections

# mbedtls 4 (with its PSA crypto) for TLS, zlib to undo gzip / deflate
PKGS = mbedtls mbedx509 tfpsacrypto zlib
CFLAGS += $(shell pkg-config --cflags $(PKGS))
LDLIBS = $(shell pkg-config --libs $(PKGS)) -lpthread

# `make SAN=1 test`: AddressSanitizer + UBSan, objects of their own
SAN ?=
ifneq ($(SAN),)
CFLAGS += -fsanitize=address,undefined,float-cast-overflow -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined,float-cast-overflow
export UBSAN_OPTIONS = print_stacktrace=1:halt_on_error=1
endif

# `make TSAN=1 test`: ThreadSanitizer (the listener's threads, TLS from
# many at once); can't be combined with SAN
TSAN ?=
ifneq ($(TSAN),)
ifneq ($(SAN),)
$(error SAN and TSAN can't be combined)
endif
CFLAGS += -fsanitize=thread -fno-omit-frame-pointer
LDFLAGS += -fsanitize=thread
export TSAN_OPTIONS = halt_on_error=1:second_deadlock_stack=1
# its _exit() flushes stdio: a forked child would repeat buffered lines
TEST_WRAP = stdbuf -oL
endif

# `make FUZZ=1 fuzz`: fuzz/NAME.c as libFuzzer binaries (clang, ASan+UBSan)
FUZZ ?=
ifneq ($(FUZZ),)
CC = clang
CFLAGS += -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer
endif

B = build/$(subst -,,$(OPT))$(if $(SAN),-san)$(if $(TSAN),-tsan)$(if $(FUZZ),-fuzz)
BIN = $(B)/bin
obj = $(patsubst %.c,$(B)/%.o,$(1))

SRC = $(wildcard src/*.c)
# what a server-only host compiles; the client is net.c
SERVE_SRC = src/listen.c src/httpd.c
CLIENT_SRC = $(filter-out $(SERVE_SRC),$(SRC))
TESTS = $(patsubst tests/%_test.c,%,$(wildcard tests/*_test.c))
FUZZERS = $(patsubst fuzz/%.c,%,$(filter-out fuzz/fuzz.h,$(wildcard fuzz/*.c)))

all: $(B)/libcserve.a

$(B)/libcserve.a: $(call obj,$(SRC))
	$(AR) rcs $@ $^

$(B)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(BIN)/test-%: $(call obj,tests/%_test.c) $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

# T=NAME runs one suite. The suites read tests/data/ relative to here.
test: $(if $(T),$(BIN)/test-$(T),$(TESTS:%=$(BIN)/test-%))
	@fail=0; for t in $^; do echo "== $$t"; $(TEST_WRAP) ./$$t || fail=1; done; exit $$fail

$(BIN)/fuzz-%: $(call obj,fuzz/%.c) $(call obj,$(SRC))
	@mkdir -p $(@D)
	$(CC) -fsanitize=fuzzer,address,undefined $^ $(LDLIBS) -o $@

fuzz:
	@test -n "$(FUZZ)" || { echo "make FUZZ=1 fuzz"; exit 1; }
	$(MAKE) --no-print-directory $(FUZZERS:%=$(BIN)/fuzz-%)

check:
	$(MAKE) --no-print-directory -j$(shell nproc) SAN=1 TSAN= test
	$(MAKE) --no-print-directory -j$(shell nproc) SAN= TSAN=1 test
	$(MAKE) --no-print-directory -j$(shell nproc) SAN= TSAN= all test
	$(MAKE) --no-print-directory SAN= TSAN= lint

FMT_SRC = $(wildcard src/*.[ch] tests/*.[ch] fuzz/*.[ch])
# clang-tidy's bugprone-* and cert-*, minus the policy checks ctui-wm's
# tools/lint.py keeps quiet for the same reasons (each is said there); no
# baseline: a finding fails
TIDY_CHECKS = -*,bugprone-*,cert-*,-cert-err33-c,-bugprone-signed-bitwise,\
-bugprone-easily-swappable-parameters,-bugprone-assignment-in-if-condition,\
-bugprone-assignment-in-selection-statement,-cert-exp45-c,\
-bugprone-suspicious-string-compare,-bugprone-reserved-identifier,\
-cert-dcl37-c,-cert-dcl51-cpp,-bugprone-multi-level-implicit-pointer-conversion,\
-bugprone-suspicious-realloc-usage,-bugprone-unchecked-string-to-number-conversion,\
-cert-err34-c,-bugprone-implicit-widening-of-multiplication-result,\
-bugprone-narrowing-conversions,-bugprone-not-null-terminated-result,\
-bugprone-switch-missing-default-case,-bugprone-unhandled-code-paths,\
-cert-int09-c,-cert-dcl16-c,-bugprone-branch-clone,-bugprone-macro-parentheses,\
-bugprone-inc-dec-in-conditions,-bugprone-signed-char-misuse,-cert-str34-c,\
-cert-msc30-c,-cert-msc50-cpp
CPPCHECK_QUIET = nullPointerOutOfMemory nullPointerOutOfResources \
	nullPointerArithmeticOutOfMemory ctunullpointerOutOfMemory memleakOnRealloc \
	varFuncNullUB constStatement missingIncludeSystem checkersReport

lint:
	clang-format --dry-run -Werror $(FMT_SRC) && echo "clang-format: clean"
	clang-tidy --quiet --warnings-as-errors='*' --checks='$(TIDY_CHECKS)' $(SRC) -- $(CFLAGS) \
		&& echo "clang-tidy: clean"
	cppcheck --quiet --error-exitcode=1 --enable=warning,portability --std=c11 -Isrc \
		$(CPPCHECK_QUIET:%=--suppress=%) src && echo "cppcheck: clean"

format:
	clang-format -i $(FMT_SRC)

clean:
	rm -rf build

.PHONY: all test fuzz check lint format clean
-include $(shell find build -name '*.d' 2>/dev/null)
