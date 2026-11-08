# c-serve: an HTTP/1.1 server and client over TLS (mbedtls), in C11.
# `make` builds the library, `make test` runs the suites, `make check` is
# the gate before a commit. Nothing is installed: a host compiles src/
# into itself (ctui-wm does, as a submodule).

CC ?= cc
OPT ?= -O2
# -ffunction-sections -fdata-sections: a host's --gc-sections drops what
# it never calls (a server that makes no requests links no client)
CFLAGS = -Wall -Wextra -Wno-format-truncation $(WARN) -std=c11 -Isrc -Ikit -g $(OPT) \
	-ffunction-sections -fdata-sections

# mbedtls 4 (with its PSA crypto) for TLS -- the vendored release, built
# here with vendor/mbedtls/config/ (DTLS-SRTP, threading) into $(MB) -- and
# the system's zlib to undo gzip / deflate. Everything compiled against
# mbedtls's headers says the same config files the library was built with:
# its structs' fields depend on them, and a mismatch is no error, only
# corrupted memory.
MB_CONFIG = -DMBEDTLS_USER_CONFIG_FILE='"$(CURDIR)/vendor/mbedtls/config/mbedtls_user.h"' \
	-DTF_PSA_CRYPTO_USER_CONFIG_FILE='"$(CURDIR)/vendor/mbedtls/config/crypto_user.h"'
CFLAGS += -I$(CURDIR)/$(MB)/include $(MB_CONFIG) $(shell pkg-config --cflags zlib)
LDLIBS = $(MB)/lib/libmbedtls.a $(MB)/lib/libmbedx509.a $(MB)/lib/libtfpsacrypto.a \
	$(shell pkg-config --libs zlib) -lpthread

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

# the vendored mbedtls: its tarball checked against VERSION's SHA-256, then
# unpacked and built for this variant -- the same sanitizers as the rest, so
# ASan and TSan see inside the crypto too -- and installed into $(MB)
MB = $(B)/mbedtls
MB_TAR = $(wildcard vendor/mbedtls/mbedtls-*.tar.bz2)
MB_STAMP = $(MB)/.built
MB_CFLAGS = -g $(OPT) -ffunction-sections -fdata-sections \
	$(filter -fsanitize=% -fno-omit-frame-pointer,$(CFLAGS))
$(MB_STAMP): $(MB_TAR) vendor/mbedtls/VERSION vendor/mbedtls/config/mbedtls_user.h \
		vendor/mbedtls/config/crypto_user.h
	@want=$$(awk '$$1 == "$(notdir $(MB_TAR))" {print $$2}' vendor/mbedtls/VERSION); \
	  got=$$(sha256sum $(MB_TAR) | cut -d' ' -f1); \
	  [ -n "$$want" ] && [ "$$got" = "$$want" ] || \
	    { echo "$(MB_TAR): not the vendored mbedtls (VERSION)"; exit 1; }
	rm -rf $(B)/mbedtls-src $(B)/mbedtls-build $(MB)
	mkdir -p $(B)/mbedtls-src
	tar -xjf $(MB_TAR) -C $(B)/mbedtls-src --strip-components=1
	cmake -S $(B)/mbedtls-src -B $(B)/mbedtls-build -G Ninja -DCMAKE_BUILD_TYPE=None \
		-DCMAKE_C_COMPILER=$(CC) -DCMAKE_C_FLAGS="$(MB_CFLAGS)" \
		-DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF \
		-DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
		-DMBEDTLS_USER_CONFIG_FILE=$(CURDIR)/vendor/mbedtls/config/mbedtls_user.h \
		-DTF_PSA_CRYPTO_USER_CONFIG_FILE=$(CURDIR)/vendor/mbedtls/config/crypto_user.h \
		-DCMAKE_INSTALL_PREFIX=$(CURDIR)/$(MB) > $(B)/mbedtls.log 2>&1 && \
	  cmake --build $(B)/mbedtls-build >> $(B)/mbedtls.log 2>&1 && \
	  cmake --install $(B)/mbedtls-build >> $(B)/mbedtls.log 2>&1 || \
	  { tail -30 $(B)/mbedtls.log; exit 1; }
	touch $@

mbedtls: $(MB_STAMP)

# kit/ is an app's toolkit (reading a request, the markup tree, catalogs,
# a page answered): what an app links, which the host itself never calls
KIT_SRC = $(wildcard kit/*.c)
SRC = $(wildcard src/*.c) $(KIT_SRC)
# what a server-only host compiles (the static files and the CGI with
# it); the client is net.c
SERVE_SRC = src/listen.c src/httpd.c src/static.c src/cgi.c src/process.c \
	src/log.c src/route.c src/policy.c src/heap.c src/pool.c src/loop.c src/tarpit.c \
	src/acme.c src/wake.c src/stream.c
CLIENT_SRC = $(filter-out $(SERVE_SRC) $(KIT_SRC),$(SRC))
TESTS = $(patsubst tests/%_test.c,%,$(wildcard tests/*_test.c))
FUZZERS = $(patsubst fuzz/%.c,%,$(filter-out fuzz/fuzz.h,$(wildcard fuzz/*.c)))

# the apps (apps/NAME/*.c, each exporting cserve_app_NAME): a .so each for
# the development host, and STATIC_APPS linked into the production one.
# EXTERNAL_APPS adds apps kept elsewhere, as NAME=DIR pairs (neurosys's:
# neurosys=/srv/http/neurosys/app): DIR's *.c, at any depth but under a
# build/ inside DIR (DIR itself may be in one: a site's prod tree is),
# compiled with DIR and DIR/gen on the include path. A second build of
# the same app from another DIR takes a B= of its own, or the two share
# objects and binaries. Several pairs go space-separated (the box's host
# carries neurosys and comms). An app's DIR/vendor/ is code it took from
# elsewhere (comms's SQLite amalgamation): compiled with it, but with
# warnings off and EXTERNAL_VENDOR_CFLAGS_<name> added, and left out of
# every lint
EXTERNAL_APPS ?=
ext_name = $(word 1,$(subst =, ,$(1)))
ext_dir = $(word 2,$(subst =, ,$(1)))
EXT_NAMES = $(foreach e,$(EXTERNAL_APPS),$(call ext_name,$(e)))
ext_dir_of = $(strip $(foreach e,$(EXTERNAL_APPS),$(if $(filter $(1),$(call ext_name,$(e))),$(call ext_dir,$(e)))))
ext_src = $(shell cd $(call ext_dir_of,$(1)) && find . -name '*.c' -not -path './build/*' \
	-not -path '*/build/*' | sed 's|^\./|$(call ext_dir_of,$(1))/|' | sort)
APPS = $(notdir $(wildcard apps/*)) $(EXT_NAMES)
STATIC_APPS ?= hello
app_src = $(foreach a,$(1),$(if $(filter $(a),$(EXT_NAMES)),$(call ext_src,$(a)),$(wildcard apps/$(a)/*.c)))
app_obj = $(foreach a,$(1),$(if $(filter $(a),$(EXT_NAMES)),$(patsubst \
	$(call ext_dir_of,$(a))/%.c,$(B)/ext/$(a)/%.o,$(call ext_src,$(a))),$(call obj,$(wildcard apps/$(a)/*.c))))

all: $(B)/libcserve.a $(BIN)/cserve $(BIN)/cserve-static $(BIN)/cserve-front \
	$(BIN)/cserve-precompress $(BIN)/cserve-acme \
	$(APPS:%=$(BIN)/apps/%.so)

# made anew: ar updates an archive in place, so an object whose source
# went (a rename) would stay in it
# the vendored mbedtls rebuilt: everything compiled (objects depend on its
# stamp, since its config decides its structs) and linked against it again
$(B)/libcserve.a: $(call obj,$(SRC)) $(MB_STAMP)
	rm -f $@
	$(AR) rcs $@ $(filter %.o,$^)

$(B)/%.o: %.c $(MB_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# an app's objects go into a .so too
$(B)/apps/%.o: CFLAGS += -fPIC

# vendored code: the sanitizers and the optimisation as everything else,
# not our warnings, nor our -std
VENDOR_CFLAGS = $(filter-out -Wall -Wextra -Wno-format-truncation $(WARN) -std=c11,$(CFLAGS)) \
	-w -std=gnu11
define EXT_RULES
$(B)/ext/$(1)/vendor/%.o: $(2)/vendor/%.c
	@mkdir -p $$(@D)
	$$(CC) $$(VENDOR_CFLAGS) $$(EXTERNAL_VENDOR_CFLAGS_$(1)) -fPIC -MMD -MP -c $$< -o $$@
$(B)/ext/$(1)/%.o: $(2)/%.c $$(MB_STAMP)
	@mkdir -p $$(@D)
	$$(CC) $$(CFLAGS) -fPIC -I$(2) -I$(2)/gen -MMD -MP -c $$< -o $$@
endef
$(foreach e,$(EXTERNAL_APPS),$(eval $(call EXT_RULES,$(call ext_name,$(e)),$(call ext_dir,$(e)))))

# the host, twice: cserve dlopen()s the apps it's given as paths (its own
# symbols exported for them: -rdynamic, the whole library), cserve-static
# has STATIC_APPS in its table and no dlopen at all
$(B)/host/main-dev.o: host/main.c $(MB_STAMP)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -DCSERVE_DLOPEN -MMD -MP -c $< -o $@

# the apps' table, rewritten only when STATIC_APPS changes what it says
$(B)/gen/apps-static.c: FORCE
	@mkdir -p $(@D)
	@{ echo '#include "app.h"'; \
	  for a in $(STATIC_APPS); do echo "extern const CSERVE_APP cserve_app_$$a;"; done; \
	  printf 'const CSERVE_APP *const cserve_apps[] = {'; \
	  for a in $(STATIC_APPS); do printf '&cserve_app_%s, ' $$a; done; \
	  echo 'NULL};'; } > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@
$(B)/gen/apps-dev.c:
	@mkdir -p $(@D)
	@printf '#include "app.h"\nconst CSERVE_APP *const cserve_apps[] = {NULL};\n' > $@
$(B)/gen/%.o: $(B)/gen/%.c $(MB_STAMP)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN)/cserve: $(B)/host/main-dev.o $(B)/gen/apps-dev.o $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -rdynamic $(filter %.o,$^) -Wl,--whole-archive $(B)/libcserve.a \
		-Wl,--no-whole-archive $(LDLIBS) -ldl -o $@

$(BIN)/cserve-static: $(B)/host/main.o $(B)/gen/apps-static.o \
		$(call app_obj,$(STATIC_APPS)) $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BIN)/cserve-precompress: $(B)/host/precompress.o $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

# the certificates' fetcher: a process of its own, never the server's
$(BIN)/cserve-acme: $(B)/host/acme.o $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BIN)/cserve-front: $(B)/host/front.o $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

.SECONDEXPANSION:
$(BIN)/apps/%.so: $$(call app_obj,%)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -shared $^ -o $@

$(BIN)/test-%: $(call obj,tests/%_test.c) $(B)/libcserve.a
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

# the host's suite runs both hosts and the app as built here
$(B)/tests/host_test.o: CFLAGS += -DCSERVE_BIN='"$(BIN)"'
$(BIN)/test-host: | $(BIN)/cserve $(BIN)/cserve-static $(BIN)/cserve-front \
	$(BIN)/cserve-precompress \
	$(APPS:%=$(BIN)/apps/%.so)

# T=NAME runs one suite. The suites read tests/data/ relative to here.
test: $(if $(T),$(BIN)/test-$(T),$(TESTS:%=$(BIN)/test-%))
	@fail=0; for t in $^; do echo "== $$t"; $(TEST_WRAP) ./$$t || fail=1; done; exit $$fail

$(BIN)/fuzz-%: $(call obj,fuzz/%.c) $(call obj,$(SRC))
	@mkdir -p $(@D)
	$(CC) -fsanitize=fuzzer,address,undefined $^ $(LDLIBS) -o $@

# the host attacked (tools/abuse.py), under each sanitizer
abuse:
	$(MAKE) --no-print-directory -j$(shell nproc) SAN=1 TSAN= STATIC_APPS=hello all
	python3 -I tools/abuse.py build/O2-san/bin --prompt 12
	$(MAKE) --no-print-directory -j$(shell nproc) SAN= TSAN=1 STATIC_APPS=hello all
	python3 -I tools/abuse.py build/O2-tsan/bin --prompt 12

# the certificates against Pebble (tools/acme.sh says how to get it)
acme:
	$(MAKE) --no-print-directory -j$(shell nproc) SAN= TSAN= all
	bash tools/acme.sh $(BIN)

fuzz:
	@test -n "$(FUZZ)" || { echo "make FUZZ=1 fuzz"; exit 1; }
	$(MAKE) --no-print-directory $(FUZZERS:%=$(BIN)/fuzz-%)

check:
	$(MAKE) --no-print-directory -j$(shell nproc) SAN=1 TSAN= test
	$(MAKE) --no-print-directory -j$(shell nproc) SAN= TSAN=1 test
	$(MAKE) --no-print-directory -j$(shell nproc) SAN= TSAN= all test
	$(MAKE) --no-print-directory SAN= TSAN= lint

# an external app's own sources are linted with ours; what it generates
# (DIR/gen/) is checked for markup only
EXT_SRC = $(foreach a,$(EXT_NAMES),$(call ext_src,$(a)))
EXT_OWN = $(foreach f,$(EXT_SRC),$(if $(findstring /gen/,$(f))$(findstring /vendor/,$(f)),,$(f)))
EXT_NOT_VENDOR = $(foreach f,$(EXT_SRC),$(if $(findstring /vendor/,$(f)),,$(f)))
EXT_HDR = $(foreach e,$(EXTERNAL_APPS),$(shell cd $(call ext_dir,$(e)) && find . -name '*.h' \
	-not -path '*/build/*' -not -path '*/gen/*' -not -path '*/vendor/*' | sed 's|^\./|$(call ext_dir,$(e))/|'))
FMT_SRC = $(wildcard src/*.[ch] kit/*.[ch] host/*.c apps/*/*.[ch] tests/*.[ch] fuzz/*.[ch]) \
	$(EXT_OWN) $(EXT_HDR)
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

# a page is a tree (kit/markup.h): only markup.c writes a '<', so a string
# literal holding a tag anywhere else in the toolkit or an app is refused
MARKUP_FREE = $(filter-out kit/markup.c,$(KIT_SRC)) $(wildcard apps/*/*.c) $(EXT_NOT_VENDOR)

# the checks lint runs, for a repo that builds on this one (comms)
tidy-checks:
	@echo '$(TIDY_CHECKS)'

lint: $(MB_STAMP)
	@if grep -n '"[^"]*<[A-Za-z/!]' $(MARKUP_FREE); then \
		echo "markup: a tag written as a string (only kit/markup.c writes '<')"; \
		exit 1; fi; echo "markup: clean"
	clang-format --dry-run -Werror $(FMT_SRC) && echo "clang-format: clean"
	clang-tidy --quiet --warnings-as-errors='*' --checks='$(TIDY_CHECKS)' \
		$(SRC) host/main.c host/acme.c $(wildcard apps/*/*.c) $(EXT_OWN) -- $(CFLAGS) -DCSERVE_DLOPEN \
		$(foreach e,$(EXTERNAL_APPS),-I$(call ext_dir,$(e)) -I$(call ext_dir,$(e))/gen) \
		&& echo "clang-tidy: clean"
	cppcheck --quiet --error-exitcode=1 --enable=warning,portability --std=c11 -Isrc -Ikit \
		-DCSERVE_DLOPEN $(CPPCHECK_QUIET:%=--suppress=%) src kit host apps \
		$(foreach e,$(EXTERNAL_APPS),-I$(call ext_dir,$(e))/gen -i$(call ext_dir,$(e))/vendor \
		$(call ext_dir,$(e))) \
		&& echo "cppcheck: clean"

format:
	clang-format -i $(FMT_SRC)

clean:
	rm -rf build

FORCE:

.PHONY: all test fuzz check abuse lint format clean FORCE mbedtls tidy-checks
# the compiler's dependency files -- not the vendored mbedtls's own trees,
# whose source has *.d directories of its own
-include $(shell find build -name '*.d' -type f -not -path '*/mbedtls-src/*' \
	-not -path '*/mbedtls-build/*' 2>/dev/null)
