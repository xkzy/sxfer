# sxfer - High-speed, one-way serial file tree transfer in Rust

CARGO   ?= cargo
BIN     := sxfer
RELEASE_BIN := target/x86_64-unknown-linux-musl/release/$(BIN)
MAN1    := $(BIN).1


PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man/man1
MAN     ?= mandoc

INSTALL ?= install

.PHONY: all clean install uninstall run help man-check test test-e2e test-noise test-regression test-watch FORCE

all: $(BIN)

$(BIN): $(RELEASE_BIN)
	cp $(RELEASE_BIN) $(BIN)

$(RELEASE_BIN): FORCE
	$(CARGO) build --release

FORCE:


# sanity check: build, then ask the binary for its usage text
run: $(BIN)
	./$(BIN) --help || true

test:
	$(CARGO) test
	@echo "All Rust unit tests passed."

test-e2e: $(BIN)
	bash test/test_e2e_full.sh

test-noise: $(BIN)
	bash test/test_noise_recovery.sh

test-regression: $(BIN)
	bash test/test_regression.sh

test-watch: $(BIN)
	bash test/test_watch_mode.sh


install: $(BIN) $(MAN1)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	$(INSTALL) -d $(DESTDIR)$(MANDIR)
	$(INSTALL) -m 0644 $(MAN1) $(DESTDIR)$(MANDIR)/$(MAN1)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN) $(DESTDIR)$(MANDIR)/$(MAN1)

# lint the man page (skipped silently when mandoc is absent)
man-check: $(MAN1)
	@if command -v $(MAN) >/dev/null; then $(MAN) -T lint $(MAN1); \
	 else echo "$(MAN) not found, skipping man page lint"; fi

clean:
	$(CARGO) clean
	rm -f $(BIN)


help:
	@echo 'targets: all (default), run, test, test-e2e, test-noise, install, uninstall, man-check, clean'
	@echo 'vars:    CARGO, PREFIX, DESTDIR, MAN'
