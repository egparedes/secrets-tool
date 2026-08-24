PREFIX  ?= /usr/local
DESTDIR ?=

BINDIR = $(DESTDIR)$(PREFIX)/bin
LIBDIR = $(DESTDIR)$(PREFIX)/share/secrets

.PHONY: all install uninstall test

all:
	@echo 'targets: install uninstall test   (PREFIX=$(PREFIX))'

install:
	mkdir -p '$(BINDIR)' '$(LIBDIR)'
	chmod 755 '$(BINDIR)' '$(LIBDIR)'
	cp bin/secrets '$(BINDIR)/secrets'
	chmod 755 '$(BINDIR)/secrets'
	cp lib/secrets-lib.sh '$(LIBDIR)/secrets-lib.sh'
	chmod 644 '$(LIBDIR)/secrets-lib.sh'

uninstall:
	rm -f '$(BINDIR)/secrets' '$(LIBDIR)/secrets-lib.sh'
	-rmdir '$(LIBDIR)'

test:
	sh tests/test-secrets.sh
