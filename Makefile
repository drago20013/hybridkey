# Build and install hybridkey. Packagers: make && make install DESTDIR=...
PREFIX      ?= /usr
BINDIR      ?= $(PREFIX)/bin
LIBDIR      ?= $(PREFIX)/lib
DATADIR     ?= $(PREFIX)/share
USERUNITDIR ?= $(LIBDIR)/systemd/user
UNITDIR     ?= $(LIBDIR)/systemd/system
SYSUSERSDIR ?= $(LIBDIR)/sysusers.d
MODLOADDIR  ?= $(LIBDIR)/modules-load.d
DOCDIR      ?= $(DATADIR)/doc/hybridkey
CARGO       ?= cargo
TARGET      ?= target/release

DOCS = README.md docs/architecture.md docs/security.md docs/testing.md docs/qr-helper-protocol.md

.PHONY: all build test install uninstall activate clean

all: build

build:
	$(CARGO) build --release --locked --workspace

test:
	$(CARGO) test --locked --workspace

install:
	install -Dm755 $(TARGET)/hybridkeyd $(DESTDIR)$(BINDIR)/hybridkeyd
	install -Dm755 $(TARGET)/hybridkey-qr $(DESTDIR)$(BINDIR)/hybridkey-qr
	install -Dm755 $(TARGET)/hybridkey-uhidd $(DESTDIR)$(BINDIR)/hybridkey-uhidd
	install -Dm755 packaging/bin/hybridkey-toggle $(DESTDIR)$(BINDIR)/hybridkey-toggle
	install -dm755 $(DESTDIR)$(USERUNITDIR) $(DESTDIR)$(UNITDIR)
	sed 's|@BINDIR@|$(BINDIR)|g' packaging/systemd/hybridkey.service.in > $(DESTDIR)$(USERUNITDIR)/hybridkey.service
	sed 's|@BINDIR@|$(BINDIR)|g' packaging/systemd/hybridkey-uhidd.service.in > $(DESTDIR)$(UNITDIR)/hybridkey-uhidd.service
	install -m644 packaging/systemd/hybridkey-uhidd.socket $(DESTDIR)$(UNITDIR)/hybridkey-uhidd.socket
	chmod 644 $(DESTDIR)$(USERUNITDIR)/hybridkey.service $(DESTDIR)$(UNITDIR)/hybridkey-uhidd.service
	install -Dm644 packaging/sysusers.d/hybridkey.conf $(DESTDIR)$(SYSUSERSDIR)/hybridkey.conf
	install -Dm644 packaging/modules-load.d/hybridkey.conf $(DESTDIR)$(MODLOADDIR)/hybridkey.conf
	install -Dm644 packaging/omarchy/hybridkey.lua $(DESTDIR)$(DATADIR)/hybridkey/hypr/hybridkey.lua
	install -Dm644 packaging/config.example.toml $(DESTDIR)$(DOCDIR)/config.example.toml
	install -Dm644 -t $(DESTDIR)$(DOCDIR) $(DOCS)

# Host-only, needs root: create the group, load uhid, start the relay socket.
# Afterwards: usermod -aG hybridkey <user>, log in again, hybridkey-toggle on.
activate:
	systemd-sysusers hybridkey.conf
	modprobe uhid
	systemctl daemon-reload
	systemctl enable --now hybridkey-uhidd.socket

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/hybridkeyd $(DESTDIR)$(BINDIR)/hybridkey-qr
	rm -f $(DESTDIR)$(BINDIR)/hybridkey-uhidd $(DESTDIR)$(BINDIR)/hybridkey-toggle
	rm -f $(DESTDIR)$(USERUNITDIR)/hybridkey.service
	rm -f $(DESTDIR)$(UNITDIR)/hybridkey-uhidd.service $(DESTDIR)$(UNITDIR)/hybridkey-uhidd.socket
	rm -f $(DESTDIR)$(SYSUSERSDIR)/hybridkey.conf
	rm -f $(DESTDIR)$(MODLOADDIR)/hybridkey.conf
	rm -rf $(DESTDIR)$(DATADIR)/hybridkey $(DESTDIR)$(DOCDIR)

clean:
	$(CARGO) clean
