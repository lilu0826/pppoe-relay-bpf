# SPDX-License-Identifier: GPL-2.0-or-later
CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf
BPF_CPPFLAGS ?= -I/usr/include/$(shell $(CC) -dumpmachine)
STATIC ?= 0
BPF_PREBUILT ?= 0
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin

ifeq ($(STATIC),1)
LINK_FLAGS = -static -fno-lto
PKG_STATIC = --static
endif

.PHONY: all clean install FORCE_LINK
all: pppoe-relay-bpf

# Relink when switching STATIC or link flags, keeping one binary name.
pppoe-relay-bpf: relay_bpf.o FORCE_LINK
	$(CC) $(CFLAGS) $(LDFLAGS) $(LINK_FLAGS) -o $@ relay_bpf.o $(shell $(PKG_CONFIG) $(PKG_STATIC) --libs libbpf) $(LDLIBS)

relay_bpf.o: relay_bpf.c bpf/relay_shared.h bpf/pppoe_relay.skel.h
	$(PKG_CONFIG) --atleast-version=1.3.0 libbpf
	$(CC) $(CPPFLAGS) $(CFLAGS) $(shell $(PKG_CONFIG) --cflags libbpf) -c $< -o $@

ifeq ($(BPF_PREBUILT),1)
# SDK cross-builds consume a skeleton generated with the host BPF toolchain.
bpf/pppoe_relay.skel.h:
	@echo "Missing prebuilt BPF skeleton: $@" >&2
	@exit 1
else
bpf/pppoe_relay.bpf.o: bpf/pppoe_relay.bpf.c bpf/relay_shared.h
	$(CLANG) $(BPF_CFLAGS) -mcpu=v3 $(BPF_CPPFLAGS) $(shell $(PKG_CONFIG) --cflags libbpf) -c $< -o $@

bpf/pppoe_relay.skel.h: bpf/pppoe_relay.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@
endif

install: all
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 pppoe-relay-bpf $(DESTDIR)$(SBINDIR)/pppoe-relay-bpf

clean:
	rm -f relay_bpf.o pppoe-relay-bpf bpf/pppoe_relay.bpf.o bpf/pppoe_relay.skel.h bpf/pppoe_relay.skel.h.tmp
