# SPDX-License-Identifier: GPL-2.0-or-later
.PHONY: all clean install test
all clean install:
	$(MAKE) -C src $@

# Requires root, Linux 6.6+, Python 3.12+, iproute2 and tcpdump.
test: all
	python3 tests/netns.py --binary src/pppoe-relay-bpf
