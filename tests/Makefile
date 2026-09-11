CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror

test_bpf: test_bpf.c ../src/bpf/pppoe_fastpath.skel.h ../src/bpf/fastpath_shared.h
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libbpf) -o $@ $< $(shell pkg-config --libs libbpf)

../src/bpf/pppoe_fastpath.skel.h:
	$(MAKE) -C ../src FASTPATH=1 bpf/pppoe_fastpath.skel.h

clean:
	rm -f test_bpf
.PHONY: clean
