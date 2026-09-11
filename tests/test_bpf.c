/* SPDX-License-Identifier: GPL-2.0-or-later
 * Independent datapath PoC: real verifier + BPF_PROG_TEST_RUN, no relay hooks. */
#include <assert.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/pkt_cls.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "../src/bpf/fastpath_shared.h"
#include "../src/bpf/pppoe_fastpath.skel.h"

_Static_assert(sizeof(struct fastpath_key) == 16, "key ABI");
_Static_assert(sizeof(struct fastpath_value) == 32, "value ABI");
_Static_assert(sizeof(struct fastpath_stats) == 32, "stats ABI");

static int prog_fd;
static int checks;

static void put16(unsigned char *p, unsigned short v)
{
    p[0] = v >> 8; p[1] = v;
}

static void run(const char *name, unsigned char *input, unsigned int len,
                unsigned char *expected, unsigned int outlen, __u32 action)
{
    unsigned char result[2048] = {0};
    struct __sk_buff ctx = { .ifindex = 1, .ingress_ifindex = 1 };
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = input, .data_size_in = len,
        .data_out = result, .data_size_out = sizeof(result),
        .ctx_in = &ctx, .ctx_size_in = sizeof(ctx), .repeat = 1);
    if (bpf_prog_test_run_opts(prog_fd, &opts)) { perror(name); assert(0); }
    if (opts.retval != action || opts.data_size_out != outlen || memcmp(result, expected, outlen)) {
        fprintf(stderr, "FAIL %s: action=%u expected=%u length=%u expected=%u\n",
                name, opts.retval, action, opts.data_size_out, outlen);
        assert(0);
    }
    printf("PASS %s\n", name);
    checks++;
}

int main(void)
{
    struct pppoe_fastpath_bpf *s = pppoe_fastpath_bpf__open_and_load();
    struct fastpath_key key = { .ifindex = 1, .sid = htons(0x1234),
        .peer_mac = {2, 0, 0, 0, 0, 1} };
    struct fastpath_value value = { .egress_ifindex = 1, .slot = 1, .generation = 7,
        .new_sid = htons(0x5678), .src_mac = {2, 0, 0, 0, 0, 3},
        .dst_mac = {2, 0, 0, 0, 0, 4}, .ingress_dst = {2, 0, 0, 0, 0, 2} };
    struct fastpath_state state = { .generation = 7, .active = 1 };
    struct timespec ts;
    __u32 zero = 0, slot = 1;
    __u64 expiry;
    unsigned char frame[128] = {0}, expected[128], altered[128];
    int map, states, tag, j, offset;
    assert(s);
    prog_fd = bpf_program__fd(s->progs.pppoe_fastpath);
    map = bpf_map__fd(s->maps.sessions);
    states = bpf_map__fd(s->maps.states);
    assert(!clock_gettime(CLOCK_MONOTONIC, &ts));
    expiry = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec + 60000000000ULL;
    assert(!bpf_map_update_elem(bpf_map__fd(s->maps.lease), &zero, &expiry, BPF_ANY));

    for (tag = 0; tag < 3; tag++) {
        memset(frame, 0, sizeof(frame));
        memcpy(frame, value.ingress_dst, 6);
        memcpy(frame + 6, key.peer_mac, 6);
        offset = tag ? 18 : 14;
        key.vlan_proto = tag ? htons(tag == 1 ? 0x8100 : 0x88a8) : 0;
        key.vlan_id = tag ? 100 : 0;
        put16(frame + 12, tag ? ntohs(key.vlan_proto) : 0x8864);
        if (tag) { put16(frame + 14, 100); put16(frame + 16, 0x8864); }
        frame[offset] = 0x11;
        put16(frame + offset + 2, 0x1234);
        put16(frame + offset + 4, 32);
        for (j = 0; j < 32; j++) frame[offset + 6 + j] = j;
        memcpy(expected, frame, sizeof(frame));
        memcpy(expected, value.dst_mac, 6);
        memcpy(expected + 6, value.src_mac, 6);
        put16(expected + offset + 2, 0x5678);
        assert(!bpf_map_update_elem(map, &key, &value, BPF_NOEXIST));
        state.active = 0;
        assert(!bpf_map_update_elem(states, &slot, &state, BPF_ANY));
        run("uncommitted direction passes untouched", frame, 100, frame, 100, (__u32)TCX_NEXT);
        state.active = 1;
        assert(!bpf_map_update_elem(states, &slot, &state, BPF_ANY));
        run(tag ? "single VLAN rewrite and padding trim" : "untagged rewrite and padding trim",
            frame, 100, expected, offset + 38, TC_ACT_REDIRECT);
        memcpy(altered, frame, sizeof(frame)); altered[5] ^= 1;
        run("wrong destination", altered, 100, altered, 100, (__u32)TCX_NEXT);
        memcpy(altered, frame, sizeof(frame)); altered[11] ^= 1;
        run("same SID different peer", altered, 100, altered, 100, (__u32)TCX_NEXT);
        memcpy(altered, frame, sizeof(frame)); altered[offset] = 0x21;
        run("bad version", altered, 100, altered, 100, (__u32)TCX_NEXT);
        memcpy(altered, frame, sizeof(frame)); altered[offset + 1] = 0xa7;
        run("non-session code", altered, 100, altered, 100, (__u32)TCX_NEXT);
        memcpy(altered, frame, sizeof(frame)); put16(altered + offset + 4, 1000);
        run("truncated PPP payload", altered, 100, altered, 100, (__u32)TCX_NEXT);
        memcpy(altered, frame, sizeof(frame)); put16(altered + offset - 2, 0x8863);
        run("discovery untouched", altered, 100, altered, 100, (__u32)TCX_NEXT);
        run("truncated PPPoE header", frame, offset + 3, frame, offset + 3, (__u32)TCX_NEXT);
        state.generation++;
        assert(!bpf_map_update_elem(states, &slot, &state, BPF_ANY));
        run("stale generation", frame, 100, frame, 100, (__u32)TCX_NEXT);
        state.generation--;
        assert(!bpf_map_update_elem(states, &slot, &state, BPF_ANY));
        assert(!bpf_map_delete_elem(map, &key));
        run("deleted mapping", frame, 100, frame, 100, (__u32)TCX_NEXT);
    }
    assert(!bpf_map_update_elem(map, &key, &value, BPF_NOEXIST));
    expiry = 0;
    assert(!bpf_map_update_elem(bpf_map__fd(s->maps.lease), &zero, &expiry, BPF_ANY));
    run("expired owner lease", frame, 100, frame, 100, (__u32)TCX_NEXT);
    pppoe_fastpath_bpf__destroy(s);
    printf("%d datapath checks passed (no live redirect asserted here)\n", checks);
    return 0;
}
