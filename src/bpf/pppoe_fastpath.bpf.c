/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fastpath_shared.h"

struct pppoe_header {
    __u8 vertype;
    __u8 code;
    __be16 sid;
    __be16 length;
};
struct vlan_header { __be16 tci; __be16 proto; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct fastpath_key);
    __type(value, struct fastpath_value);
} sessions SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5001);
    __type(key, __u32);
    __type(value, struct fastpath_state);
} states SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5001);
    __type(key, __u32);
    __type(value, struct fastpath_stats);
} activity SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fastpath_totals);
} totals SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lease SEC(".maps");

/* TCX_NEXT preserves other TCX/legacy TC programs on packets we do not own. */
SEC("tc/ingress")
int pppoe_fastpath(struct __sk_buff *skb)
{
    struct fastpath_key key = {};
    struct fastpath_value out;
    struct fastpath_value *entry;
    struct fastpath_state *state;
    struct fastpath_stats *stats;
    struct fastpath_totals *total;
    struct ethhdr eth;
    struct pppoe_header ph;
    __u32 zero = 0, offset = ETH_HLEN, frame_len;
    __u64 now, *deadline;
    __be16 proto;

    /* load_bytes handles non-linear skbs; every fixed header read is checked. */
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)))
        return TCX_NEXT;
    proto = eth.h_proto;
    if (skb->vlan_present) {
        key.vlan_proto = (__be16)skb->vlan_proto;
        key.vlan_id = skb->vlan_tci & 0xfff;
    }
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_header vh;
        /* One tag total. QinQ deliberately takes the original path. */
        if (skb->vlan_present || bpf_skb_load_bytes(skb, offset, &vh, sizeof(vh)))
            return TCX_NEXT;
        key.vlan_proto = proto;
        key.vlan_id = bpf_ntohs(vh.tci) & 0xfff;
        proto = vh.proto;
        offset += sizeof(vh);
    }
    if (proto != bpf_htons(ETH_P_PPP_SES))
        return TCX_NEXT;
    if (bpf_skb_load_bytes(skb, offset, &ph, sizeof(ph)))
        return TCX_NEXT;
    if (ph.vertype != 0x11 || ph.code != 0)
        return TCX_NEXT;
    frame_len = offset + sizeof(ph) + bpf_ntohs(ph.length);
    if (frame_len > skb->len)
        return TCX_NEXT;

    total = bpf_map_lookup_elem(&totals, &zero);
    deadline = bpf_map_lookup_elem(&lease, &zero);
    now = bpf_ktime_get_ns();
    if (!deadline || now >= *deadline)
        return TCX_NEXT;
    key.ifindex = skb->ifindex;
    key.sid = ph.sid;
    __builtin_memcpy(key.peer_mac, eth.h_source, ETH_ALEN);
    entry = bpf_map_lookup_elem(&sessions, &key);
    if (!entry) {
        if (total) total->misses++;
        return TCX_NEXT;
    }
    out = *entry;
    state = bpf_map_lookup_elem(&states, &out.slot);
    if (!state || !state->active || state->generation != out.generation ||
        __builtin_memcmp(eth.h_dest, out.ingress_dst, ETH_ALEN))
        return TCX_NEXT;

    /* From this point a failed write must DROP, never pass a partially
     * rewritten frame to the userspace fallback. */
    if (skb->len > frame_len && bpf_skb_change_tail(skb, frame_len, 0))
        goto write_error;
    __builtin_memcpy(eth.h_source, out.src_mac, ETH_ALEN);
    __builtin_memcpy(eth.h_dest, out.dst_mac, ETH_ALEN);
    if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) ||
        bpf_skb_store_bytes(skb, offset + 2, &out.new_sid, 2,
                            BPF_F_RECOMPUTE_CSUM | BPF_F_INVALIDATE_HASH))
        goto write_error;

    stats = bpf_map_lookup_elem(&activity, &out.slot);
    if (stats) {
        if (stats->generation != out.generation) {
            stats->packets = 0;
            stats->bytes = 0;
            stats->generation = out.generation;
        }
        stats->packets++;
        stats->bytes += frame_len;
        stats->last_seen_ns = now;
    }
    if (total) {
        total->packets++;
        total->bytes += frame_len;
    }
    return bpf_redirect(out.egress_ifindex, 0);

write_error:
    if (total) total->errors++;
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
