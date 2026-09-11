/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RP_FASTPATH_SHARED_H
#define RP_FASTPATH_SHARED_H
#include <linux/types.h>

/* SID and VLAN EtherType: network order. All other integers: host order.
 * All padding is explicit and must be zeroed by userspace. */
struct fastpath_key {
    __u32 ifindex;              /* current logical TC device, skb->ifindex */
    __be16 sid;
    __u8 peer_mac[6];           /* upstream findSession() includes peer MAC */
    __be16 vlan_proto;          /* 0 for decapsulated logical interfaces */
    __u16 vlan_id;
};

struct fastpath_value {
    __u32 egress_ifindex;
    __u32 slot;
    __u32 generation;
    __be16 new_sid;
    __u8 src_mac[6];
    __u8 dst_mac[6];
    __u8 ingress_dst[6];        /* upstream requires destination == iface MAC */
};

/* A single activation update commits BOTH direction entries. */
struct fastpath_state {
    __u32 generation;
    __u32 active;
};

struct fastpath_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
    __u32 generation;
    __u32 pad;
};

struct fastpath_totals {
    __u64 packets;
    __u64 bytes;
    __u64 misses;
    __u64 errors;
};

#define FP_LEASE_NS (5ULL * 1000000000ULL)
#endif
