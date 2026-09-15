/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RELAY_BPF_SHARED_H
#define RELAY_BPF_SHARED_H
#include <linux/types.h>

#define RB_INTERFACES 8
#define RB_SESSIONS 65534
#define RB_CLIENT 1
#define RB_SERVER 2
#define RB_FRAME 1514
#define RB_TAG_DATA 22
#define RB_TAG_SIZE (RB_TAG_DATA + 4)

struct rb_iface {
    __u32 ifindex, roles;
    __u8 mac[6];
    __u16 pad;
};
struct rb_config {
    __u64 cookie;
    __u32 count, capacity, enabled, pad;
    struct rb_iface interfaces[RB_INTERFACES];
};
struct rb_key {
    __u32 ifindex;
    __be16 sid;
    __u8 mac[6];
};
struct rb_pair {
    struct rb_key client, server;
    __u8 client_local[6], server_local[6];
    __u32 active;
    __u64 generation;
};
struct rb_index { __u32 slot, pad; __u64 generation; };
enum rb_counter {
    RB_PASS, RB_DISCOVERY, RB_SESSION, RB_BYTES, RB_PADT,
    RB_CREATED, RB_DUPLICATE, RB_FULL, RB_BUSY, RB_INVALID,
    RB_ERROR, RB_COUNTERS
};
struct rb_totals { __u64 value[RB_COUNTERS]; };
#endif
