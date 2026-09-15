/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "relay_shared.h"

struct rb_slot { struct bpf_spin_lock lock; struct rb_pair pair; };
struct rb_allocator { __u64 busy; __u32 cursor, pad; __u64 generation; };
struct rb_packet {
    __u8 dst[6], src[6];
    __be16 proto;
    __u8 version, code;
    __be16 sid, length;
} __attribute__((packed));
struct rb_scratch { __u8 in[RB_FRAME], out[RB_FRAME]; };

#define ARRAY_MAP(name, value_type, n) \
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, n); \
    __type(key, __u32); __type(value, value_type); } name SEC(".maps")
ARRAY_MAP(config, struct rb_config, 1);
ARRAY_MAP(slots, struct rb_slot, RB_SESSIONS + 1);
ARRAY_MAP(allocator, struct rb_allocator, 1);
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, RB_SESSIONS);
    __type(key, struct rb_key);
    __type(value, struct rb_index);
} ac_index SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rb_scratch);
} scratch SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rb_totals);
} totals SEC(".maps");

static __always_inline int mac_equal(const __u8 *a, const __u8 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
           a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}
static __always_inline int key_equal(const struct rb_key *a, const struct rb_key *b)
{
    return a->ifindex == b->ifindex && a->sid == b->sid && mac_equal(a->mac, b->mac);
}
static __always_inline void count(enum rb_counter which)
{
    __u32 zero = 0;
    struct rb_totals *t = bpf_map_lookup_elem(&totals, &zero);
    if (t) t->value[which]++;
}
static __always_inline int pass(void) { count(RB_PASS); return TCX_NEXT; }
static __always_inline int invalid(void) { count(RB_INVALID); return TC_ACT_SHOT; }
static __always_inline int error(void) { count(RB_ERROR); return TC_ACT_SHOT; }

/* Snapshot and PADT invalidation share a slot lock. No helpers under this lock.
 * An already-snapshotted data packet may finish after PADT, as on a wire.
 * Inactive slots retain their AC index until the next allocation reclaims them. */
/* Global BPF subprograms are verified independently, once per load. Keeping
 * this static multiplies all lookup branches by every Discovery call site. */
__noinline int lookup_pair(struct rb_key *key, __u32 roles,
                                 struct rb_pair *pair, int closing)
{
    struct rb_index index = {};
    struct rb_slot *slot;
    int found = 0;
    if (!key || !pair) return 0;
    if (roles & RB_CLIENT) {
        index.slot = bpf_ntohs(key->sid);
        slot = bpf_map_lookup_elem(&slots, &index.slot);
        if (slot) {
            bpf_spin_lock(&slot->lock);
            if (slot->pair.active == 1 && key_equal(key, &slot->pair.client)) {
                *pair = slot->pair;
                if (closing) slot->pair.active = 0;
                found = 1;
            }
            bpf_spin_unlock(&slot->lock);
        }
        if (found) return RB_CLIENT;
    }
    if (roles & RB_SERVER) {
        struct rb_index *entry = bpf_map_lookup_elem(&ac_index, key);
        if (!entry) return 0;
        index = *entry;
        slot = bpf_map_lookup_elem(&slots, &index.slot);
        if (!slot) return 0;
        bpf_spin_lock(&slot->lock);
        if (slot->pair.active == 1 && slot->pair.generation == index.generation &&
            key_equal(key, &slot->pair.server)) {
            *pair = slot->pair;
            if (closing) slot->pair.active = 0;
            found = 1;
        }
        bpf_spin_unlock(&slot->lock);
        if (found) return RB_SERVER;
    }
    return 0;
}

struct alloc_search {
    __u32 start, capacity, found;
    struct rb_pair old;
    struct rb_key client;
};
static long find_free(__u32 i, void *opaque)
{
    struct alloc_search *s = opaque;
    __u32 key = s->start + i;
    if (key > s->capacity) key -= s->capacity;
    /* On a -B port, client and AC namespaces can overlap. Never allocate
     * an indistinguishable (interface, peer MAC, SID) tuple. */
    struct rb_key probe = s->client;
    probe.sid = bpf_htons(key);
    struct rb_index *entry = bpf_map_lookup_elem(&ac_index, &probe);
    if (entry) {
        struct rb_index index = *entry;
        struct rb_slot *other = bpf_map_lookup_elem(&slots, &index.slot);
        int occupied = 0;
        if (other) {
            bpf_spin_lock(&other->lock);
            occupied = other->pair.active == 1 && other->pair.generation == index.generation &&
                       key_equal(&probe, &other->pair.server);
            bpf_spin_unlock(&other->lock);
        }
        if (occupied) return 0;
    }
    struct rb_slot *slot = bpf_map_lookup_elem(&slots, &key);
    if (!slot) return 0;
    bpf_spin_lock(&slot->lock);
    if (!slot->pair.active) {
        s->old = slot->pair;
        slot->pair.active = 2;
        s->found = key;
    }
    bpf_spin_unlock(&slot->lock);
    return s->found ? 1 : 0;
}

/* Only PADS creators take this non-waiting transaction gate. Data and PADT
 * never take it. A simultaneous PADS is dropped and counted, so the client
 * retries PADR. No map helper is called while holding a BPF spin lock. */
__noinline int create_pair(struct rb_config *cfg, struct rb_pair *pair)
{
    __u32 zero = 0;
    struct rb_allocator *a = bpf_map_lookup_elem(&allocator, &zero);
    struct rb_index *entry, index = {};
    struct rb_pair existing = {};
    struct alloc_search search = {};
    struct rb_slot *slot;
    int result = -1;
    if (!cfg || !pair) return -1;
    if (!a) return -1;
    if (__sync_val_compare_and_swap(&a->busy, 0, 1)) {
        count(RB_BUSY);
        return -2;
    }
    if (lookup_pair(&pair->server, RB_CLIENT, &existing, 0)) goto unlock;
    if (lookup_pair(&pair->server, RB_SERVER, &existing, 0)) {
        if (pair->client.ifindex == existing.client.ifindex &&
            mac_equal(pair->client.mac, existing.client.mac)) {
            pair->client.sid = existing.client.sid;
            count(RB_DUPLICATE);
            result = 0;
        }
        goto unlock;
    }
    search.capacity = cfg->capacity;
    search.client = pair->client;
    if (!search.capacity || search.capacity > RB_SESSIONS) goto unlock;
    search.start = a->cursor + 1;
    if (search.start > search.capacity) search.start = 1;
    bpf_loop(search.capacity, find_free, &search, 0);
    if (!search.found) { count(RB_FULL); result = -3; goto unlock; }
    slot = bpf_map_lookup_elem(&slots, &search.found);
    if (!slot) goto unlock;
    /* A stale slot must not delete an index subsequently assigned elsewhere. */
    entry = bpf_map_lookup_elem(&ac_index, &search.old.server);
    if (entry && entry->slot == search.found && entry->generation == search.old.generation)
        bpf_map_delete_elem(&ac_index, &search.old.server);
    a->cursor = search.found;
    index.slot = search.found;
    index.generation = ++a->generation;
    pair->client.sid = bpf_htons(search.found);
    pair->generation = index.generation;
    pair->active = 1;
    /* Existing entries here refer only to inactive slots. Creators serialize. */
    if (bpf_map_update_elem(&ac_index, &pair->server, &index, BPF_ANY)) {
        bpf_spin_lock(&slot->lock);
        slot->pair.active = 0;
        bpf_spin_unlock(&slot->lock);
        goto unlock;
    }
    bpf_spin_lock(&slot->lock);
    slot->pair = *pair;
    bpf_spin_unlock(&slot->lock);
    count(RB_CREATED);
    result = 0;
unlock:
    __sync_val_compare_and_swap(&a->busy, 1, 0);
    return result;
}

struct tag_scan {
    struct rb_scratch *s;
    __u32 pos, end, relay, host, host_size, bad;
};
static long scan_tag(__u32 unused, void *opaque)
{
    struct tag_scan *c = opaque;
    __u32 p = c->pos, n, kind;
    (void)unused;
    if (p == c->end) return 1;
    if (p > RB_FRAME - 4 || p + 4 > c->end) { c->bad = 1; return 1; }
    kind = ((__u32)c->s->in[p] << 8) | c->s->in[p + 1];
    n = ((__u32)c->s->in[p + 2] << 8) | c->s->in[p + 3];
    if (p + 4 + n > c->end) { c->bad = 1; return 1; }
    if (!kind) {
        if (n) c->bad = 1;
        c->pos = c->end;
        return 1;
    }
    if (kind == 0x0110) {
        if (c->relay) { c->bad = 1; return 1; }
        c->relay = p;
    }
    if (kind == 0x0103) { c->host = p; c->host_size = n + 4; }
    c->pos = p + 4 + n;
    return 0;
}
struct copy_ctx { struct rb_scratch *s; __u32 length, at; int delta; };
static long copy_frame(__u32 i, void *opaque)
{
    struct copy_ctx *c = opaque;
    __u32 src = i;
    if (i >= c->length || i >= RB_FRAME) return 1;
    if (i >= c->at) {
        if (c->delta > 0 && i < c->at + RB_TAG_SIZE) return 0;
        src = i - c->delta;
    }
    if (src < RB_FRAME) c->s->out[i] = c->s->in[src];
    return 0;
}
static __always_inline int emit(struct __sk_buff *skb, struct rb_scratch *s,
                               __u32 length, __u32 ifindex)
{
    if (length < 20 || length > RB_FRAME) return error();
    if (bpf_skb_change_tail(skb, length, 0) ||
        bpf_skb_store_bytes(skb, 0, s->out, length, BPF_F_INVALIDATE_HASH)) return error();
    count(RB_DISCOVERY);
    return bpf_redirect(ifindex, 0);
}

struct host_copy { struct rb_scratch *s; __u32 from, length; };
static long copy_host(__u32 i, void *opaque)
{
    struct host_copy *c = opaque;
    __u32 src = c->from + i, dst = 20 + i;
    if (i >= c->length || src >= RB_FRAME || dst >= RB_FRAME) return 1;
    c->s->out[dst] = c->s->in[src];
    return 0;
}

/* A full table rejects this new session at both ends, using this incoming
 * skb. It never evicts an established session to accommodate another one. */
static __noinline int capacity_error(struct __sk_buff *skb, struct rb_scratch *s,
                                    struct rb_config *cfg, struct tag_scan *scan,
                                    __u32 target)
{
    struct rb_packet *original = (void *)s->in, *out = (void *)s->out;
    struct host_copy copy = { .s = s, .from = scan->host, .length = scan->host_size };
    const char message[] = "Relay capacity exhausted";
    __u32 length = 20 + copy.length + 4 + sizeof(message) - 1;
    if (target >= RB_INTERFACES || length > RB_FRAME) return error();
    /* First terminate the AC-side session which could not be represented. */
    *out = *original;
    __builtin_memcpy(out->dst, original->src, 6);
    __builtin_memcpy(out->src, original->dst, 6);
    out->code = 0xa7; out->length = 0;
    if (bpf_skb_change_tail(skb, 20, 0) ||
        bpf_skb_store_bytes(skb, 0, out, 20, BPF_F_INVALIDATE_HASH)) return error();
    if (bpf_clone_redirect(skb, skb->ifindex, 0)) count(RB_ERROR);
    /* The original PADS relay tag still identifies the client in scratch. */
    __u32 at = scan->relay;
    if (at > RB_FRAME - RB_TAG_SIZE) return error();
    __builtin_memcpy(out->dst, &s->in[at + 20], 6);
    __builtin_memcpy(out->src, cfg->interfaces[target].mac, 6);
    out->code = 0x65; out->sid = 0; out->length = bpf_htons(length - 20);
    bpf_loop(RB_FRAME, copy_host, &copy, 0);
    if (copy.length > RB_FRAME - 20 - 4 - (sizeof(message) - 1)) return error();
    __u32 pos = 20 + copy.length;
    if (pos > RB_FRAME - 4 - (sizeof(message) - 1)) return error();
    s->out[pos] = 2; s->out[pos + 1] = 3; /* Generic-Error */
    s->out[pos + 2] = 0; s->out[pos + 3] = sizeof(message) - 1;
    __builtin_memcpy(&s->out[pos + 4], message, sizeof(message) - 1);
    return emit(skb, s, length, cfg->interfaces[target].ifindex);
}

/* The relay tag is opaque to clients: magic, per-load random cookie, interface
 * array index and peer MAC. Cookie separates local/foreign Discovery replies;
 * it is not authentication against an on-link client which can observe it. */
static __always_inline void put_tag(struct rb_scratch *s, __u32 at,
                                   __u64 cookie, __u32 port, const __u8 *mac)
{
    if (at > RB_FRAME - RB_TAG_SIZE) return;
    s->out[at] = 1; s->out[at + 1] = 0x10;
    s->out[at + 2] = 0; s->out[at + 3] = RB_TAG_DATA;
    __u32 magic = bpf_htonl(0x52425031), wire_port = bpf_htonl(port);
    __builtin_memcpy(&s->out[at + 4], &magic, 4);
    __builtin_memcpy(&s->out[at + 8], &cookie, 8);
    __builtin_memcpy(&s->out[at + 16], &wire_port, 4);
    __builtin_memcpy(&s->out[at + 20], mac, 6);
}

__noinline int discovery(struct __sk_buff *skb, struct rb_config *cfg,
                               __u32 port, struct rb_packet *header)
{
    if (!cfg || !header || port >= RB_INTERFACES) return invalid();
    __u32 zero = 0, target = 0, length = 20 + bpf_ntohs(header->length);
    __u64 cookie;
    __u32 magic;
    __u8 peer[6];
    struct rb_scratch *s = bpf_map_lookup_elem(&scratch, &zero);
    struct rb_iface *in = &cfg->interfaces[port];
    struct rb_packet *out;
    struct tag_scan scan = {};
    struct copy_ctx copy = {};
    if (!s || length > RB_FRAME || length < 20) return invalid();
    if (bpf_skb_load_bytes(skb, 0, s->in, length)) return invalid();
    scan.s = s; scan.pos = 20; scan.end = length;
    bpf_loop(RB_FRAME / 4, scan_tag, &scan, 0);
    if (scan.bad || scan.pos != scan.end) return invalid();
    copy.s = s; copy.length = length; copy.at = RB_FRAME;
    if (header->code == 0x09) {
        const __u8 broadcast[6] = {255,255,255,255,255,255};
        if (!(in->roles & RB_CLIENT) || !mac_equal(header->dst, broadcast)) return pass();
        if (header->sid || (header->src[0] & 1) || scan.relay || length > RB_FRAME - RB_TAG_SIZE)
            return invalid();
        copy.length += RB_TAG_SIZE; copy.at = 20; copy.delta = RB_TAG_SIZE;
        bpf_loop(RB_FRAME, copy_frame, &copy, 0);
        put_tag(s, 20, cfg->cookie, port, header->src);
        out = (void *)s->out;
        out->length = bpf_htons(copy.length - 20);
        if (bpf_skb_change_tail(skb, copy.length, 0)) return error();
        for (__u32 i = 0; i < RB_INTERFACES; i++) {
            if (i >= cfg->count) break;
            if (i == port || !(cfg->interfaces[i].roles & RB_SERVER)) continue;
            __builtin_memcpy(out->src, cfg->interfaces[i].mac, 6);
            if (bpf_skb_store_bytes(skb, 0, s->out, copy.length, BPF_F_INVALIDATE_HASH) ||
                bpf_clone_redirect(skb, cfg->interfaces[i].ifindex, 0)) count(RB_ERROR);
        }
        count(RB_DISCOVERY);
        return TC_ACT_SHOT; /* only the clones leave */
    }
    if (!mac_equal(header->dst, in->mac) || !scan.relay) return pass();
    __u32 at = scan.relay;
    if (at > RB_FRAME - RB_TAG_SIZE || at + RB_TAG_SIZE > length) return pass();
    if (s->in[at + 2] || s->in[at + 3] != RB_TAG_DATA) return pass();
    __builtin_memcpy(&magic, &s->in[at + 4], 4);
    __builtin_memcpy(&cookie, &s->in[at + 8], 8);
    if (magic != bpf_htonl(0x52425031) || cookie != cfg->cookie) return pass();
    __builtin_memcpy(&target, &s->in[at + 16], 4);
    target = bpf_ntohl(target);
    __builtin_memcpy(peer, &s->in[at + 20], 6);
    if (target >= RB_INTERFACES || target >= cfg->count || target == port ||
        (peer[0] & 1) || (header->src[0] & 1)) return invalid();
    /* Older verifiers lose the subregister bound across a spilled reload.
     * Keep the bound explicit at the actual indexed map access. */
    barrier_var(target);
    target &= RB_INTERFACES - 1;
    struct rb_iface *egress = &cfg->interfaces[target];
    if (header->code == 0x19) {
        if (!(in->roles & RB_CLIENT) || !(egress->roles & RB_SERVER) || header->sid) return invalid();
    } else {
        if (!(in->roles & RB_SERVER) || !(egress->roles & RB_CLIENT)) return invalid();
        if (header->code == 0x07 && header->sid) return invalid();
    }
    if (header->code == 0x65) {
        if (header->sid) {
            struct rb_pair pair = {};
            pair.server.ifindex = in->ifindex; pair.server.sid = header->sid;
            pair.client.ifindex = egress->ifindex;
            __builtin_memcpy(pair.server.mac, header->src, 6);
            __builtin_memcpy(pair.client.mac, peer, 6);
            __builtin_memcpy(pair.client_local, egress->mac, 6);
            __builtin_memcpy(pair.server_local, in->mac, 6);
            int result = create_pair(cfg, &pair);
            if (result == -3) return capacity_error(skb, s, cfg, &scan, target);
            if (result) return error();
            header->sid = pair.client.sid;
        }
        copy.length -= RB_TAG_SIZE; copy.at = at; copy.delta = -RB_TAG_SIZE;
    }
    bpf_loop(RB_FRAME, copy_frame, &copy, 0);
    if (header->code != 0x65) put_tag(s, at, cfg->cookie, port, header->src);
    out = (void *)s->out;
    __builtin_memcpy(out->dst, peer, 6);
    __builtin_memcpy(out->src, egress->mac, 6);
    out->sid = header->sid;
    out->length = bpf_htons(copy.length - 20);
    return emit(skb, s, copy.length, egress->ifindex);
}

static __noinline int forward_session(struct __sk_buff *skb, struct rb_packet *header,
                                      __u32 roles, int closing)
{
    __u32 zero = 0;
    struct rb_key key = { .ifindex = skb->ifindex, .sid = header->sid };
    struct rb_pair pair = {};
    __builtin_memcpy(key.mac, header->src, 6);
    int side = lookup_pair(&key, roles, &pair, closing);
    if (!side) return pass();
    __u32 output;
    if (side == RB_CLIENT) {
        output = pair.server.ifindex; header->sid = pair.server.sid;
        __builtin_memcpy(header->src, pair.server_local, 6);
        __builtin_memcpy(header->dst, pair.server.mac, 6);
    } else {
        output = pair.client.ifindex; header->sid = pair.client.sid;
        __builtin_memcpy(header->src, pair.client_local, 6);
        __builtin_memcpy(header->dst, pair.client.mac, 6);
    }
    __u32 length = 20 + bpf_ntohs(header->length);
    if (skb->len != length && bpf_skb_change_tail(skb, length, 0)) return error();
    if (bpf_skb_store_bytes(skb, 0, header, sizeof(*header), BPF_F_INVALIDATE_HASH)) return error();
    struct rb_totals *t = bpf_map_lookup_elem(&totals, &zero);
    if (t) { t->value[closing ? RB_PADT : RB_SESSION]++; t->value[RB_BYTES] += length; }
    return bpf_redirect(output, 0);
}

SEC("tc/ingress")
int pppoe_relay(struct __sk_buff *skb)
{
    __u32 zero = 0, port = RB_INTERFACES;
    struct rb_config *cfg = bpf_map_lookup_elem(&config, &zero);
    struct rb_packet header;
    if (!cfg || !cfg->enabled) return TCX_NEXT;
    if (bpf_skb_load_bytes(skb, 0, &header, sizeof(header))) return pass();
    if (header.proto != bpf_htons(0x8863) && header.proto != bpf_htons(0x8864)) return pass();
    /* Attach to the logical VLAN interface, not its trunk. */
    if (skb->vlan_present) return pass();
    for (__u32 i = 0; i < RB_INTERFACES; i++) {
        if (i < cfg->count && cfg->interfaces[i].ifindex == skb->ifindex) { port = i; break; }
    }
    if (port >= RB_INTERFACES) return pass();
    if (header.version != 0x11 || 20 + (__u32)bpf_ntohs(header.length) > skb->len) return invalid();
    if (header.proto == bpf_htons(0x8863) &&
        (header.code == 0x09 || header.code == 0x07 || header.code == 0x19 || header.code == 0x65))
        return discovery(skb, cfg, port, &header);
    int closing = header.proto == bpf_htons(0x8863) && header.code == 0xa7;
    if (!closing && (header.proto != bpf_htons(0x8864) || header.code)) return pass();
    if (!mac_equal(header.dst, cfg->interfaces[port].mac)) return pass();
    return forward_session(skb, &header, cfg->interfaces[port].roles, closing);
}
char LICENSE[] SEC("license") = "GPL";
