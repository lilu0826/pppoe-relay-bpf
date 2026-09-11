/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "relay.h"
#include "fastpath.h"
#include "bpf/fastpath_shared.h"
#include "bpf/pppoe_fastpath.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

static struct pppoe_fastpath_bpf *obj;
static struct bpf_link *links[MAX_INTERFACES];
static const PPPoEInterface *interfaces;
static unsigned int indices[MAX_INTERFACES];
static int carrier_seen[MAX_INTERFACES];
static int count, debug_log, foreground_log, cpus;
static int ioctl_fd = -1, route_fd = -1;
static unsigned int generation;
static struct fastpath_stats *cpu_activity;
static struct fastpath_totals *cpu_totals;
static __u64 last_report;
static __u64 last_poll;
extern PPPoESession *ActiveSessions;
extern volatile unsigned int Epoch;

static void log_message(int level, const char *fmt, ...)
{
    va_list ap;
    char message[512];
    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    syslog(level, "%s", message);
    if (foreground_log) fprintf(stderr, "%s\n", message);
}

static __u64 now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void report_stats(void)
{
    __u32 zero = 0;
    struct fastpath_totals sum = {0};
    int i;
    if (!obj || !cpu_totals) return;
    if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.totals), &zero, cpu_totals)) return;
    for (i = 0; i < cpus; i++) {
        sum.packets += cpu_totals[i].packets;
        sum.bytes += cpu_totals[i].bytes;
        sum.misses += cpu_totals[i].misses;
        sum.errors += cpu_totals[i].errors;
    }
    log_message(LOG_INFO, "FASTPATH STATS packets=%llu bytes=%llu miss=%llu errors=%llu",
                (unsigned long long)sum.packets, (unsigned long long)sum.bytes,
                (unsigned long long)sum.misses, (unsigned long long)sum.errors);
}

void fastpath_cleanup(void)
{
    int i;
    __u32 zero = 0;
    __u64 disabled = 0;
    if (obj) {
        /* Invalidate before detach; links are not pinned and close on SIGKILL too. */
        int fd = bpf_map__fd(obj->maps.lease);
        if (fd >= 0) (void)bpf_map_update_elem(fd, &zero, &disabled, BPF_ANY);
        report_stats();
    }
    for (i = 0; i < MAX_INTERFACES; i++) {
        bpf_link__destroy(links[i]);
        links[i] = NULL;
    }
    pppoe_fastpath_bpf__destroy(obj);
    obj = NULL;
    if (route_fd >= 0) close(route_fd);
    if (ioctl_fd >= 0) close(ioctl_fd);
    route_fd = ioctl_fd = -1;
    free(cpu_activity);
    free(cpu_totals);
    cpu_activity = NULL;
    cpu_totals = NULL;
}

static void fallback(const char *operation, int error)
{
    PPPoESession *s;
    /* A map/monitor failure can prevent the last activity read. Give formerly
     * accelerated sessions one full idle interval to resume on userspace. */
    for (s = ActiveSessions; s; s = s->next)
        if (s->fp_active) s->epoch = Epoch;
    log_message(LOG_WARNING, "FASTPATH FALLBACK: %s: %s; continuing userspace relay",
                operation, strerror(error > 0 ? error : EIO));
    fastpath_cleanup();
}

/* Read live ifindex/MAC, never assume the relay tag's array index is an ifindex. */
static int interface_matches(int n, int initializing)
{
    struct ifreq req = {0};
    size_t length = strnlen(interfaces[n].name, IFNAMSIZ);
    if (length >= IFNAMSIZ) return 0;
    memcpy(req.ifr_name, interfaces[n].name, length);
    if (ioctl(ioctl_fd, SIOCGIFINDEX, &req)) {
        log_message(LOG_WARNING, "FASTPATH interface %s index query: %s", req.ifr_name, strerror(errno));
        return 0;
    }
    if (initializing) indices[n] = req.ifr_ifindex;
    else if (indices[n] != (unsigned int)req.ifr_ifindex) return 0;
    if (ioctl(ioctl_fd, SIOCGIFFLAGS, &req)) return 0;
    /* veth/bridge can be administratively UP while asynchronous linkwatch has
     * not yet set IFF_RUNNING. Attach with empty maps during that startup window;
     * after carrier has been observed, losing it invalidates old sessions. */
    if (!(req.ifr_flags & IFF_UP) ||
        (!initializing && carrier_seen[n] && !(req.ifr_flags & IFF_RUNNING))) {
        log_message(LOG_WARNING, "FASTPATH interface %s not running: flags=0x%x",
                    req.ifr_name, (unsigned short)req.ifr_flags);
        return 0;
    }
    if (req.ifr_flags & IFF_RUNNING) carrier_seen[n] = 1;
    if (ioctl(ioctl_fd, SIOCGIFHWADDR, &req)) return 0;
    if (memcmp(req.ifr_hwaddr.sa_data, interfaces[n].mac, ETH_ALEN)) {
        log_message(LOG_WARNING, "FASTPATH interface %s MAC changed", req.ifr_name);
        return 0;
    }
    return 1;
}

static unsigned int interface_index(const PPPoEInterface *iface)
{
    int i;
    for (i = 0; i < count; i++)
        if (iface == &interfaces[i]) return indices[i];
    return 0;
}

int fastpath_enabled(void) { return obj != NULL; }
int fastpath_event_fd(void) { return route_fd; }

int fastpath_init(const PPPoEInterface *ifs, int n, int max_sessions, int debug, int foreground)
{
    int i, err;
    struct sockaddr_nl addr = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK };
    __u32 zero = 0;
    __u64 deadline;
    debug_log = debug;
    foreground_log = foreground;
    interfaces = ifs;
    count = n;
    if (n < 2 || n > MAX_INTERFACES || max_sessions < 1 || max_sessions > 65534) {
        fallback("invalid interface/session configuration", EINVAL);
        return 0;
    }
    ioctl_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    route_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (ioctl_fd < 0 || route_fd < 0 || route_fd >= FD_SETSIZE ||
        bind(route_fd, (struct sockaddr *)&addr, sizeof(addr))) {
        fallback("link monitor", errno);
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (!interface_matches(i, 1)) {
            fallback("interface down or MAC changed", ENODEV);
            return 0;
        }
    }
    cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) { fallback("possible CPUs", EINVAL); return 0; }
    cpu_activity = calloc((size_t)cpus, sizeof(*cpu_activity));
    cpu_totals = calloc((size_t)cpus, sizeof(*cpu_totals));
    if (!cpu_activity || !cpu_totals) { fallback("statistics allocation", ENOMEM); return 0; }
    obj = pppoe_fastpath_bpf__open();
    if (!obj) { fallback("BPF object open", errno); return 0; }
    err = bpf_map__set_max_entries(obj->maps.sessions, (unsigned int)max_sessions * 2);
    if (!err) err = bpf_map__set_max_entries(obj->maps.states, max_sessions + 1);
    if (!err) err = bpf_map__set_max_entries(obj->maps.activity, max_sessions + 1);
    if (err) { fallback("map sizing", -err); return 0; }
    bpf_program__set_expected_attach_type(obj->progs.pppoe_fastpath, BPF_TCX_INGRESS);
    err = pppoe_fastpath_bpf__load(obj);
    if (err) { fallback("BPF load (requires BPF privileges)", -err); return 0; }
    for (i = 0; i < count; i++) {
        struct bpf_link *link = bpf_program__attach_tcx(obj->progs.pppoe_fastpath, indices[i], NULL);
        err = (int)libbpf_get_error(link);
        if (!link || err) {
            fallback("TC ingress attach (requires Linux 6.6+ TCX)", err ? -err : errno);
            return 0;
        }
        links[i] = link;
    }
    deadline = now_ns() + FP_LEASE_NS;
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.lease), &zero, &deadline, BPF_ANY)) {
        fallback("lease update", errno);
        return 0;
    }
    log_message(LOG_INFO, "Fastpath: TC/eBPF enabled (TCX ingress, unpinned links)");
    for (i = 0; i < count; i++)
        log_message(LOG_INFO, "FASTPATH INTERFACE %s(%u)", interfaces[i].name, indices[i]);
    return 1;
}

static void make_direction(const SessionHash *in, struct fastpath_key *key,
                           struct fastpath_value *value, __u32 slot, __u32 gen)
{
    const SessionHash *out = in->peer;
    memset(key, 0, sizeof(*key));
    memset(value, 0, sizeof(*value));
    key->ifindex = interface_index(in->interface);
    key->sid = in->sesNum;
    memcpy(key->peer_mac, in->peerMac, ETH_ALEN);
    /* Production attaches to the registered logical interface. VLAN netdevs
     * have already decapsulated here; raw tagged trunk entries aren't guessed. */
    value->egress_ifindex = interface_index(out->interface);
    value->new_sid = out->sesNum;
    value->slot = slot;
    value->generation = gen;
    memcpy(value->src_mac, out->interface->mac, ETH_ALEN);
    memcpy(value->dst_mac, out->peerMac, ETH_ALEN);
    memcpy(value->ingress_dst, in->interface->mac, ETH_ALEN);
}

static void log_session(const char *event, const PPPoESession *s)
{
    const SessionHash *c = s->clientHash, *a = s->acHash;
    if (!debug_log) return;
    log_message(LOG_INFO,
        "FASTPATH %s client=%s(%u) peer=%02x:%02x:%02x:%02x:%02x:%02x sid=0x%04x "
        "server=%s(%u) peer=%02x:%02x:%02x:%02x:%02x:%02x sid=0x%04x generation=%u",
        event, c->interface->name, interface_index(c->interface),
        c->peerMac[0], c->peerMac[1], c->peerMac[2], c->peerMac[3], c->peerMac[4], c->peerMac[5],
        ntohs(c->sesNum), a->interface->name, interface_index(a->interface),
        a->peerMac[0], a->peerMac[1], a->peerMac[2], a->peerMac[3], a->peerMac[4], a->peerMac[5],
        ntohs(a->sesNum), s->fp_generation);
}

void fastpath_add_session(PPPoESession *s)
{
    struct fastpath_key keys[2];
    struct fastpath_value values[2];
    struct fastpath_state state = {0};
    __u32 slot = ntohs(s->sesNum);
    int fd;
    if (!obj || s->fp_active) return;
    if (++generation == 0) { fallback("generation exhausted", EOVERFLOW); return; }
    make_direction(s->clientHash, &keys[0], &values[0], slot, generation);
    make_direction(s->acHash, &keys[1], &values[1], slot, generation);
    state.generation = generation;
    fd = bpf_map__fd(obj->maps.sessions);
    if (bpf_map_update_elem(fd, &keys[0], &values[0], BPF_NOEXIST) ||
        bpf_map_update_elem(fd, &keys[1], &values[1], BPF_NOEXIST)) {
        /* No state committed: neither entry can forward. Closing all links/maps
         * also guarantees rollback if an individual map delete would fail. */
        fallback("session map update", errno);
        return;
    }
    state.active = 1;
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.states), &slot, &state, BPF_ANY)) {
        fallback("session activation", errno);
        return;
    }
    s->fp_generation = generation;
    s->fp_active = 1;
    log_session("ADD", s);
}

void fastpath_del_session(PPPoESession *s)
{
    struct fastpath_key keys[2];
    struct fastpath_value unused;
    struct fastpath_state state = {0};
    __u32 slot = ntohs(s->sesNum);
    int fd;
    if (!s->fp_active) return;
    s->fp_active = 0;
    if (!obj) return;
    log_session("DEL", s);
    /* Disable both directions BEFORE removing either entry and freeing SID. */
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.states), &slot, &state, BPF_ANY)) {
        fallback("session deactivation", errno);
        return;
    }
    make_direction(s->clientHash, &keys[0], &unused, slot, s->fp_generation);
    make_direction(s->acHash, &keys[1], &unused, slot, s->fp_generation);
    fd = bpf_map__fd(obj->maps.sessions);
    if (bpf_map_delete_elem(fd, &keys[0]) || bpf_map_delete_elem(fd, &keys[1]))
        fallback("session map delete", errno);
}

void fastpath_tick(PPPoESession *active, unsigned int epoch)
{
    unsigned int invalid = 0;
    PPPoESession *s, *next;
    __u64 now, deadline;
    __u32 zero = 0;
    int i, size;
    union { struct nlmsghdr align; char bytes[16384]; } buffer;
    if (!obj) return;
    now = now_ns();
    /* Bound maintenance work even when fallback packets wake select often. */
    if (now && now - last_poll < 1000000000ULL) {
        char byte;
        if (recv(route_fd, &byte, 1, MSG_PEEK | MSG_DONTWAIT) < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    }
    last_poll = now;
    /* Consume events even if a link went down AND back up between ticks. */
    while ((size = recv(route_fd, buffer.bytes, sizeof(buffer.bytes), MSG_DONTWAIT)) > 0) {
        struct nlmsghdr *h;
        for (h = (struct nlmsghdr *)buffer.bytes; NLMSG_OK(h, size); h = NLMSG_NEXT(h, size)) {
            struct ifinfomsg *info;
            if (h->nlmsg_type == NLMSG_ERROR || h->nlmsg_type == NLMSG_OVERRUN) {
                fallback("link monitor lost events", ENOBUFS); return;
            }
            if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK) continue;
            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*info))) continue;
            info = NLMSG_DATA(h);
            for (i = 0; i < count; i++) {
                if (indices[i] == (unsigned int)info->ifi_index &&
                    (h->nlmsg_type == RTM_DELLINK || !(info->ifi_flags & IFF_UP) ||
                     (carrier_seen[i] && !(info->ifi_flags & IFF_RUNNING)))) invalid |= 1U << i;
                if (indices[i] == (unsigned int)info->ifi_index && (info->ifi_flags & IFF_RUNNING))
                    carrier_seen[i] = 1;
            }
        }
    }
    if (size < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        fallback("link monitor receive", errno); return;
    }
    for (i = 0; i < count; i++)
        if (!interface_matches(i, 0)) invalid |= 1U << i;
    if (invalid) {
        /* Detach globally before any old ifindex can be reused. Retire sessions
         * on changed interfaces; other sessions continue on the original path. */
        fallback("interface down/deleted/changed", ENODEV);
        for (s = active; s; s = next) {
            next = s->next;
            for (i = 0; i < count; i++) {
                if ((invalid & (1U << i)) &&
                    (s->clientHash->interface == &interfaces[i] || s->acHash->interface == &interfaces[i])) {
                    freeSession(s, "Fastpath interface changed");
                    break;
                }
            }
        }
        return;
    }
    now = now_ns();
    if (!now) { fallback("monotonic clock", EIO); return; }
    deadline = now + FP_LEASE_NS;
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.lease), &zero, &deadline, BPF_ANY)) {
        fallback("lease refresh", errno); return;
    }
    for (s = active; s; s = s->next) {
        __u32 slot = ntohs(s->sesNum);
        __u64 latest = 0, age;
        if (!s->fp_active) continue;
        if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.activity), &slot, cpu_activity)) {
            fallback("activity lookup", errno); return;
        }
        for (i = 0; i < cpus; i++)
            if (cpu_activity[i].generation == s->fp_generation && cpu_activity[i].last_seen_ns > latest)
                latest = cpu_activity[i].last_seen_ns;
        if (!latest) continue;
        age = now > latest ? (now - latest) / 1000000000ULL : 0;
        if (age < (unsigned int)(epoch - s->epoch))
            s->epoch = epoch - (unsigned int)age;
    }
    if (debug_log && now - last_report >= 10000000000ULL) {
        report_stats();
        last_report = now;
    }
}
