/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Lifecycle/configuration only: deliberately no PPPoE packet sockets. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf/relay_shared.h"
#include "bpf/pppoe_relay.skel.h"

static volatile sig_atomic_t stopping;
static bool debug;
static bool check_only;
static char names[RB_INTERFACES][IFNAMSIZ];
static bool carrier_seen[RB_INTERFACES];
static void stop(int sig) { (void)sig; stopping = 1; }
static int liblog(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !debug) return 0;
    return vfprintf(stderr, format, args);
}
static void usage(FILE *f)
{
    fprintf(f, "Usage: pppoe-relay-bpf -C client -S server [-C client2] [-B both]\n"
               "  -C IFACE    client-facing interface (repeatable)\n"
               "  -S IFACE    server-facing interface (repeatable)\n"
               "  -B IFACE    interface serving both roles (repeatable)\n"
               "  -n NUMBER   maximum sessions (1..65534, default 5000)\n"
               "  --debug     libbpf diagnostics and five-second counters\n"
               "  --check     verify configuration/BPF load, then exit without attaching\n"
               "  -h, --help  show this help\n"
               "Runs in foreground; no idle timeout. Linux 6.6+ TCX / libbpf 1.3+.\n");
}
static int number(const char *text, unsigned maximum, unsigned *result)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || !*text || *end || text[0] == '-' || n > maximum) return -1;
    *result = n;
    return 0;
}
static int iface(int fd, unsigned i, struct rb_iface *result, bool initial)
{
    struct ifreq req = {};
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", names[i]);
    if (ioctl(fd, SIOCGIFINDEX, &req)) return -1;
    unsigned index = req.ifr_ifindex;
    if (ioctl(fd, SIOCGIFFLAGS, &req)) return -1;
    if (!(req.ifr_flags & IFF_UP) || (carrier_seen[i] && !(req.ifr_flags & IFF_RUNNING))) {
        errno = ENETDOWN;
        return -1;
    }
    if (req.ifr_flags & IFF_RUNNING) carrier_seen[i] = true;
    if (ioctl(fd, SIOCGIFHWADDR, &req)) return -1;
    if (req.ifr_hwaddr.sa_family != ARPHRD_ETHER) { errno = EPROTONOSUPPORT; return -1; }
    if (!initial && (index != result->ifindex || memcmp(result->mac, req.ifr_hwaddr.sa_data, 6))) {
        errno = ESTALE;
        return -1;
    }
    result->ifindex = index;
    memcpy(result->mac, req.ifr_hwaddr.sa_data, 6);
    return 0;
}
static void stats(struct pppoe_relay_bpf *obj, struct rb_totals *cpu, int ncpu)
{
    __u32 zero = 0;
    struct rb_totals sum = {};
    if (bpf_map_lookup_elem(bpf_map__fd(obj->maps.totals), &zero, cpu)) return;
    for (int c = 0; c < ncpu; c++)
        for (int k = 0; k < RB_COUNTERS; k++) sum.value[k] += cpu[c].value[k];
    fprintf(stderr, "BPF RELAY stats: session=%llu bytes=%llu discovery=%llu padt=%llu "
            "created=%llu duplicate=%llu full=%llu busy=%llu invalid=%llu error=%llu pass=%llu\n",
            (unsigned long long)sum.value[RB_SESSION], (unsigned long long)sum.value[RB_BYTES],
            (unsigned long long)sum.value[RB_DISCOVERY], (unsigned long long)sum.value[RB_PADT],
            (unsigned long long)sum.value[RB_CREATED], (unsigned long long)sum.value[RB_DUPLICATE],
            (unsigned long long)sum.value[RB_FULL], (unsigned long long)sum.value[RB_BUSY],
            (unsigned long long)sum.value[RB_INVALID], (unsigned long long)sum.value[RB_ERROR],
            (unsigned long long)sum.value[RB_PASS]);
}
int main(int argc, char **argv)
{
    struct rb_config cfg = { .capacity = 5000 };
    struct pppoe_relay_bpf *obj = NULL;
    struct bpf_link *links[RB_INTERFACES] = {};
    struct rb_totals *cpu = NULL;
    struct sockaddr_nl address = { .nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK };
    struct option options[] = {{"debug", no_argument, NULL, 'd'}, {"help", no_argument, NULL, 'h'},
                               {"check", no_argument, NULL, 256}, {0}};
    int opt, fd = -1, nl = -1, lockfd = -1, result = 1, ncpu = 0;
    unsigned n, clients = 0, servers = 0;
    __u32 zero = 0;
    while ((opt = getopt_long(argc, argv, "C:S:B:n:hd", options, NULL)) != -1) {
        switch (opt) {
        case 'C': case 'S': case 'B':
            if (cfg.count == RB_INTERFACES || !*optarg || strlen(optarg) >= IFNAMSIZ) goto bad_options;
            for (unsigned i = 0; i < cfg.count; i++)
                if (!strcmp(names[i], optarg)) goto bad_options;
            strcpy(names[cfg.count], optarg);
            cfg.interfaces[cfg.count++].roles = opt == 'C' ? RB_CLIENT : opt == 'S' ? RB_SERVER : RB_CLIENT | RB_SERVER;
            clients += opt != 'S'; servers += opt != 'C';
            break;
        case 'n':
            if (number(optarg, RB_SESSIONS, &n) || !n) goto bad_options;
            cfg.capacity = n;
            break;
        case 'd': debug = true; break;
        case 256: check_only = true; break;
        case 'h': usage(stdout); return 0;
        default: goto bad_options;
        }
    }
    if (optind != argc || !clients || !servers || cfg.count < 2) goto bad_options;
    signal(SIGTERM, stop); signal(SIGINT, stop);
    libbpf_set_print(liblog);
    struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &limit);
    /* One instance per network namespace. No persistent BPF maps or links. */
    struct stat ns;
    char lockname[128];
    if (stat("/proc/self/ns/net", &ns)) goto system_error;
    snprintf(lockname, sizeof(lockname), "/run/pppoe-relay-bpf-%llu.lock", (unsigned long long)ns.st_ino);
    if (!check_only) {
        lockfd = open(lockname, O_CREAT | O_CLOEXEC | O_RDWR | O_NOFOLLOW, 0600);
        if (lockfd < 0 || flock(lockfd, LOCK_EX | LOCK_NB)) goto system_error;
    }
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    nl = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0 || nl < 0 || bind(nl, (void *)&address, sizeof(address))) goto system_error;
    for (unsigned i = 0; i < cfg.count; i++) {
        if (iface(fd, i, &cfg.interfaces[i], true)) goto interface_error;
        for (unsigned j = 0; j < i; j++)
            if (cfg.interfaces[i].ifindex == cfg.interfaces[j].ifindex) goto bad_options;
    }
    if (getrandom(&cfg.cookie, sizeof(cfg.cookie), 0) != sizeof(cfg.cookie)) goto system_error;
    obj = pppoe_relay_bpf__open();
    if (!obj) goto system_error;
    if (bpf_map__set_max_entries(obj->maps.slots, cfg.capacity + 1) ||
        bpf_map__set_max_entries(obj->maps.ac_index, cfg.capacity)) goto system_error;
    bpf_program__set_expected_attach_type(obj->progs.pppoe_relay, BPF_TCX_INGRESS);
    if (pppoe_relay_bpf__load(obj)) goto system_error;
    if (check_only) {
        struct bpf_prog_info info = {};
        __u32 info_size = sizeof(info);
        if (bpf_prog_get_info_by_fd(bpf_program__fd(obj->progs.pppoe_relay), &info, &info_size))
            goto system_error;
        fprintf(stderr, "BPF RELAY check passed: %u interfaces, %u sessions, verified_insns=%u; no links attached\n",
                cfg.count, cfg.capacity, info.verified_insns);
        result = 0;
        goto out;
    }
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.config), &zero, &cfg, BPF_ANY)) goto system_error;
    for (unsigned i = 0; i < cfg.count; i++) {
        links[i] = bpf_program__attach_tcx(obj->progs.pppoe_relay, cfg.interfaces[i].ifindex, NULL);
        long err = libbpf_get_error(links[i]);
        if (err) { links[i] = NULL; errno = -err; goto system_error; }
        if (!links[i]) goto system_error;
    }
    /* All attachments exist before a single interface starts relaying. */
    cfg.enabled = 1;
    if (bpf_map_update_elem(bpf_map__fd(obj->maps.config), &zero, &cfg, BPF_ANY)) goto system_error;
    fprintf(stderr, "BPF RELAY enabled: %u interfaces, capacity=%u sessions; no packet receive sockets\n",
            cfg.count, cfg.capacity);
    ncpu = libbpf_num_possible_cpus();
    if (ncpu > 0) cpu = calloc(ncpu, sizeof(*cpu));
    time_t last = time(NULL);
    while (!stopping) {
        struct pollfd p = {.fd = nl, .events = POLLIN};
        int polled = poll(&p, 1, 1000);
        if (polled < 0 && errno != EINTR) goto system_error;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) goto interface_error;
        if (p.revents & POLLIN) {
            char buffer[8192];
            ssize_t size;
            while ((size = recv(nl, buffer, sizeof(buffer), MSG_DONTWAIT | MSG_TRUNC)) > 0) {
                if ((size_t)size > sizeof(buffer)) goto interface_error;
                int remaining = size;
                for (struct nlmsghdr *h = (void *)buffer; NLMSG_OK(h, remaining); h = NLMSG_NEXT(h, remaining)) {
                    if (h->nlmsg_type == NLMSG_ERROR || h->nlmsg_type == NLMSG_OVERRUN) goto interface_error;
                    if ((h->nlmsg_type != RTM_DELLINK && h->nlmsg_type != RTM_NEWLINK) ||
                        h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) continue;
                    struct ifinfomsg *info = NLMSG_DATA(h);
                    for (unsigned i = 0; i < cfg.count; i++) {
                        if ((unsigned)info->ifi_index != cfg.interfaces[i].ifindex) continue;
                        if (h->nlmsg_type == RTM_DELLINK || !(info->ifi_flags & IFF_UP) ||
                            (carrier_seen[i] && !(info->ifi_flags & IFF_RUNNING))) goto interface_error;
                        int bytes = IFLA_PAYLOAD(h);
                        for (struct rtattr *a = IFLA_RTA(info); RTA_OK(a, bytes); a = RTA_NEXT(a, bytes)) {
                            if (a->rta_type == IFLA_ADDRESS &&
                                (RTA_PAYLOAD(a) != 6 || memcmp(RTA_DATA(a), cfg.interfaces[i].mac, 6))) goto interface_error;
                            if (a->rta_type == IFLA_IFNAME &&
                                (RTA_PAYLOAD(a) != strlen(names[i]) + 1 ||
                                 memcmp(RTA_DATA(a), names[i], strlen(names[i]) + 1))) goto interface_error;
                        }
                    }
                }
            }
            if (size < 0 && errno != EAGAIN && errno != EINTR) goto system_error;
        }
        for (unsigned i = 0; i < cfg.count; i++)
            if (iface(fd, i, &cfg.interfaces[i], false)) goto interface_error;
        if (debug && cpu && time(NULL) - last >= 5) { stats(obj, cpu, ncpu); last = time(NULL); }
    }
    result = 0;
    goto out;
bad_options:
    usage(stderr);
    goto out;
interface_error:
    fprintf(stderr, "BPF RELAY: interface changed/unavailable; detaching; clients must redial.\n");
    goto out;
system_error:
    fprintf(stderr, "BPF RELAY: setup/runtime failure: %s; no userspace fallback.\n", strerror(errno));
out:
    if (obj && bpf_map__fd(obj->maps.config) >= 0) {
        cfg.enabled = 0;
        (void)bpf_map_update_elem(bpf_map__fd(obj->maps.config), &zero, &cfg, BPF_ANY);
    }
    for (unsigned i = 0; i < RB_INTERFACES; i++) bpf_link__destroy(links[i]);
    pppoe_relay_bpf__destroy(obj);
    free(cpu);
    if (nl >= 0) close(nl);
    if (fd >= 0) close(fd);
    if (lockfd >= 0) close(lockfd);
    return result;
}
