#!/usr/bin/env python3
"""Native relay tests. Root, Linux 6.6+, Python 3.12+, disposable netns only."""
import argparse
import json
import os
import re
from pathlib import Path
import signal
import struct
import time
from lab import (Lab, CLI, LAN, WAN, AC, AC2, DISC, SESS, frame, tag, tags,
                   receive, collect, command)


def handshake(lab, cd=None, client=CLI, local=LAN, ac=AC, sid=0x4567,
              offers=False, expect_full=False):
    cd = cd or lab.cd
    unique = b"native-host-uniq\x00\xff"
    service = tag(0x0101, b"")
    cd.send(frame(b"\xff" * 6, client, DISC, 9, 0, service + tag(0x0103, unique)))
    padi = receive(lab.ad, lambda p: p[15] == 9 and p[6:12] == WAN)
    rt = next(v for k, v in tags(padi) if k == 0x0110)
    assert len(rt) == 22 and dict(tags(padi))[0x0103] == unique
    for mac, name in ([(AC, b"BRAS-A"), (AC2, b"BRAS-B")] if offers else [(ac, b"BRAS")]):
        offer = service + tag(0x0102, name) + tag(0x0104, mac + b"cookie") + tag(0x0103, unique) + tag(0x0110, rt)
        lab.ad.send(frame(WAN, mac, DISC, 7, 0, offer))
        pado = receive(cd, lambda p: p[15] == 7 and p[:6] == client)
        assert pado[6:12] == local
        assert dict(tags(pado))[0x0102] == name
        if mac == ac:
            selected = pado
    collect(lab.ad, .03)
    cd.send(frame(local, client, DISC, 0x19, 0, selected[20:]))
    padr = receive(lab.ad, lambda p: p[15] == 0x19)
    assert padr[:6] == ac and padr[6:12] == WAN
    assert dict(tags(padr))[0x0104] == ac + b"cookie"
    pads = frame(WAN, ac, DISC, 0x65, sid, padr[20:])
    lab.ad.send(pads)
    reply = receive(cd, lambda p: p[15] == 0x65 and p[:6] == client)
    mapped = struct.unpack_from("!H", reply, 16)[0]
    assert dict(tags(reply))[0x0103] == unique
    assert 0x0110 not in dict(tags(reply))
    if expect_full:
        assert mapped == 0 and 0x0203 in dict(tags(reply))
        padt = receive(lab.ad, lambda p: p[15] == 0xa7 and p[:6] == ac)
        assert struct.unpack_from("!H", padt, 16)[0] == sid
    elif sid:
        assert mapped
        # A burst of duplicate PADS must all refer to the same committed SID.
        for _ in range(8):
            lab.ad.send(pads)
        replies = [p for p in collect(cd, .3) if p[15] == 0x65]
        assert replies and all(p == reply for p in replies)
    else:
        assert not mapped
    return mapped


def no_packet_sockets(lab):
    pid = lab.proc.pid
    inodes = {line.split()[-1] for line in Path(f"/proc/{pid}/net/packet").read_text().splitlines()[1:]}
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        link = os.readlink(fd)
        assert not (link.startswith("socket:[") and link[8:-1] in inodes), link


def local_coexistence(lab):
    # A local pppd shares WAN's MAC, but has no relay tag or relay mapping.
    observer = lab.packet_socket(lab.r, lab.wan, DISC)
    for code in (7, 0x65, 0xa7):
        packet = frame(WAN, AC, DISC, code, 0 if code == 7 else 0x7ffe, tag(0x0103, b"local"))
        lab.ad.send(packet)
        assert receive(observer, lambda p: p == packet) == packet
    collect(lab.wan_observer, .02)
    packet = frame(WAN, AC, SESS, 0, 0x7ffe, b"\x00\x21LOCAL-PPP")
    lab.ass.send(packet)
    assert receive(lab.wan_observer, lambda p: p == packet) == packet
    assert not [p for p in collect(lab.cs) if b"LOCAL-PPP" in p]
    no_packet_sockets(lab)


def run(binary, results, topology):
    lab = Lab(topology, binary, results, extra_client=topology == "veth")
    try:
        no_packet_sockets(lab)
        local_coexistence(lab)
        # Two ACs advertise behind the same relay MAC. Choose the second.
        sid = handshake(lab, ac=AC2, offers=True)
        lab.burst(sid, acmac=AC2)
        sid2 = handshake(lab, ac=AC)  # same wire SID, different AC MAC
        assert sid != sid2
        lab.burst(sid2)
        lab.padt(sid, acmac=AC2)
        lab.burst(sid2)  # deleting one must not remove the other
        # Server-originated PADT, followed by duplicate PADT, is also safe.
        lab.ad.send(frame(WAN, AC, DISC, 0xa7, 0x4567))
        assert receive(lab.cd, lambda p: p[15] == 0xa7) == frame(CLI, LAN, DISC, 0xa7, sid2)
        lab.ad.send(frame(WAN, AC, DISC, 0xa7, 0x4567))
        lab.no_forward(sid2)
        assert handshake(lab, sid=0) == 0  # error PADS does not allocate
        active = [handshake(lab, sid=0x1000 + n) for n in range(8)]
        assert len(set(active)) == 8
        handshake(lab, sid=0x2000, expect_full=True)
        for n, mapped in enumerate(active):
            lab.burst(mapped, acsid=0x1000 + n, amount=2)
        lab.padt(active[0], acsid=0x1000)
        # Same client MAC on a second port must route to that port only.
        if topology == "veth":
            c2 = lab.packet_socket(lab.c, "cli2", DISC)
            s2 = lab.packet_socket(lab.c, "cli2", SESS)
            local2 = bytes.fromhex("020000000012")
            mapped = handshake(lab, cd=c2, client=CLI, local=local2, sid=0x3000)
            lab.ass.send(frame(WAN, AC, SESS, 0, 0x3000, b"\xc0\x21SECOND-PORT"))
            assert receive(s2, lambda p: b"SECOND-PORT" in p) == frame(CLI, local2, SESS, 0, mapped, b"\xc0\x21SECOND-PORT")
            assert not [p for p in collect(lab.cs) if b"SECOND-PORT" in p]
            s2.send(frame(local2, CLI, SESS, 0, mapped, b"\xc0\x21SECOND-UP"))
            assert receive(lab.ass, lambda p: b"SECOND-UP" in p) == frame(AC, WAN, SESS, 0, 0x3000, b"\xc0\x21SECOND-UP")
        else:
            mapped = handshake(lab, sid=0x3000)
            lab.burst(mapped, acsid=0x3000)
        local_coexistence(lab)
        lab.stop_and_check(signal.SIGKILL)
    finally:
        lab.close()
    lab.check_pcaps()
    print(f"PASS native {topology}", flush=True)


def lifecycle_and_both(binary, results):
    lab = Lab("both", binary, results, both_ports=True)
    try:
        # First session consumes client SID 1 and AC SID 2 on WAN/AC.
        first = handshake(lab, sid=2)
        assert first == 1
        # Reverse the client/server roles. Candidate client SID 2 on WAN/AC
        # is ambiguous with the first session and must be skipped.
        lab.ad.send(frame(b"\xff" * 6, AC, DISC, 9, 0, tag(0x0101, b"")))
        padi = receive(lab.cd, lambda p: p[15] == 9 and p[6:12] == LAN)
        lab.cd.send(frame(LAN, CLI, DISC, 7, 0, padi[20:]))
        pado = receive(lab.ad, lambda p: p[15] == 7 and p[:6] == AC)
        lab.ad.send(frame(WAN, AC, DISC, 0x19, 0, pado[20:]))
        padr = receive(lab.cd, lambda p: p[15] == 0x19 and p[:6] == CLI)
        lab.cd.send(frame(LAN, CLI, DISC, 0x65, 0x6000, padr[20:]))
        pads = receive(lab.ad, lambda p: p[15] == 0x65 and p[:6] == AC)
        assert struct.unpack_from("!H", pads, 16)[0] == 3
        lab.burst(first, acsid=2)
        # Interface events invalidate the whole backend, without stale links.
        lab.ip(lab.r, "link", "set", lab.lan, "address", "02:00:00:00:00:fe")
        assert lab.proc.wait(timeout=5) != 0
        assert "interface changed" in lab.log.read_text()
        collect(lab.lan_observer, .02)
        lab.no_forward(first)
        assert any(b"NEGATIVE" in p for p in collect(lab.lan_observer))
    finally:
        lab.close()
    lab.check_pcaps()
    print("PASS native -B tuple collision and interface teardown", flush=True)


def capacity_checks(binary, results):
    # The initial suite always loaded with -n 8. Exercise the real default
    # and upper bound too, and ensure --check works beside a running relay.
    lab = Lab("capacity", binary, results, capacity=None)
    records = []
    try:
        sid = handshake(lab)
        lab.burst(sid)
        extra = []
        for i in range(6):
            name = f"extra{i}"
            lab.ip(lab.r, "link", "add", name, "type", "dummy")
            lab.ip(lab.r, "link", "set", name, "up")
            extra += ["-C", name]
        for more in ([], extra):
            for capacity in (1, 8, None, 65534):
                args = ["-C", lab.lan, "-S", lab.wan] + more
                if capacity is not None:
                    args += ["-n", str(capacity)]
                checked = command("ip", "netns", "exec", lab.r, binary, "--check", *args)
                match = re.search(r"verified_insns=(\d+)", checked.stderr)
                assert match and "no links attached" in checked.stderr, checked.stderr
                # Reserve at least half the kernel's 1M verification budget;
                # different kernel versions prune different numbers of states.
                assert 0 < int(match[1]) < 500000, checked.stderr
                records.append({"interfaces": 8 if more else 2, "capacity": capacity or 5000,
                                "default": capacity is None, "verified_insns": int(match[1])})
        lab.burst(sid)
        no_packet_sockets(lab)
        lab.stop_and_check(signal.SIGTERM)
    finally:
        lab.close()
    lab.check_pcaps()
    (results / "capacity-checks.json").write_text(json.dumps(records, indent=2))
    print("PASS native default 5000 forwarding and --check matrix (1/8/5000/65534, 2/8 ports)", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("src/pppoe-relay-bpf"))
    parser.add_argument("--results", type=Path, default=Path("test-results"))
    parser.add_argument("--topology", choices=("veth", "bridge", "vlan", "vlan-ad", "all"), default="all")
    args = parser.parse_args()
    if os.geteuid() or not hasattr(os, "setns"):
        raise SystemExit("requires root and Linux Python 3.12+")
    binary, results = args.binary.resolve(), args.results.resolve()
    assert command(binary, "--help").returncode == 0
    for bad in (("-F",), ("-i", "0"), ("--fastpath",), ("-n", "0"), ("-C", "lo", "-C", "lo")):
        assert command(binary, *bad, check=False).returncode != 0
    for topology in (("veth", "bridge", "vlan", "vlan-ad") if args.topology == "all" else (args.topology,)):
        run(binary, results, topology)
    if args.topology == "all":
        lifecycle_and_both(binary, results)
        capacity_checks(binary, results)
    (results / "summary.json").write_text(json.dumps({"status": "passed", "kernel": os.uname().release}))


if __name__ == "__main__":
    main()
