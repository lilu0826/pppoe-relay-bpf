#!/usr/bin/env python3
"""Linux 6.6+, root, Python 3.12. Tests only disposable network namespaces.

Real PADI/PADO/PADR/PADS, protocol-specific AF_PACKET observers, byte-for-byte
session output checks and tcpdump PCAP duplicate checks. No ISP/pppd required.
"""
import argparse
import collections
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time
import uuid

DISC, SESS = 0x8863, 0x8864
CLI = bytes.fromhex("020000000001")
LAN = bytes.fromhex("020000000002")
WAN = bytes.fromhex("020000000003")
AC = bytes.fromhex("020000000004")
AC2 = bytes.fromhex("020000000005")


def command(*args, check=True):
    return subprocess.run(list(map(str, args)), check=check, capture_output=True, text=True)


def frame(dst, src, proto, code, sid, payload=b""):
    return dst + src + struct.pack("!HBBHH", proto, 0x11, code, sid, len(payload)) + payload


def canonical(packet):
    if len(packet) < 20:
        return packet
    return packet[:20 + struct.unpack_from("!H", packet, 18)[0]]


def tags(packet):
    result = []
    pos = 20
    packet = canonical(packet)
    while pos + 4 <= len(packet):
        kind, size = struct.unpack_from("!HH", packet, pos)
        value = packet[pos + 4:pos + 4 + size]
        assert len(value) == size
        result.append((kind, value))
        pos += 4 + size
    return result


def tag(kind, data):
    return struct.pack("!HH", kind, len(data)) + data


def receive(sock, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        packet = canonical(sock.recv(65535))
        if predicate(packet):
            return packet
    raise AssertionError("expected frame was not received")


def collect(sock, duration=0.15):
    packets = []
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        packets.append(canonical(sock.recv(65535)))
    return packets


def wait_log(path, marker, proc, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace")
        if marker in text:
            return
        if proc.poll() is not None:
            raise AssertionError(f"process exited {proc.returncode}: {text}")
        time.sleep(0.05)
    raise AssertionError(f"missing log {marker}: {path.read_text(errors='replace')}")


def pcap_packets(path):
    data = path.read_bytes()
    assert len(data) >= 24, f"empty capture {path}"
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    assert struct.unpack_from(endian + "I", data, 20)[0] == 1, "expected Ethernet pcap"
    pos = 24
    while pos < len(data):
        assert pos + 16 <= len(data)
        size = struct.unpack_from(endian + "I", data, pos + 8)[0]
        pos += 16
        assert pos + size <= len(data)
        yield canonical(data[pos:pos + size])
        pos += size


class Lab:
    def __init__(self, topology, binary, mode, results, idle=0):
        self.topology, self.mode = topology, mode
        prefix = "rpfp-" + uuid.uuid4().hex[:8]
        self.c, self.r, self.a = [prefix + suffix for suffix in ("c", "r", "a")]
        self.namespaces, self.sockets, self.captures = [], [], []
        self.proc = None
        self.logfile = None
        self.expected_pcaps = collections.Counter()
        self.serial = 0
        self.result = results / f"{topology}-{mode}"
        self.result.mkdir(parents=True, exist_ok=True)
        self.log = self.result / "relay.log"
        try:
            for ns in (self.c, self.r, self.a):
                command("ip", "netns", "add", ns)
                self.namespaces.append(ns)
                self.ip(ns, "link", "set", "lo", "up")
            self.ip(self.r, "link", "add", "lan", "type", "veth", "peer", "name", "cli", "netns", self.c)
            self.ip(self.r, "link", "add", "wan", "type", "veth", "peer", "name", "ac", "netns", self.a)
            for ns, dev, mac in ((self.c, "cli", CLI), (self.r, "lan", LAN),
                                 (self.r, "wan", WAN), (self.a, "ac", AC)):
                self.ip(ns, "link", "set", dev, "address", mac.hex(":"), "up")
            self.lan, self.wan, self.cli, self.ac = "lan", "wan", "cli", "ac"
            if topology == "bridge":
                self.ip(self.r, "link", "add", "br-lan", "type", "bridge", "stp_state", "0", "forward_delay", "0")
                self.ip(self.r, "link", "set", "br-lan", "address", LAN.hex(":"))
                self.ip(self.r, "link", "set", "lan", "master", "br-lan")
                self.ip(self.r, "link", "set", "br-lan", "up")
                self.lan = "br-lan"
            elif topology in ("vlan", "vlan-ad"):
                protocol = "802.1ad" if topology == "vlan-ad" else "802.1Q"
                for ns, dev, vid in ((self.c, "cli", 100), (self.r, "lan", 100),
                                     (self.r, "wan", 200), (self.a, "ac", 200)):
                    self.ip(ns, "link", "add", "link", dev, "name", dev + ".v", "type", "vlan",
                            "protocol", protocol, "id", str(vid))
                    self.ip(ns, "link", "set", dev + ".v", "up")
                self.lan, self.wan, self.cli, self.ac = "lan.v", "wan.v", "cli.v", "ac.v"
            self.cd = self.packet_socket(self.c, self.cli, DISC)
            self.cs = self.packet_socket(self.c, self.cli, SESS)
            self.ad = self.packet_socket(self.a, self.ac, DISC)
            self.ass = self.packet_socket(self.a, self.ac, SESS)
            # Same PF_PACKET/SOCK_RAW/protocol binding as upstream openInterface().
            self.lan_observer = self.packet_socket(self.r, self.lan, SESS)
            self.wan_observer = self.packet_socket(self.r, self.wan, SESS)
            for ns, dev, label in ((self.c, self.cli, "client"), (self.a, self.ac, "server")):
                pcap = self.result / f"{label}.pcap"
                log = self.result / f"tcpdump-{label}.log"
                output = log.open("w")
                proc = subprocess.Popen(["ip", "netns", "exec", ns, "tcpdump", "-n", "-U", "-s", "0",
                                         "-i", dev, "-Q", "in", "-w", str(pcap)],
                                        stdout=output, stderr=output, env={**os.environ, "LC_ALL": "C"})
                self.captures.append((proc, output, pcap))
                wait_log(log, "listening on", proc)
            args = ["ip", "netns", "exec", self.r]
            if mode == "failure":
                args += ["setpriv", "--bounding-set=-bpf,-sys_admin,-net_admin"]
            args += [str(binary), "-F", "-C", self.lan, "-S", self.wan, "-i", str(idle), "-n", "8"]
            if mode in ("fastpath", "failure", "stub"):
                args += ["--fastpath-debug"]
            self.logfile = self.log.open("w")
            # Save the kernel's link state next to the relay diagnostics.
            (self.result / "links.json").write_text(self.ip(self.r, "-j", "-d", "link", "show").stdout)
            self.proc = subprocess.Popen(args, stdout=self.logfile, stderr=self.logfile)
            if mode == "fastpath":
                wait_log(self.log, "Fastpath: TC/eBPF enabled", self.proc)
            elif mode in ("failure", "stub"):
                wait_log(self.log, "FASTPATH FALLBACK:", self.proc)
            else:
                time.sleep(0.2)
                assert self.proc.poll() is None
        except BaseException:
            self.close()
            raise

    @staticmethod
    def ip(ns, *args):
        return command("ip", "-n", ns, *args)

    def packet_socket(self, ns, iface, proto):
        original = os.open("/proc/self/ns/net", os.O_RDONLY)
        target = os.open("/var/run/netns/" + ns, os.O_RDONLY)
        try:
            os.setns(target, 0)
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
            sock.bind((iface, proto))
            sock.setblocking(False)
            self.sockets.append(sock)
            return sock
        finally:
            os.setns(original, 0)
            os.close(target)
            os.close(original)

    def discovery(self, acmac=AC, acsid=0x4567):
        self.cd.send(frame(b"\xff" * 6, CLI, DISC, 0x09, 0, tag(0x0101, b"")))
        padi = receive(self.ad, lambda p: p[15] == 0x09 and p[6:12] == WAN)
        relay_tag = next(value for kind, value in tags(padi) if kind == 0x0110)
        assert len(relay_tag) == 10
        self.ad.send(frame(WAN, acmac, DISC, 0x07, 0, tag(0x0110, relay_tag)))
        pado = receive(self.cd, lambda p: p[15] == 0x07 and p[:6] == CLI)
        assert pado[6:12] == LAN
        self.cd.send(frame(LAN, CLI, DISC, 0x19, 0, pado[20:]))
        padr = receive(self.ad, lambda p: p[15] == 0x19 and p[:6] == acmac)
        pads = frame(WAN, acmac, DISC, 0x65, acsid, padr[20:])
        self.ad.send(pads)
        reply = receive(self.cd, lambda p: p[15] == 0x65 and p[:6] == CLI)
        sid = struct.unpack_from("!H", reply, 16)[0]
        assert sid and reply[6:12] == LAN
        assert all(kind != 0x0110 for kind, _ in tags(reply))
        # Retransmitted PADS must reuse the existing mapping.
        self.ad.send(pads)
        duplicate = receive(self.cd, lambda p: p[15] == 0x65 and p[:6] == CLI)
        assert reply == duplicate
        return sid

    def burst(self, sid, acmac=AC, acsid=0x4567, amount=16, accelerated=None):
        if accelerated is None:
            accelerated = self.mode == "fastpath"
        outputs = []
        for send_sock, recv_sock, observer, dst, src, in_sid, outdst, outsrc, out_sid in (
            (self.cs, self.ass, self.lan_observer, LAN, CLI, sid, acmac, WAN, acsid),
            (self.ass, self.cs, self.wan_observer, WAN, acmac, acsid, CLI, LAN, sid),
        ):
            collect(recv_sock, 0.01)
            collect(observer, 0.01)
            expected = []
            for i in range(amount):
                self.serial += 1
                # Opaque PPP payload: IPv4/IPv6/LCP + arbitrary bytes. These tests
                # verify forwarding, not a negotiated IP/TCP network stack.
                payload = (b"\x00\x21", b"\x00\x57", b"\xc0\x21")[i % 3]
                payload += b"FPTEST" + struct.pack("!I", self.serial) + bytes(range(48))
                original = frame(dst, src, SESS, 0, in_sid, payload)
                output = frame(outdst, outsrc, SESS, 0, out_sid, payload)
                expected.append(output)
                self.expected_pcaps[output] += 1
                send_sock.send(original + b"\0" * 16)  # upstream trims frame padding
            got = [p for p in collect(recv_sock, 0.4) if b"FPTEST" in p]
            assert collections.Counter(got) == collections.Counter(expected), "lost, duplicate or wrong rewrite"
            observed = [p for p in collect(observer, 0.05) if b"FPTEST" in p]
            assert len(observed) == (0 if accelerated else amount), "wrong userspace socket delivery"
            outputs += got
        assert self.proc.poll() is None
        return sorted(outputs)

    def no_forward(self, sid, dst=LAN, src=CLI, acsid=None):
        collect(self.ass, 0.01)
        self.cs.send(frame(dst, src, SESS, 0, sid, b"\x00\x21NEGATIVE"))
        assert not [p for p in collect(self.ass) if b"NEGATIVE" in p]

    def padt(self, sid, acmac=AC, acsid=0x4567):
        self.cd.send(frame(LAN, CLI, DISC, 0xa7, sid))
        packet = receive(self.ad, lambda p: p[15] == 0xa7 and p[:6] == acmac)
        assert packet == frame(acmac, WAN, DISC, 0xa7, acsid)
        time.sleep(0.05)
        self.no_forward(sid)
        collect(self.cs, 0.01)
        self.ass.send(frame(WAN, acmac, SESS, 0, acsid, b"\x00\x21NEGATIVE"))
        assert not [p for p in collect(self.cs) if b"NEGATIVE" in p]

    def stop_and_check(self, sig):
        self.proc.send_signal(sig)
        self.proc.wait(timeout=5)
        # Once all link FDs close, the protocol socket must receive again.
        collect(self.lan_observer, 0.01)
        self.no_forward(1)
        observed = [p for p in collect(self.lan_observer) if b"NEGATIVE" in p]
        assert len(observed) == 1, "TC program still consumes frames after exit"

    def owned_map(self, name):
        # Never select a map globally by name: only FDs owned by this lab's relay.
        for path in Path(f"/proc/{self.proc.pid}/fdinfo").iterdir():
            for line in path.read_text().splitlines():
                if line.startswith("map_id:"):
                    ident = int(line.split()[1])
                    info = json.loads(command("bpftool", "-j", "map", "show", "id", ident).stdout)
                    if isinstance(info, list):
                        info = info[0]
                    if info["name"] == name:
                        return ident, info
        raise AssertionError(f"relay does not own map {name}")

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.logfile:
            self.logfile.close()
        for proc, output, _ in self.captures:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            output.close()
        for sock in self.sockets:
            sock.close()
        for ns in reversed(self.namespaces):
            command("ip", "netns", "del", ns, check=False)
        self.namespaces.clear()

    def check_pcaps(self):
        captured = collections.Counter()
        for _, _, path in self.captures:
            captured.update(p for p in pcap_packets(path) if b"FPTEST" in p)
        assert captured == self.expected_pcaps, "tcpdump: wrong number/content of output frames"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("src/pppoe-relay"))
    parser.add_argument("--stub-binary", type=Path)
    parser.add_argument("--results", type=Path, default=Path("test-results"))
    parser.add_argument("--idle-test", action="store_true")
    args = parser.parse_args()
    if os.geteuid() or not hasattr(os, "setns"):
        raise SystemExit("requires root and Linux Python 3.12+")
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    checks = []
    for topology in ("veth", "bridge", "vlan", "vlan-ad"):
        reference = None
        for mode in ("userspace", "fastpath"):
            lab = Lab(topology, args.binary.resolve(), mode, results)
            with contextlib.closing(lab):
                sid = lab.discovery()
                output = lab.burst(sid)
                if reference is None:
                    reference = output
                else:
                    assert reference == output, "fastpath differs from userspace frames"
                sid2 = lab.discovery(AC2)  # same AC SID, different BRAS MAC
                assert sid2 != sid
                lab.burst(sid2, AC2)
                lab.burst(sid)
                lab.no_forward(sid, src=AC2)
                lab.no_forward(sid, dst=AC2)
                lab.no_forward(0x7fff)
                lab.padt(sid)
                lab.burst(sid2, AC2)
                new_sid = lab.discovery(acsid=0x6789)
                lab.burst(new_sid, acsid=0x6789)
                lab.stop_and_check(signal.SIGTERM)
            lab.check_pcaps()
            checks.append(f"{topology}/{mode}: discovery, duplicate PADS, MAC+SID, bidirectional bytes, "
                          "socket bypass, PCAP no duplicates, PADT, redial, SIGTERM")
            print("PASS", checks[-1], flush=True)
    for mode, binary in [("failure", args.binary)] + ([("stub", args.stub_binary)] if args.stub_binary else []):
        lab = Lab("veth", binary.resolve(), mode, results)
        with contextlib.closing(lab):
            sid = lab.discovery()
            lab.burst(sid)
        lab.check_pcaps()
        checks.append(f"{mode}: fallback still establishes and forwards sessions")
        print("PASS", checks[-1], flush=True)
    for sig in (signal.SIGINT, signal.SIGKILL):
        lab = Lab("veth", args.binary.resolve(), "fastpath", results / sig.name)
        with contextlib.closing(lab):
            sid = lab.discovery()
            lab.burst(sid)
            lab.stop_and_check(sig)
        lab.check_pcaps()
        checks.append(f"{sig.name}: kernel releases TCX links")
        print("PASS", checks[-1], flush=True)
    lab = Lab("veth", args.binary.resolve(), "fastpath", results / "link-change")
    with contextlib.closing(lab):
        sid = lab.discovery()
        lab.burst(sid)
        lab.ip(lab.r, "link", "set", lab.wan, "down")
        wait_log(lab.log, "FASTPATH FALLBACK: interface", lab.proc)
        lab.ip(lab.r, "link", "set", lab.wan, "up")
        lab.no_forward(sid)
        sid = lab.discovery(acsid=0x7777)
        lab.burst(sid, acsid=0x7777, accelerated=False)
    lab.check_pcaps()
    checks.append("link down: retire affected sessions, detach, redial via fallback")
    print("PASS", checks[-1], flush=True)
    for fault in ("first-update", "second-update", "deactivation"):
        lab = Lab("veth", args.binary.resolve(), "fastpath", results / fault)
        with contextlib.closing(lab):
            sid = lab.discovery()
            lab.burst(sid)
            ident, info = lab.owned_map("states" if fault == "deactivation" else "sessions")
            if fault == "second-update":
                # One session occupies two entries. Leave exactly one free:
                # first direction succeeds; second fails with a real full map.
                for i in range(info["max_entries"] - 3):
                    key = struct.pack("=I", 0) + struct.pack("!H", i + 1) + bytes(10)
                    command("bpftool", "map", "update", "id", ident, "key", "hex",
                            *key.hex(" ").split(), "value", "hex", *bytes(32).hex(" ").split())
            else:
                command("bpftool", "map", "freeze", "id", ident)
            if fault == "deactivation":
                lab.padt(sid)
                wait_log(lab.log, "FASTPATH FALLBACK: session deactivation", lab.proc)
                sid = lab.discovery(acsid=0x7777)
                lab.burst(sid, acsid=0x7777, accelerated=False)
            else:
                sid2 = lab.discovery(AC2)
                wait_log(lab.log, "FASTPATH FALLBACK: session map update", lab.proc)
                lab.burst(sid2, AC2, accelerated=False)
                lab.burst(sid, accelerated=False)
        lab.check_pcaps()
        checks.append(f"{fault}: actual map failure rolls back and preserves userspace forwarding")
        print("PASS", checks[-1], flush=True)
    if args.idle_test:
        lab = Lab("veth", args.binary.resolve(), "fastpath", results / "idle", idle=2)
        with contextlib.closing(lab):
            sid = lab.discovery()
            end = time.monotonic() + 33
            while time.monotonic() < end:
                lab.burst(sid, amount=1)
            # At least one upstream 30-second cleanup ran during traffic.
            lab.burst(sid, amount=1)
            receive(lab.cd, lambda p: p[15] == 0xa7, timeout=35)
            lab.no_forward(sid)
        lab.check_pcaps()
        checks.append("idle: active kernel traffic survives cleanup; inactivity sends PADT")
        print("PASS", checks[-1], flush=True)
    (results / "summary.json").write_text(json.dumps({"kernel": os.uname().release, "passed": checks}, indent=2))


if __name__ == "__main__":
    main()
