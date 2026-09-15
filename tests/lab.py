#!/usr/bin/env python3
"""Linux 6.6+, root, Python 3.12. Tests only disposable network namespaces.

Real PADI/PADO/PADR/PADS, protocol-specific AF_PACKET observers, byte-for-byte
session output checks and tcpdump PCAP duplicate checks. No ISP/pppd required.
"""
import collections
import os
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


def ppp_payload(kind, serial):
    data = b"RBTEST" + struct.pack("!I", serial) + bytes(range(48))
    udp = struct.pack("!HHHH", 12345, 54321, 8 + len(data), 0) + data
    if kind == 0:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), serial & 0xffff,
                             0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        total = sum(struct.unpack("!10H", header))
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
        header = header[:10] + struct.pack("!H", (~total) & 0xffff) + header[12:]
        return b"\x00\x21" + header + udp
    if kind == 1:
        # A syntactically valid IPv6 packet with No Next Header; relay treats
        # all following bytes opaquely. This is not an IPv6 connectivity test.
        header = struct.pack("!IHBB16s16s", 6 << 28, len(data), 59, 64,
                             bytes.fromhex("20010db8000000000000000000000001"),
                             bytes.fromhex("20010db8000000000000000000000002"))
        return b"\x00\x57" + header + data
    return b"\xc0\x21" + struct.pack("!BBHI", 9, serial & 0xff, 8 + len(data), 0) + data


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
    def __init__(self, topology, binary, results, extra_client=False, both_ports=False, capacity=8):
        self.topology = topology
        prefix = "pbr-" + uuid.uuid4().hex[:8]
        self.c, self.r, self.a = [prefix + suffix for suffix in ("c", "r", "a")]
        self.namespaces, self.sockets, self.captures = [], [], []
        self.proc = None
        self.logfile = None
        self.expected_pcaps = collections.Counter()
        self.serial = 0
        self.result = results / topology
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
            if extra_client:
                self.ip(self.r, "link", "add", "lan2", "type", "veth", "peer", "name", "cli2", "netns", self.c)
                self.ip(self.r, "link", "set", "lan2", "address", "02:00:00:00:00:12", "up")
                self.ip(self.c, "link", "set", "cli2", "address", "02:00:00:00:00:11", "up")
            # Protocol-bound observers verify that relayed sessions bypass packet sockets.
            self.lan_observer = self.packet_socket(self.r, self.lan, SESS)
            self.wan_observer = self.packet_socket(self.r, self.wan, SESS)
            for ns, dev, label in ((self.c, self.cli, "client"), (self.a, self.ac, "server")):
                pcap = self.result / f"{label}.pcap"
                log = self.result / f"tcpdump-{label}.log"
                output = log.open("w")
                proc = subprocess.Popen(["ip", "netns", "exec", ns, "tcpdump", "--immediate-mode", "-n", "-U", "-s", "0",
                                         "-i", dev, "-Q", "in", "-w", str(pcap)],
                                        stdout=output, stderr=output, env={**os.environ, "LC_ALL": "C"})
                self.captures.append((proc, output, pcap))
                wait_log(log, "listening on", proc)
            args = ["ip", "netns", "exec", self.r]
            args += [str(binary), "-B" if both_ports else "-C", self.lan,
                     "-B" if both_ports else "-S", self.wan]
            if capacity is not None:
                args += ["-n", str(capacity)]
            if extra_client:
                args += ["-C", "lan2"]
            self.logfile = self.log.open("w")
            # Save the kernel's link state next to the relay diagnostics.
            (self.result / "links.json").write_text(self.ip(self.r, "-j", "-d", "link", "show").stdout)
            self.proc = subprocess.Popen(args, stdout=self.logfile, stderr=self.logfile)
            wait_log(self.log, "BPF RELAY enabled:", self.proc, timeout=30)
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

    def burst(self, sid, acmac=AC, acsid=0x4567, amount=16):
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
                payload = ppp_payload(i % 3, self.serial)
                original = frame(dst, src, SESS, 0, in_sid, payload)
                output = frame(outdst, outsrc, SESS, 0, out_sid, payload)
                expected.append(output)
                self.expected_pcaps[output] += 1
                send_sock.send(original + b"\0" * 16)  # relay trims frame padding
            got = [p for p in collect(recv_sock, 0.4) if b"RBTEST" in p]
            assert collections.Counter(got) == collections.Counter(expected), (
                f"lost, duplicate or wrong rewrite: got={len(got)} expected={len(expected)} "
                f"missing={[p.hex() for p in (collections.Counter(expected) - collections.Counter(got))][:2]} "
                f"extra={[p.hex() for p in (collections.Counter(got) - collections.Counter(expected))][:2]}")
            observed = [p for p in collect(observer, 0.05) if b"RBTEST" in p]
            assert len(observed) == 0, "wrong userspace socket delivery"
            outputs += got
        assert self.proc.poll() is None
        return sorted(outputs)

    def no_forward(self, sid, dst=LAN, src=CLI):
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
            captured.update(p for p in pcap_packets(path) if b"RBTEST" in p)
        assert captured == self.expected_pcaps, "tcpdump: wrong number/content of output frames"
