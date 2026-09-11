# 验证说明

## 运行自动测试

在具备 root、BPF/NET_ADMIN 权限的 Linux 6.6+ 主机，使用 Python 3.12+：

```sh
cd src
sh configure --disable-plugin
make FASTPATH=0 pppoe-relay
mkdir -p ../artifacts/linux
cp pppoe-relay ../artifacts/linux/pppoe-relay-userspace
make FASTPATH=1 pppoe-relay
cd ..
make -C tests
sudo tests/test_bpf
sudo python3 tests/netns.py --stub-binary artifacts/linux/pppoe-relay-userspace --idle-test
```

测试创建随机名称的独立 client/relay/AC netns 和 veth，只删除自己创建的命名空间。
不接触宿主 WAN/LAN。失败会保留 test-results 中日志和 pcap；CI 把它们作为 artifact 上传。
TCX 不支持、BPF 权限不足、tcpdump 启动失败均为测试失败，不标为“通过”。

独立 BPF 测试先经过真实 verifier，验证改写、padding、VLAN、错误帧、未提交映射、旧 generation、
删除映射和 lease 失效；此步骤不证明实际出口可达。

真实网络测试执行 Discovery 建立会话，再对比 userspace/fastpath 输出字节，测量同样绑定
0x8864 的 AF_PACKET observer 是否收到命中帧，要求每个输入只有一个输出，且 tcpdump pcap 再次核对数量。
覆盖 veth、bridge master、802.1Q/802.1ad 逻辑 VLAN、两 BRAS 相同 SID、双向数据、
重复 PADS、未知 SID/错误 MAC、PADT、重拨、SIGTERM/SIGINT/SIGKILL、权限失败、无 BPF 构建、
接口 down/up、活跃会话不被 timeout 误删和空闲会话最终发 PADT。
另外只定位测试 relay 持有的 map FD，使用 freeze 和填满容量制造首次写入失败、
第二方向写入失败及删除前 deactivation 失败，验证真实错误路径能完整回退。

测试里的 PPP payload 是不透明的 IPv4/IPv6/LCP 字节，**没有进行 pppd 的认证、IPCP、IPv6CP、
真实 TCP/UDP/ping 或运营商拨号**。这些属于下一节现场验收。

## PVE / OpenWrt LXC 现场验收

1. 记录 PVE 宿主 `uname -a`、容器权限和实际接口/VLAN配置。LXC 使用宿主内核；
   OpenWrt SDK 的内核版本不能证明 PVE 内核支持 TCX。
2. 用 `pppoe-relay -F -S eth1 -C br-lan --fastpath-debug` 确认 enabled 或具体 FALLBACK 原因。
3. Debian 真实拨号，验证 PADI/PADO/PADR/PADS、认证、IPv4/IPv6、ping、TCP 和 UDP；
   同时验证 OpenWrt 自身另一条 PPPoE 会话不受影响。
4. 在 br-lan、其 slave 和 WAN 分别 `tcpdump -eni IFACE -s0 -w FILE.pcap`；
   对相同 payload 序号比较 MAC/SID 和单出口数量。两侧应独立抓包，不用 `-i any` 的重复观察计数替代。
5. 观察 FASTPATH ADD/DEL、STATS，以及 `bpftool net` 的 tcx attachment；
   TCX 不属于 legacy `tc filter`，不能仅因后者空列表就认定没有挂载。
6. 重拨、PADT、停止 relay，再确认旧 SID 没有继续转发；接口 down/up 后要求重新建会话。
7. 两组相同流量 A/B 对比：普通模式、--fastpath。记录 `pidstat -p PID 1`、
   `top -H`、system/softirq CPU、吞吐、PPS、RTT、丢包。测试时不要默认每包打印日志。

只有现场有真实数据后，才能写“降低了多少 CPU”。CI 编译和合成帧测试不构成性能结论。
