# RP-PPPoE 4.0 源码核对与 fastpath 设计

## 源码来源

原始包：[rp-pppoe-4.0.tar.gz](https://downloads.uls.co.za/rp-pppoe/rp-pppoe-4.0.tar.gz)。
SHA256：`41ac34e5db4482f7a558780d3b897bdbb21fae3fef4645d2852c3c0c19d81cea`。
版本由原始 `src/Makefile.in` 中 `RP_VERSION=4.0` 确认；许可证见 `doc/LICENSE`。

先完整阅读原始 `relay.c`、`relay.h`、`if.c`，并核对 `pppoe.h`、
`common.c` 中 tag 解析及构建入口。以下函数名和行为均来自该版本实际代码。

## 原版控制面和数据结构

| 事项 | 实际代码与行为 |
|---|---|
| 接口 | `PPPoEInterface`：name、discoverySock、sessionSock、clientOK、acOK、mac；没有 Linux ifindex |
| 注册接口 | `addInterface()` 分别打开 0x8863 和 0x8864 的 socket，角色来自 -C/-S/-B |
| 打开 socket | `if.c:openInterface()` 使用 PF_PACKET / SOCK_RAW / htons(type)，按 ifindex 和协议 bind |
| 会话 | `PPPoESession`：acHash、clientHash、epoch、sesNum，以及活动/空闲链表 |
| 索引 | `SessionHash`：interface、peerMac、sesNum、ses、peer；peer 指向另一方向 |
| SID 分配 | `initRelay()` 为槽位分配 `htons(i+1)`；客户端拿到 relay 分配的 SID |
| 建立 | `relayHandlePADS()` 校验 Relay-Session-ID 后调用 `createSession()` |
| BRAS SID | `acHash->sesNum=packet->session`；直接保存网络字节序 |
| 客户端 SID | `clientHash->sesNum=sess->sesNum`；网络字节序 |
| 查询 | `findSession(peer MAC, SID)`；原版全局 hash **不包含接口** |
| 删除 | `freeSession()` 回收 session 并 `unhash()` 两个索引 |
| PADT | `relayHandlePADT()` 改写并发送 PADT，然后 `freeSession()` |
| 活动 | `relayGotSessionPacket()` 每次用户态转发更新 `ses->epoch=Epoch` |
| 超时 | `alarmHandler()` 推进 Epoch；`cleanSessions()` 按 `Epoch-epoch > IdleTimeout` 发双向 PADT 并回收 |
| 清理周期 | `max(30, IdleTimeout/20)` 秒；`-i 0` 原版不启动 alarm |

`Relay-Session-ID` 中的 `ifIndex` 是 **Interfaces[] 数组下标**，不是内核 ifindex。
PADI 填入客户端方向数组下标与 MAC；PADO/PADR 替换为反向信息；PADS 删除该 tag。
PADS 的 SID=0 时只转发错误，不创建会话；重复 PADS 查找到已有会话后重发相同客户端 SID。

原版有一些不宜“顺便修正”的行为：PADT 使用 sessionSock 发送，但帧自身仍为
Discovery EtherType；`relaySendError()` 的两种 socket 选择也由原实现决定。
本改造保留这些行为。其原始 `findSession()` 不校验入接口；加速只接受已注册的会话接口，
其他入接口仍走原路径，因此没有扩大 fastpath 匹配范围。

## Debian → BRAS 的实际转发

函数链：

```text
relayLoop(): select(sessionSock)
  → relayGotSessionPacket(client interface)
  → receivePacket(): recv()
  → 验证 vertype=0x11、code=0、目的 MAC、PPPoE length；去掉尾部 padding
  → findSession(packet.ethHdr.h_source, packet.session)
  → ses->epoch = Epoch
  → sh = sh->peer
  → 改写 SID、以太网源/目的 MAC
  → sendPacket(NULL, sh->interface->sessionSock, packet, size): send()
```

| 字段 | LAN 输入 | WAN 输出 |
|---|---|---|
| 接口 | `clientHash->interface`，如 br-lan | `acHash->interface`，如 eth1 |
| SID | `clientHash->sesNum` | `acHash->sesNum` |
| 源 MAC | `clientHash->peerMac`（Debian） | `acHash->interface->mac`（WAN/relay） |
| 目的 MAC | `clientHash->interface->mac` | `acHash->peerMac`（BRAS） |
| PPP payload | 原始 PPP 字节 | 不修改 |

反方向用 acHash 查找，再取 clientHash；输出源 MAC 为 LAN/relay MAC，目的为 Debian，SID 为 relay 分配值。
SID 在帧和 map 内均为网络字节序；仅日志及数组槽位用 `ntohs()`。

## 与任务书建议模型的差异

1. **key 必须包含对端 MAC。** 不同 BRAS 可复用同一个 SID，仅 `(ifindex,SID)` 会串会话。
   key 使用 `(ifindex,SID,peer MAC,VLAN EtherType,VID)`；value 还核对入帧目的 MAC。
2. **两个方向需要一次提交开关。** 先以 `BPF_NOEXIST` 写两个 hash entry，再更新一个
   slot 的 generation/active。任一步失败关闭全部 fastpath links，继续原会话。
   删除时先禁用 slot，再删两个 entry；失败也全局回退，避免遗留转发。
3. **必须把内核活动同步给原 cleaner。** per-CPU activity 保存 generation、packets、bytes、
   monotonic last_seen；每秒汇总活跃 session 并刷新 epoch。处理 SIGALRM 中断时也维护，避免心跳饿死。
   读取失败时回退，并给曾加速会话一个完整 idle interval 恢复用户态活动。
4. **padding 是原转发语义的一部分。** 内核按声明的 PPPoE length 去掉尾部 padding。
   修改后 helper 若失败，丢弃该帧，不能把部分改写的帧交给 fallback。
5. **TCX 替代手工 clsact。** TCX 仍是 TC ingress（非 XDP），需要 Linux 6.6+、libbpf 1.3+。
   使用未 pin 的 BPF link，SIGTERM/SIGINT 正常清理，SIGKILL 时 FD 关闭也由内核卸载；
   不创建/删除共享 qdisc。旧内核或权限不足直接回退。非命中返回 TCX_NEXT，保留后续 TC 程序和网络栈。
6. **不需要 vmlinux.h。** 程序仅访问稳定 UAPI `__sk_buff` 和 wire header，
   不读取内核私有结构，无需 CO-RE 字段重定位；使用 libbpf、BTF map 声明和嵌入式 skeleton。

## TC、packet socket 和 bridge 的判断

在 [Linux v6.6 net/core/dev.c](https://github.com/torvalds/linux/blob/v6.6/net/core/dev.c)
的 `__netif_receive_skb_core()` 中，ETH_P_ALL taps 位于 ingress 之前，
协议特定 socket 的分发在后面。因此 tcpdump 能看见输入，不代表原版绑定 0x8864 的 socket 也收到。
PoC 必须同时测协议 socket 收包数和实际出口帧数，不能只看 tcpdump。

[Linux v6.6 br_input.c](https://github.com/torvalds/linux/blob/v6.6/net/bridge/br_input.c)
的本地上送把 skb->dev 改为 bridge，再调用 netif_receive_skb。因此从源码推断，
发给 bridge 自身 MAC 的 relay 流量应能在 master ingress 被拦截；实现使用当前
`skb->ifindex`，而非最初物理入口的 `skb->ingress_ifindex`。
本项目选择 master，不提前截走 bridge slave 的正常桥转发，也不绕过 bridge VLAN 策略。
`tests/netns.py` 单独验证 veth 和 bridge；实际 PVE/LXC 仍需现场验证，不能由源码推断替代。

## VLAN 边界

BPF 解析无标签、单个 802.1Q/802.1ad in-band 标签及 skb VLAN metadata；双标签返回原路径。
生产注册使用逻辑接口（如 `-C lan.100 -S wan.200`）。Discovery 和原版 Session socket
本来就在这些逻辑接口看到已解封装的帧，map key 的 VLAN 字段为 0；出口 VLAN netdev 再封装。
这支持两侧不同 VID，且 fallback 语义保持一致。

**不承诺直接 `-C lan` 就能中继 trunk 上的任意 VLAN。** 原版没有 VLAN Discovery 控制面；
不能仅给 fastpath 加解析就宣称 trunk 模式完整可用。原始 tagged map 解析单独通过
BPF_PROG_TEST_RUN 测试，逻辑 VLAN 路径通过真实 netns 测试。没有假定用户现场 VLAN 配置。

## 生命周期和运行限制

初始化在 daemonize 之后，避免旧关闭 FD 逻辑释放 BPF links；默认不开启 fastpath。
每秒 heartbeat 延长 5 秒 lease；进程长时间停顿时内核自动放行回原栈。
netlink link 事件配合 ioctl 检查监听 down/delete/ifindex/MAC 变化：先全局卸载，
再释放受影响会话，其他会话回退；不会自动重绑旧 session 到新接口。

停用 gate 时，已经完成 lookup 的在途包最多完成当前转发；无法撤回已进入内核执行的帧。
generation 防止旧 map entry 在 SID 复用后重新生效。非命中用户态包可能是启用前排队的，
因此**不依据 fp_active 再丢弃用户态 socket 队列中的包**。

统计 packets/bytes 是成功改写并请求 redirect 的数量，不是远端送达确认。网络设备仍可能丢包。
大规模 -n、CPU 数较多时 per-CPU map 占用增大；分配失败会回退，不能导致 relay 启动失败。
