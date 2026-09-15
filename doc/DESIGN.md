# 实现与维护

## 程序职责

`src/relay_bpf.c` 解析参数、加载 BPF、持有 TCX link、监控接口并读取统计。
它不创建 PPPoE packet socket，不接收或转发业务报文。

`src/bpf/pppoe_relay.bpf.c` 提供一个 ingress 程序，挂载到每个配置接口。
这些挂载共享同一套 maps。入口通过 ifindex 判断接口角色。

- PADI：加入本实例的 Relay-Session-ID，复制到服务器侧接口。
- PADO/PADR：携带真实端点和接口信息，保留 AC-Name、AC-Cookie 和 Host-Uniq，路由到选定 AC。
- PADS：分配客户端 SID，建立双向映射，删除本 relay 的 tag 后回复客户端。
- Session：匹配接口、MAC、SID，改写两端 MAC/SID 并转发；PPP payload 保持不变。
- PADT：失效会话并转发。容量耗尽时，利用入包返回错误 PADS 并通知 AC。
- 本机 PPPoE、未知会话及其他不归本 relay 处理的流量继续进入网络栈。

客户端看到多个 AC 使用同一个 relay MAC 是正常的：PADR 回带所选 PADO 的
Relay-Session-ID，里面保存的真实 AC 地址决定转发目的地。

## 有界状态

| Map | 用途 | 容量 |
|---|---|---|
| config | 接口、角色、实例 cookie、启用状态 | 1 |
| slots | 会话主记录；客户端 SID 对应槽位 | `-n` + 1 |
| ac_index | 服务器接口/MAC/SID 到槽位的索引 | `-n` |
| allocator | 分配游标、代次及创建门闩 | 1 |
| scratch | Discovery 报文处理缓冲 | 每 CPU 1 |
| totals | 累计统计 | 每 CPU 1 |

默认最多 5000 个会话。处理一个数据包不会新建一个会话条目；统计数字增长也不会
按数字大小分配内存。Map 的内核内存不会全部体现在管理进程的 RSS 中。

创建事务使用非等待门闩；竞争时计数并丢弃该次 PADS，依赖端点重传。
会话快照和 active 状态由 spin lock 保护；generation 防止槽位复用时匹配旧索引。
容量满时不淘汰仍有效的连接。PADT 释放的槽位可复用，陈旧索引在分配时回收。

## 生命周期与边界

- 始终前台运行，不进行空闲超时清理。无 PADT 的异常断线可能留下槽位，直到实例重启。
- 一个网络命名空间只运行一个实例；最多 8 个不同接口、65534 个会话。
- 接口变更、失效或管理进程退出会卸载程序。重启后客户端需要重拨，不能热迁移会话。
- bridge 使用 bridge master；VLAN 使用逻辑 VLAN 接口。直接处理 trunk/QinQ 不在当前范围内，Discovery 缓冲上限为 1514 字节；未验证 jumbo PPPoE。
- `--check` 加载并验证 BPF，但不挂载、不修改正在运行实例的 maps；它不等于完成了链路转发验证。

## Verifier 兼容性

BPF 编译固定 `-mcpu=v3`。`lookup_pair`、`create_pair`、`discovery` 保持全局
`__noinline` 子程序并在函数入口检查参数。不要仅为代码风格改成 static/内联：
此前这种变化会使 PVE 6.8 的 verifier 状态数量超过限制。

## 测试

`sudo make test` 使用临时 network namespaces 构建客户端、relay 和 AC。
覆盖 veth、bridge、802.1Q/802.1ad 逻辑 VLAN、多客户端端口、多 AC 选择、双向
逐字节改写、重复 PADS、PADT、满表和复用、本机流量共存、退出卸载及接口变更。
PCAP 检查重复转发，并验证管理进程没有 AF_PACKET socket。
容量矩阵覆盖 1/8/5000/65534 个会话与 2/8 个接口的 verifier 加载。

测试需要 Linux 6.6+、BPF/网络管理权限、Python 3.12+、iproute2 和 tcpdump。
结果保存在 `test-results/`。模拟协议测试不替代真实 ISP、多核压力和长期运行验证。
