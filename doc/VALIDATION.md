# BPF-only 仓库清理验证

日期：2026-09-15。此次移除了旧程序和构建系统，收拢为 `pppoe-relay-bpf`，
并删除 `-F`、`-i` 兼容参数。BPF 转发源码和共享结构未作行为修改。

## 构建与服务

在隔离的 Alpine 3.20 / Linux 6.6.31-0-virt 中执行：

- 全新 `make -j2`：BPF 编译、skeleton 生成、动态链接成功。
- `make STATIC=1`：同名二进制静态链接成功；GCC 13.2.1、clang 17.0.6、libbpf 1.4.2。
- `make install STATIC=1 DESTDIR=...`：仅安装 `/usr/sbin/pppoe-relay-bpf` 一个文件。
- `BPF_PREBUILT=1`：禁用 clang/bpftool 路径后仍可由 skeleton 构建；缺失 skeleton 时明确失败。
- OpenWrt init 的 shell 语法和模拟 procd 调用：空配置不启动，配置后传入正确的接口、容量和 debug 参数。
- SDK 构建脚本通过 Bash 语法检查。**本次没有执行完整 OpenWrt SDK/IPK 构建**；CI 已调整为只构建、打包这一款程序。

## 协议回归

同一个静态二进制在 Linux 6.6.31-0-virt 和 PVE 6.8.4-3-pve 中完整通过 `tests/netns.py`：

- veth、bridge master、802.1Q/802.1ad 逻辑 VLAN。
- 多 AC 选择、相同 AC SID 区分、重复 PADS、双向 MAC/SID 改写和 PCAP 无重复。
- 多客户端口、本机 PPPoE 流量共存、没有 AF_PACKET FD。
- PADT 双向清理、容量满响应、槽位复用、接口变更和进程退出卸载。
- 默认 5000 会话容量下转发；1/8/5000/65534 容量、2/8 接口的加载矩阵。
- `--help` 成功，已移除参数 `-F`、`-i 0`、`--fastpath` 返回失败。

证据随本次本地构建产物保存在 `artifacts/pppoe-relay-bpf-x86_64/evidence/`。
测试仅操作本地隔离虚拟机及其临时网络命名空间，没有连接或修改现场服务器。
