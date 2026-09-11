# RP-PPPoE 4.0 Relay TC/eBPF Fastpath

基于 RP-PPPoE 4.0 的可选 PPPoE Session 内核转发。
Discovery、Relay-Session-ID、SID 分配、PADT 和会话管理继续使用原版实现。
未开启 fastpath 时使用原用户态转发；BPF 初始化或 map 操作失败会记录原因并回退。

```sh
pppoe-relay -F -S eth1 -C br-lan --fastpath
```

需要 **Linux 6.6+ TCX 和 BPF 权限**。OpenWrt LXC 使用的是 **PVE 宿主内核**。
程序自动挂载所有 -C/-S/-B 注册接口，不需要手工查 MAC/SID、写 map 或执行 tc。
TCX link 不 pin，退出及 SIGKILL 后由内核释放。生产使用前按 [现场验证说明](doc/VALIDATION.md) 验收。

## GitHub Actions

推送 main、PR 或手动 Run workflow 会运行 [.github/workflows/build-relay.yml](.github/workflows/build-relay.yml)：

- `linux`：Ubuntu 24.04 上构建 userspace/fastpath 两种二进制，运行独立 BPF 测试、
  netns 实测和 tcpdump 比对，上传二进制、日志、pcap、测试结果。
- `openwrt`：使用 **OpenWrt 24.10.3 x86_64 SDK** 交叉编译本仓库，上传
  `rp-pppoe-relay-fastpath_4.0-*.ipk`、库依赖及 SHA256SUMS/SOURCE_COMMIT。

**relay 源码来自本仓库当前提交**。工作流通过 checkout 获取代码，构建脚本用 git archive
把该提交的 src/doc 放入 SDK 自定义包。不会从 OpenWrt feed 下载或构建官方 rp-pppoe。
SDK 和 libbpf/libelf/zlib 依赖仍来自 OpenWrt；这是工具链及系统库来源。
SDK 固定版本并校验 SHA256。只构建 relay，不构建 PPP client/server/plugin。

两个 job 独立：IPK 构建成功不等于内核验证通过；需同时查看 `linux` 测试结果。
Linux artifact 为 glibc 可执行文件，**OpenWrt 请使用 musl IPK**。

## Linux 编译

安装 gcc/make、clang（支持 BPF target）、bpftool、libbpf-dev（1.3+）、libelf-dev、
zlib1g-dev、pkg-config；测试还需 iproute2、tcpdump、Python 3.12+。

```sh
git clone https://github.com/lilu0826/rp-pppoe-relay.git
cd rp-pppoe-relay/src
sh configure --disable-plugin
make FASTPATH=1 pppoe-relay
sudo ./pppoe-relay -F -S eth1 -C br-lan --fastpath-debug
```

BPF object 通过 skeleton 嵌入可执行文件，运行时无需外部 .bpf.o。
`make FASTPATH=0 pppoe-relay` 构建无 libbpf 依赖版本；它接受 --fastpath 但会明确记录 FALLBACK。
默认 `make` 的 FASTPATH=0，保留原版构建路径。

| 参数 | 含义 |
|---|---|
| `-S/-C/-B` | 原有 server/client/both 接口角色 |
| `-n` | 原有最大会话数，map 容量为两倍会话数 |
| `-i` | 原有 idle timeout；0 表示不超时 |
| `-F` | 原有前台运行 |
| `-X` / `--fastpath` | 开启可选 TC ingress 数据面 |
| `--fastpath-debug` | 开启 fastpath，记录 ADD/DEL 和每 10 秒统计 |

## OpenWrt 安装

Actions artifact 解压后，把 IPK 复制到匹配版本的 OpenWrt。先保存旧 relay 配置、
停止旧 relay 服务；新旧 relay 不能同时使用相同接口。

```sh
# 已安装官方 rp-pppoe-relay 时，先停止并移除该 relay 包：
/etc/init.d/pppoe-relay stop
opkg remove rp-pppoe-relay

# 在解压出的 IPK 目录；依赖也在 artifact 中，或由已配置的软件源安装：
sha256sum -c SHA256SUMS
opkg install ./libbpf*.ipk ./libelf*.ipk ./zlib*.ipk ./rp-pppoe-relay-fastpath_*.ipk
```

新包服务默认不启动业务。编辑 `/etc/default/pppoe-relay-fastpath`，按现场接口设置：

```sh
OPTIONS="-S eth1 -C br-lan --fastpath"
```

然后：

```sh
/etc/init.d/pppoe-relay-fastpath enable
/etc/init.d/pppoe-relay-fastpath restart
logread -e FASTPATH
```

删除 OPTIONS 中的 --fastpath 后重启即可恢复原用户态数据面。权限或内核不支持时会自动回退。
此包不修改本机 PPPoE 拨号配置，也不新增 LuCI/UCI 页面。

VLAN 请指定逻辑 VLAN 接口，例如 `-C lan.100 -S wan.200`。直接挂裸 trunk 并透传
任意标签的 Discovery 不在本版范围；详见 [源码分析与设计](doc/FASTPATH-DESIGN.md)。

## 验证和来源

- [源码函数、逐方向 MAC/SID 映射、TC/socket/bridge 分析](doc/FASTPATH-DESIGN.md)
- [自动测试与 PVE/LXC 现场验收步骤](doc/VALIDATION.md)
- [原版 README](README.upstream.md) · [许可证](doc/LICENSE)

源包 SHA256：`41ac34e5db4482f7a558780d3b897bdbb21fae3fef4645d2852c3c0c19d81cea`。
CI 合成帧测试不等于运营商实际拨号测试，也不能代替 CPU/吞吐性能实测。
