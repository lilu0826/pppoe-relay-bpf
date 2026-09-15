# pppoe-relay-bpf

[GitHub 仓库](https://github.com/lilu0826/pppoe-relay-bpf) · [版本下载](https://github.com/lilu0826/pppoe-relay-bpf/releases)

在内核 TCX/eBPF 中完成 PPPoE Discovery、会话映射、MAC/SID 改写及 PADT 转发。
管理进程只负责加载、卸载、接口监控和统计，不按包收发 PPPoE。

`main` 仅维护这一套原生 BPF relay，构建只生成 `pppoe-relay-bpf`。

## 启动

```sh
pppoe-relay-bpf -S eth1 -C br-lan
```

- `-S IFACE`：服务器侧接口，可重复。
- `-C IFACE`：客户端侧接口，可重复。
- `-B IFACE`：兼具两种角色的接口，可重复。
- `-n NUMBER`：会话容量，默认 5000，范围 1–65534。
- `--check`：验证配置和 BPF 加载后退出，不挂载。
- `--debug`：输出 libbpf 诊断和每 5 秒累计统计；`-d` 为简写。
- `-h` / `--help`：帮助。

最多配置 8 个不同接口，至少两个接口且包含客户端与服务器角色。
始终前台运行，不做空闲超时清理。`-F`、`-i` 已移除，传入会报错。
本机 PPPoE 可以与 relay 共用上游接口，不匹配 relay 的流量继续交给网络栈。

## Linux 构建

需要 Linux 6.6+ TCX、libbpf 1.3+、C 编译器、支持 BPF 的 clang、bpftool、
pkg-config 及 libbpf/libelf/zlib 开发文件。无需 configure。

```sh
make -j2
sudo src/pppoe-relay-bpf --check -S eth1 -C br-lan
sudo make install
```

BPF object 已嵌入二进制，运行时无需 clang/bpftool 或外置 BPF 文件。
安装默认路径为 `/usr/sbin/pppoe-relay-bpf`，支持 `PREFIX`、`SBINDIR`、`DESTDIR`。
动态链接构建需要目标机安装对应运行库。

使用 musl 工具链并安装 libbpf 及其依赖的静态库后，可执行 `make STATIC=1`，
输出名称仍是 `src/pppoe-relay-bpf`。切换 C 编译器时先执行 `make clean`。

## OpenWrt

```sh
bash scripts/build-openwrt.sh 24.10
bash scripts/build-openwrt.sh 25.12
```

脚本分别使用固定校验和的 OpenWrt **24.10.8** 和 **25.12.5** x86_64 SDK，
从当前源码构建唯一应用包。24.10 输出 `.ipk`，25.12 输出 `.apk`，
分别保存在 `artifacts/openwrt/24.10.8/` 和 `artifacts/openwrt/25.12.5/`。
两套 SDK 使用独立构建目录；依赖源码固定到各 SDK 对应的 OpenWrt 提交。
构建宿主使用 Linux x86_64，具体工具安装见 GitHub Actions。
运行依赖 `libbpf` 由 OpenWrt 包管理器安装。

包内二进制、服务、配置分别为：

```text
/usr/sbin/pppoe-relay-bpf
/etc/init.d/pppoe-relay-bpf
/etc/default/pppoe-relay-bpf
```

配置 `OPTIONS="-S eth1 -C br-lan"` 后启用服务。默认配置为空，不会擅自选择接口。
从旧安装迁移时先停止旧服务，删除启动参数里的 `-F`、`-i 0` 和后端选择参数，
使用新服务名；重启会清空中继会话，客户端需要重拨。

详细步骤见 [使用说明](doc/BPF-RELAY-QUICKSTART.md)。

## 验证与实现

```sh
sudo make test
```

测试需要 Python 3.12+、iproute2、tcpdump，并有创建 network namespace 和加载
BPF 的权限。覆盖 Discovery、多端口、多 AC、Session、PADT、本机共存和退出卸载。

[实现与边界](doc/DESIGN.md) · [本次验证记录](doc/VALIDATION.md)

## 许可

GPL-2.0-or-later，见 [LICENSE](LICENSE)。项目由 rp-pppoe relay 的开发与验证工作演进而来；
当前实现和构建已独立，历史代码及其版权声明保留在 Git 历史中。
