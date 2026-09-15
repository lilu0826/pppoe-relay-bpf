# 使用说明

## 手动运行

```sh
pppoe-relay-bpf --check -S eth1 -C br-lan
pppoe-relay-bpf -S eth1 -C br-lan
```

`eth1` 是上游，`br-lan` 是客户端所在 bridge。多个客户端口可重复添加 `-C`。
接口必须已启用；VLAN 请填写逻辑接口，例如 `eth1.100`。
始终前台运行；按 Ctrl-C 或发送 SIGTERM 停止。

诊断时添加 `--debug`，缩小会话容量可使用 `-n 128`。
`--check` 不会挂载，但运行实例还需要具备 TCX attach 权限。
LXC 使用宿主内核，是否可用取决于宿主内核和容器授予的 BPF/网络管理权限。

## OpenWrt 服务

从 [版本下载](https://github.com/lilu0826/pppoe-relay-bpf/releases) 获取对应版本的
x86_64 包，并确保系统依赖源可用。OpenWrt 24.10 使用 IPK：

```sh
opkg install /tmp/pppoe-relay-bpf_*.ipk
```

OpenWrt 25.12 使用 APK。自行构建的包不在系统官方签名信任列表中，安装时指定：

```sh
apk add --allow-untrusted /tmp/pppoe-relay-bpf_*.apk
```

这两种包不可混用；包名均为 `pppoe-relay-bpf`。

编辑 `/etc/default/pppoe-relay-bpf`：

```sh
OPTIONS="-S eth1 -C br-lan"
```

启动：

```sh
/etc/init.d/pppoe-relay-bpf enable
/etc/init.d/pppoe-relay-bpf start
logread -e 'BPF RELAY'
```

修改配置后使用 `restart`。第一次从旧服务迁移，要先停止并禁用旧服务，避免两个
relay 同时操作接口。新版本不接受 `-F`、`-i 0`、`--fastpath`，不需要 BACKEND 配置。

## 统计怎么看

`--debug` 每 5 秒输出一次**累计值**，不是该 5 秒的增量。

| 字段 | 含义 |
|---|---|
| session | 进入成功会话改写/重定向路径的数据包数，不是会话数量 |
| bytes | 会话数据及 PADT 改写/重定向路径计数的字节数 |
| discovery | Discovery 转发计数 |
| padt | PADT 转发计数 |
| created | 累计成功创建会话数，不是当前在线数 |
| duplicate | 重复 PADS 命中已存在映射 |
| full | 无可用会话容量 |
| busy | 会话创建门闩竞争 |
| invalid | 识别为无效的报文 |
| error | 内部处理/改写等错误 |
| pass | 未被本 relay 接管、继续交给网络栈的包 |

`pass` 不表示送给 relay 用户进程；本机拨号和其他网络流量也可能增加该计数。
`verified_insns` 是内核验证程序时处理的指令计数，不是预留会话数或常驻对象数。
进程 CPU 接近零表示没有逐包用户态收发，BPF 转发仍消耗内核 CPU。
这些计数不能单独证明对端已收到全部报文。

## 会话与重启

收到 PADT 会释放会话。不做空闲超时，无 PADT 的异常断线可能遗留槽位；容量由
`-n` 固定限制，不会随转发包数无限增长。重启会释放旧 maps 和全部会话状态，
原有中继客户端需要重新拨号。接口变更/失效也会触发卸载，procd 按策略重启。
