# monitor-agent

[monitor](https://github.com/Su-cyber-art/monitor) 的跨平台 agent（Linux、Windows、macOS）。采集本机指标，经 WebSocket 上报 hub。

Linux 使用 musl 静态链接单文件；Windows 和 macOS 发布各自的原生程序。

## 特性

- Linux 直接读 `/proc`、`/sys/class/net` 与 `statvfs`；Windows/macOS 使用原生系统接口（sysinfo）采集
- 内存对齐 `free(1)` 的 used 列，磁盘对齐 `df(1)` 的 Used 列
- 监控数据不写本地文件，流量累加由 hub 负责；启用远程升级时仅在自身目录保存下载和回退文件
- token 走 `Authorization` 头，不进反向代理的 access log
- 非回环地址拒绝明文 `ws://`

## 安装

在 hub 的面板添加节点，选择目标系统，复制生成的命令在目标主机执行。Linux 示例：

```bash
curl -fsSL https://your-hub/install.sh | sh -s -- --server https://your-hub --token <token>
```

Linux 安装脚本识别 systemd 与 OpenRC，实际二进制装到 `/opt/monitor/agent/monitor-agent`，
`/opt/monitor/monitor-agent` 保留为链接，token 写入
`/opt/monitor/agent.env`（0600）——和 hub 同一个目录，那台机器上只有这一处要看。

## 运行

```bash
monitor-agent --server https://your-hub --token <token>
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--server` | 必填 | hub 地址，也可用 `MONITOR_SERVER` |
| `--token` | 必填 | 节点 token，也可用 `MONITOR_TOKEN` |
| `--interval` | 1 | 上报间隔（秒），1–3600 |
| `--iface` | 空 | 流量统计的网卡，逗号分隔，也可用 `MONITOR_IFACE`；见下 |
| `--allow-upgrade` | 关闭 | 接受主控的远程升级指令；也可用 `MONITOR_ALLOW_UPGRADE=1`，安装脚本默认开启 |
| `--version` | — | 打印版本并退出 |

### 远程升级

v1.3.0 起配合新版 hub，可在后台选择多台在线节点统一升级。旧节点需要先运行一次新版安装脚本的 `--upgrade`，以安装新协议和可写目录；后续无需逐台执行升级命令。

agent 以普通用户运行，只能修改自己的二进制目录。收到 `agent.upgrade` 的 `{id, version}` 后，从现有主控下载指定版本，校验操作系统、架构和 `--version` 输出，在保留旧二进制的同时替换自身并重启（Unix 使用 `exec`，Windows 服务使用 SCM 的恢复策略）。下载期间监控和探测继续运行，token、网卡和采样间隔沿用原有设置。

新进程的 `hello` 带回实际版本和请求 ID，由 hub 确认完成。90 秒仍不能连接主控时恢复旧二进制；确认之前若进程被服务管理器重新启动，也会读取本地升级记录并回退。`upgrade.result` 会回报下载、切换和失败状态。

### 统计哪些网卡的流量

默认规则是同一份线上的字节只数一次：lo、容器与虚拟机网卡、隧道不计；bond、网桥、VLAN、macvlan
这类叠在别的网卡上的设备也不计，只计它们底下的那块。除了按名字，还按内核给出的链路类型、`DEVTYPE`、
`lower_*` 链接和所属网桥判断，改过名的隧道、网桥，以及挂在网桥上的虚拟机 tap（如 libvirt 的 `vnet0`）
和容器 veth 同样认得出。PPPoE 只认 OpenWrt 的 `pppoe-wan`：pppd 拨号的
`ppp0` 默认照计，因为 LTE 拨号时它是唯一的链路，用 pppd 拨 PPPoE 的机器要用 `--iface` 指定。

转发流量的机器（软路由、桥接了软路由的宿主机）上，同一个包会经过两块真网卡，哪块面向运营商只有
使用者知道，这时用 `--iface`：

- `--iface eth1` 或 `--iface pppoe-wan`：只统计列出的网卡，写全名时内置规则不再生效
- `--iface -eth0`：从本来会计入的网卡里去掉一块（如软路由的 LAN 口），`-` 开头的都是排除，排除优先于列出。
  一批机器都有一块同名的内网网卡时，一条批量命令就能在每台上去掉它
- 只认完整的网卡名，不支持通配

启动时打印一行 `counting traffic on: ...`，列出此刻计入的网卡。所计网卡的集合一旦变化（改了 `--iface`、
网卡增减或被重新归类），上报的 `boot_id` 也跟着变，hub 重新对基线，不会把新旧两组读数之差记成流量。

## 上报字段

`src/collect.rs` 中的 `Facts` 与 `Metrics` 两个 struct 直接序列化为线上 JSON，是字段的权威定义。

- **`Facts`** 连接时上报一次：主机名、系统、内核、架构、虚拟化类型、CPU 型号与核数、内存与磁盘总量、本机 IPv4 / IPv6（每族一个，公网地址优先；IPv6 不取临时地址和已废弃地址）
- **`Metrics`** 每 `--interval` 秒上报：CPU、负载、内存、swap、磁盘、网卡收发速率与内核累计计数器、TCP / UDP 连接数、进程数、运行时间

`net_rx_total` / `net_tx_total` 为所计网卡的内核 lifetime 计数器之和，原样上报；`boot_id` 取自
`/proc/sys/kernel/random/boot_id`，后接 `/` 与所计网卡集合的摘要，标明这两个读数在哪段区间内可以相减，
是 hub 判定计数器重新开始的唯一依据，**不要删**。`iface` 回报当前的 `--iface`，供面板显示与预填。

连接 hub 时逐个尝试解析出的地址，除最后一个外每个限 5 秒。网卡上只有内网 IPv4（NAT）时先连 hub 的
IPv4：NAT 的公网地址不在网卡上，hub 只有看到一条 IPv4 连接才知道它。

协议说明见文档站的[架构与协议](https://monitor-document.pages.dev/dev/architecture)。

## 构建

需要 Rust stable。

```bash
cargo build --release
cargo test
cargo clippy --all-targets
```

发布包含 Linux musl、Windows MSVC `.exe`、macOS Mach-O 三个平台的 x86_64 / aarch64 程序及 Ed25519 签名。推送与 Cargo.toml 版本一致的 `v*` tag，由 `.github/workflows/release.yml` 构建。CI 在 Linux、Windows、macOS 上分别执行测试和 clippy。

## 许可

MIT

## Windows 与 macOS

需要 hub v1.8.0 或更新版本，并发布 agent v1.4.0 或更新版本的全部平台产物和签名；旧 hub 的下载接口只提供 Linux 程序。面板「安装 Agent」与「批量添加」可选择目标系统，已上报节点会预选对应系统。

- Windows：在管理员 PowerShell 执行面板命令，安装为 `monitor-agent` 原生 Windows 服务，使用 LocalService 账户。程序位于 `%ProgramData%\monitor\agent\monitor-agent.exe`，凭证位于受 ACL 保护的 `%ProgramData%\monitor\agent.json`。使用 `Get-Service monitor-agent` 查看状态。手动更新、卸载分别运行安装脚本的 `-Upgrade`、`-Uninstall`。
- macOS：以 root 执行面板命令，安装为 `dev.monitor.agent` launchd 服务，使用独立 `_monitor-agent` 账户。程序位于 `/usr/local/monitor/agent/monitor-agent`，服务定义位于 `/Library/LaunchDaemons/dev.monitor.agent.plist`，日志位于 `/usr/local/monitor/agent.log`。安装脚本支持 `--upgrade` 和 `--uninstall`。
- 两个平台均支持 CPU、内存、swap、磁盘、网卡流量、进程数量、运行时间、TCP 探测及远程升级。Windows 网卡名支持空格，例如 `--iface "Ethernet 2,-Wi-Fi"`；默认排除回环和常见虚拟网卡，特殊网络使用 `--iface` 指定。
- Windows 没有 Unix 的 1/5/15 分钟负载，兼容字段上报 `[0,0,0]`。Windows/macOS 暂不识别虚拟化类型；TCP/UDP 数量为系统允许当前账户枚举的 socket 数量。macOS 磁盘统计排除重复的系统卷，使用系统提供的可用容量口径。
- 流量计数仍由 hub 累加；启动标识包含系统启动时间和所选网卡集合，网卡增减会重新对齐基线。

本机前台调试可以直接运行 `monitor-agent[.exe] --server https://your-hub --token TOKEN`。服务模式下的配置文件由安装脚本维护。
