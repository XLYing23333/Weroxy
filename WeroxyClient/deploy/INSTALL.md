# WeroxyClient 0.5.1 Linux 原生安装

仅发布 Linux 原生安装包，内含静态 Go 程序、版本信息、systemd 单元与许可证。运行时无需 Docker、JRE、Node.js 或证书。

| 系统 | 架构 | 格式 |
|---|---|---|
| Ubuntu 22/24、Debian 12/13 | amd64、arm64 | deb |
| Fedora、CentOS 7 | x86_64、aarch64 | RPM |
| Arch Linux | x86_64 | pacman |

从可信发布来源取得包与 SHA256SUMS，在包目录运行 `sha256sum -c SHA256SUMS`。Debian/Ubuntu 使用 `sudo apt install ./weroxy-client_0.5.1_amd64.deb`；Fedora 使用 dnf、CentOS 7 使用 yum、Arch 使用 `sudo pacman -U ./<包.pkg.tar.zst>`。

包管理器拥有 `/usr/bin/weroxy-client` 与 `/usr/lib/systemd/system/weroxycli.service`。首次安装不启动、不启用服务。安装脚本为调用用户准备受限 Profile；直接 root 安装时，其他用户第一次运行再准备自己的 Profile。

## 交互菜单

运行 `weroxy-client`。上下方向键选择、Enter 执行、Esc 返回、q 退出；支持窗口缩放，退出恢复终端。无终端时显示命令帮助，不执行操作。

```text
profile
start/restart
stop
status
systemctl
    enable
    disable
doctor
主机加固
uninstall
```

- **profile**：只填写 Host、Port、Key，明文输入。Port 默认 29999，代表 Server 的 Control 入口，按 Enter 保留默认或已有值。已有字段留空保留，Esc 取消不保存。Key 从 Server Web 复制，内网目标与封禁均在 Web 管理。
- **start/restart**：验证 Profile、同步服务配置；停止时启动，运行时重启。保存 Profile 后必须执行此项才能应用到后台服务。
- **stop**：停止当前服务，不改变自启设置。
- **status**：系统名称/架构、服务运行、自启、实际控制连接与上下行流量。无权读取或状态缺失时显示未知。
- **systemctl enable/disable**：只切换开机自启，不启动、不停止服务。
- **doctor**：检查地址、Control 端口、设备凭据和服务分配的数据入口。
- **uninstall**：停止→关闭自启→删除当前用户 Profile、关联凭据及 `/etc/weroxycli` 服务配置→原生包管理器卸载；成功退出。保留其他用户配置。直接包管理器卸载会保留配置。

普通连接与服务操作无需 YES 确认；加固写入需要单独确认。操作显示成功或具体错误；失败后可以留在菜单修正。管理服务时需要 root 或 sudo，sudo 密码由系统正常处理。

## 配置与权限

个人 Profile 为 `~/.config/weroxy_client/client.conf`，目录 0700、配置和密钥 0600。sudo 运行菜单仍使用调用用户的 Profile；`menu --config /绝对路径/client.conf` 优先。服务使用 `/etc/weroxycli/client.conf` 的受限副本，不执行主目录内的程序。

损坏配置可以通过 profile 重新填写；替换前保存权限 0600 的 `.repair-*.bak`。写入采用原子替换。Profile 的三个字段示例：

```ini
server.host=server.example.com
server.port=29999
client.key_file=.weroxy-key-生成的文件名
```

CLI 可通过标准输入初始化，避免密钥出现在进程参数：

```sh
weroxy-client init --config /路径/client.conf --host server.example.com --port 29999 --key-stdin
weroxy-client doctor --config /路径/client.conf
weroxy-client run --config /路径/client.conf
```

## 升级

升级前保留旧安装包并备份配置。用系统包管理器安装与服务端配套的客户端包，在 **profile** 核对 Host、Port 和 Key，再选择 **start/restart**。包管理器升级保留配置与开机自启状态。

## 从源码打包

使用 go.mod 锁定的 Go 工具链，在仓库根目录执行：

```sh
GO_BIN=/path/to/go WeroxyClient/deploy/package.sh 0.5.1
```

打包工具使用隔离 Docker 容器，运行时无需 Docker。输出为 `dist/client/0.5.1/` 的 deb、RPM、pacman 包、构建基准、源码与发布 SHA-256 清单。架构支持不等于每个系统组合已经实测。

## 可选：主机加固

TUI 提供“主机加固”；参数 Enter 使用默认值。也可运行 `weroxy-client harden status --json`、`harden ssh --dry-run`、`harden fail2ban --dry-run`。只有显式确认的 Debian 12 主机配置操作才调用 sudo。默认保留 SSH 登录方式，不修改 UFW；应用后需要第二 SSH 会话确认，否则五分钟自动回滚。详见 `Docs/operations/client-ssh-hardening.md`。该功能不影响穿透的运行时依赖。
