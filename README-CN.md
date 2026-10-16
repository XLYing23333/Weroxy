<p align="center">
  <img src="assets/BarLOGO.png" alt="Weroxy — Lightweight TCP tunneling" width="880" />
</p>

<h1 align="center">Weroxy</h1>

<p align="center">
  <strong>轻量 TCP 内网穿透 · Go 原生客户端 · Docker 服务端 · 嵌入式 Web</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.4.0-c4a574" alt="Version 0.4.0" />
  <img src="https://img.shields.io/badge/Go-1.27.1-00ADD8?logo=go&amp;logoColor=white" alt="Go 1.27.1" />
  <img src="https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&amp;logoColor=white" alt="Vue 3" />
  <img src="https://img.shields.io/badge/Storage-SQLite-003B57?logo=sqlite&amp;logoColor=white" alt="SQLite storage" />
  <img src="https://img.shields.io/badge/Server-Docker-2496ED?logo=docker&amp;logoColor=white" alt="Docker deployment" />
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong> · <a href="#server-安装">Server 安装</a> · <a href="#client-安装与使用">Client 安装</a> · <a href="#文档导航">文档</a>
</p>

---

轻量 TCP 内网穿透：Go Server、Go Client、SQLite 和嵌入式 Vue 管理页面。Web 只有总览、设备配置与转发、设置三个一级页面，支持中英文及三种主题。控制连接与数据握手内嵌 Noise，握手完成后业务流沿用原协议；每条 Weroxy 会话使用独立 TCP 数据连接；共享、独占与自动扩缩数据端口不会自动增加物理带宽。

## 项目特性

| | 能力 |
| :--- | :--- |
| **轻量部署** | Server 通过交互式菜单安装和管理 Docker，自动校验 SHA-256；Client 使用原生安装包。 |
| **独立会话** | Control 全程加密，Data 仅握手加密，之后每条会话使用独立裸数据连接。 |
| **智能端口** | 共享、独占、自动扩缩与 Drain；入口冲突拒绝启动，池端口占用自动避让。 |
| **管理 Web** | 总览、设备与转发、设置三个页面；中文 / English，System / Light / Dark。 |

### 目录

[安装包](#安装包) · [Server 安装](#server-安装) · [Client 安装](#client-安装与使用) · [构建与测试](#源码构建与测试) · [文档导航](#文档导航) · [致谢](#致谢)

## 安装包

| 组件 | 交付内容 | 架构 |
| :--- | :--- | :--- |
| **WeroxyServer** | Docker 镜像、部署脚本、SHA-256 与构建基准 | Linux amd64 |
| **WeroxyClient** | deb / RPM / pacman 原生安装包 | deb：amd64、arm64；RPM：x86_64、aarch64；pacman：x86_64 |

Server 发布包文件名为 `weroxy-server_0.4.0_linux_amd64.release.tar.gz`，包含可执行管理入口 `manage`、Docker 镜像和部署文件。下载与主机架构匹配的包后，按下方步骤安装。

Client 程序由系统包管理器安装，提供 deb、RPM 和 pacman 包。Client tar.gz 包含对应架构的 deb 与安装说明，不提供 Windows 分发。


[GitHub 公开仓库](https://github.com/XLYing23333/Weroxy) · [v0.4.0 Release](https://github.com/XLYing23333/Weroxy/releases/tag/v0.4.0)

| 下载 | 平台 |
| :--- | :--- |
| [Server](https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/weroxy-server_0.4.0_linux_amd64.release.tar.gz) | Linux amd64 |
| [Client deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/weroxy-client_0.4.0_amd64.deb) | Debian/Ubuntu amd64 |
| [Client deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/weroxy-client_0.4.0_arm64.deb) | Debian/Ubuntu arm64 |
| [Client tar.gz](https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/weroxy-client_0.4.0_linux_amd64.tar.gz) | Linux amd64 (deb bundle) |
| [Client tar.gz](https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/weroxy-client_0.4.0_linux_arm64.tar.gz) | Linux arm64 (deb bundle) |
| [SHA-256](https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/SHA256SUMS) | All assets |

## Server 安装

预编译 Server 镜像为 Linux amd64。**解压后运行 `sudo ./manage`，通过终端菜单完成安装及 Docker 管理。** 脚本自动校验 SHA-256、导入镜像、检查端口、放行并验证防火墙，不需要手动执行 Docker 或 Python 命令。

### 1. 解压并进入管理菜单

```sh
set -eu
release=https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0
work=$(mktemp -d)
cd "$work"
wget "$release/weroxy-server_0.4.0_linux_amd64.release.tar.gz"
wget "$release/SHA256SUMS"
grep '  weroxy-server_0.4.0_linux_amd64.release.tar.gz$' SHA256SUMS | sha256sum -c -
sudo install -d -m 700 /opt/weroxy
sudo tar -xzf weroxy-server_0.4.0_linux_amd64.release.tar.gz -C /opt/weroxy
sudo /opt/weroxy/manage
```

选择“安装”，等待各阶段完成。宿主机需要 Python 3.10+、Docker Engine、Compose 插件、systemd、`ss`，以及 Debian/Ubuntu 上已启用的 UFW。缺少组件会显示处理提示；脚本不会擅自安装系统组件或启用防火墙。首次运行时，manage 校验发布包后自动修正包目录和管理文件的所有者及权限；数据库、备份和其他文件不会递归修改。建议按上面的步骤解压到 `/opt/weroxy`。

Server 菜单使用英文：方向键选择、Enter 执行、Esc/q 返回或退出，R 刷新状态。每项操作有用途说明；结果页面支持方向键、Page Up/Down、Home/End 滚动，Enter/Esc/q 返回后保留菜单位置。耗时操作期间仍可缩放和查看输出，完成安全阶段前不能返回。重置密码隐藏输入。非终端运行只显示帮助，不自动安装。

> [!IMPORTANT]
> “安装”仅用于全新数据库。已有部署请选择启动或升级，保留账户、端口与密钥。校验用于检测文件损坏，不替代发布签名；发布包及管理入口应来自可信来源。

#### 启动菜单时提示 locale 错误

如果出现 `locale.Error: unsupported locale setting`，说明服务器未安装环境变量指定的语言环境。可使用以下命令启动菜单：

```sh
sudo env LC_ALL=C.UTF-8 LANG=C.UTF-8 /opt/weroxy/manage
```

这只为本次运行指定语言环境，不修改系统配置；适用于报错的旧发布包。新版 manage 会自动选择可用的语言环境，并同步给 Docker、systemctl 等子命令，无需手动设置。

#### 提示部署目录所有者或权限不正确

新版 manage 会在 SHA-256 校验通过后，自动将发布包根目录设置为 root:root/0700、管理子目录设置为 root:root/0755，并修正清单中的管理文件。若旧发布包出现 `Deployment directory must be root-owned and not group/world writable`，可使用以下命令：

```sh
# 查看当前所有者及权限
stat -c '%U:%G %a %n' /opt/weroxy /opt/weroxy/deploy

# 仅修正这两个目录，不递归修改数据文件
sudo chown root:root /opt/weroxy /opt/weroxy/deploy
sudo chmod 700 /opt/weroxy
sudo chmod 755 /opt/weroxy/deploy

# 重新进入菜单，再选择“安装”
sudo env LC_ALL=C.UTF-8 LANG=C.UTF-8 /opt/weroxy/manage
```

如果安装在其他路径，请相应替换 `/opt/weroxy`。manage 不会修改包外的父目录：若提示 `Unsafe parent directory`，请将发布包重新解压到 `/opt/weroxy`；不要将用户主目录递归改为 root。校验失败或符号链接不会自动修复，请重新下载并解压可信发布包。不要使用 `chmod -R 777`。

### 管理命令

菜单和以下命令使用相同逻辑；无需自行调用 Docker。示例使用绝对路径，可从任意目录执行；若已在发布包目录内，也可使用 `sudo ./manage`。

| 操作 | 命令 |
| :--- | :--- |
| 安装 | `sudo /opt/weroxy/manage install` |
| 启动 | `sudo /opt/weroxy/manage start` |
| 停止 | `sudo /opt/weroxy/manage stop` |
| 重启 | `sudo /opt/weroxy/manage restart` |
| 状态 | `sudo /opt/weroxy/manage status` |
| 重置密码 | `sudo /opt/weroxy/manage reset-password --username YOUR_USERNAME` |
| 卸载容器与本部署任务（保留数据） | `sudo /opt/weroxy/manage uninstall` |

校验随安装、启动和重启自动执行。SHA-256 用于检测文件损坏，不替代可信发布签名。

### 2. 初始化管理员

安装完成后显示随机初始化路径，之后也可选择“Start”重新显示：`http://<服务器地址>:9415/init<64位随机串>`。用真实服务器 IP 替换占位地址，一次性设置账户。**没有默认用户名或密码**；用户名设置后不可修改，密码至少 6 字节。初始化路径是临时凭据，请勿公开；重启后仍有效，初始化成功后立即失效。常规登录入口是 `http://<服务器地址>:9415/`。

### 3. 配置设备与转发

在 Web 新建设备，复制其连接密钥，添加公网端口与内网目标。Client 运行在内网目标所在机器，其 `127.0.0.1:22` 指的是 Client 本机 SSH。公网访客通过 Server 的 Forward 端口连接。Client 只需填写 Host、Control Port 和 Key；内网目标与封禁由 Server Web 管理。`/list` 默认关闭，开启后无需登录，仅显示设备、协议、公网端口、状态，不显示内网目标。

### 端口与防火墙

| 用途 | 默认 TCP 端口 |
|---|---|
| Web / 可选公开 `/list` | 9415 |
| Weroxy Control（TCP） | 29999 |
| Legacy 普通 | 4900 |
| 公网 Forward 池 | 29000–29099 |
| Data 池（TCP） | 29100–29199 |

管理脚本预检关键入口，冲突时拒绝启动；自动跳过被占用的池端口并同步 Docker 发布与可用容量。默认 100+100 是业务端口数，不是 TCP 连接上限。云侧安全组仍需允许实际使用端口；Docker 映射、本地监听和客户端可达是不同证据。

## 升级与备份

0.4.0 的 Server 与 Client 必须配套升级：Weroxy v2 使用 Noise，拒绝旧明文 Weroxy 协议，不自动降级。Control 全程加密，Data 仅握手加密，业务内容沿用原协议；SSH 自身负责内容加密及主机验证。Legacy 只保留普通 4900，Web 仍为 HTTP；不需要 TLS、证书或额外客户端。

升级前停止服务并私密备份完整 `deploy/data` 与管理配置。完整备份包含设备密钥的加密主秘密；只备份 SQLite 文件不足以恢复全部凭据。不要在已有数据上再次执行首次安装；底层升级与恢复流程见 [Docker 部署文档](WeroxyServer/deploy/docker/README.md#升级与恢复)。旧版本安装包可留作回退。

忘记密码时选择“Reset password”，输入原用户名与两次新密码，或执行 `sudo /opt/weroxy/manage reset-password --username YOUR_USERNAME`。用户名不变，新密码至少 6 字节。

## Client 安装与使用

```sh
set -eu
release=https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch"; exit 1 ;; esac
work=$(mktemp -d)
cd "$work"
pkg="weroxy-client_0.4.0_${arch}.deb"
wget "$release/$pkg"
wget "$release/SHA256SUMS"
grep "  $pkg\$" SHA256SUMS | sha256sum -c -
sudo apt install "./$pkg"
weroxy-client
```

使用 RPM 时运行 `sudo dnf install ./<包.rpm>`（CentOS 7 使用 yum），Arch 使用 `sudo pacman -U ./<包.pkg.tar.zst>`。

运行 `weroxy-client`，上下方向键选择，Enter 执行，Esc 返回，q 退出：

```text
profile
start/restart
stop
status
systemctl → enable / disable
doctor
SSH 与 fail2ban
uninstall
第三方声明 / Notices
```

在 **profile** 填写 Host、Port、Key，全部明文输入。Port 默认 **29999（Control 端口）**，直接 Enter 即可；已有配置留空保留，Esc 取消不保存。内网目标与封禁在 Server Web 配置，无需证书或本地 allow。

Profile 位于 `~/.config/weroxy_client/client.conf`，目录 0700、配置与密钥 0600；sudo 打开菜单仍使用调用用户的配置。保存后选择 **start/restart**，自动同步服务配置并启动或重启。安装及保存配置都不会自动启用开机自启；**systemctl → enable / disable** 只切换自启。**status** 显示系统、服务、自启、控制连接及流量；**doctor** 检查连接。

TUI **uninstall** 会停止、取消自启、删除当前用户与服务 Profile，再卸载软件，保留其他用户配置。直接通过包管理器卸载则保留配置。更多说明见 [Client 安装指南](WeroxyClient/deploy/INSTALL.md)。

## 源码构建与测试

Go 版本以两个 `go.mod` 为准；前端构建需要 Node.js 22/npm，运行不需要 Node、JRE 或外部数据库。

```sh
VERSION=0.4.0 GO_BIN=/path/to/go WeroxyServer/deploy/build.sh
# 从源码构建 Docker 镜像（在仓库根目录）
docker build -f WeroxyServer/DockerFile --build-arg VERSION=0.4.0 -t weroxy-server:0.4.0 WeroxyServer
# Client 原生包构建见 WeroxyClient/deploy/INSTALL.md
```

Server 与 Client 分别在各自模块运行 `go test ./...`；Web 运行 `npm run typecheck`、`node --experimental-strip-types --test test/display.test.mjs`、`npm run build`；部署脚本测试为 `python3 -m unittest discover -s WeroxyServer/deploy/docker -p 'test_*.py'`。

## 0.4.0 传输与加固

- Control 全程使用 Noise，Data 仅在绑定握手阶段加密。READY 后不再增加业务加密层；SSH 沿用自身加密及主机密钥验证。
- 配置仍为 Host、Port、Key，不需要 TLS、证书或额外客户端。Server 与 Client 必须成对升级，旧 Weroxy 明文协议不会自动降级接入。
- Web 仍为 HTTP，普通明文业务不会因此获得加密。密码哈希和数据库密钥加密不代替网络传输保护。
- TUI 的 **SSH 与 fail2ban** 提供只读检测、安装配置、dry-run 和回滚入口，显示默认参数并允许 Enter 接受。仅 Linux Debian 12/systemd 的写入流程经过隔离验收；实际写入前须明确确认，SSH 配置须通过第二会话确认，未确认时定时回滚。
- 设备访客显示累计连接与当前活动连接数；累计统计独立于近期明细并在正常重启后恢复。异常退出可能丢失最近未持久化的数据，不保证崩溃时零损失。

## 凭据与源码发布

不要提交真实设备 Key、密码、私钥、数据库、运行配置、日志、备份或本机构建产物。`.gitignore` 排除常见路径，发布前仍需检查暂存区和历史；忽略规则不能清除已经提交的秘密。测试中使用的固定样例不是生产凭据。若真实凭据曾公开，应先轮换，重建 Git 历史不能撤回其他人的克隆。

Legacy 可选互操作测试需要仓库外的 JRE 8、Java 发行包及忽略的 `RAW/lanproxy-go-client`；缺少测试夹具时跳过，不构成兼容性验收。可用 `WEROXY_INTEROP_CLIENT_HOME` 指定本机 Java 客户端安装目录。

## 协议与兼容性

Legacy 与 Weroxy 协议入口分离，不将动态数据端口协议用于旧 Client。用户指定 Java lanproxyCli 的现网身份与完整互操作证据仍不足，不宣称已验证兼容。不要直接替换其他 Lanproxy 部署。

## 文档导航

| 文档 | 内容 |
| :--- | :--- |
| [Server Docker 部署](WeroxyServer/deploy/docker/README.md) | 初始化、端口发布、防火墙和恢复 |
| [Client 安装与迁移](WeroxyClient/deploy/INSTALL.md) | 原生包、TUI、配置、自启、升级与卸载 |

## 致谢

感谢以下开源项目及其贡献者：

- [lanproxy](https://github.com/ffay/lanproxy)：项目灵感与 Legacy 协议、行为对照。
- [lanproxy-go-client](https://github.com/ffay/lanproxy-go-client) 与 [lanproxy-client / lanproxyCli](https://github.com/frank-lam/lanproxy-client)：客户端协议与行为参考。
- [Go](https://go.dev/)、[Vue](https://vuejs.org/)、[Element Plus](https://element-plus.org/)、[Apache ECharts](https://echarts.apache.org/) 与 [SQLite](https://sqlite.org/)：Weroxy 使用的语言、界面与存储基础。

---

<p align="center">
  <a href="README.md">English</a> · <a href="#项目特性">返回顶部</a>
</p>

第三方声明已嵌入两端可执行文件，可离线执行 `weroxy-client notices` 或 `weroxy-Server notices`
（Docker：`docker exec <容器名> /weroxy-Server notices`）查看。
Client 菜单、Server 设置页和 Server 安装管理器（`./manage notices`）也提供查看入口。
Client 原生安装包将声明安装到 `/usr/share/doc/weroxy-client/THIRD_PARTY_NOTICES`；
Server 发布包随安装器附带声明，镜像中位于 `/THIRD_PARTY_NOTICES`。

声明清单覆盖全部已声明的直接/间接 Go 模块，以及 Web npm 锁文件中的所有包（含构建工具、平台可选包），
各 APP 按自身依赖范围嵌入。详见[依赖清单及上游文本缺项](legal/README.md)。
可执行 `python3 scripts/third_party_notices.py --check` 离线检查；依赖变更导致声明过期时，构建/打包会拒绝继续。


## 给 Agent 的安装提示词

复制下段并补充目标机器与组件；Host、Port、Key 可在安装后通过 TUI 配置。

```text
请为目标主机安装 Weroxy v0.4.0，项目 https://github.com/XLYing23333/Weroxy，
发布页 https://github.com/XLYing23333/Weroxy/releases/tag/v0.4.0。
目标主机：[填写 SSH 主机或本机]；组件：[Server / Client]。
先阅读仓库 README-CN.md 和 INSTALL_AGENT.md，检测操作系统、架构、已安装 Weroxy、
占用端口及其他生产服务。下载对应 Release 资产并校验同一版本 SHA256SUMS。
Server 使用 amd64 发布包和 manage；Client 使用本机架构的 deb（或对应 RPM/pacman）。
如已有数据，先私密备份，不执行首次安装、不覆盖旧数据。不得删除其他应用、修改宿主机
SSH/fail2ban、全局清理 Docker 或直接改动共享防火墙。Server manage 的自动 UFW 集成
如与此限制冲突，先给出端口规划和具体影响，待用户明确授权后再执行。
设备 Key、管理员密码和初始化 URL 不得放进命令参数、日志、报告或 Git。
配置成功后检查版本、服务状态和 doctor；自启及 SSH/fail2ban 加固单独取得授权。
报告真实结果和未验证项，不把本地 echo 测试当作真实跨节点验收。
```
