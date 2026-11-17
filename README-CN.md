<p align="center"><img src="assets/LOGO-BAR.png" alt="Weroxy TCP 内网穿透项目横幅" width="880" /></p>

<h1 align="center">Weroxy</h1>

<p align="center"><strong>通过自己管理的公网服务器访问内网 TCP 服务。</strong></p>

<p align="center">
  <a href="https://github.com/XLYing23333/Weroxy/releases/latest"><img src="https://img.shields.io/github/v/release/XLYing23333/Weroxy" alt="Weroxy 最新正式版本" /></a>
  <img src="https://img.shields.io/badge/Go-00ADD8?logo=go&amp;logoColor=white" alt="使用 Go 开发" />
  <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&amp;logoColor=white" alt="服务端通过 Docker 部署" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache 2.0 许可证" /></a>
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong> · <a href="#下载">下载</a> · <a href="#快速开始">快速开始</a> · <a href="#文档">文档</a>
</p>

---

用 Docker 将 **WeroxyServer** 部署到公网 Linux 主机，在能访问内网服务的 Linux 主机上运行 **WeroxyClient**。在 Web 管理界面配置端口转发和访问规则、管理设备密钥并查看流量。

Web 管理使用 HTTP。需要加密转发的业务流量时，使用 SSH 等自带加密的应用协议。

## 下载

[v0.5.1 发布页](https://github.com/XLYing23333/Weroxy/releases/tag/v0.5.1) · [SHA256SUMS 校验清单](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/SHA256SUMS)

| 组件 | Linux 平台 | 下载 |
| --- | --- | --- |
| WeroxyServer | amd64，含 Docker 镜像和管理菜单 | [服务端压缩包](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-server_0.5.1_linux_amd64.release.tar.gz) |
| WeroxyClient | Debian / Ubuntu | [amd64 .deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client_0.5.1_amd64.deb) · [arm64 .deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client_0.5.1_arm64.deb) |
| WeroxyClient | RPM 系 Linux | [x86_64 .rpm](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client-0.5.1-1.x86_64.rpm) · [aarch64 .rpm](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client-0.5.1-1.aarch64.rpm) |
| WeroxyClient | Arch Linux | [x86_64 pacman 包](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client-0.5.1-1-x86_64.pkg.tar.zst) |

## 快速开始

### 1. 部署服务端

准备 amd64 Linux 主机，以及 Docker Engine、Docker Compose 插件、Python 3.10 或更高版本、systemd 和 `ss`。如需自动配置防火墙，在 Debian 系主机上启用 UFW。

在服务端压缩包与 `SHA256SUMS` 所在目录，校验指定压缩包，校验通过后解压并打开管理菜单。

```sh
package=weroxy-server_0.5.1_linux_amd64.release.tar.gz
awk -v file="$package" '$2 == file' SHA256SUMS | sha256sum -c - &&
  sudo install -d -m 700 /opt/weroxy &&
  sudo tar -xzf "$package" -C /opt/weroxy &&
  sudo /opt/weroxy/manage
```

选择 **Install**，用安装程序显示的一次性地址创建管理员。打开 `http://<server-host>:9415/`，在 **配置** 中添加 Weroxy 设备并复制密钥。为设备添加转发，公网端口填 `29000`，内网主机和端口填 `127.0.0.1`、`22`，即可转发到客户端本机的 SSH 服务。

| 入口 | 默认 TCP 端口 | 使用者 |
| --- | --- | --- |
| Web 管理 | `9415` | 管理员 |
| Weroxy 控制 | `29999` | WeroxyClient |
| Weroxy 数据端口池 | `29100–29199` | WeroxyClient |
| 公网转发端口池 | `29000–29099` | 访客 |

在宿主机防火墙和云安全组中放行所需端口。

### 2. 连接客户端

在 Debian 或 Ubuntu 上，进入对应架构的 `.deb` 文件与 `SHA256SUMS` 所在目录，执行以下命令。

```sh
package="weroxy-client_0.5.1_$(dpkg --print-architecture).deb"
awk -v file="$package" '$2 == file' SHA256SUMS | sha256sum -c - &&
  sudo apt install "./$package" &&
  weroxy-client
```

RPM 和 Arch 安装步骤见[客户端安装指南](WeroxyClient/deploy/INSTALL.md)。

在 **profile** 中填写服务端地址、控制端口（默认 `29999`）和设备密钥，然后选择 **start/restart**。从访客机器运行 `ssh -p 29000 USER@SERVER_HOST`，填入目标主机的 SSH 用户名和服务端公网地址。

## 文档

- [Docker 部署指南](WeroxyServer/deploy/docker/README.md)
- [客户端安装与服务管理](WeroxyClient/deploy/INSTALL.md)

## 许可证

[Apache License 2.0](LICENSE)。项目受 [lanproxy](https://github.com/ffay/lanproxy) 启发。
