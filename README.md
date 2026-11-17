<p align="center"><img src="assets/LOGO-BAR.png" alt="Weroxy TCP tunneling banner" width="880" /></p>

<h1 align="center">Weroxy</h1>

<p align="center"><strong>Expose private TCP services through a public server you control.</strong></p>

<p align="center">
  <a href="https://github.com/XLYing23333/Weroxy/releases/latest"><img src="https://img.shields.io/github/v/release/XLYing23333/Weroxy" alt="Latest Weroxy release" /></a>
  <img src="https://img.shields.io/badge/Go-00ADD8?logo=go&amp;logoColor=white" alt="Written in Go" />
  <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&amp;logoColor=white" alt="Docker server deployment" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue" alt="Apache License 2.0" /></a>
</p>

<p align="center">
  <strong>English</strong> · <a href="README-CN.md">简体中文</a> · <a href="#downloads">Downloads</a> · <a href="#quick-start">Quick start</a> · <a href="#documentation">Docs</a>
</p>

---

Run **WeroxyServer** on a public Linux host with Docker and **WeroxyClient** on a Linux host that can reach the private service. Use the web dashboard to configure forwards and access rules, manage device keys, and monitor traffic.

Web management uses HTTP. For encrypted traffic through a forward, use an encrypted application protocol such as SSH.

## Downloads

[v0.5.1 release](https://github.com/XLYing23333/Weroxy/releases/tag/v0.5.1) · [SHA256SUMS](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/SHA256SUMS)

| Component | Linux platform | Download |
| --- | --- | --- |
| WeroxyServer | amd64, Docker image and management menu | [Server archive](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-server_0.5.1_linux_amd64.release.tar.gz) |
| WeroxyClient | Debian / Ubuntu | [amd64 .deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client_0.5.1_amd64.deb) · [arm64 .deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client_0.5.1_arm64.deb) |
| WeroxyClient | RPM-based Linux | [x86_64 .rpm](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client-0.5.1-1.x86_64.rpm) · [aarch64 .rpm](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client-0.5.1-1.aarch64.rpm) |
| WeroxyClient | Arch Linux | [x86_64 pacman package](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.1/weroxy-client-0.5.1-1-x86_64.pkg.tar.zst) |

## Quick Start

### 1. Set up the server

Use an amd64 Linux host with Docker Engine, the Docker Compose plugin, Python 3.10 or later, systemd, and `ss`. For automatic firewall setup, use active UFW on a Debian-family host.

From the directory containing the server archive and `SHA256SUMS`, verify the exact archive before extracting it and opening the management menu.

```sh
package=weroxy-server_0.5.1_linux_amd64.release.tar.gz
awk -v file="$package" '$2 == file' SHA256SUMS | sha256sum -c - &&
  sudo install -d -m 700 /opt/weroxy &&
  sudo tar -xzf "$package" -C /opt/weroxy &&
  sudo /opt/weroxy/manage
```

Select **Install** and create the administrator account using the one-time URL. In **Config** at `http://<server-host>:9415/`, add a Weroxy device and copy its key. Add a forward with public port `29000`, target host `127.0.0.1`, and target port `22` to reach SSH on the client machine.

| Entry point | Default TCP port | Who connects |
| --- | --- | --- |
| Web management | `9415` | Administrator |
| Weroxy control | `29999` | WeroxyClient |
| Weroxy data pool | `29100–29199` | WeroxyClient |
| Public forward pool | `29000–29099` | Visitors |

Allow the required ports in the host and cloud firewalls.

### 2. Connect the client

On Debian or Ubuntu, run the following from the directory containing the matching `.deb` and `SHA256SUMS`.

```sh
package="weroxy-client_0.5.1_$(dpkg --print-architecture).deb"
awk -v file="$package" '$2 == file' SHA256SUMS | sha256sum -c - &&
  sudo apt install "./$package" &&
  weroxy-client
```

For RPM and Arch packages, see the [client installation guide](WeroxyClient/deploy/INSTALL.md).

In **profile**, enter the server host, control port (default `29999`), and device key. Select **start/restart**. From a visitor machine, run `ssh -p 29000 USER@SERVER_HOST` with the target machine's SSH user and the server's public address.

## Documentation

- [Docker deployment](WeroxyServer/deploy/docker/README.md)
- [Client installation and service management](WeroxyClient/deploy/INSTALL.md)

## License

[Apache License 2.0](LICENSE). Inspired by [lanproxy](https://github.com/ffay/lanproxy).
