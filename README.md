<p align="center">
  <img src="assets/BarLOGO.png" alt="Weroxy — Lightweight TCP tunneling" width="880" />
</p>

<h1 align="center">Weroxy</h1>

<p align="center">
  <strong>Lightweight TCP tunneling · Native Go client · Docker server · Embedded Web</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.5.0-c4a574" alt="Version 0.5.0" />
  <img src="https://img.shields.io/badge/Go-1.27.1-00ADD8?logo=go&amp;logoColor=white" alt="Go 1.27.1" />
  <img src="https://img.shields.io/badge/Vue-3-4FC08D?logo=vuedotjs&amp;logoColor=white" alt="Vue 3" />
  <img src="https://img.shields.io/badge/Storage-SQLite-003B57?logo=sqlite&amp;logoColor=white" alt="SQLite storage" />
  <img src="https://img.shields.io/badge/Server-Docker-2496ED?logo=docker&amp;logoColor=white" alt="Docker deployment" />
</p>

<p align="center">
  <strong>English</strong> · <a href="README-CN.md">简体中文</a> · <a href="#server-installation">Server setup</a> · <a href="#client-installation">Client setup</a> · <a href="#documentation">Documentation</a>
</p>

---

A lightweight TCP tunnel with a Go Server and Client, SQLite, and an embedded Vue dashboard. The three management pages are Dashboard, Devices/Forwards, and Settings, with Chinese/English and System/Light/Dark themes. Each Weroxy session has its own TCP data connection; shared and exclusive data ports support automatic expansion and draining. Multiple ports do not increase physical bandwidth.

## Features

| | What you get |
| :--- | :--- |
| **Lightweight deployment** | Interactive Docker installation and management with automatic SHA-256 verification; native Client packages. |
| **Independent sessions** | Noise-protected Control and Data binding, followed by a separate raw business stream for each session. |
| **Smart ports** | Shared/exclusive allocation, expansion and draining; entry conflicts reject startup, occupied pool ports are skipped. |
| **Management Web** | Dashboard, Devices/Forwards, and Settings; Chinese / English, System / Light / Dark. |

### Contents

[Packages](#packages) · [Server installation](#server-installation) · [Client installation](#client-installation) · [Build & verify](#build-and-verify) · [Documentation](#documentation) · [Acknowledgements](#acknowledgements)

## Packages

| Component | Distribution | Architecture |
| :--- | :--- | :--- |
| **WeroxyServer** | Docker image, deployment scripts, SHA-256 and build provenance | Linux amd64 |
| **WeroxyClient** | Native deb / RPM / pacman packages | deb: amd64, arm64; RPM: x86_64, aarch64; pacman: x86_64 |

The Server release is named `weroxy-server_0.5.0_linux_amd64.release.tar.gz` and includes the executable `manage` entry point, Docker image and deployment files. Download the package matching your host architecture, then follow the steps below.

The system package manager owns the Client program. Client releases provide deb, RPM and pacman packages. Client tar.gz bundles contain the matching deb and installation notes; no Windows release is provided.


[GitHub repository](https://github.com/XLYing23333/Weroxy) · [v0.5.0 release](https://github.com/XLYing23333/Weroxy/releases/tag/v0.5.0)

| Download | Platform |
| :--- | :--- |
| [Server](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0/weroxy-server_0.5.0_linux_amd64.release.tar.gz) | Linux amd64 |
| [Client deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0/weroxy-client_0.5.0_amd64.deb) | Debian/Ubuntu amd64 |
| [Client deb](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0/weroxy-client_0.5.0_arm64.deb) | Debian/Ubuntu arm64 |
| [Client tar.gz](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0/weroxy-client_0.5.0_linux_amd64.tar.gz) | Linux amd64 (deb bundle) |
| [Client tar.gz](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0/weroxy-client_0.5.0_linux_arm64.tar.gz) | Linux arm64 (deb bundle) |
| [SHA-256](https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0/SHA256SUMS) | All assets |

## Server installation

The prebuilt image is Linux amd64. **Extract the package and run `sudo ./manage` to install and manage Docker through a terminal menu.** The manager checks SHA-256, imports the image, checks ports and verifies firewall access automatically.

### 1. Extract and open the manager

```sh
set -eu
release=https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0
work=$(mktemp -d)
cd "$work"
wget "$release/weroxy-server_0.5.0_linux_amd64.release.tar.gz"
wget "$release/SHA256SUMS"
grep '  weroxy-server_0.5.0_linux_amd64.release.tar.gz$' SHA256SUMS | sha256sum -c -
sudo install -d -m 700 /opt/weroxy
sudo tar -xzf weroxy-server_0.5.0_linux_amd64.release.tar.gz -C /opt/weroxy
sudo /opt/weroxy/manage
```

Choose **Install**. The host needs Python 3.10+, Docker Engine, the Compose plugin, systemd, `ss`, and active UFW on Debian/Ubuntu. Missing prerequisites produce actionable errors; the manager does not install system components or enable the firewall. After SHA-256 verification, manage automatically repairs ownership and permissions of the release directories and listed management files. Databases, backups and other files are not recursively changed. Extract into `/opt/weroxy` as shown above.

The Server menu uses English. Use arrows to select, Enter to run, Esc/q to return or exit, and R to refresh status. Each action has a description. Results support arrows, Page Up/Down and Home/End; returning preserves the selected action. Long operations remain responsive to scrolling and resizing, and finish their safe stage before allowing a return. Password reset input is hidden. Without a terminal, the entry point displays help and performs no installation.

> [!IMPORTANT]
> Install is for a fresh database only. Existing deployments use Start or Upgrade, preserving credentials and ports. Checksums detect damaged files; they do not replace release signatures. Obtain the package and manager from a trusted source.

#### Locale error when opening the menu

If startup fails with `locale.Error: unsupported locale setting`, the host does not have the locale specified by its environment variables. Start the menu with:

```sh
sudo env LC_ALL=C.UTF-8 LANG=C.UTF-8 /opt/weroxy/manage
```

This sets the locale for this invocation only and does not change system configuration. It is a workaround for affected older packages. The updated manage selects an available locale automatically and passes it to Docker, systemctl and other child commands.

#### Deployment directory ownership or permission error

The updated manage first verifies SHA-256, then automatically sets the release root to root:root/0700, management directories to root:root/0755, and repairs listed management files. For older packages reporting `Deployment directory must be root-owned and not group/world writable`, use:

```sh
# Check current ownership and permissions
stat -c '%U:%G %a %n' /opt/weroxy /opt/weroxy/deploy

# Fix only these two directories, without changing data files recursively
sudo chown root:root /opt/weroxy /opt/weroxy/deploy
sudo chmod 700 /opt/weroxy
sudo chmod 755 /opt/weroxy/deploy

# Open the menu again and select Install
sudo env LC_ALL=C.UTF-8 LANG=C.UTF-8 /opt/weroxy/manage
```

Replace `/opt/weroxy` if you installed elsewhere. Parent directories outside the release are never modified. If manage reports `Unsafe parent directory`, extract the release into `/opt/weroxy`; do not recursively change ownership of your home directory. Failed checksums or symlinks require downloading and extracting a trusted release again. Do not use `chmod -R 777`.

### Management commands

The menu and these commands share the same implementation. Absolute paths work from any directory; inside the extracted package directory, you can also use `sudo ./manage`.

| Operation | Command |
| :--- | :--- |
| Install | `sudo /opt/weroxy/manage install` |
| Start | `sudo /opt/weroxy/manage start` |
| Stop | `sudo /opt/weroxy/manage stop` |
| Restart | `sudo /opt/weroxy/manage restart` |
| Status | `sudo /opt/weroxy/manage status` |
| Reset password | `sudo /opt/weroxy/manage reset-password --username YOUR_USERNAME` |
| Uninstall containers/tasks, retaining data | `sudo /opt/weroxy/manage uninstall` |

Installation, start and restart verify the package automatically. SHA-256 detects corruption; it does not replace a trusted release signature.

### 2. Initialize the administrator

Open the random `http://<server-IP>:9415/init<64-hex-token>` URL shown after installation or run Start again to display it and create the single administrator. There are **no default credentials**. The username is immutable; passwords require at least 6 bytes and can be changed in Settings. Treat the setup URL as a credential. It survives restarts and expires on successful initialization. Normal access is `http://<server-IP>:9415/`.

### 3. Configure devices and forwards

Create a device in Web, copy its key, and add a public Forward with its private target. Configure the Client on the target machine, using only Host, Control Port and Key. `127.0.0.1:22` refers to the Client machine's SSH. `/list` is disabled by default; when enabled it exposes ports, device names, protocols and status, without private targets.

### Ports and firewall

| Purpose | Default TCP port |
|---|---|
| Management HTTP / optional public `/list` | 9415 |
| Weroxy Control, TCP | 29999 |
| Legacy | 4900 |
| Forward pool | 29000–29099 |
| TCP Data pool | 29100–29199 |

The manager rejects occupied entry ports and skips occupied pool ports, updating Docker publication and usable capacity. The default 100+100 ports are not a TCP connection limit. Review cloud security groups and test external reachability.

## Upgrade and recovery

Upgrade Server and Client together: 0.5.0 uses Weroxy v2 with embedded Noise and rejects old plaintext Weroxy connections without fallback. Control is encrypted throughout; Data is encrypted only during binding, then carries the original business stream. SSH retains its own encryption and host-key verification. Legacy remains plain 4900 and Web remains HTTP; no TLS, certificates or additional client is required.

Stop the service and privately back up the complete `deploy/data` directory and deployment configuration before upgrading. A SQLite-only backup does not contain all credential-encryption secrets. Do not run first installation against an existing database. See [deployment upgrade and recovery](WeroxyServer/deploy/docker/README.md#升级与恢复) for the underlying migration workflow. Retain previous packages for recovery.

For a forgotten password, choose Reset password or run `sudo /opt/weroxy/manage reset-password --username YOUR_USERNAME`. Enter and confirm a password of at least 6 bytes; the username is unchanged.

## Client installation

```sh
set -eu
release=https://github.com/XLYing23333/Weroxy/releases/download/v0.5.0
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64) ;; *) echo "Unsupported architecture: $arch"; exit 1 ;; esac
work=$(mktemp -d)
cd "$work"
pkg="weroxy-client_0.5.0_${arch}.deb"
wget "$release/$pkg"
wget "$release/SHA256SUMS"
grep "  $pkg\$" SHA256SUMS | sha256sum -c -
sudo apt install "./$pkg"
weroxy-client
```

Use dnf/yum for RPM, or `pacman -U` for Arch. Run `weroxy-client`; arrows select, Enter executes, Esc returns and q exits:

```text
profile
start/restart
stop
status
开机自启 → enable / disable
doctor
主机加固
uninstall
```

**profile** asks only for Host, Port and Key, with visible input. Port defaults to **29999 (Control)**; press Enter to accept. Blank input keeps existing values; Esc cancels without saving. Configure internal targets and bans in Server Web; no certificate or local allow list is required.

Profiles use `~/.config/weroxy_client/client.conf` (directory 0700, configuration/key 0600). Running the menu through sudo uses the invoking user's profile. After saving, **start/restart** synchronizes it with the service and starts or restarts the Client. Installation and saving do not enable autostart. **开机自启 → enable / disable** changes only autostart. **status** shows system, service, boot state, actual control connection and traffic; **doctor** diagnoses connectivity.

TUI **uninstall** stops the service, disables autostart, deletes the current user's and service profiles, then removes the native package; other users' profiles remain. Direct package removal retains configuration. See the [Client guide](WeroxyClient/deploy/INSTALL.md).

## Build and verify

Use the Go version pinned in each module and Node.js 22/npm for Web builds. Runtime requires no Node.js, JRE or external database.

```sh
VERSION=0.5.0 GO_BIN=/path/to/go WeroxyServer/deploy/build.sh
docker build -f WeroxyServer/DockerFile --build-arg VERSION=0.5.0 -t weroxy-server:0.5.0 WeroxyServer
```

Run `go test ./...` separately in Server and Client. In `WeroxyServer/web`, run `npm run typecheck`, `node --experimental-strip-types --test test/display.test.mjs`, and `npm run build`. Deployment tests: `python3 -m unittest discover -s WeroxyServer/deploy/docker -p 'test_*.py'`.

## 0.5.0 transport and hardening

- Noise protects the full Control connection and the Data binding handshake. After READY, business bytes retain their original protocol; SSH retains its own encryption and host-key verification.
- Configuration remains Host, Port and Key. No TLS, certificates or additional client is required. Upgrade both components together; there is no fallback to the old plaintext Weroxy protocol.
- Web remains HTTP. Plaintext business protocols remain plaintext. Password hashing and encrypted credentials at rest do not protect network traffic.
- The TUI **主机加固** entry provides inspection, installation/configuration, dry-run and rollback, with displayed defaults accepted by Enter. The optional login protection is implemented with fail2ban; the service manager is systemd. Write operations were verified in isolated Debian 12/systemd. Writes require explicit confirmation; SSH changes require a second session to confirm, with timed rollback otherwise.
- Visitor totals and active connections are separate. Cumulative totals survive normal restarts independently of recent-detail retention. An abnormal exit may lose the latest unpersisted updates.

## Credentials and source publication

Keep real device keys, passwords, private keys, databases, runtime profiles, logs, backups and local binaries out of Git. Ignore rules cover common paths but do not remove committed secrets; inspect the staged tree and history before publishing. Fixed test fixtures are not production credentials. Rotate any exposed real credential first: rewriting history cannot recall existing clones.

Optional Legacy interoperability tests require local JRE 8, Java distribution files and the ignored `RAW/lanproxy-go-client` fixture. Missing fixtures cause a skip, which is not compatibility evidence. Set `WEROXY_INTEROP_CLIENT_HOME` to select the local Java client installation.

## Protocol and compatibility

Legacy and Weroxy have separate entrances and codecs. The user-specified Java lanproxyCli has insufficient real-client compatibility evidence; do not assume compatibility or replace another Lanproxy deployment.

## Documentation

| Guide | Contents |
| :--- | :--- |
| [Server Docker deployment](WeroxyServer/deploy/docker/README.md) | Initialization, port publication, firewall and recovery |
| [Client installation and migration](WeroxyClient/deploy/INSTALL.md) | Native packages, TUI, configuration, autostart, upgrades and uninstall |

## Acknowledgements

Thank you to these open-source projects and their contributors:

- [lanproxy](https://github.com/ffay/lanproxy): project inspiration and a reference for Legacy protocol and behavior.
- [lanproxy-go-client](https://github.com/ffay/lanproxy-go-client) and [lanproxy-client / lanproxyCli](https://github.com/frank-lam/lanproxy-client): client protocol and behavior references.
- [Go](https://go.dev/), [Vue](https://vuejs.org/), [Element Plus](https://element-plus.org/), [Apache ECharts](https://echarts.apache.org/) and [SQLite](https://sqlite.org/): the language, UI and storage foundations used by Weroxy.

---

<p align="center">
  <a href="README-CN.md">简体中文</a> · <a href="#features">Back to top</a>
</p>

## Third-party licenses

Third-party notices are embedded in both executables and can be read offline with
`weroxy-client notices` or `weroxy-Server notices` (Docker: `docker exec <container> /weroxy-Server notices`).
The normal Web and terminal menus use functional labels and do not display library/tool branding.
The explicit installer CLI `./manage notices` also prints the distribution notices.
Native Client packages install the text under `/usr/share/doc/weroxy-client/THIRD_PARTY_NOTICES`;
Server releases include the text alongside the installer and at `/THIRD_PARTY_NOTICES` in the image.

The notice inventory covers all declared direct/indirect Go modules and every Web npm lock entry,
including build tools and optional platform packages. Each app embeds its own dependency scope.
Dependencies include Noise, SQLite, Vue, Element Plus and ECharts. The host helper uses fail2ban and the deployment manager uses Docker/Compose.
BSD/MIT redistribution terms and Apache notices require retaining upstream copyright/license texts in distributed software.
The redundant combined root notice is omitted; required scoped texts remain in [Server](WeroxyServer/THIRD_PARTY_NOTICES) and [Client](WeroxyClient/THIRD_PARTY_NOTICES).
See [inventory and upstream text gaps](legal/README.md). Check it offline with
`python3 scripts/third_party_notices.py --check`; builds/packages reject stale dependency inventories.


## Installation prompt for an Agent

Copy the prompt below and fill in the host and component. Configure Host, Port and Key through the Client TUI afterward.

```text
Install Weroxy v0.5.0 from https://github.com/XLYing23333/Weroxy.
Release: https://github.com/XLYing23333/Weroxy/releases/tag/v0.5.0.
Target host: [SSH host or local]; component: [Server / Client].
Read README.md and INSTALL_AGENT.md first. Inspect OS, architecture, existing Weroxy,
occupied ports and other production services. Download matching release assets and verify
SHA256SUMS from the same version. Use the amd64 Server archive/manage or a native Client package.
Back up existing data privately; do not run first-install on an existing deployment.
Do not delete other apps, modify host SSH/fail2ban, prune Docker globally or alter shared
firewall settings. If manage's automatic UFW integration conflicts with these limits,
show the exact port plan and effects, and obtain explicit authorization before running it.
Never put keys, passwords or initialization URLs in argv, logs, reports or Git.
Check versions, service status and doctor. Obtain separate authorization for autostart
or SSH/fail2ban hardening. Report actual evidence and unverified items accurately.
```

### Updates

Choose **Update** in the Server or Client terminal manager to check the latest stable GitHub release. Confirm to download, verify SHA-256 and upgrade with a rollback backup. Connections restart during installation. Server Web Settings shows version reminders and a Release link; it does not install updates. Internet access to GitHub over HTTPS is needed only for checking and downloading updates.

For an existing 0.4.0 installation, install 0.5.0 using the verified release package first; the new Update menu is available starting with 0.5.0. Server updates retain data and port mappings. Keep `.update-previous` and `deploy/rollback-data` until the upgrade has been verified; archive these backups before the next Server update.
