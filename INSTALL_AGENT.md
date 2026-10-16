# Installing Weroxy with an Agent / Agent 安装约定

Project: https://github.com/XLYing23333/Weroxy
Release: https://github.com/XLYing23333/Weroxy/releases/tag/v0.4.0
Assets: https://github.com/XLYing23333/Weroxy/releases/download/v0.4.0/

Read README.md or README-CN.md for commands and prerequisites. This file describes
installation; it does not authorize touching an unspecified host or changing
unrelated production services.

## Before installation / 安装前

- Confirm target host, Server/Client role, OS and CPU architecture. Server release:
  Linux amd64. Client: amd64/arm64 deb, x86_64/aarch64 RPM, x86_64 pacman.
- Inspect existing Weroxy services, containers, data and occupied ports. Record
  other production services before acting. Never expose credentials in the report.
- Fetch assets and SHA256SUMS from the same v0.4.0 release. Verify the selected
  file with sha256sum before extraction or package installation. Checksums detect
  corruption; they are not an independent publisher signature.
- Both endpoints must use protocol Major 2. Upgrade the pair together; do not
  automatically fall back to plaintext Control or rotate existing Keys silently.

## Server

Use `weroxy-server_0.4.0_linux_amd64.release.tar.gz`. It includes an offline Docker
image, the `manage` entry point, deployment code, notices, and provenance.
Extract into a fresh root-owned `/opt/weroxy` directory, then run `sudo ./manage`.
Do not extract over a live deployment. Existing installations need private data
and configuration backups plus an explicit upgrade plan; first-install is only
for a new database. Follow WeroxyServer/deploy/docker/README.md.

Prerequisites: Python 3.10+, Docker Engine, Compose v2, systemd and ss. The managed
Debian/Ubuntu installation also expects active UFW and can change Weroxy UFW rules
and create Weroxy publication tasks. If authorization excludes host firewall
changes, do not run Install/Start/Restart to bypass that restriction: report the
specific required integration and obtain authorization or use a separately
reviewed container-only deployment plan. Never alter SSH or unrelated services.

After installation, check container health and version, actual published ports,
Web availability and preservation of other services. The random initialization
URL is a credential: display it only through the user's private terminal/session.
No default account/password is shipped. Web remains HTTP 9415; do not send its
credentials across an untrusted management network.

## Client

Prefer the native package for the host. The Client tar.gz is a deb bundle, not an
alternative service installer; extract and install its matching deb. Debian/Ubuntu:
`sudo apt install ./weroxy-client_0.4.0_<architecture>.deb`.
RPM uses dnf/yum; pacman uses `pacman -U`. Never run package installation scripts
separately. Do not overwrite another user's profile or enable autostart implicitly.

Open `weroxy-client` in an interactive terminal and configure only Host, Port and
Key through profile. Default Control port is 29999. For automation use the existing
stdin-based configuration interface; never put Key in argv or a Git-tracked file.
Targets/forwards are configured in Server Web. Start via start/restart; confirm
`weroxy-client version`, status and doctor. SSH/fail2ban changes and systemctl
Enable are separate choices, not required for basic tunnel installation.

## Verification and reporting / 验证与报告

- Control is encrypted by Noise. Data binding is protected, then raw forwarding
  resumes; ordinary HTTP/database traffic is not encrypted by this feature.
- SSH requires its own host-key verification. Preserve host SSH/fail2ban settings.
- Check `notices` and version commands and package documentation. Report only
  tests actually executed; distinguish local echo, real cross-host forwarding,
  system reboot, and SSH hardening tests. Installation alone proves none of these.
- Never prune Docker globally, reboot the host, delete unrelated applications,
  publish tokens/passwords/keys, or include private backups in Git or a Release.
