# Docker deployment

The server release contains a Docker image and the `manage` entry point. The host needs Python 3.10 or later, Docker Engine with Compose, systemd, `ss`, and active UFW on Debian or Ubuntu.

## Installation

Download the server archive and `SHA256SUMS` from the [v0.5.1 release](https://github.com/XLYing23333/Weroxy/releases/tag/v0.5.1). In the download directory, verify the archive, extract it, and open the management menu.

```sh
package=weroxy-server_0.5.1_linux_amd64.release.tar.gz
awk -v file="$package" '$2 == file' SHA256SUMS | sha256sum -c - &&
  sudo install -d -m 700 /opt/weroxy &&
  sudo tar -xzf "$package" -C /opt/weroxy &&
  sudo /opt/weroxy/manage
```

Select **Install** for a fresh database. The menu checks the package, imports the image, and configures publication and firewall access. It displays an initialization URL for creating the administrator. Treat this URL as a credential; it expires when initialization succeeds. There are no default credentials. The normal management address is `http://<server-IP>:9415/`.

| Purpose | Default TCP port |
|---|---|
| Web and optional `/list` | 9415 |
| Weroxy control | 29999 |
| Legacy | 4900 |
| Forward pool | 29000–29099 |
| Data pool | 29100–29199 |

Occupied entry ports prevent startup; occupied pool ports are skipped. Check host and cloud firewall rules and verify external reachability. Control traffic and data binding use Noise; the subsequent business stream uses its own protocol. The management interface uses HTTP.

## Management

Run `sudo /opt/weroxy/manage` for the interactive menu, or use a command:

```sh
sudo /opt/weroxy/manage status
sudo /opt/weroxy/manage start
sudo /opt/weroxy/manage stop
sudo /opt/weroxy/manage restart
sudo /opt/weroxy/manage reset-password --username YOUR_USERNAME
sudo /opt/weroxy/manage uninstall
```

Uninstall removes the deployment's containers and tasks while retaining data. Password reset preserves the username; passwords must be at least six bytes.

## Backup and recovery

Stop the service and securely back up the complete `deploy/data` directory and deployment configuration before upgrading. The data directory includes encryption material needed to recover device credentials; a SQLite-only backup is insufficient. Keep a verified package available for recovery. The deployment manager also provides offline backup, upgrade, and rollback operations.
