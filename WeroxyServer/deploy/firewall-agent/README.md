# Host firewall agent (functional preview)

The agent is the same `weroxy-Server` executable installed separately on the Linux host. It is **not** part of the unprivileged Server container. Do not mount the Docker socket into WeroxyServer. Native nftables and an iptables backend are implemented. Installation, Docker scope generation, kernel integrity checks and Web-driven policy synchronization are supported. Effective host filtering and connectivity require verification; leave `allow_apply` false until the configuration has been reviewed.

1. Review `firewall-agent.example.json`. Set `client_uid` to the host UID allowed to submit rules. Replace the documentation addresses with the actual published host IP, container IP, Docker bridge, port mapping and all trusted management source IPs (including both families if the management port is published over IPv4 and IPv6). A container rebuild may change the container IP, so this config must be refreshed before kernel rules can be trusted.
2. Install the JSON at `/etc/weroxy/firewall-agent.json` with root ownership and mode `0600`, and review the example systemd unit before installing it. `firewall-agent` refuses a symlink, a non-root owner, an unsafe mode, an unknown backend, invalid addresses, or an empty endpoint list.
3. Run `weroxy-Server firewall-agent --config /etc/weroxy/firewall-agent.json` on an isolated test host. The fixed socket `/run/weroxy-firewall/agent.sock` is local, mode `0600`, and owned by `client_uid`. The agent checks `SO_PEERCRED` for that UID or root. It never listens on TCP.

Each request is one newline-terminated JSON object, at most 32 KiB. Operations are `query`, `plan`, `apply`, and `revoke`. An `apply` request carries a monotonic `generation` and at most 128 rules of `{ "source": "192.0.2.0/24", "listen_host": "0.0.0.0", "target_port": 29000, "expires_at": "<UTC timestamp within 24 hours>" }`; the expiry must be within 24 hours of the request. `plan` returns the exact Weroxy-table nft script without applying it. `revoke` uses an empty rule array and a newer generation. The root-owned config must explicitly set `allow_apply: true` before the agent can execute either mutation. A repeated generation is accepted only with identical rule content.

The generated table is `inet weroxy`, with only `input` and `forward` chains at priority `-145`. A request names a listen host and target port inside the Server namespace; the agent expands it only to operator-approved published endpoints, so a Docker host-port remap cannot silently change the Ban scope. Bridge rules constrain the outgoing bridge, source CIDR, post-DNAT destination tuple, and conntrack original host address/port. Host-mode rules constrain the host address and port. The agent only flushes its own chains, never a global ruleset or Docker-owned table. It runs `nft -c` before an update, serializes requests, bounds command output and time, and prunes expired rules each minute while running. A failed nft batch does not advance the agent generation. This does not yet prove effective host filtering: the Web UI reports `unverified` even when the agent says it applied a batch.

`weroxy-Server firewall-plan --data <Weroxy data dir> --config /etc/weroxy/firewall-agent.json` works offline with the root-owned agent configuration; omit `--config` to ask a running agent for its approved endpoint list and its read-only `plan` result. It opens a temporary SQLite preview, reads the agent-approved endpoint list and compiles active application Bans to a candidate nft script. In socket mode it sends only the agent `plan` operation; in offline mode it calls the same pure rule compiler without opening the socket. Both modes print matched/unmatched Ban counts; it never sends `apply` or `revoke`. The same internal target port may be published on another host port, but a Ban is matched by the listener host, target port and source address family. A shared Data Port is never used as a substitute for a Forward-specific Ban. Server synchronization is disabled by default and requires an agent configured to allow writes.

## iptables backend

Set `backend` to `iptables` for an iptables-managed host. The agent compiles IPv4 and IPv6 restore batches independently, uses `--test` and `--noflush`, and flushes only `WEROXY-IN` / `WEROXY-FWD`. Host traffic enters from INPUT; Docker bridge traffic requires an existing DOCKER-USER chain. Missing Docker iptables integration fails explicitly; a native Docker nftables deployment must use the nft backend instead.

Rules match source CIDR and authorized destination. Bridge rules also match outgoing bridge and conntrack original public address/port. Own chains end in an ownership marker and RETURN; unmarked existing chains are rejected. Hooks have a Weroxy comment and are not duplicated. Binary paths are fixed, root-owned and not writable by other users; symlink resolution verifies the executable while preserving the iptables multicall invocation name. Execution has output/time budgets and no shell. Failure attempts to restore previous owned rules across both families; failed recovery reports failure without advancing generation. Cross-family changes are not atomic, and actual rollback and chain integrity still require verification.


## 配套安装入口

构建本机架构的 Server 可执行文件并记录 SHA-256，准备实际宿主机端口、网桥及容器地址配置后，在部署宿主机执行：

```text
sudo python3 install.py --binary /path/to/weroxy-Server --sha256 <sha256> --config /path/to/reviewed.json
```

安装器验证二进制哈希和大小，在 root 受限临时目录执行 `firewall-agent --check`（只读取配置，不建立 socket、不调用内核规则），然后安装独立可执行文件、0600 配置和 systemd unit。不自动启用或启动，不替换已有安装。默认强制 `allow_apply:false`；确需允许后续规则写入时，安装时显式提供 `--enable-apply`。安装路径和全部祖先须受 root 保护。

审阅后可按 systemd 流程启动／启用 `weroxy-firewall-agent.service`。Docker 使用 `COMPOSE_FILE=compose.yaml:firewall.compose.yaml`，Legacy TLS 则追加同一补充模板；主 Server 只挂载 `/run/weroxy-firewall` 目录，不挂 Docker Socket、不增加 capability。agent socket 为 0600 且仅接受配置 UID／root；通常非 root 容器 UID 为 10001，开启 user namespace remapping 时必须填写实际映射的宿主机 UID，不支持状态不能伪报生效。

目录由 root 创建并限制写入，socket 重建由目录挂载自动可见。配置最多 512 个精确发布 endpoint，支持默认 200 个业务端口及双栈展开；请求仍最多 128 条来源规则，总展开最多 1024 条内核规则，响应读取最多 1 MiB。实际安装和网络变化需要在部署环境中验证。

## 内核完整性状态

成功写入后 agent 记录内核规则指纹。查询和重复幂等写入重新读取规则：nft 读取自有表的结构及规则（忽略动态 handle 和工具元数据）；iptables 读取自有链并确认 INPUT／DOCKER-USER 的 Weroxy hook 在首条且唯一。内容改变或读取失败返回 `kernel_status:drift` / `kernel_integrity`，不以旧内存记录宣称当前规则存在。

这只是规则安装状态，仍不宣称公网连通；无变化继续使用 `agent_applied_unverified`。指纹保存在 agent 进程内；重启恢复和范围更新见下文。

## agent 重启恢复

规则写入前，agent 将完整已授权意图以 root 0600 文件原子写入 `/var/lib/weroxy-firewall/state.json`，同步文件及目录，再执行内核变更。记录代际、规则摘要、配置范围摘要和原到期时间；失败的待应用意图也保留其代际，不能被较老请求覆盖。

重启读取有界日志并校验所有者、权限、摘要和当前配置范围，只在 `allow_apply:true` 下重新应用仍有效的规则，到期项立即删除。进程运行期间每分钟继续清理，不延长原 TTL。日志损坏、授权 endpoint 或后端变化、恢复失败会停止启动并明确报错，不能当作空配置成功。要改变授权范围，须先在旧配置下撤销旧批次并按配置更新流程处理状态日志；不得直接删除日志并声称规则已撤销。

部署环境中应验证强杀、重启、TTL 和日志损坏时的恢复行为。

## Docker 范围生成和更新

`docker-config.py` 只在宿主机读取 Docker 和本机地址，不安装或应用规则。显式指定网络、实际宿主机地址、管理来源及后端，将 stdout 保存为待审阅 JSON：

```text
python3 docker-config.py --container <container> --network <network> --public-ip <host-ip> --management-source <admin-ip> --backend iptables > reviewed.json
# 首次安装按上一节 install.py；以后变更地址／发布／网桥
sudo python3 update-config.py --config reviewed.json --enable-apply
```

生成器只接受运行中的目标容器、实际绑定的桥接网络及本机持有的精确 IP，展开当前 TCP 发布与原始公网端口；拒绝跨地址族 proxy、缺少同族容器 IP、无匹配发布和超预算，不把未知路径生成成可用防护。默认输出关闭写入，需管理员审阅后显式授权。非 bridge 网络需单独审阅手工 host endpoint，不伪装成 DNAT。

更新器先用旧授权范围和更高代际撤销旧批次，再停止 agent、归档旧范围日志、受限原子替换配置并启动检查；失败恢复旧配置及已撤销的日志。若旧批次不能撤销，拒绝变更。新配置不自动继承旧 Ban，Server 根据同步设置重新同步应用层策略；空窗期间应用层防护保持。不要同时手工修改配置、运行多个更新器或对同一实例并发安装。应在部署环境中验证中断后的日志／服务恢复以及 nft 和 iptables 的实际连通性。


## 自动范围刷新

安装器同时交付宿主机 watcher 及 `weroxy-firewall-scope.service` 模板，仍不自动启动。管理员将已审阅的 docker-config.py 参数以 JSON 字符串数组保存为 `/etc/weroxy/docker-scope.json`（root 0600），例如 `["--container","weroxy","--network","weroxy_default","--public-ip","203.0.113.1","--management-source","198.51.100.10","--backend","iptables"]`，替换成真实地址与名称。

watcher 每 30 秒读取实际发布和网络，只有结果变化时执行受控配置更新；参数仅允许规定的 Docker 范围选项，不接受命令或规则脚本。配置更新仍由 root 组件执行，主 Server 不访问 Docker。失败记录日志并保留原范围，不伪报同步成功；实际网络迁移及恢复需要在部署环境中验证。

全局设置提供真实规则预览、内核同步启用／重试和撤销；Server 的持久同步模式默认关闭，root agent 也必须另行允许写入。开启后每 15 秒从 SQLite 读取 Ban 和有效 Forward 集合，摘要不变且内核完整性正常时复用已应用批次。实际内核规则和部署效果需要验证。
