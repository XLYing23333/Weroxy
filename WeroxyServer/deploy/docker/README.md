# WeroxyServer 0.4.0 Docker 部署

解压发布包，在根目录运行 `sudo ./manage`，进入英文终端菜单。Python 3 只用于宿主机管理脚本；Server 镜像不含 Python，使用非 root、只读根文件系统，不接 Docker Socket。

## 安装与管理

宿主机需要 Python 3.10+、Docker Engine、Compose 插件、systemd、ss，以及 Debian/Ubuntu 上已启用的 UFW。脚本不会擅自安装组件或启用防火墙。完整解压、权限及 locale 处理见 [中文 README](../../../README-CN.md#server-安装)。

菜单与命令入口共用安装逻辑：`install / start / stop / restart / status / reset-password / uninstall`。安装、启动、重启先校验镜像及部署文件 SHA-256，拒绝符号链接和越界路径；校验后自动收紧发布目录及管理文件权限。导入后核对实际镜像身份。校验用于检测损坏，不替代发布签名。

首次安装初始化默认端口池，无固定账户。启动后显示 `http://<server-IP>:9415/init<64位随机串>`；按该随机路径设置用户名与密码。用户名 1–64 位 ASCII 字母、数字、点、下划线或连字符；密码 6–1024 字节。初始化后用户名不可改，密码可在 Web 修改。随机凭据仅保存在受限 `data/setup.secret`，重启保持，成功设置账户即删除并失效。已有库不得执行首次初始化。

停止保留数据，并暂停本部署的发布刷新任务；启动恢复任务。卸载只移除经身份核实的本部署容器及任务，数据保留。非终端无参数显示帮助。

## 端口与防火墙

| 入口 | 默认 TCP 端口 |
|---|---|
| Legacy 普通 | 4900 |
| Weroxy Control | 29999 |
| HTTP Web 与可选公开 /list | 9415 |
| Forward 池 | 29000–29099 |
| Data 池 | 29100–29199 |

0.4.0 的 Control 全程使用 Noise，Data 仅在绑定握手阶段加密，之后为原业务字节流；每条业务 Session 独立连接；不提供 TLS、4993、HTTPS API、证书生成及续期任务，不检查 Nginx，不为新部署放行 80/443。默认 100+100 是业务端口数，不是会话上限。多端口用于分配与隔离，不增加物理带宽。

启动前关键入口冲突即拒绝；池中被其他程序占用的端口会跳过，并同步 Docker 发布及可用容量。启动后核实实际映射、UFW 与 Docker 入站规则，并拨号验证监听。失败回滚本次启动和新增规则。云安全组及公网可达性仍需从外部核对，不能由本地 bind 推断。

宿主机发布地址默认 0.0.0.0；已有部署必须保留实际端口和密钥。每分钟的发布刷新任务只读取本部署 Docker 元数据，主容器没有 Docker 权限。源码开发保留原 manage.py 命令入口。

## 升级与恢复

保留旧安装包。升级前停止服务，备份完整数据与管理配置：SQLite 之外的加密主秘密也必须保留。受限备份不可公开。旧 SQLite 历史迁移继续存在，迁移 39 删除已废弃的 HTTPS 设置表；迁移前自动备份。账户、设备 Key、转发及统计历史保留。

底层兼容管理器保留离线 backup、upgrade、rollback。对于已经使用匹配 0.4.0 部署脚本的安装，可运行：

```sh
sudo python3 /opt/weroxy/deploy/manage.py backup
sudo python3 /opt/weroxy/deploy/manage.py upgrade --image weroxy-server:0.4.0
```

upgrade 使用已导入并核实的新镜像，升级前完整离线备份；失败恢复旧镜像与任务，数据回滚遵守凭据隔离规则。不要将上述底层镜像升级命令当作自动替换发布包脚本的命令；旧 0.2.0 部署需先备份并使用新发布包中的匹配管理文件。Server 与 Client 必须成对升级，旧 TLS Weroxy Client 无法连接新 TCP 入口；Legacy 4993 改用 4900。

旧 HTTPS 集成只根据固定部署路径及旧归属凭据清理；只处理本部署旧 Caddy 容器、定时任务及专用域名配置。旧证书保存至 `deploy/backups/retired-https-*` 的受限备份，不继续用于运行。其他 Nginx 站点、服务及共享防火墙规则不改。独立旧实现归档在 development，未进入发布包。

## 重置密码

```sh
sudo /opt/weroxy/manage reset-password --username 原用户名
```

隐藏输入，至少 6 字节；账户名不变。密码不进入命令参数或日志。初始化路径和 Client Key 同样属于凭据，不应公开。

## 自动环境处理与菜单导航

`manage` 自动回退到可用 locale 并传给子命令。以 root 运行正式发布包时，校验 SHA-256 后自动修正包目录及清单文件的所有者/权限；数据与备份不递归修改。父目录不安全时需重新解压到 `/opt/weroxy`，不修改父目录或源码 checkout。

方向键选择、Enter 执行、Esc/q 返回，R 刷新。结果用方向键/Page Up/Page Down/Home/End 滚动；返回保留选择。耗时操作中支持窗口缩放与输出滚动，安全阶段完成后才能返回。
