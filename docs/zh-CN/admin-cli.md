# 命令行管理

[English](../admin-cli.md) | **简体中文**

`govweave admin` 通过与 Web 控制台相同的管理员 HTTP API 管理运行中的实例，包含在标准 Go 二进制、容器和离线包内，无需 Python、Node 或单独安装 CLI。成功结果以 JSON 输出到 stdout，错误写入 stderr 并返回非零退出码。命令不直接改写服务数据目录，也不调用模型。

## 在后台运行服务

在源码仓库使用现有 Docker 部署：

```bash
docker compose up -d --build
docker compose logs --tail=100 -f
```

使用 `docker compose stop` 停止服务并保留数据卷。配置和持久化见[部署指南](deployment.md)。二进制服务仍以前台进程方式交由外部管理；`admin` 是管理客户端，不是进程守护程序。

执行 `make build` 构建本机客户端，或使用离线包中的二进制：

```bash
./bin/govweave admin --help
./bin/govweave admin status
```

默认地址为 `http://127.0.0.1:8080`。`--url` 填网关根地址，不加 `/v1` 或其他路径。远程管理使用 HTTPS；HTTP 只允许回环地址或 `localhost`，可配合 SSH 端口转发。CLI 不跟随重定向、不使用环境 HTTP 代理。`--timeout 15s` 为每条 HTTP 请求设置超时，可选 1–60 秒。写入超时不能证明写入失败，应先读取当前状态再决定是否重试。

## 从终端登录

新实例可以在 Bash 中无回显输入初始管理员密码：

```bash
read -r -s -p '管理员密码：' gw_password
printf '\n'
printf '%s\n' "$gw_password" | ./bin/govweave admin --password-stdin setup
unset gw_password
```

已有实例登录一次后，通过显式指定的会话文件连续管理：

```bash
session_dir=$(mktemp -d)
read -r -s -p '管理员密码：' gw_password
printf '\n'
printf '%s\n' "$gw_password" | ./bin/govweave admin \
  --session-file "$session_dir/govweave.session.json" --password-stdin login
unset gw_password

gw() { ./bin/govweave admin --session-file "$session_dir/govweave.session.json" "$@"; }
gw applications list
gw connections list
gw policy show
```

`--url`、`--session-file`、密码选项等全局参数放在**命令之前**。选择远程地址时，登录和后续命令使用相同的 `--url`。会话绑定该完整来源，服务端最长八小时过期，退出登录或服务重启后失效。会话文件含管理员访问凭证，权限为 `0600`，不保存密码；登录不会覆盖已有文件。到期或服务重启后，使用新文件重新登录。

不指定 `--session-file` 时，管理命令接受 `--password-stdin` 或 `--password-file /private/path`，执行后自动注销临时会话。密码文件必须是私有普通文件。原有每分钟十次登录／初始设置尝试的全局限制也统计成功登录，连续操作应复用会话。没有直接传入密码的命令行参数。

## 配置应用和策略

| 命令 | 行为 |
| --- | --- |
| `applications list`、`connections list` | 列出资源元数据和当前网关修订号 |
| `applications create --file FILE`、`connections create --file FILE` | 使用相应管理 API 的 JSON 输入创建资源 |
| `applications update --id ID --file FILE`、`connections update --id ID --file FILE` | 使用 JSON 中的修订号更新资源 |
| `applications rotate --id ID --revision N`、`applications revoke --id ID --revision N` | 轮换密钥或撤销应用访问 |
| `policy show --application ID` | 查看实际生效配置及默认继承／独立配置来源 |
| `policy set --application ID --revision N --mode redact` | 只修改该应用的设置，未指定项保留原值 |
| `policy inherit --application ID --revision N` | 移除独立绑定，恢复使用当前默认策略 |
| `policy history --application ID` | 按新到旧查看历史生效配置 |
| `policy restore --application ID --revision N --from-revision OLD` | 将历史生效配置复制为新的独立绑定 |
| `requests list --application ID --limit 20` | 最多 100 条近期元数据记录，不读取留存正文 |

创建／更新文件必须是 `0600` 普通文件、最大 16 KiB，字段遵循 [OpenAPI](../../api/openapi.yaml)。创建资源时使用修订号零；更新、轮换或撤销时，使用具体应用或连接条目上的修订号，不使用顶层网关修订号。策略命令使用独立的共享输出策略修订号。创建应用和轮换密钥会在 stdout 返回**只展示一次的应用密钥**，请将输出送到预定的秘密管理流程。资源列表不返回已有应用密钥或上游凭证。

例如，读取应用策略后，将以下 `APP_ID` 和修订号 `7` 替换为实际读取的值：

```bash
gw policy show --application APP_ID
gw policy set --application APP_ID --revision 7 \
  --mode redact --detector sensitive-text-v3 --categories credential,email,phone
gw policy history --application APP_ID
```

`policy show`、`history`、`set` 不带 `--application` 时选择默认策略；更新默认配置会保留已有应用独立策略。`--scope all` 或逗号分隔的应用 ID 只改变默认策略范围。`--public-emails ''` 显式清空邮箱例外。遇到版本冲突不会自动重试。继承、历史和证据语义见[应用独立策略](sensitive-output.md#应用独立策略)。

完成操作后：

```bash
gw logout
rmdir "$session_dir"
unset -f gw
unset session_dir
```

退出会注销所选会话并删除对应文件，浏览器会话独立。如果服务不可达，退出会报告失败并保留文件，方便稍后重试注销；单次操作完成但无法确认临时会话注销时，也会返回错误，不会声称已经完成清理。
