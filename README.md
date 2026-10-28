# gpg-bridge

Rust 实现的临时远程 OpenPGP 签名服务：Windows 保存私钥并使用现有 GnuPG agent，Codex/Linux 通过一条连接串配对，Git 照常提交。

## 使用

需要 Windows 上已有 Gpg4win/GnuPG 密钥，云端安装 Git 和 GnuPG。服务端要在你当前登录的 Windows 用户终端运行，才能正常使用桌面 Pinentry。无需导出私钥，不安装 Windows 系统服务。

### 1. Windows：启动本机服务

在解压目录执行：

```powershell
.\bin\windows-x86_64\gpg-bridge.exe serve
```

程序自动发现 GnuPG 和 Tailscale，列出签名身份，优先推荐已有选择或 Git 的 `user.signingkey`。只有一个身份时自动选择；多个时按编号选择，可用逗号多选。显示姓名/邮箱、到期日、指纹尾部，以及本机/硬件密钥记录。硬件记录并不证明设备已插入。

只选择身份即可；程序在该身份下选取创建时间最新的有效、具有签名能力且有私钥/硬件记录的子钥（若没有则用可签名主钥），本次会话固定到具体指纹。下次启动会重新检查并选择；不悄悄切换正在运行的会话。

记住的只有公开主钥指纹；重新选择：

```powershell
.\bin\windows-x86_64\gpg-bridge.exe serve --choose
```

默认只监听 `127.0.0.1:17389`。加上 `--tailscale-serve` 可自动启用 Tailscale Serve：

```powershell
.\bin\windows-x86_64\gpg-bridge.exe serve --tailscale-serve
```

需要已安装并登录 Tailscale，并按提示启用 tailnet HTTPS。程序自动执行 `tailscale serve --bg http://127.0.0.1:17389`；自定义回环 `--bind` 时转发到对应地址。命令失败或超时会中止启动，输出写入标准错误。Windows 同时检查 Tailscale 默认安装目录。退出后 Serve 配置仍保留，可用 `tailscale serve --https=443 off` 关闭该入口。

也可以不加参数，在另一个终端手动运行：

```powershell
tailscale serve --bg 17389
```

服务端向标准输出打印一行 `gpgbridge:v1:...`，这是临时签名凭证。动作日志只写标准错误和可选日志文件，不包含这行凭证。复制该行给预期的 Codex 任务即可。

若未能自动发现，使用显式地址：

```powershell
.\bin\windows-x86_64\gpg-bridge.exe serve --endpoint https://your-pc.your-tailnet.ts.net
```

GPG 不在默认安装目录时：

```powershell
.\bin\windows-x86_64\gpg-bridge.exe serve --gpg 'C:\path\to\gpg.exe' --endpoint https://your-pc.your-tailnet.ts.net
```

### 2. Codex：配置网络

如果你的 Codex Cloud 入口提供 `Advanced > VPN`，配置 Tailscale，同时允许 Windows 服务端的完整主机名，并在 Tailscale 访问规则中只开放该服务需要的访问。

若该入口没有 VPN，可选择 Windows 的 Tailscale Funnel：

```powershell
tailscale funnel --bg 17389
```

Funnel 将 HTTPS 入口发布到公网；Codex 仍须允许这个域名。程序的应用层认证与端到端加密始终保留。Serve/Funnel 的开关由你管理，停止 gpg-bridge 不会更改已有 Tailscale 配置。

HTTPS 校验使用系统信任根，兼容已正确安装 CA 的企业/云端代理；不会关闭证书校验。客户端尊重标准代理环境变量（例如 `HTTPS_PROXY`、`HTTP_PROXY`、`ALL_PROXY`、`NO_PROXY`）。云端平台要求经过代理时，保留其设置。应用不会自动重写网络规则、安装 VPN 或申请绕过限制。

### 3. Codex/Linux：粘贴并使用

随附 Linux x86_64 客户端使用 musl 静态链接，不依赖特定 glibc 版本。把 `bin/linux-x86_64/gpg-bridge` 放到一个**固定位置**，给予执行权限；生成的 Git 适配脚本会记录它的绝对路径。然后在目标仓库执行：

```bash
/path/to/gpg-bridge connect
# 粘贴连接串，按回车
/path/to/gpg-bridge status
git commit -m 'your change'
git verify-commit HEAD
```

也可以用 `connect --ticket-file /private/path/ticket.txt`，但凭证文件的权限及清理由你负责。建议直接粘贴到 stdin，避免命令行和 shell history 保存口令。

连接时只修改**当前仓库**的签名设置，保留原配置供恢复；导入的公钥放在独立验签目录，不接触用户原有钥匙串。多个授权身份时默认使用服务端列表的第一个；`status` 可查看全部完整子钥指纹，需要切换时把 `user.signingkey` 设为另一获授权指纹加 `!`。

```bash
git tag -s v1.0 -m 'release'
git verify-tag v1.0
/path/to/gpg-bridge disconnect
```

`disconnect` 删除本地凭证和独立公钥目录，恢复原有 Git 设置；连接后你手工改过的设置会保留。连接串过期之后仍能 disconnect。服务离线或过期后，只要还没有 disconnect，验签仍可通过这个独立目录在本地完成。

不要手工调用隐藏的 `gpg` 子命令；它是 Git 的适配入口。

## Windows 动作日志与确认

默认每次签名在 Windows 输入 `y` 才放行；`N`/回车拒绝。120 秒超时或会话到期也会拒绝。每次确认绑定本次请求和摘要，迟到的回答不会授权其他请求。若之前的终端输入还在等待，需先按回车清掉它，新的请求才能得到确认提示。

需要省心的无人值守会话时，显式开启：

```powershell
.\bin\windows-x86_64\gpg-bridge.exe serve --auto-approve --ttl 3600 --log-file .\session-001.log
```

`--ttl` 单位为秒，默认 8 小时，最大 24 小时。日志文件必须是新文件，避免意外覆盖或混写。Ctrl+C 或会话到期停止服务并撤销会话；新启动会生成新的身份和口令。

打印内容包括认证成功/失败、读取公钥、签名请求、作者/提交说明或 tag、实际签名钥匙、字节数、SHA-256 摘要、成功/拒绝及耗时。可用 `--verbose` 打印转义后的待签名内容前 300 字符。日志里的 UID、提交说明等不可信文本会转义控制字符并限制长度。日志可能包含姓名、邮箱、提交说明，应按个人数据保管。

每个操作使用一次独立的加密请求连接；这里没有常驻的“远端在线列表”。服务只看到发到它的动作，看不到云端的 shell 命令、文件修改或完整 diff。Git commit 数据含 tree/parent 引用，不含文件内容。服务端不会声称验证了客户端所属仓库或审查了代码。

## 安全边界

- 标准 Noise 协议 `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s`（snow），在 HTTP/HTTPS 内提供服务端身份校验、会话口令认证和内容加密。不自行设计密码算法。
- 每次 RPC 都用新握手：先完成两步握手，再发送加密操作。握手阶段绝不执行签名。一个请求状态只能消费一次；长度经过认证，拒绝篡改、重放和帧截断。不自动重试签名。
- 默认只接受 Git commit/tag 的基本文本结构；这只是减少误用，**不证明仓库归属或你认可内容**。`--allow-data` 才允许其他数据签名。
- 限定本会话允许的具体签名指纹，固定本机 GPG 程序和参数；每次签名重新检查有效期/撤销/私钥记录，使用 `fingerprint!` 固定钥匙，并检查 `SIG_CREATED` 实际指纹。
- 不提供解密、私钥导出、agent 原始协议转发、任意命令执行或远端文件路径访问。口令与私钥解锁都在 Windows/Pinentry 内完成。
- 待签名内容限制为 1 MiB，HTTP 请求/响应限制为 2 MiB；握手有速率/状态数量限制，签名串行处理，限制并发请求、读取及 GPG 操作时间。不是面向恶意公网高流量的抗 DDoS 网关，优先使用 tailnet 内访问。
- 连接串就是临时签名授权：拥有它的人在有效期内都能连接；自动模式下能请求允许范围内的签名。不要提交到仓库或长期保存到共享聊天/日志。协议不防同一云端任务里已能读取凭证的进程。
- 云端凭证以 0600 文件保存在实际 Git 目录（含 worktree 的独立 Git 目录）中；读取时拒绝符号链接、非当前用户所有及宽松权限的文件。执行时必须信任该仓库的 Git 元数据及本地程序。
- HTTP 也保留 Noise 加密，但 HTTP 元数据可见且不伪装成 TLS；经云端代理和公网时推荐 HTTPS。连接串的地址支持 IP/端口或 DNS 名称。应用层加密不隐藏端点、流量大小和时间。

服务端支持 Windows/Linux；客户端凭证权限与 Git 安装流程当前支持 Linux/macOS。macOS 需自行编译。Windows 服务必须运行在拥有钥匙的登录用户下，不应以 SYSTEM 或另一个账户启动。

## 构建与检查

使用当前 stable Rust（依赖版本锁在 Cargo.lock）：

```bash
cargo build --release --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 scripts/e2e.py --binary target/release/gpg-bridge
```

最后一项在临时目录生成无口令测试密钥并启动临时 agent，运行真实 Git commit/tag 签名、验签、拒绝未授权钥匙、本机确认、过期以及配置恢复测试；不读取现有私钥。

如果运行环境禁止 Unix socket，真实 gpg-agent 无法启动，可选择显式的便携测试模式：

```bash
python3 -m pip install PGPy
python3 scripts/e2e.py --binary target/release/gpg-bridge --portable-fixture
```

此模式用临时 PGPy 密钥替代**服务端签名程序**，仍由真实 GnuPG 完成客户端验签；它验证协议/Git 集成，但**不能证明 gpg-agent 或 Windows Pinentry 兼容性**。`scripts/portable_gpg.py` 仅供测试，绝不能用于生产。

GitHub Actions 工作流提供 Linux/Windows 原生构建和单元测试，并在 Linux 上执行真实 agent 集成测试。工作流已附源码，尚未在远端运行。

## 首版验证范围

随附 `VALIDATION.md` 记录本次实际执行的检查和未验证部分。Windows 本机 Gpg4win、硬件钥匙、Pinentry 和实际 Codex/Tailscale 链路需在你的设备上联调；不要把跨平台编译等同于这些已经通过。

参考接口：

- https://git-scm.com/docs/git-config （gpg.program）
- https://github.com/gpg/gnupg/blob/master/doc/DETAILS （机器可读密钥列表与 SIG_CREATED）
- https://docs.rs/snow/0.10.0/snow/ （Noise 实现）
- https://tailscale.com/docs/features/tailscale-serve
- https://tailscale.com/docs/features/tailscale-funnel
- https://learn.chatgpt.com/docs/environments/cloud-environments
