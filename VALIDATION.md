# 首版验证记录

版本：0.1.0。记录日期：2026-10-24（Asia/Shanghai）。

## 已完成

- `cargo fmt --check` 通过。
- `cargo clippy --locked --all-targets -- -D warnings` 通过（Linux）。
- `cargo test --locked`：12 个单元测试通过。
- Windows x86_64 GNU 目标 release 交叉构建成功，生成 PE32+ 控制台可执行文件；依赖导入表只含 Windows 系统 DLL，没有额外的 MinGW DLL。
- Linux x86_64 musl release 构建成功，静态 PIE，可直接执行，不依赖宿主 glibc 版本。
- 最终客户端的 HTTPS 信任使用系统根证书，不关闭验证；支持标准 HTTP/HTTPS/SOCKS 代理配置。

单元测试覆盖错误 PSK、错误服务端身份、最大 1 MiB 内容的多帧加密、篡改、重放、整帧截断、连接串校验、无效/到期主钥与子钥、离线主钥、子钥优先策略、Git 参数解析、终端控制字符转义，以及凭证权限/符号链接/覆盖拒绝。

## 集成验证

执行：

```bash
python3 scripts/e2e.py --binary target/x86_64-unknown-linux-musl/release/gpg-bridge --portable-fixture
```

通过以下检查：

1. Rust 服务端、Noise 认证加密、客户端及 Git 签名适配完整往返。
2. 生成 Git commit 和 annotated tag，并由真实 GnuPG `git verify-commit` / `git verify-tag` 验证签名。
3. 实际签名子钥与会话允许指纹一致；客户端只有公钥，无私钥。
4. 可执行文件与仓库路径含空格和单引号时仍能签名与验签。
5. 请求使用另一把未授权钥匙会失败，且不创建新提交。
6. 修改配对 PSK 后认证失败。
7. 超过 1 MiB 的签名输入被拒绝，且不创建提交。
8. 服务离线后仍能本地验签。
9. disconnect 恢复原 Git 配置值；后续手工修改的设置保留。
10. 本机确认输入 N 拒绝，输入 Y 放行。
11. 会话到期后服务退出，签名失败，但仍能清理配置。
12. 审计日志包含作者/动作/结果，不包含连接串。

**范围说明：** 此环境禁止创建 Unix socket，因此真实 Linux gpg-agent 无法启动。上述便携模式仅将服务端 GnuPG 程序换成 PGPy 测试签名器，并由真实 GnuPG 验证结果；不会宣称已验证真实 agent。正常模式的真实 GnuPG 集成脚本与 CI 配置已随附，未在远端运行。

## 仍需设备联调

- Windows 本机 Gpg4win/gpg-agent 与 Pinentry 实际运行。
- 智能卡、YubiKey 等设备插拔和触摸确认。
- 你的 Codex Cloud 网络白名单、代理、Tailscale Serve/VPN 或 Funnel。
- Windows 本机原生执行及退出行为：本次只完成 Windows 目标交叉构建，未在 Windows 主机运行。

程序在交付时没有连接你的 Windows、修改你的 Codex 环境，也没有在外部平台发布。首次建议使用默认的逐次确认模式进行联调。
