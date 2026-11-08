# 聆思 Skills

`lynsight-skills` 让 Codex 或 WorkBuddy 在同一局域网内搜索、读取 iPhone 聆思共享的录音文字。手机批准配对后，电脑才能读取本次共享范围内的原始转写、校正文和纪要。

将 [`SKILL.md`](SKILL.md) 和 [`scripts/`](scripts/) 一起放到助手的 `lynsight-skills` 目录中。Codex 默认使用 `~/.codex/skills/lynsight-skills`，WorkBuddy 使用 `~/.workbuddy/skills/lynsight-skills`。电脑需要 Node.js 22 或更高版本。在 iPhone 聆思的「齿轮 → 局域网共享」开启共享，再在助手里说「连接聆思」。用 iPhone 扫描助手窗口里显示的二维码并确认授权。

本地开发可在仓库根目录运行：

```sh
node --test tests/connection.test.cjs
```
