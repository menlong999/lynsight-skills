# 聆思 Skills

`lynsight-skills` 让 Codex 或 WorkBuddy 在同一局域网内搜索、读取 iPhone 聆思共享的录音文字。手机批准配对后，电脑才能读取本次共享范围内的原始转写、校正文和纪要。

## 安装到电脑

1. 下载或克隆本仓库。把根目录的 [`SKILL.md`](SKILL.md) 和 [`scripts/`](scripts/) 一起放入当前助手的 `lynsight-skills` 目录。
   - Codex 使用 `$CODEX_HOME/skills/lynsight-skills`，默认是用户目录下的 `.codex/skills/lynsight-skills`。
   - WorkBuddy 使用用户目录下的 `.workbuddy/skills/lynsight-skills`。
2. 在电脑终端用 `node --version` 确认 Node.js 版本为 22 或更高。如果助手里找不到新 Skill，重新打开助手。
3. 手机和电脑连接同一个 Wi-Fi。在 iPhone 聆思的「齿轮 → 让 AI 访问」选好录音范围，点「开启访问」并停留在这一页。
4. 在电脑的助手里说「连接聆思」。第一次使用时，在手机点「扫描电脑二维码」，扫描电脑上的二维码，再点「允许这台电脑」。已配对的电脑可以直接连接。

连上后，可以对助手说「帮我在聆思找上周的会议纪要」。

本地开发可在仓库根目录运行：

```sh
node --test tests/connection.test.cjs
```
