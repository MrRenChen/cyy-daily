# 草原云 · GitHub Actions 每日自动运行

把 `core.py` 放在 GitHub 的托管 runner 上，每天北京时间 **11:30** 自动跑 4 个号，不用开电脑、不用挂手机。

---

## ⚠️ 实测结论（2026-11-10）：当前不可用，卡在地域封禁

已用 `workflow_dispatch` 真实跑过两轮，结论是**海外 runner 的 IP 被平台边缘节点直接拒绝**，与脚本无关：

| 探测目标 | 结果 |
|---|---|
| runner 出口 IP | `132.196.22.56` 美国 爱荷华州 得梅因，AS8075 Microsoft |
| `https://cyy.nmgcyy.com.cn/` | **444** 掐断连接 |
| `https://cyy.nmgcyy.com.cn/fcpublic/` | **545**，`server: TencentEdgeOne`，body `Error return from script` |
| `https://cyy.nmgcyy.com.cn/member/login/memberLogin` | **545** 同上 |
| `https://ya.iyunxh.com/` | 200 正常 |
| `https://static2-ya.iyunxh.com/` | 200 正常 |
| `https://nmgrb.y-h5.iyunxh.com/` | 403 被拒 |

`cyy.nmgcyy.com.cn` 托管在腾讯云 EdgeOne，边缘规则只放行中国大陆来源；登录、打卡上报、阅读完成上报都走这个域名，所以脚本报 `[登录] 响应非 JSON: HTTP 545`，四个号全灭。

自检能通过是因为租户配置（`static2-ya.iyunxh.com`）和任务列表（`ya.iyunxh.com`）没设地域限制，容易造成"自检通过=能用"的误判。

**因此定时任务已注释停用**，避免每天必然失败一次。可行的三条路见第六节。

---

## 一、这套东西怎么工作

```
GitHub 定时器 (03:30 UTC = 11:30 CST)
        │
        ▼
ubuntu-latest runner  ←  从 Secrets 读出 4 个账号
        │
        ├─ python core.py --check     环境自检（不登录）
        └─ python core.py             登录 → 打卡 → 做任务 → 阅读上报
        │
        ▼
run.log → 运行摘要 + Artifact（保留 7 天）
```

账号密码存在 **Repository Secrets** 里，不会写进代码、不会出现在日志（日志里手机号是打码的 `177****1473`）。

---

## 二、必须提前知道的三个约束

**1. 出口 IP 是海外机房**
runner 跑在微软 Azure 的海外节点。如果平台对境外 IP 有拦截，会表现为登录失败、滑块反复不通过、或"任务全做完但服务端显示未完成"。这是唯一无法在地面验证的变量，所以部署完第一件事就是手动跑一次看结果。被拦时的补救办法见第六节。

**2. 定时不是精确的**
GitHub 的 cron 是"尽力而为"，03:30 UTC 的任务实际可能在 11:30–12:00 之间任意时刻启动，偶尔会被跳过。这是平台行为，不是脚本问题。

**3. 公开仓库的 schedule 会因长期无提交被停用**
所以 `daily.yml` 里额外挂了一条每月 1 号的 `keepalive` 任务，自动提交一个 `.keepalive` 文件保活。如果收到 GitHub 的 "scheduled workflow disabled" 邮件，去 Actions 页面手动点一次 Run workflow 就能恢复。

> 公开仓库的 Actions 分钟数**无限**，不会因为额度用尽被停。账号密码在 Secrets 里，公开仓库也看不到。

---

## 三、部署步骤（已由我代做，这里是记录）

1. 建公开仓库并推送本目录（含 `.github/`）。
2. 写入 Secret `CYY_ACCOUNTS`，格式：

```
手机号#密码;手机号#密码;手机号#密码;手机号#密码
```

- `;` 或换行分隔账号，`#`、`:`、`,` 都能分隔手机号和密码，`#` 最不容易冲突；
- 密码里**不能**含 `;` `#` `:` `,`；
- Secret 保存后读不回来，改密码只能覆盖重写。

3. 触发第一次运行：`gh workflow run daily.yml`，或网页 Actions → cyy-daily → Run workflow。

---

## 四、可选 Secrets

| Name | 作用 |
|---|---|
| `CYY_ACCOUNTS` | **必填**，账号列表 |
| `CYY_STATIC_PROXY` | 全局代理，格式 `http://user:pass@host:port` 或 `socks5://host:port`。境外 IP 被拦时填这个 |
| `PROXY_API` | 代理池提取链接（每次请求返回一个 IP） |
| `PLUSPLUS_TOKEN` | 跑完把结果推到微信（pushplus.plus 注册即得） |

带 `CYY_STATIC_PROXY` 时脚本会先验证代理出口 IP 再干活，代理挂了会报错而不是偷偷走真实 IP（`ENABLE_DIRECT_FALLBACK` 默认关闭）。

---

## 五、参数在哪改

`.github/workflows/daily.yml` → 「运行任务」这一步的环境变量：

| 变量 | 默认 | 作用 |
|---|---|---|
| `CYY_READ_SECONDS` | `60` | 阅读秒数下限，实际取 `max(此值, 任务要求)` 再 +0~12 秒抖动 |
| `CYY_ACCOUNT_GAP` | `6` | 账号间隔基准（分钟），实际 4.8~12 分钟；`0` = 连跑 |
| `CYY_MAX_TASKS` | `0` | 每个号最多做几条任务，`0` = 全部 |
| `CYY_RANDOMIZE` | `1` | 间隔浮动 + 秒数抖动 + 任务顺序打乱，建议保持 1 |

**改时间**：GitHub 只认 UTC，北京时间 = UTC + 8。

| 想要北京时间 | 填 cron |
|---|---|
| **11:30** | **`30 3 * * *`** ← 当前 |
| 07:30 | `30 23 * * *` |
| 12:00 | `0 4 * * *` |

时间本身已经错开整点（`:30`），不需要再避讳。

---

## 六、地域封禁怎么办（三选一）

| 方案 | 出口 IP | 可行性 | 成本 | 说明 |
|---|---|---|---|---|
| **A. 手机 Termux（已在跑）** | 家庭宽带 | ✅ 已验证 | 0 | 旧手机上已经部署好并跑通过，最稳 |
| **B. 国内轻量云服务器** | 中国大陆机房 | ✅ 大概率可行 | ¥10~30/月 | 阿里云/腾讯云轻量，装 python + cron，逻辑与 Termux 完全一样 |
| **C. 给 GitHub 配国内代理** | 代理出口 | ⚠️ 取决于代理 | ¥0.5~1/GB | 配 `CYY_STATIC_PROXY` Secret 后把 cron 注释去掉；必须是**中国大陆住宅/家宽** IP，机房 IP 仍可能被 EdgeOne 判风险 |

代理方案的具体操作：把它写成 `http://user:pass@host:port` 或 `socks5://host:port` 存进 `CYY_STATIC_PROXY`，脚本会先验证出口 IP 再干活；配好后把 `daily.yml` 里两行 `# - cron:` 的注释去掉，定时即恢复。

---

## 七、常见日志含义

| 日志 | 含义 | 处理 |
|---|---|---|
| `完成：4 成功 / 0 失败` | 全部正常 | 不用管 |
| `登录失败: code=299` | 当天密码错误次数用完 | 别重试，等第二天 |
| `重复数据` | 这个任务今天已经做过了 | 正常，算成功 |
| `member_id不能为空` + `未完成该任务` | 上报缺字段，脚本已修 | 如果再现，说明接口改了 |
| `完成：0 成功 / 4 失败` | 全军覆没 | 先看是不是 IP 被拦，再看密码 |
| `Could not find a suitable TLS CA certificate bundle` | 证书路径问题 | Linux runner 不会出现（用 certifi） |

---

## 八、本地对照物

- `core.py` 与手机 Termux 上那份**完全一致**，只是仓库这份额外支持 `CYY_STATIC_PROXY` 环境变量；
- 桌面版 `草原云v4.4.exe` 是同一套逻辑的图形界面版，可以留着应急手动跑。
