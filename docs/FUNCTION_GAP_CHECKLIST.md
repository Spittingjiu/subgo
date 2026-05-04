# subgo 功能差异清单（对标 sui-sub）

> 老板最新口径：subgo 不需要读取旧数据、不优先做旧库迁移；按全新 Go 系统建设，后期一个一个重新导入源。目标是在功能上全面对标现有 Sub/sui-sub，并利用 Go 的优势把关键链路做得更快、更强、更稳。

## 状态标记

- ✅ 已完成
- 🟡 进行中
- ⬜ 待补齐
- 🔒 安全/稳定性重点

## 0. 当前已完成

- ✅ GitHub 仓库：`https://github.com/Spittingjiu/subgo`
- ✅ Go module 与基础目录结构
- ✅ 展示域名：`https://subgo.zzao.de/`
- ✅ systemd 部署：`subgo.service`
- ✅ HTTPS/Nginx 反代
- ✅ `/healthz`、`/api/version`
- ✅ Go 优势落地说明：`docs/GO_ADVANTAGES.md`

## 1. 基础架构与数据层

| 功能 | 旧 Sub 状态 | subgo 状态 | Go 重构要求 |
|---|---:|---:|---|
| SQLite 数据存储 | ✅ | ⬜ | 新 schema 即可，不做旧 DB 迁移优先 |
| schema migration | 部分隐式 ALTER | ⬜ | Go migration 显式版本化，可重复执行 |
| repository 层 | 单文件 SQL | ⬜ | 强类型 repository + transaction |
| 配置加载 | env + 常量 | ✅ 基础 | viper/env/file，保留 env 优先 |
| 服务启动 | Node 单进程 | ✅ | Go 单二进制 + systemd |
| 前端资源 | public 静态 | ⬜ | 后期 embed 到二进制 |

## 2. 登录与管理账号

| 功能 | 旧 Sub endpoint | subgo 状态 | 备注 |
|---|---|---:|---|
| 登录 | `POST /api/auth/login` | ⬜ | Cookie session 或 JWT cookie |
| 登出 | `POST /api/auth/logout` | ⬜ | 清 cookie |
| 当前用户 | `GET /api/auth/me` | ⬜ | 前端 bootstrap 依赖 |
| 管理账号读取 | `GET /api/admin/user` | ⬜ | 不返回敏感信息 |
| 管理账号修改 | `POST /api/admin/user` | ⬜ | 密码 hash 存储，禁止明文 |
| CSRF/同源防护 | middleware | ⬜ 🔒 | Go middleware 下沉 |

## 3. 源管理（后期逐个导入源）

| 源类型 | 旧 Sub 状态 | subgo 状态 | 要求 |
|---|---:|---:|---|
| SUI API 源 `sui_api` | ✅ | ⬜ | 支持 token 或账号密码换 token |
| SBUI/S-Matrix 源 `sbui` | ✅ | ⬜ | 支持 discover + `/api/v1/sub/default` |
| Cloudflare/raw subscription `cf_sub` | ✅ | ⬜ | HTTP 拉取 + SSRF 防线 |
| 本地节点 `local` | ✅ | ⬜ | 手工录入 raw link |
| localhost 源兼容 | ✅ | ⬜ | 视情况保留 |
| 源列表 | `GET /api/sources` | ⬜ | 支持状态、上次同步时间 |
| 新增源 | `POST /api/sources` | ⬜ | 新系统从零导入 |
| 修改源 | `PUT /api/sources/:id` | ⬜ | token/地址/名称/启停 |
| 删除源 | `DELETE /api/sources/:id` | ⬜ | 清关联节点与订阅引用 |
| 单源同步 | `POST /api/sources/:id/sync` | ⬜ | 必须先做，避免 sync-all 被慢源拖死 |
| 全量同步 | `POST /api/sources/sync-all` | ⬜ | worker pool 并发，单源失败隔离 |
| 同步失败隐藏节点 | ✅ | ⬜ | 对标旧逻辑：失败源节点不显示/不输出 |

## 4. 节点管理

| 功能 | 旧 Sub endpoint | subgo 状态 | 要求 |
|---|---|---:|---|
| 节点列表 | `GET /api/nodes` | ⬜ | 支持 source filter、enabled filter |
| 前端节点视图 | `GET /api/view/nodes` | ⬜ | 可先由统一 API 替代 |
| 节点稳定 hash | internal | ⬜ | raw link canonical hash |
| 显示编号 | internal | ⬜ | 保持可读 ID，如 `S1-001`/`L-001` |
| 节点开关 | `POST /api/nodes/:id/toggle` | ⬜ | 影响订阅输出 |
| 节点重命名 | `PUT /api/nodes/:id/rename` | ⬜ | raw link name 同步改写 |
| 本地节点新增 | `POST /api/local-nodes` | ⬜ | 输入 raw link，解析校验 |
| 本地节点删除 | `DELETE /api/local-nodes/:id` | ⬜ | 仅 local 允许删除 |
| 协议识别 | internal | ⬜ | vless/hy2/ss/trojan/vmess 等 |

## 5. 订阅管理与输出

| 功能 | 旧 Sub endpoint | subgo 状态 | Go 重构要求 |
|---|---|---:|---|
| 订阅列表 | `GET /api/subscriptions` | ⬜ | token、节点数、访问统计 |
| 创建订阅 | `POST /api/subscriptions` | ⬜ | 按 source_ids/node_ids 组合 |
| 修改订阅 | `PUT /api/subscriptions/:id` | ⬜ | 支持重命名、节点范围调整 |
| 删除订阅 | `DELETE /api/subscriptions/:id` | ⬜ | 删除 token |
| plain 输出 | `/sub/:token`, `/api/sub/:token/plain` | ⬜ | streaming writer |
| Clash/Mihomo 输出 | `/sub/:token/clash` | ⬜ | 强类型生成 YAML |
| 订阅访问日志 | `GET /api/admin/subscription-logs` | ⬜ | 异步/批量写，避免阻塞拉订阅 |
| 自动裁剪不可用节点 | 字段已存在 | ⬜ | 和连通性检测联动 |
| 模板支持 | clash template URL | ⬜ | 可后置，先保证内置模板 |

## 6. 连通性检测与 mihomo 内核

| 功能 | 旧 Sub endpoint | subgo 状态 | Go 优势落地 |
|---|---|---:|---|
| 内核状态 | `GET /api/kernel/status` | ⬜ | 检测版本/路径 |
| 安装 mihomo | `POST /api/kernel/install` | ⬜ | 下载校验、原子替换 |
| 卸载 mihomo | `POST /api/kernel/uninstall` | ⬜ | 安全删除指定路径 |
| 单批检测 | `POST /api/nodes/connectivity/check` | ⬜ | context timeout + worker pool |
| 检测结果 | `GET /api/nodes/connectivity` | ⬜ | latency/status/error |
| 手动全量检测 | `POST /api/admin/connectivity/run-now` | ⬜ | 后台任务化 |
| 自动周期检测 | settings | ⬜ | ticker + 防重入 |

## 7. 上游面板管理

| 功能 | 旧 Sub endpoint | subgo 状态 | 备注 |
|---|---|---:|---|
| 安全反代 | `ALL /panel-proxy/:sourceId/*` | ⬜ 🔒 | Cookie/Origin/Referer 改写，SSRF 防线 |
| SUI inbound 列表 | `GET /api/sui/:sourceId/inbounds` | ⬜ | SUI adapter |
| 一键 Reality | `POST /api/sui/:sourceId/reality-quick` | ⬜ | 上游创建，不是本机创建 |
| inbound 重命名 | `PUT /api/sui/:sourceId/inbounds/:inboundId/rename` | ⬜ | SUI/SBUI 分支适配 |
| inbound 删除 | `DELETE /api/sui/:sourceId/inbounds/:inboundId` | ⬜ | 高风险操作需确认/审计 |
| SUI bridge push | `POST /api/bridge/push-source` | ⬜ | 后置，E2EE meta 一起做 |

## 8. 前端页面

| 页面/模块 | 旧 Sub 状态 | subgo 状态 | 要求 |
|---|---:|---:|---|
| 登录页 | ✅ | ⬜ | 简洁可用 |
| 首页统计 | ✅ | ⬜ | 源/节点/订阅/健康概览 |
| 源管理 | ✅ | ⬜ | 新增、编辑、同步、删除 |
| 节点管理 | ✅ | ⬜ | 过滤、开关、重命名、本地节点 |
| 订阅管理 | ✅ | ⬜ | 创建/复制 plain/clash 链接 |
| 连通性检测 | ✅ | ⬜ | 批量检测、结果展示 |
| 上游 SUI 管理 | ✅ | ⬜ | inbounds、一键 Reality |
| 移动端适配 | 部分 | ⬜ | 后台必须手机可用 |

## 9. 安全红线

- ⬜ SSRF 阻断：禁止请求私网、loopback、link-local、metadata IP。
- ⬜ URL scheme 限制：仅 http/https。
- ⬜ 上游 credential/token 不进入前端 bootstrap。
- ⬜ panel proxy 不透传 subgo 自身 cookie 到上游。
- ⬜ Set-Cookie 改写必须绑定 proxy path/source。
- ⬜ 删除源、删除 inbound、本地节点删除等写操作需要审计。
- ⬜ 订阅 token 使用高熵随机值。

## 10. 推荐实施顺序

1. ⬜ 新 schema + migration + repository
2. ⬜ 登录/session/admin settings
3. ⬜ local node + plain subscription 输出（最快形成闭环）
4. ⬜ raw/cf_sub source 导入与同步
5. ⬜ subscription CRUD + Clash/Mihomo 输出
6. ⬜ SBUI source adapter
7. ⬜ SUI source adapter
8. ⬜ 连通性检测 worker pool
9. ⬜ 前端管理台补齐
10. ⬜ panel proxy 与上游管理能力
11. ⬜ 灰度对比旧 Sub 行为，逐项补齐

## 11. 不做/后置

- 不优先读取旧 `sui-sub.db`。
- 不优先做旧数据自动迁移。
- 不为了兼容旧实现牺牲 Go 架构；但对外功能要对标。
