# subgo Go 全面重构计划

## 旧版能力盘点

来源：`sui-sub` Node/Express + SQLite 单体。

### 必须兼容的核心能力

1. 管理登录与会话
   - `/api/auth/login/logout/me`
   - 管理账号、订阅日志、CSRF/会话保护
2. 源管理
   - SUI API 源
   - Cloudflare/raw subscription 源
   - SBUI / S-Matrix 源
   - local 本地节点源
   - 单源同步、全量同步、同步失败隐藏节点
3. 节点管理
   - 节点列表、显示编号、开关、重命名
   - 本地节点新增/删除
   - 节点 hash 稳定化、名称改写
4. 订阅管理与输出
   - 多订阅 token
   - 按 source/node 组合输出
   - plain links
   - Clash/Mihomo YAML
   - 订阅访问日志
5. 连通性检测
   - mihomo 内核安装/卸载/状态
   - 节点连通性批量检测
   - 自动检测与不可用节点裁剪
6. 上游面板能力
   - `/panel-proxy/:sourceId/*` 安全反代
   - SUI inbound 列表、Reality 一键创建、删除、重命名
   - SBUI inbound 适配
7. 安全边界
   - SSRF 防护
   - Cookie/Set-Cookie 代理改写
   - 私网地址阻断
   - 上游 token/账号密码不泄漏

## Go 架构拆分

- `cmd/subgo`：启动入口
- `internal/config`：配置加载、环境变量
- `internal/db`：SQLite 连接、schema migration
- `internal/models`：数据模型
- `internal/server`：HTTP router / middleware
- `internal/services/auth`：登录、session、admin settings
- `internal/services/source`：源 CRUD 与同步编排
- `internal/services/node`：节点解析、入库、显示编号、状态
- `internal/services/subscription`：订阅 CRUD 与输出
- `internal/services/connectivity`：mihomo 安装与检测
- `internal/adapters/sui`：SUI API client
- `internal/adapters/sbui`：SBUI/S-Matrix adapter
- `internal/adapters/rawsub`：raw subscription adapter
- `internal/subconv`：链接解析、Clash/Mihomo YAML 生成
- `web`：后续前端资源

## 迁移策略

### Phase 0：仓库与骨架
- 初始化 GitHub 仓库 `subgo`
- 建立 Go module、目录结构、README、重构计划
- 提供 health/version API

### Phase 1：新数据层与 schema
- 设计 subgo 新 SQLite schema
- migration 显式版本化，可重复执行
- 建 model 与 repository 层
- 不优先读取旧 `sui-sub.db`，后期通过新增源逐个导入

### Phase 2：订阅核心链路
- raw link 解析
- plain 输出
- Clash/Mihomo YAML 输出
- subscription token 与访问日志

### Phase 3：源同步
- local/raw subscription/SBUI/SUI 适配器
- 单源同步、全量同步
- 同步失败源节点隐藏

### Phase 4：管理 API 与前端
- 登录、源管理、节点管理、订阅管理
- 旧前端功能等价迁移或新前端

### Phase 5：连通性检测与上游管理
- mihomo 管理
- 节点检测
- SUI/SBUI inbound 管理
- panel proxy

### Phase 6：灰度上线
- 使用新系统重新导入源
- 与旧版输出逐项 diff
- Nginx 新域名/路径灰度
- 通过后再切正式入口

## 功能对标清单

详见 `docs/FUNCTION_GAP_CHECKLIST.md`。后续按清单逐项补齐，直到功能全面对标 Sub/sui-sub。

## 第一版验收标准

- `go test ./...` 通过
- `go run ./cmd/subgo` 可启动
- `/healthz`、`/api/version` 返回正常
- 仓库已推送 GitHub
