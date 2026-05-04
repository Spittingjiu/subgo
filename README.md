# subgo

Go 语言重构版 Sub / sui-sub：面向多源节点聚合、订阅编排、连通性检测与统一分发。

## 目标

- 用 Go 重构现有 Node 单文件实现，拆成清晰模块，便于长期维护。
- 兼容现有 `sui-sub` 核心能力：多源接入、节点同步、本地节点、订阅输出、sing-box/Clash 输出、连通性检测、SUI/SBUI 适配。
- 第一阶段不替换线上服务，先完成可运行骨架与迁移设计。

## 当前状态

仓库已初始化，展示页已部署到 `https://subgo.zzao.de/`。功能差异清单见 `docs/FUNCTION_GAP_CHECKLIST.md`，后续按清单逐项补齐，功能上全面对标 Sub/sui-sub。

## 本地运行

```bash
go run ./cmd/subgo
```

默认监听：`127.0.0.1:8781`。管理台：`/app`。
