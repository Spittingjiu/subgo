# subgo：Go 语言优势落地清单

subgo 不是把 Node 代码逐行翻译成 Go，而是借 Go 的工程优势重做 Sub 的关键路径。

## 1. 并发同步与检测

- 每个 source 同步使用 `context.Context` 管理超时和取消。
- 连通性检测使用 bounded worker pool，防止一次检测把机器打满。
- sync-all 不再被单个慢源拖死；慢源只影响自己，状态写入后节点可自动隐藏。

## 2. 强类型订阅解析

- raw link 解析为协议结构体：VLESS/HY2/SS/Trojan 等。
- Reality、xhttp、flow、sni、sid、pbk 等关键字段单独建模。
- Clash/Mihomo/Sing-box 输出从结构体生成，减少字符串拼接导致的缺参/错参。

## 3. 单二进制与低运维成本

- 目标形态：一个 subgo 二进制 + SQLite 数据目录 + systemd。
- 前端资源后续可 embed，部署/回滚只需要替换二进制。
- CI 可以直接产出 Linux amd64/arm64 release artifact。

## 4. 高吞吐订阅输出

- 订阅输出采用 streaming writer，避免大订阅一次性堆进内存。
- 热门订阅 token 可做短 TTL 缓存。
- 访问日志异步写入，避免客户端拉订阅被日志 IO 拖慢。

## 5. 安全边界下沉

- SSRF/私网 IP 阻断做成 HTTP client transport/middleware。
- panel proxy 的 Cookie/Origin/Referer 改写集中实现。
- 上游 token、panel credential 不进入前端 bootstrap payload。

## 6. 可测试与可迁移

- schema migration 独立包管理。
- 旧 `sui-sub.db` 迁移必须可重复 dry-run。
- 订阅转换、节点过滤、同步失败隐藏、Reality/xhttp 参数映射都写单测。
