# Upgrade contract: requested subgo items 4–8 (2026-10-25)

Only implement the user-authorized conversion diagnostics, credential/script boundaries, subscription editor correctness, search/bulk/mobile controls, and observable tasks/feedback. Keep node/source/subscription data, tokens, public URLs and existing API compatibility. Do not rewrite node identity/snapshot pruning or empty-selection models (audit items 1–2); targeted control compatibility fixes needed for items 7–8 are permitted. Do not rebuild subgo2; its shared backend/security remains supported.

Working tree: `/root/.openclaw/workspace/subgo`, production untouched until parent deploys. Baseline source equals `/opt/subgo/src`, workspace HEAD d89d063, production f9dac6d with preserved patches. Audit and previous synthetic evidence: `../reviews/subgo-2026-10-25/`.

## Ownership (no cross-worker source edits)

- Conversion: `internal/subconv/**`, `internal/services/subscription/**`, new `internal/server/conversion_routes.go` + tests. No server.go/config/auth/frontend writes.
- Security: `internal/services/auth/**`, `internal/db/db.go`, `internal/config/config.go`, new `internal/server/security.go` + tests. Produce explicit integration instructions; no server.go or frontend writes, no production secrets/config changes.
- Tasks: `internal/server/server.go`, new task-related server files, `internal/services/connectivity/**`, `internal/services/source/**` (context/locking only), `internal/services/node/**`, new `internal/services/jobs/**`. Preserve algorithms outside requested scope. No auth/config/db/frontend/subscription/subconv source edits.
- Frontend: `web/**` including local pinned QR library and license. No backend or config writes. Parent integrates shared hooks, controls release/deployment/DNS/TLS, and QA.

Do not commit/push/reset, restart services, access production DB/credentials, run real upstream mutations/sync or true production speedtests. Test only with blank synthetic DBs/mocked sources/local fixtures. Read official protocol/platform docs before introducing new configuration syntax. No dependency installs or browser troubleshooting rabbit holes; report precise blockers.

## Agreed JSON contracts

All new management endpoints are authenticated, same-origin checked. No diagnostics/task output may contain raw links, bearer tokens or passwords.

### Conversion (conversion owner)

- `POST /api/subscriptions/preview` JSON `{node_hashes:[...], source_ids?:[...]}`. This is a non-mutating preview of an explicit node selection; empty selection must not accidentally query all nodes.
- `GET /api/subscriptions/:id/diagnostics` preview existing subscription's effective export, with no access-count/log increment.
- Result `{ok:true, report:{input_count,converted_count,skipped_count,valid,errors:[],warnings:[],items:[{index,node_id?,name,protocol,status,code,reason}]}}`.
- Preserve existing plain/Clash public routes; correct conversion mappings, deterministic globally unique names and final configuration references; report unsupported/invalid nodes. Existing wrappers remain source-compatible. Expose counts via safe response headers when feasible. No raw credentials in reports.
- Register new management routes via `s.registerConversionRoutes(api)` in conversion_routes.go; parent/tasks owner adds this hook after implementation.

### Jobs / bulk (tasks owner)

- `POST /api/tasks/sync` `{source_ids?:[...]}`. Absent source_ids means all enabled non-local sources; explicit empty scope must not expand to all.
- `POST /api/tasks/connectivity` `{node_ids?:[real ids], source_id?:id, limit?:n}`. Respect scope, enabled sources/nodes and missing status; explicit empty array does not mean all.
- `GET /api/tasks` active + bounded recent tasks and recent-success summary; `GET /api/tasks/:id`; `POST /api/tasks/:id/cancel`.
- Result `{ok:true,task:{id,type,status,total,completed,succeeded,failed,progress_percent,elapsed_ms,created_at,started_at?,finished_at?,message,error,results:[],cancellable}}`.
- Status vocabulary queued/running/completed/partial/failed/cancelling/cancelled. Cancellation must reach source HTTP requests / connectivity subprocesses, and processes must be Wait-ed.
- `POST /api/nodes/bulk-toggle` `{node_ids:[real ids],enabled:boolean}`; transactional validation and explicit target state; no bulk deletion. Return `{ok:true,updated:n}`.
- Preserve old synchronous endpoints as compatibility aliases backed by the same guarded executor where practical, so old UI/API consumers do not silently break. Surface scheduled sync progress too; no notification posting.

### Security / panel origin (security owner + parent deployment)

- Persistent session generation/revocation: password/account change invalidates old sessions; current logout revokes current session; log-retention-only changes must not revoke sessions. Keep current passwords and signed secret; remove known insecure fallback.
- Management Origin/Fetch-Metadata protection; cookie HttpOnly + Secure when canonical deployment is HTTPS, including subgo2 proxy paths without X-Forwarded-Proto. Session-bound tokens and proxy tickets cannot substitute for each other.
- Isolated proxy origin default deployment choice `https://subgo-panel.2000319.xyz`, configurable via `SUBGO_PANEL_PROXY_BASE_URL`. Parent provisions only if unallocated; no replacement of an existing site.
- `POST /api/panel-proxy/ticket` `{source_id:id}` returns `{ok:true,url:isolated short-lived ticket URL}`. Host-bound, source-scoped, short-lived one-time launch ticket -> host-only Secure HttpOnly proxy cookie scoped to that source. Strip ticket from URL promptly, no-referrer/no-store. Old main-origin proxy GET may securely redirect authenticated users; never serve active upstream scripts on management origin.
- Proxy origin cannot serve management API even if an attacker sets Host; scoped proxy cookie cannot authenticate management routes. Strip unsafe Domain and protect subgo cookie names; preserve appropriate upstream cookie expiry/Secure flags.
- Parent moves existing secret from unit into 0600 EnvironmentFile, sets observed service user's/group's DB/WAL/backup permissions and UMask 0077. Preserve current data paths/account and unit Group; no secrets in stdout/reports.

### Frontend (frontend owner)

- Always display complete selected set and source groupings independently of candidate filter; show add/remove preview before save; retain selections on searches/filter changes; reject stale modal/network responses via sequence/AbortController.
- Name/protocol/source/health search/filter, explicitly scoped selection/bulk enable/disable, actual real IDs not display labels. No accidental whole-host actions.
- Real task progress/cancel/history/recent success with bounded polling only while jobs active; no fake auto-connectivity controls if backend doesn't implement them.
- Global visible toast/aria-live and local modal errors; robust 401 handling; busy states; eliminate upstream-string inline-handler interpolation.
- Offline/self-hosted QR generation (no third-party requests), direct-copy action separate from QR; pinned library license. Coordinate serving asset route with parent.
- Mobile 320/420 px and 200% zoom: controls reachable, dialog semantics/Escape/focus return, maintain focus after checkbox updates; no user-scalable=no. Preserve existing visual style and all legacy flows.

## Verification / delivery

Each owner saves concise changes + tests + integration hooks + remaining limitations to `/root/.openclaw/workspace/projects/subgo-upgrade-20261025/<lane>.md`. Favor bounded tests over wide new tooling. Parent performs full Go test/vet/build/race, API negative cases, real browser interaction on synthetic/staging data, public TLS checks and data integrity comparison. No claiming mock DOM tests as browser layout proof. Keep this task open until all 4–8 items are verified/deployed or a genuinely unavailable authority is identified.
