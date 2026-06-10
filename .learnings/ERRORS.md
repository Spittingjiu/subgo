
## [ERR-20260504-001] json_binding_tags
**Logged**: 2026-05-04T07:43:00Z
**Priority**: medium
**Status**: resolved
**Area**: backend

### Summary
First subgo local-node/subscription smoke test failed because combined Go struct fields shared an incorrect JSON tag.

### Error
`POST /api/local-nodes` returned HTTP 400 even though the request body included `raw_link`.

### Context
Anonymous inline request structs used combined fields like `RawLink, Name string \`json:"raw_link"\`` and `NodeIDs, SourceIDs []int64 \`json:"node_ids"\``, so only one JSON key was represented correctly and source/node IDs were not bound as intended.

### Suggested Fix
Use explicit fields and tags for every request field; avoid grouped fields in API binding structs.

### Metadata
- Reproducible: yes
- Related Files: internal/server/server.go

### Resolution
- **Resolved**: 2026-05-04T07:43:00Z
- **Notes**: Split request structs into explicitly tagged fields and reran smoke tests.

## [ERR-20260610-001] subgo_mihomo_kernel_refactor_build
**Logged**: 2026-06-10T11:36:30Z
**Priority**: low
**Status**: resolved
**Area**: backend

### Summary
Initial Subgo connectivity-kernel refactor failed build because old sing-box imports/constants were partially removed while legacy fallback helper code still referenced them.

### Error
`archive/tar` imported and not used; later `undefined: KernelBin` in `connectivity.go`.

### Context
Changed Subgo testing kernel from sing-box to Mihomo. The default connectivity path was moved to `checkWithMihomo`, but legacy `checkWithSingBox` remained compiled for fallback/reference.

### Suggested Fix
When switching default engine but keeping fallback code, either remove the fallback fully or keep a distinct legacy constant (`LegacySingBoxBin`) and clean unused imports.

### Metadata
- Reproducible: yes
- Related Files: `/opt/subgo/src/internal/services/connectivity/connectivity.go`

### Resolution
- **Resolved**: 2026-06-10T11:38:00Z
- **Notes**: Removed unused `archive/tar`, added `LegacySingBoxBin`, and `go test ./...` passes.
