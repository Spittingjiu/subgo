
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
