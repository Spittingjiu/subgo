
## [LRN-20260504-001] correction
**Logged**: 2026-05-04T07:50:00Z
**Priority**: high
**Status**: resolved
**Area**: frontend

### Summary
For subgo, “deploy to webpage” means the domain root must show a usable web UI, not a technical landing page plus hidden `/app`.

### Details
User corrected that they wanted `subgo.zzao.de` to display the actual subgo result in the browser. The previous response over-focused on backend/API progress and left the root page as a project preview, which was not the intended deliverable.

### Suggested Action
Make `/` the management UI, keep project explanation under `/about`, and validate with a browser screenshot rather than only curl/API checks.

### Metadata
- Source: user_feedback
- Related Files: internal/server/server.go
- Tags: web-ui, delivery, subgo

### Resolution
- **Resolved**: 2026-05-04T07:50:00Z
- **Notes**: Root route changed to usable management UI; `/about` keeps project description.
