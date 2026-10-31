package subscription

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Spittingjiu/subgo/internal/models"
	"github.com/Spittingjiu/subgo/internal/subconv"
)

// Preview is read-only and ALWAYS interprets nodeHashes as an explicit set.
// Even nil/empty input returns zero nodes; sourceIDs may only narrow that set.
func (s *Service) Preview(nodeHashes []string, sourceIDs []int64, autoPruneUnreachable bool, template []byte) (subconv.Report, error) {
	return s.PreviewContext(context.Background(), nodeHashes, sourceIDs, autoPruneUnreachable, template)
}

func (s *Service) PreviewContext(ctx context.Context, nodeHashes []string, sourceIDs []int64, autoPruneUnreachable bool, template []byte) (subconv.Report, error) {
	sub := models.Subscription{Enabled: true, NodeHashes: nodeHashes, SourceIDs: sourceIDs, AutoPruneUnreachable: autoPruneUnreachable}
	inputs, err := s.exportInputs(ctx, sub, true, true)
	if err != nil {
		return subconv.Report{}, err
	}
	_, report, _ := subconv.ClashYAMLForInputs(inputs, template)
	// Configuration failures are represented in the report, not hidden behind
	// an HTTP 500. Only database/read failures return a service error.
	return report, nil
}

// Diagnostics previews the existing subscription's *current* effective public
// Clash selection. It deliberately retains the legacy nodes/sources/all model
// and records neither a public fetch nor a privileged mutation.
func (s *Service) Diagnostics(id int64, template []byte) (subconv.Report, error) {
	return s.DiagnosticsContext(context.Background(), id, template)
}

func (s *Service) DiagnosticsContext(ctx context.Context, id int64, template []byte) (subconv.Report, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,token,source_ids_json,node_ids_json,enabled,auto_prune_unreachable,access_count,last_accessed_at,created_at,updated_at FROM subscriptions WHERE id=?`, id)
	sub, err := scanSub(row, "")
	if err != nil {
		return subconv.Report{}, err
	}
	inputs, err := s.exportInputs(ctx, sub, false, false)
	if err != nil {
		return subconv.Report{}, err
	}
	_, report, _ := subconv.ClashYAMLForInputs(inputs, template)
	if !sub.Enabled {
		report.AddError("subscription_disabled", "The subscription is disabled and its public export is unavailable.")
	}
	var hashes []string
	var sources []int64
	if json.Unmarshal([]byte(sub.NodeHashesJSON), &hashes) != nil || json.Unmarshal([]byte(sub.SourceIDsJSON), &sources) != nil {
		report.AddError("invalid_stored_selection", "The stored selection JSON is malformed; current legacy export behavior is reported without rewriting the selection model.")
	}
	if len(sub.NodeHashes) == 0 && len(sub.SourceIDs) == 0 {
		report.AddWarning("legacy_empty_scope", "Both stored selections are empty; the existing public exporter selects all enabled sources. Diagnostics does not change this legacy selection model.")
	}
	return report, nil
}

// ClashWithReport is a source-compatible extension of Clash for HTTP count
// headers/diagnostics. The public endpoint still records exactly one access.
func (s *Service) ClashWithReport(token, clientIP, ua string, template []byte) (string, subconv.Report, error) {
	sub, err := s.getByToken(token)
	if err != nil {
		return "", subconv.Report{}, err
	}
	if !sub.Enabled {
		return "", subconv.Report{}, errors.New("subscription disabled")
	}
	inputs, err := s.exportInputs(context.Background(), sub, false, false)
	if err != nil {
		if !isLocalTestIP(clientIP) {
			now := time.Now().UTC().Format(time.RFC3339)
			_, _ = s.db.Exec(`INSERT INTO subscription_logs(token,subscription_id,subscription_name,route_type,client_ip,user_agent,status,error_message,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, token, sub.ID, sub.Name, "clash", clientIP, ua, "fail", "导出节点错误: "+err.Error(), now)
		}
		return "", subconv.Report{}, err
	}
	out, report, err := subconv.ClashYAMLForInputs(inputs, template)
	now := time.Now().UTC().Format(time.RFC3339)
	if err != nil {
		if !isLocalTestIP(clientIP) {
			_, _ = s.db.Exec(`INSERT INTO subscription_logs(token,subscription_id,subscription_name,route_type,client_ip,user_agent,status,error_message,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, token, sub.ID, sub.Name, "clash", clientIP, ua, "fail", "Clash配置转换失败: "+err.Error(), now)
		}
		return "", report, err
	}
	if !isLocalTestIP(clientIP) {
		_, _ = s.db.Exec(`UPDATE subscriptions SET access_count=access_count+1,last_accessed_at=? WHERE id=?`, now, sub.ID)
		_, _ = s.db.Exec(`INSERT INTO subscription_logs(token,subscription_id,subscription_name,route_type,client_ip,user_agent,status,error_message,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, token, sub.ID, sub.Name, "clash", clientIP, ua, "success", "", now)
	}
	return out, report, nil
}

// exportInputs only reads nodes/state. Selection precedence for saved/public
// subscriptions remains nodes > sources > all, exactly as the legacy links SQL.
// Explicit previews cannot reach the sources/all branches, including nil slices.
func (s *Service) exportInputs(ctx context.Context, sub models.Subscription, explicitNodes, narrowSources bool) ([]subconv.ConversionInput, error) {
	if explicitNodes && len(sub.NodeHashes) == 0 {
		return []subconv.ConversionInput{}, nil
	}
	q := `SELECT n.id,n.node_hash,n.raw_link,n.node_name,n.protocol,n.source_id,n.enabled,COALESCE(n.missing_since,''),s.id,COALESCE(s.enabled,0),COALESCE(s.name,''),EXISTS(SELECT 1 FROM node_connectivity nc WHERE nc.node_id=n.id AND nc.status='fail') FROM nodes n LEFT JOIN sources s ON s.id=n.source_id`
	args := []any{}
	if len(sub.NodeHashes) > 0 {
		q += ` WHERE n.node_hash IN (` + placeholders(len(sub.NodeHashes)) + `)`
		for _, hash := range sub.NodeHashes {
			args = append(args, hash)
		}
	} else if len(sub.SourceIDs) > 0 {
		q += ` WHERE n.source_id IN (` + placeholders(len(sub.SourceIDs)) + `)`
		for _, id := range sub.SourceIDs {
			args = append(args, id)
		}
	}
	q += ` ORDER BY n.id ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inputs := []subconv.ConversionInput{}
	found := map[string]subconv.ConversionInput{}
	allowedSources := map[int64]bool{}
	for _, id := range sub.SourceIDs {
		allowedSources[id] = true
	}
	for rows.Next() {
		var input subconv.ConversionInput
		var missing string
		var sourceExists sql.NullInt64
		var nodeEnabled, sourceEnabled, connectivityFail int
		if err := rows.Scan(&input.NodeID, &input.NodeHash, &input.RawLink, &input.Name, &input.Protocol, &input.SourceID, &nodeEnabled, &missing, &sourceExists, &sourceEnabled, &input.SourceName, &connectivityFail); err != nil {
			return nil, err
		}
		found[input.NodeHash] = input
		switch {
		case !sub.Enabled:
			input.SkipCode, input.SkipReason = "subscription_disabled", "The subscription is disabled."
		case narrowSources && len(allowedSources) > 0 && !allowedSources[input.SourceID]:
			input.SkipCode, input.SkipReason = "outside_source_scope", "The selected node is outside the explicitly supplied source filter."
		case !sourceExists.Valid:
			input.SkipCode, input.SkipReason = "source_missing", "The selected node no longer has a source."
		case sourceEnabled != 1:
			input.SkipCode, input.SkipReason = "source_disabled", "The selected node's source is disabled."
		case nodeEnabled != 1:
			input.SkipCode, input.SkipReason = "node_disabled", "The selected node is disabled."
		case missing != "":
			input.SkipCode, input.SkipReason = "node_missing", "The selected node is missing from the current source snapshot."
		case sub.AutoPruneUnreachable && connectivityFail == 1:
			input.SkipCode, input.SkipReason = "unreachable_pruned", "The selected node is excluded by the current auto-prune setting and stored failed connectivity status."
		}
		inputs = append(inputs, input)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Keep missing and repeated explicitly selected hashes and source metadata
	// visible. These are the same non-secret identities used by management APIs;
	// they are never interpreted as raw links or expanded to a wider scope.
	seen := map[string]bool{}
	for _, hash := range sub.NodeHashes {
		if seen[hash] {
			input, present := found[hash]
			if !present {
				input = subconv.ConversionInput{NodeHash: hash, Name: "unavailable-node", Protocol: "unknown"}
			}
			input.SkipCode, input.SkipReason = "duplicate_selection", "The same node was selected more than once; duplicate selection is ignored."
			inputs = append(inputs, input)
		} else if _, present := found[hash]; !present {
			inputs = append(inputs, subconv.ConversionInput{NodeHash: hash, Name: "unavailable-node", Protocol: "unknown", SkipCode: "node_not_found", SkipReason: "The selected node hash no longer identifies a stored node."})
		}
		seen[hash] = true
	}
	return inputs, nil
}

// Selection parameters are data, not SQL identifiers. The route caps request
// size, and these helpers preserve the established hashed node identity model.
func validPreviewScope(hashes []string, sourceIDs []int64) bool {
	if len(hashes) > 2000 || len(sourceIDs) > 2000 {
		return false
	}
	for _, hash := range hashes {
		if strings.TrimSpace(hash) == "" || len(hash) > 256 || strings.Contains(hash, "://") {
			return false
		}
	}
	for _, id := range sourceIDs {
		if id < 1 {
			return false
		}
	}
	return true
}

// ValidatePreviewScope is exported for the management route, not for mutation
// endpoints. It does not reject an explicitly empty selection.
func ValidatePreviewScope(hashes []string, sourceIDs []int64) bool {
	return validPreviewScope(hashes, sourceIDs)
}
