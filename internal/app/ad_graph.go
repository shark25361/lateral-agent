package app

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ADGraph is the durable, evidence-backed Active Directory view for a mission.
// It deliberately stores relationships and their provenance, never credential
// values, command lines, tokens, or arbitrary report output.
type ADGraph struct {
	Nodes     []ADGraphNode     `json:"nodes,omitempty"`
	Edges     []ADGraphEdge     `json:"edges,omitempty"`
	Evidence  []ADGraphEvidence `json:"evidence,omitempty"`
	UpdatedAt time.Time         `json:"updated_at,omitempty"`
}

type ADGraphNode struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Label      string            `json:"label"`
	AssetID    string            `json:"asset_id,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type ADGraphEdge struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Target      string   `json:"target"`
	Kind        string   `json:"kind"`
	Label       string   `json:"label,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Port        string   `json:"port,omitempty"`
	Directed    bool     `json:"directed"`
	Status      string   `json:"status"`
	Selected    bool     `json:"selected,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

type ADGraphEvidence struct {
	ID                string    `json:"id"`
	ExecutionID       string    `json:"execution_id,omitempty"`
	ParentExecutionID string    `json:"parent_execution_id,omitempty"`
	StepID            string    `json:"step_id,omitempty"`
	CatalogID         string    `json:"catalog_id,omitempty"`
	Relation          string    `json:"relation"`
	Summary           string    `json:"summary"`
	Path              string    `json:"path,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
}

type ADSelectedRoute struct {
	SourceAssetID      string   `json:"source_asset_id,omitempty"`
	DestinationAssetID string   `json:"destination_asset_id,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	PlanID             string   `json:"plan_id,omitempty"`
	CatalogID          string   `json:"catalog_id,omitempty"`
	Name               string   `json:"name,omitempty"`
	Status             string   `json:"status,omitempty"`
	NodeIDs            []string `json:"node_ids,omitempty"`
	EdgeIDs            []string `json:"edge_ids,omitempty"`
}

type ADGraphView struct {
	MissionID     string            `json:"mission_id"`
	MissionStatus string            `json:"mission_status"`
	Nodes         []ADGraphNode     `json:"nodes"`
	Edges         []ADGraphEdge     `json:"edges"`
	Evidence      []ADGraphEvidence `json:"evidence"`
	SelectedRoute ADSelectedRoute   `json:"selected_route"`
	UpdatedAt     time.Time         `json:"updated_at,omitempty"`
}

type adEvidenceContext struct {
	AssetID string
	StepID  string
	Path    string
}

type adGraphBuilder struct {
	graph         ADGraph
	nodes         map[string]int
	edges         map[string]int
	evidence      map[string]int
	item          ValidatedItem
	observedAt    time.Time
	decodedOutput int
}

func newADGraphBuilder(item ValidatedItem) *adGraphBuilder {
	observed := item.ReportObservedAt
	if observed.IsZero() {
		observed = item.CompletedAt
	}
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	return &adGraphBuilder{nodes: map[string]int{}, edges: map[string]int{}, evidence: map[string]int{}, item: item, observedAt: observed}
}

func normalizedField(value string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func normalizedMap(node map[string]any) map[string]any {
	out := make(map[string]any, len(node))
	for key, value := range node {
		out[normalizedField(key)] = value
	}
	return out
}

func graphString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return ""
	}
}

func graphField(node map[string]any, aliases ...string) string {
	normalized := normalizedMap(node)
	for _, alias := range aliases {
		if value := graphString(normalized[normalizedField(alias)]); value != "" {
			return value
		}
	}
	return ""
}

func graphBool(node map[string]any, aliases ...string) (bool, bool) {
	normalized := normalizedMap(node)
	for _, alias := range aliases {
		value, exists := normalized[normalizedField(alias)]
		if !exists {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed, true
		case string:
			parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
			if err == nil {
				return parsed, true
			}
		}
	}
	return false, false
}

func graphValues(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case map[string]any, string:
		return []any{typed}
	default:
		return nil
	}
}

func graphNodeID(kind, label string) string {
	return normalizedField(kind) + ":" + strings.ToLower(strings.TrimSpace(label))
}

func (b *adGraphBuilder) ensureNode(kind, label, assetID string, properties map[string]string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	identityLabel := label
	if kind == "machine" && assetID != "" {
		identityLabel = assetID
	}
	id := graphNodeID(kind, identityLabel)
	if index, exists := b.nodes[id]; exists {
		node := &b.graph.Nodes[index]
		if node.Label == node.AssetID && label != "" && label != assetID {
			node.Label = label
		}
		if node.AssetID == "" {
			node.AssetID = assetID
		}
		if node.Properties == nil && len(properties) > 0 {
			node.Properties = map[string]string{}
		}
		for key, value := range properties {
			if value != "" {
				node.Properties[key] = value
			}
		}
		return id
	}
	clean := map[string]string{}
	for key, value := range properties {
		if strings.TrimSpace(value) != "" {
			clean[key] = strings.TrimSpace(value)
		}
	}
	b.nodes[id] = len(b.graph.Nodes)
	b.graph.Nodes = append(b.graph.Nodes, ADGraphNode{ID: id, Kind: kind, Label: label, AssetID: assetID, Properties: clean})
	return id
}

func shortGraphID(value any) string {
	digest := hash(value)
	if len(digest) > 20 {
		return digest[:20]
	}
	return digest
}

func (b *adGraphBuilder) addEdge(kind, source, target, label, protocol, port string, directed bool, ctx adEvidenceContext) {
	b.addEdgeWithStatus(kind, source, target, label, protocol, port, directed, "observed", ctx)
}

func (b *adGraphBuilder) addEdgeWithStatus(kind, source, target, label, protocol, port string, directed bool, status string, ctx adEvidenceContext) string {
	if source == "" || target == "" || source == target {
		return ""
	}
	key := strings.Join([]string{kind, source, target, strings.ToLower(label), strings.ToLower(protocol), port}, "\x00")
	edgeID := "edge:" + shortGraphID(key)
	evidenceID := "evidence:" + shortGraphID(strings.Join([]string{b.item.ExecutionID, ctx.StepID, key}, "\x00"))
	if _, exists := b.evidence[evidenceID]; !exists {
		b.evidence[evidenceID] = len(b.graph.Evidence)
		b.graph.Evidence = append(b.graph.Evidence, ADGraphEvidence{
			ID: evidenceID, ExecutionID: b.item.ExecutionID, StepID: ctx.StepID, CatalogID: b.item.CatalogID,
			Relation: kind, Summary: fmt.Sprintf("%s: %s -> %s", strings.ReplaceAll(kind, "_", " "), source, target), Path: ctx.Path, ObservedAt: b.observedAt,
		})
	}
	if index, exists := b.edges[edgeID]; exists {
		edge := &b.graph.Edges[index]
		if status == "verified" {
			edge.Status = status
		}
		if !containsString(edge.EvidenceIDs, evidenceID) {
			edge.EvidenceIDs = append(edge.EvidenceIDs, evidenceID)
		}
		return evidenceID
	}
	b.edges[edgeID] = len(b.graph.Edges)
	b.graph.Edges = append(b.graph.Edges, ADGraphEdge{ID: edgeID, Source: source, Target: target, Kind: kind, Label: label, Protocol: protocol, Port: port, Directed: directed, Status: status, EvidenceIDs: []string{evidenceID}})
	return evidenceID
}

func domainQualified(name, domain string) string {
	if name == "" || domain == "" || strings.Contains(name, "\\") || strings.Contains(name, "@") {
		return name
	}
	return domain + "\\" + name
}

func (b *adGraphBuilder) addDomainMembership(machine, assetID, domain string, ctx adEvidenceContext) {
	machineID := b.ensureNode("machine", machine, assetID, nil)
	domainID := b.ensureNode("domain", domain, "", nil)
	b.addEdge("member_of_domain", machineID, domainID, "domain member", "", "", true, ctx)
}

func (b *adGraphBuilder) parseMachines(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		if label := graphString(raw); label != "" {
			// A hostname in discovery output is not a FourCore asset ID.
			b.ensureNode("machine", label, "", nil)
			continue
		}
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		assetID := graphField(node, "asset_id", "endpoint_id")
		machine := graphField(node, "computer", "computer_name", "machine", "hostname", "host", "fqdn", "name", "asset_id", "id")
		domain := graphField(node, "domain", "domain_name", "dns_domain")
		b.ensureNode("machine", machine, assetID, map[string]string{"domain": domain, "os": graphField(node, "os", "platform")})
		if domain != "" {
			b.addDomainMembership(machine, assetID, domain, ctx)
		}
	}
}

func (b *adGraphBuilder) parseIdentities(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		if label := graphString(raw); label != "" {
			b.ensureNode("identity", label, "", nil)
			continue
		}
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		identity := graphField(node, "identity", "principal", "username", "user", "account", "sam_account_name", "name", "id")
		identity = domainQualified(identity, domain)
		identityID := b.ensureNode("identity", identity, "", map[string]string{"domain": domain, "sid": graphField(node, "sid", "object_sid")})
		if domain != "" {
			domainID := b.ensureNode("domain", domain, "", nil)
			b.addEdge("identity_in_domain", identityID, domainID, "domain identity", "", "", true, ctx)
		}
	}
}

func memberIdentity(raw any, domain string) (kind, label string) {
	if text := graphString(raw); text != "" {
		kind = "identity"
		if strings.HasSuffix(text, "$") {
			kind = "machine"
		}
		return kind, domainQualified(text, domain)
	}
	node, ok := raw.(map[string]any)
	if !ok {
		return "", ""
	}
	kind = strings.ToLower(graphField(node, "kind", "type", "object_class", "principal_type"))
	switch {
	case strings.Contains(kind, "computer") || strings.Contains(kind, "machine") || strings.Contains(kind, "host"):
		kind = "machine"
	case strings.Contains(kind, "group"):
		kind = "group"
	default:
		kind = "identity"
	}
	label = graphField(node, "identity", "principal", "member", "username", "user", "account", "computer", "machine", "hostname", "name", "id")
	memberDomain := graphField(node, "domain", "domain_name")
	if memberDomain == "" {
		memberDomain = domain
	}
	return kind, domainQualified(label, memberDomain)
}

func (b *adGraphBuilder) parseGroups(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			if label := graphString(raw); label != "" {
				b.ensureNode("group", label, "", nil)
			}
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		group := domainQualified(graphField(node, "group", "group_name", "name", "id"), domain)
		groupID := b.ensureNode("group", group, "", map[string]string{"domain": domain, "sid": graphField(node, "sid", "object_sid")})
		if domain != "" {
			domainID := b.ensureNode("domain", domain, "", nil)
			b.addEdge("group_in_domain", groupID, domainID, "domain group", "", "", true, ctx)
		}
		normalized := normalizedMap(node)
		for _, member := range graphValues(normalized["members"]) {
			kind, label := memberIdentity(member, domain)
			memberID := b.ensureNode(kind, label, "", nil)
			b.addEdge("member_of_group", memberID, groupID, "member", "", "", true, ctx)
		}
	}
}

func (b *adGraphBuilder) parseGroupMemberships(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		group := domainQualified(graphField(node, "group", "group_name", "target_group"), domain)
		kind, member := memberIdentity(node, domain)
		if member == group {
			member = graphField(node, "member", "principal", "identity", "user", "account", "computer", "machine")
		}
		memberID := b.ensureNode(kind, member, "", nil)
		groupID := b.ensureNode("group", group, "", map[string]string{"domain": domain})
		b.addEdge("member_of_group", memberID, groupID, graphField(node, "membership_type", "role"), "", "", true, ctx)
	}
}

func (b *adGraphBuilder) parseTrusts(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		source := graphField(node, "source_domain", "from_domain", "domain", "source")
		target := graphField(node, "target_domain", "to_domain", "trusted_domain", "target")
		sourceID := b.ensureNode("domain", source, "", nil)
		targetID := b.ensureNode("domain", target, "", nil)
		direction := graphField(node, "direction", "trust_direction")
		trustType := graphField(node, "trust_type", "type")
		label := strings.Trim(strings.Join([]string{direction, trustType}, " "), " ")
		b.addEdge("domain_trust", sourceID, targetID, label, "", "", !strings.Contains(strings.ToLower(direction), "bidirectional"), ctx)
	}
}

func (b *adGraphBuilder) parseSessions(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		identity := domainQualified(graphField(node, "identity", "principal", "username", "user", "account"), domain)
		machine := graphField(node, "asset_id", "computer", "computer_name", "machine", "hostname", "host", "target")
		if machine == "" {
			machine = ctx.AssetID
		}
		identityID := b.ensureNode("identity", identity, "", map[string]string{"domain": domain})
		machineID := b.ensureNode("machine", machine, "", nil)
		b.addEdge("session_on", identityID, machineID, graphField(node, "session_type", "logon_type", "protocol"), "", "", true, ctx)
	}
}

func (b *adGraphBuilder) parseShares(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		machine := graphField(node, "asset_id", "computer", "machine", "hostname", "host", "server")
		if machine == "" {
			machine = ctx.AssetID
		}
		share := graphField(node, "share", "share_name", "name", "path")
		shareLabel := share
		if machine != "" && share != "" {
			shareLabel = machine + "\\" + strings.TrimLeft(share, "\\")
		}
		machineID := b.ensureNode("machine", machine, "", nil)
		shareID := b.ensureNode("share", shareLabel, "", map[string]string{"path": graphField(node, "path", "unc_path")})
		b.addEdge("hosts_share", machineID, shareID, "network share", "smb", "445", true, ctx)
		for _, alias := range []string{"accessibleby", "principals", "users"} {
			for _, principal := range graphValues(normalizedMap(node)[alias]) {
				kind, label := memberIdentity(principal, graphField(node, "domain"))
				principalID := b.ensureNode(kind, label, "", nil)
				b.addEdge("can_access_share", principalID, shareID, "share access", "smb", "445", true, ctx)
			}
		}
	}
}

func (b *adGraphBuilder) parseACLs(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		principal := domainQualified(graphField(node, "principal", "trustee", "identity", "user", "account", "source"), domain)
		if domain == "" {
			if separator := strings.Index(principal, "\\"); separator > 0 {
				domain = principal[:separator]
			}
		}
		target := graphField(node, "object", "object_name", "resource", "target", "target_object", "path")
		targetKind := strings.ToLower(graphField(node, "object_type", "target_type", "resource_type"))
		switch {
		case strings.Contains(targetKind, "group"):
			targetKind = "group"
			target = domainQualified(target, domain)
		case strings.Contains(targetKind, "computer") || strings.Contains(targetKind, "machine"):
			targetKind = "machine"
		case strings.Contains(targetKind, "share") || strings.HasPrefix(target, `\\`):
			targetKind = "share"
		default:
			targetKind = "resource"
		}
		principalKind := "identity"
		_, knownGroup := b.nodes[graphNodeID("group", principal)]
		if strings.Contains(strings.ToLower(graphField(node, "principal_type", "trustee_type", "source_type")), "group") || knownGroup {
			principalKind = "group"
		}
		principalID := b.ensureNode(principalKind, principal, "", map[string]string{"domain": domain})
		targetAssetID := ""
		if targetKind == "machine" {
			targetAssetID = graphField(node, "target_asset_id", "destination_asset_id", "object_asset_id")
			if target == "" {
				target = targetAssetID
			}
		}
		targetID := b.ensureNode(targetKind, target, targetAssetID, nil)
		rights := graphField(node, "rights", "permissions", "access", "access_mask", "ace_type")
		edgeKind := "acl"
		if targetKind == "machine" && containsAny(strings.ToLower(rights), "admin", "genericall", "full control", "writeall", "write_dacl", "write owner") {
			edgeKind = "admin_to"
		}
		b.addEdge(edgeKind, principalID, targetID, rights, "", "", true, ctx)
	}
}

func (b *adGraphBuilder) parseDelegations(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		source := domainQualified(graphField(node, "principal", "identity", "account", "source", "delegating_principal"), domain)
		target := graphField(node, "target", "target_service", "service", "computer", "machine", "hostname", "delegate_to")
		targetKind := "machine"
		if strings.Contains(target, "/") {
			targetKind = "service"
		}
		sourceID := b.ensureNode("identity", source, "", map[string]string{"domain": domain})
		targetID := b.ensureNode(targetKind, target, "", nil)
		b.addEdge("delegation", sourceID, targetID, graphField(node, "delegation_type", "type", "rights"), "", "", true, ctx)
	}
}

func (b *adGraphBuilder) parseServices(value any, ctx adEvidenceContext, reachableContainer bool) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		reachable, explicit := graphBool(node, "reachable", "service_reachable", "open")
		if (explicit && !reachable) || (reachableContainer && (!explicit || !reachable)) {
			continue
		}
		sourceAssetID := graphField(node, "source_asset_id", "source_id")
		source := sourceAssetID
		if source == "" {
			source = graphField(node, "source", "from")
		}
		if source == "" {
			source = ctx.AssetID
			sourceAssetID = ctx.AssetID
		}
		targetAssetID := graphField(node, "destination_asset_id", "destination_id", "target_asset_id")
		target := targetAssetID
		if target == "" {
			target = graphField(node, "target", "computer", "machine", "hostname", "host")
		}
		protocol := strings.ToLower(graphField(node, "protocol", "remote_protocol", "service", "name"))
		port := graphField(node, "port", "service_port")
		if target == "" && !reachableContainer {
			target = ctx.AssetID
			targetAssetID = ctx.AssetID
		}
		targetMachineID := b.ensureNode("machine", target, targetAssetID, nil)
		serviceLabel := strings.Trim(strings.Join([]string{target, protocol, port}, ":"), ":")
		serviceID := b.ensureNode("service", serviceLabel, "", map[string]string{"protocol": protocol, "port": port})
		b.addEdge("service_on", targetMachineID, serviceID, protocol, protocol, port, true, ctx)
		if source != "" && explicit && reachable {
			sourceID := b.ensureNode("machine", source, sourceAssetID, nil)
			b.addEdge("service_reachable", sourceID, serviceID, protocol, protocol, port, true, ctx)
		}
	}
}

// parseProtocolAccess records narrowly scoped, observed protocol capabilities.
// A useful edge must name both a principal/source and a destination; a bare
// boolean is intentionally ignored because it cannot support an auditable path.
func (b *adGraphBuilder) parseProtocolAccess(value any, protocol string, ctx adEvidenceContext) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if !validLateralProtocol(protocol) {
		return
	}
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if allowed, explicit := graphBool(node, "allowed", "value"); !explicit || !allowed {
			continue
		}
		sourceAssetID := graphField(node, "source_asset_id", "source_id")
		source := sourceAssetID
		sourceKind := "machine"
		if source == "" {
			source = graphField(node, "principal", "identity", "user", "account", "group", "source")
			sourceKind = "identity"
		}
		targetAssetID := graphField(node, "destination_asset_id", "destination_id", "target_asset_id", "asset_id")
		target := targetAssetID
		if target == "" {
			target = graphField(node, "target", "computer", "machine", "hostname", "host")
		}
		if source == "" || target == "" {
			continue
		}
		domain := graphField(node, "domain", "domain_name")
		if sourceKind == "identity" {
			source = domainQualified(source, domain)
			if strings.Contains(strings.ToLower(graphField(node, "principal_type", "source_type", "kind")), "group") {
				sourceKind = "group"
			}
		}
		sourceID := b.ensureNode(sourceKind, source, sourceAssetID, map[string]string{"domain": domain})
		targetID := b.ensureNode("machine", target, targetAssetID, nil)
		b.addEdge("can_"+protocol, sourceID, targetID, graphField(node, "reason", "rights", "evidence"), protocol, portString(protocolPort(protocol)), true, ctx)
	}
}

func (b *adGraphBuilder) parseDomainMemberships(value any, ctx adEvidenceContext) {
	for _, raw := range graphValues(value) {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		machine := graphField(node, "asset_id", "computer", "machine", "hostname", "host", "member")
		if machine == "" {
			machine = ctx.AssetID
		}
		assetID := graphField(node, "asset_id", "endpoint_id")
		b.addDomainMembership(machine, assetID, graphField(node, "domain", "domain_name", "dns_domain"), ctx)
	}
}

func (b *adGraphBuilder) parseDirectRoute(node map[string]any, ctx adEvidenceContext) {
	source := graphField(node, "source_asset_id", "source_id")
	target := graphField(node, "destination_asset_id", "destination_id", "target_asset_id")
	protocol := strings.ToLower(graphField(node, "protocol", "remote_protocol"))
	if source == "" || target == "" || protocol == "" {
		return
	}
	reachable, hasReachable := graphBool(node, "reachable", "service_reachable")
	if !hasReachable || !reachable {
		return
	}
	b.parseServices(map[string]any{"source_asset_id": source, "destination_asset_id": target, "protocol": protocol, "port": graphField(node, "port"), "reachable": true}, ctx, true)
}

func providerStepPath(path string) bool {
	if !strings.HasPrefix(path, "report.assets[") {
		return false
	}
	last := path[strings.LastIndex(path, ".")+1:]
	return strings.HasPrefix(last, "steps[") || strings.HasPrefix(last, "action_steps[")
}

var discoveryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var discoveryTrust = regexp.MustCompile(`^\d+:\s+\S+\s+([A-Za-z0-9.-]+)\s+\(`)

// The FourCore discovery chain returns bounded command output rather than
// structured AD objects. Interpret only a few exact, successful action names
// with anchored output formats; never treat a ping or chain success as access.
func (b *adGraphBuilder) parseKnownDiscoveryText(step map[string]any, ctx adEvidenceContext) {
	if b.item.CatalogID != "CHAIN_TI067_TERMINALFIX_DISCOVERY_TTPS" || ctx.AssetID == "" || ctx.StepID == "" {
		return
	}
	output, ok := step["output"].(map[string]any)
	if !ok {
		return
	}
	text := graphField(output, "output")
	if text == "" || len(text) > 64<<10 {
		return
	}
	ctx.Path += ".output.output"
	lines := strings.Split(strings.ReplaceAll(text, "\r", ""), "\n")
	if len(lines) > 256 {
		return
	}
	switch graphField(step, "name") {
	case "Multilingual System Information Discovery using Systeminfo and Findstr":
		var host, domain string
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if strings.HasPrefix(line, "Host Name:") {
				host = strings.TrimSpace(strings.TrimPrefix(line, "Host Name:"))
			}
			if strings.HasPrefix(line, "Domain:") {
				domain = strings.TrimSpace(strings.TrimPrefix(line, "Domain:"))
			}
		}
		if discoveryName.MatchString(host) && discoveryName.MatchString(domain) && strings.Contains(domain, ".") {
			b.addDomainMembership(host, ctx.AssetID, domain, ctx)
		}
	case "Domain Trust Enumeration via NLTEST":
		var source string
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if strings.Contains(line, "(Primary Domain)") {
				if match := discoveryTrust.FindStringSubmatch(line); match != nil && strings.Contains(match[1], ".") {
					source = match[1]
				}
			}
		}
		if source == "" {
			return
		}
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			match := discoveryTrust.FindStringSubmatch(line)
			if match == nil || match[1] == source || !strings.Contains(match[1], ".") {
				continue
			}
			from := b.ensureNode("domain", source, "", nil)
			to := b.ensureNode("domain", match[1], "", nil)
			both := strings.Contains(line, "(Direct Outbound)") && strings.Contains(line, "(Direct Inbound)")
			b.addEdge("domain_trust", from, to, "NLTEST reported trust", "", "", !both, ctx)
		}
	case "Domain Administrators Enumeration via Net.exe":
		var domain, group string
		members := false
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if strings.HasPrefix(line, "The request will be processed at a domain controller for domain ") {
				domain = strings.TrimSuffix(strings.TrimPrefix(line, "The request will be processed at a domain controller for domain "), ".")
			}
			if strings.HasPrefix(line, "Group name") {
				group = strings.TrimSpace(strings.TrimPrefix(line, "Group name"))
			}
		}
		if !discoveryName.MatchString(domain) || !strings.Contains(domain, ".") || group != "Domain Admins" {
			return
		}
		groupID := b.ensureNode("group", domain+"\\"+group, "", map[string]string{"domain": domain})
		domainID := b.ensureNode("domain", domain, "", nil)
		b.addEdge("group_in_domain", groupID, domainID, "domain group", "", "", true, ctx)
		count := 0
		for _, raw := range lines {
			line := strings.TrimSpace(raw)
			if line == "Members" {
				members = true
				continue
			}
			if !members || line == "" || strings.HasPrefix(line, "---") {
				continue
			}
			if strings.HasPrefix(line, "The command completed") {
				break
			}
			for _, name := range strings.Fields(line) {
				if !discoveryName.MatchString(name) || count >= 64 {
					continue
				}
				principalID := b.ensureNode("identity", domainQualified(name, domain), "", nil)
				b.addEdge("member_of_group", principalID, groupID, "NLTEST/net group output", "", "", true, ctx)
				count++
			}
		}
	}
}

func (b *adGraphBuilder) walk(value any, ctx adEvidenceContext, depth int) {
	if depth > 12 {
		return
	}
	switch node := value.(type) {
	case []any:
		for index, child := range node {
			childCtx := ctx
			childCtx.Path = fmt.Sprintf("%s[%d]", ctx.Path, index)
			b.walk(child, childCtx, depth+1)
		}
	case string:
		trimmed := strings.TrimSpace(node)
		if b.decodedOutput >= 32 || len(trimmed) == 0 || len(trimmed) > 1<<20 || (trimmed[0] != '{' && trimmed[0] != '[') {
			return
		}
		var decoded any
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		if decoder.Decode(&decoded) == nil {
			b.decodedOutput++
			b.walk(decoded, ctx, depth+1)
		}
	case map[string]any:
		if providerStepPath(ctx.Path) {
			succeeded, explicit := graphBool(node, "success")
			done, hasDone := graphBool(node, "done")
			if !explicit || !succeeded || (hasDone && !done) {
				// A failed or unconfirmed parent may contain a successful child
				// action, but its own output cannot establish a relationship.
				if child, ok := node["action_steps"]; ok {
					childCtx := ctx
					childCtx.Path += ".action_steps"
					b.walk(child, childCtx, depth+1)
				}
				return
			}
		}
		if asset := graphField(node, "asset_id", "endpoint_id"); asset != "" {
			ctx.AssetID = asset
			b.ensureNode("machine", asset, asset, nil)
		}
		if step := graphField(node, "step_id", "id", "action_id"); step != "" && (node["success"] != nil || node["done"] != nil || node["action_id"] != nil || node["stage_name"] != nil) {
			ctx.StepID = step
		}
		if providerStepPath(ctx.Path) {
			b.parseKnownDiscoveryText(node, ctx)
		}
		if domain := graphField(node, "domain", "domain_name", "dns_domain"); domain != "" && ctx.AssetID != "" {
			b.addDomainMembership(ctx.AssetID, ctx.AssetID, domain, ctx)
		}
		b.parseDirectRoute(node, ctx)
		for key, child := range node {
			normalized := normalizedField(key)
			childCtx := ctx
			if childCtx.Path == "" {
				childCtx.Path = key
			} else {
				childCtx.Path += "." + key
			}
			switch normalized {
			case "domains":
				for _, domain := range graphValues(child) {
					if label := graphString(domain); label != "" {
						b.ensureNode("domain", label, "", nil)
					} else if record, ok := domain.(map[string]any); ok {
						b.ensureNode("domain", graphField(record, "domain", "domain_name", "dns_name", "name", "id"), "", nil)
					}
				}
			case "domainmembership", "domainmemberships":
				b.parseDomainMemberships(child, childCtx)
			case "machines", "computers", "hosts", "endpoints":
				b.parseMachines(child, childCtx)
			case "users", "identities", "principals", "accounts":
				b.parseIdentities(child, childCtx)
			case "groups", "adgroups":
				b.parseGroups(child, childCtx)
			case "groupmembership", "groupmemberships", "memberships":
				b.parseGroupMemberships(child, childCtx)
			case "trust", "trusts", "domaintrusts":
				b.parseTrusts(child, childCtx)
			case "session", "sessions", "usersessions", "loggedonsessions":
				b.parseSessions(child, childCtx)
			case "share", "shares", "networkshares":
				b.parseShares(child, childCtx)
			case "acl", "acls", "accesscontrollists", "aces":
				b.parseACLs(child, childCtx)
			case "delegation", "delegations", "constraineddelegation", "resourcebasedconstraineddelegation":
				b.parseDelegations(child, childCtx)
			case "reachableservices", "servicereachability":
				b.parseServices(child, childCtx, true)
			case "services":
				b.parseServices(child, childCtx, false)
			case "cansmb":
				b.parseProtocolAccess(child, "smb", childCtx)
			case "canrdp":
				b.parseProtocolAccess(child, "rdp", childCtx)
			case "canwinrm":
				b.parseProtocolAccess(child, "winrm", childCtx)
			case "canssh":
				b.parseProtocolAccess(child, "ssh", childCtx)
			case "protocolaccess", "remoteaccessrights":
				for _, access := range graphValues(child) {
					if record, ok := access.(map[string]any); ok {
						b.parseProtocolAccess(record, graphField(record, "protocol", "service"), childCtx)
					}
				}
			}
			b.walk(child, childCtx, depth+1)
		}
	}
}

func extractADEvidence(item ValidatedItem) ADGraph {
	if item.Kind == "endpoint_chain" {
		if reportedID := stringField(item.Report, "id"); reportedID != "" && reportedID != item.ExecutionID {
			return ADGraph{}
		}
		if reportedChain := stringField(item.Report, "chain_id"); reportedChain != "" && reportedChain != item.CatalogID {
			return ADGraph{}
		}
	}
	builder := newADGraphBuilder(item)
	// A failed/aborted report may still contain successful individual steps.
	// Parse those steps, but not unbound top-level AD assertions from a run
	// that never completed.
	if item.Status == "completed" {
		builder.walk(item.Report, adEvidenceContext{Path: "report"}, 0)
	} else if assets, ok := item.Report["assets"]; ok {
		builder.walk(map[string]any{"assets": assets}, adEvidenceContext{Path: "report"}, 0)
	}
	// A completed FourCore lateral chain is evidence that the simulation ran
	// on its source, not evidence of access to an unspecified remote machine.
	// Keep it visible in the mission graph without creating a fictitious hop.
	if item.Kind == "endpoint_chain" && item.Status == "completed" && item.Contract != nil &&
		contractProduces(*item.Contract, "lateral_movement_validated") {
		if successful, stepID := reportHasSuccessfulStep(item.Report); successful {
			source := item.SourceAssetID
			if source == "" && len(item.AssetIDs) == 1 {
				source = item.AssetIDs[0]
			}
			label := strings.TrimSpace(item.Name)
			if label == "" {
				label = item.CatalogID
			}
			if source != "" && label != "" && item.ExecutionID != "" {
				sourceID := builder.ensureNode("machine", source, source, nil)
				simulationID := builder.ensureNode("simulation", label, "", map[string]string{"catalog_id": item.CatalogID})
				builder.addEdgeWithStatus("lateral_simulated", sourceID, simulationID, "successful chain action; no remote access inferred", "", "", true, "simulated", adEvidenceContext{StepID: stepID, Path: "report.assets.steps"})
			}
		}
	}
	// An authenticated FourCore execution report may itself contain a
	// destination-specific successful remote-action result. Preserve its
	// provenance as provider-observed, distinct from the signed verifier's
	// stronger destination-verified edge below.
	for _, observation := range fourCoreRemoteObservations(item) {
		sourceID := builder.ensureNode("machine", observation.Source, observation.Source, nil)
		targetID := builder.ensureNode("machine", observation.Destination, observation.Destination, nil)
		evidenceID := builder.addEdgeWithStatus("remote_access", sourceID, targetID, "FourCore-reported as "+observation.Identity, observation.Protocol, "", true, "observed", adEvidenceContext{StepID: observation.StepID, Path: "report.assets.steps"})
		if index, ok := builder.evidence[evidenceID]; ok {
			builder.graph.Evidence[index].ParentExecutionID = observation.ParentExecutionID
		}
	}
	if item.TrustedDestinationEvidence {
		if route, ok := item.Report["route_evidence"].(map[string]any); ok {
			remote, explicit := graphBool(route, "remote_execution_observed")
			source := graphField(route, "source_asset_id")
			target := graphField(route, "destination_asset_id")
			protocol := strings.ToLower(graphField(route, "protocol"))
			if explicit && remote && source != "" && target != "" && validLateralProtocol(protocol) {
				sourceID := builder.ensureNode("machine", source, source, nil)
				targetID := builder.ensureNode("machine", target, target, nil)
				builder.addEdgeWithStatus("remote_access", sourceID, targetID, graphField(route, "remote_identity", "destination_identity", "identity"), protocol, graphField(route, "port"), true, "verified", adEvidenceContext{Path: "report.route_evidence"})
			}
		}
	}
	builder.graph.UpdatedAt = builder.observedAt
	canonicalizeADGraphNodes(&builder.graph)
	sortADGraph(&builder.graph)
	return builder.graph
}

func canonicalizeADGraphNodes(graph *ADGraph) {
	canonicalMachines := map[string]string{}
	canonicalGroups := map[string]string{}
	// An unqualified hostname/group name is only safe to merge when unique.
	unique := func(index map[string]string, key, id string) {
		if previous, exists := index[key]; exists && previous != id {
			index[key] = ""
		} else if !exists {
			index[key] = id
		}
	}
	for _, node := range graph.Nodes {
		if node.Kind == "machine" && node.AssetID != "" {
			unique(canonicalMachines, normalizedField(node.Label), node.ID)
			unique(canonicalMachines, normalizedField(node.AssetID), node.ID)
		}
		if node.Kind == "group" && strings.Contains(node.Label, "\\") {
			parts := strings.Split(node.Label, "\\")
			unique(canonicalGroups, normalizedField(parts[len(parts)-1]), node.ID)
		}
	}
	redirect := map[string]string{}
	for _, node := range graph.Nodes {
		if node.Kind == "machine" && node.AssetID == "" {
			if canonical := canonicalMachines[normalizedField(node.Label)]; canonical != "" && canonical != node.ID {
				redirect[node.ID] = canonical
			}
		}
		if node.Kind == "group" && !strings.Contains(node.Label, "\\") {
			if canonical := canonicalGroups[normalizedField(node.Label)]; canonical != "" && canonical != node.ID {
				redirect[node.ID] = canonical
			}
		}
	}
	if len(redirect) == 0 {
		return
	}
	kept := graph.Nodes[:0]
	for _, node := range graph.Nodes {
		if redirect[node.ID] == "" {
			kept = append(kept, node)
		}
	}
	graph.Nodes = kept
	edges := make([]ADGraphEdge, 0, len(graph.Edges))
	byKey := map[string]int{}
	for _, edge := range graph.Edges {
		if replacement := redirect[edge.Source]; replacement != "" {
			edge.Source = replacement
		}
		if replacement := redirect[edge.Target]; replacement != "" {
			edge.Target = replacement
		}
		if edge.Source == edge.Target {
			continue
		}
		key := strings.Join([]string{edge.Kind, edge.Source, edge.Target, strings.ToLower(edge.Label), strings.ToLower(edge.Protocol), edge.Port}, "\x00")
		edge.ID = "edge:" + shortGraphID(key)
		if index, found := byKey[key]; found {
			if edge.Status == "verified" {
				edges[index].Status = "verified"
			}
			for _, evidenceID := range edge.EvidenceIDs {
				if !containsString(edges[index].EvidenceIDs, evidenceID) {
					edges[index].EvidenceIDs = append(edges[index].EvidenceIDs, evidenceID)
				}
			}
			continue
		}
		byKey[key] = len(edges)
		edges = append(edges, edge)
	}
	graph.Edges = edges
}

func mergeADGraph(existing ADGraph, additions ADGraph) ADGraph {
	nodes := map[string]int{}
	for index := range existing.Nodes {
		nodes[existing.Nodes[index].ID] = index
	}
	for _, node := range additions.Nodes {
		if index, found := nodes[node.ID]; found {
			current := &existing.Nodes[index]
			if current.Label == current.AssetID && node.Label != "" && node.Label != node.AssetID {
				current.Label = node.Label
			}
			if current.AssetID == "" {
				current.AssetID = node.AssetID
			}
			if current.Properties == nil && len(node.Properties) > 0 {
				current.Properties = map[string]string{}
			}
			for key, value := range node.Properties {
				current.Properties[key] = value
			}
			continue
		}
		nodes[node.ID] = len(existing.Nodes)
		existing.Nodes = append(existing.Nodes, node)
	}
	evidence := map[string]bool{}
	for _, item := range existing.Evidence {
		evidence[item.ID] = true
	}
	for _, item := range additions.Evidence {
		if !evidence[item.ID] {
			evidence[item.ID] = true
			existing.Evidence = append(existing.Evidence, item)
		}
	}
	edges := map[string]int{}
	for index := range existing.Edges {
		edges[existing.Edges[index].ID] = index
	}
	for _, edge := range additions.Edges {
		if index, found := edges[edge.ID]; found {
			if edge.Status == "verified" {
				existing.Edges[index].Status = "verified"
			}
			for _, evidenceID := range edge.EvidenceIDs {
				if !containsString(existing.Edges[index].EvidenceIDs, evidenceID) {
					existing.Edges[index].EvidenceIDs = append(existing.Edges[index].EvidenceIDs, evidenceID)
				}
			}
			continue
		}
		edges[edge.ID] = len(existing.Edges)
		existing.Edges = append(existing.Edges, edge)
	}
	if additions.UpdatedAt.After(existing.UpdatedAt) {
		existing.UpdatedAt = additions.UpdatedAt
	}
	canonicalizeADGraphNodes(&existing)
	sortADGraph(&existing)
	return existing
}

func sortADGraph(graph *ADGraph) {
	sort.Slice(graph.Nodes, func(i, j int) bool {
		if graph.Nodes[i].Kind != graph.Nodes[j].Kind {
			return graph.Nodes[i].Kind < graph.Nodes[j].Kind
		}
		return graph.Nodes[i].Label < graph.Nodes[j].Label
	})
	sort.Slice(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].Kind != graph.Edges[j].Kind {
			return graph.Edges[i].Kind < graph.Edges[j].Kind
		}
		return graph.Edges[i].ID < graph.Edges[j].ID
	})
	sort.Slice(graph.Evidence, func(i, j int) bool {
		if !graph.Evidence[i].ObservedAt.Equal(graph.Evidence[j].ObservedAt) {
			return graph.Evidence[i].ObservedAt.Before(graph.Evidence[j].ObservedAt)
		}
		return graph.Evidence[i].ID < graph.Evidence[j].ID
	})
}

func ensureViewNode(view *ADGraphView, kind, label, assetID string) string {
	if kind == "machine" && assetID != "" {
		for _, node := range view.Nodes {
			if node.Kind == "machine" && node.AssetID == assetID {
				return node.ID
			}
		}
	}
	id := graphNodeID(kind, label)
	for _, node := range view.Nodes {
		if node.ID == id {
			return id
		}
	}
	view.Nodes = append(view.Nodes, ADGraphNode{ID: id, Kind: kind, Label: label, AssetID: assetID})
	return id
}

func adGraphContentHash(graph ADGraph) string {
	// UpdatedAt is presentation metadata. Excluding it prevents a read-time
	// backfill from rewriting an otherwise identical mission record.
	graph.UpdatedAt = time.Time{}
	return hash(graph)
}

func (s *Service) backfillMissionADGraph(mission Mission) (Mission, error) {
	plans, err := s.Store.Plans()
	if err != nil {
		return Mission{}, err
	}
	graph := mission.ADGraph
	for _, plan := range plans {
		if plan.MissionID != mission.ID {
			continue
		}
		for _, item := range plan.Items {
			switch item.Status {
			case "pending", "submitting", "running", "collecting_evidence", "skipped":
				continue
			}
			if len(item.Report) == 0 {
				continue
			}
			graph = mergeADGraph(graph, extractADEvidence(item))
		}
	}
	if adGraphContentHash(graph) == adGraphContentHash(mission.ADGraph) {
		return mission, nil
	}
	if err := s.Store.UpdateMission(mission.ID, func(stored *Mission) error {
		stored.ADGraph = graph
		return nil
	}); err != nil {
		return Mission{}, err
	}
	mission.ADGraph = graph
	return mission, nil
}

func (s *Service) MissionADGraph(id string) (ADGraphView, error) {
	mission, err := s.missionByID(id)
	if err != nil {
		return ADGraphView{}, err
	}
	// Older missions may already have durable execution reports from before the
	// graph adapter was added. Build their graph once from those stored reports
	// so opening the viewer does not require another simulation.
	mission, err = s.backfillMissionADGraph(mission)
	if err != nil {
		return ADGraphView{}, err
	}
	view := ADGraphView{MissionID: mission.ID, MissionStatus: mission.Status, Nodes: append([]ADGraphNode(nil), mission.ADGraph.Nodes...), Edges: append([]ADGraphEdge(nil), mission.ADGraph.Edges...), Evidence: append([]ADGraphEvidence(nil), mission.ADGraph.Evidence...), UpdatedAt: mission.ADGraph.UpdatedAt}
	for _, requirement := range mission.Requirements {
		if requirement.Source != "" {
			ensureViewNode(&view, "machine", requirement.Source, requirement.Source)
		}
		if requirement.Target != "" && requirement.TargetKind != "email_chain" {
			ensureViewNode(&view, "machine", requirement.Target, requirement.Target)
		}
	}
	var selectedItem *ValidatedItem
	selectedPlanID := ""
	if mission.CurrentPlanID != "" {
		var plan Plan
		if err := s.Store.Get("plans", mission.CurrentPlanID, &plan); err == nil {
			selectedPlanID = plan.ID
			for index := range plan.Items {
				if plan.Items[index].SourceAssetID != "" && plan.Items[index].DestinationAssetID != "" {
					selectedItem = &plan.Items[index]
					break
				}
			}
		}
	}
	if selectedItem != nil {
		sourceID := ensureViewNode(&view, "machine", selectedItem.SourceAssetID, selectedItem.SourceAssetID)
		targetID := ensureViewNode(&view, "machine", selectedItem.DestinationAssetID, selectedItem.DestinationAssetID)
		if selectedItem.LateralInput != nil && len(selectedItem.LateralInput.RouteEdgeIDs) > 0 {
			selectedEdges := map[string]bool{}
			for _, edgeID := range selectedItem.LateralInput.RouteEdgeIDs {
				selectedEdges[edgeID] = true
			}
			for index := range view.Edges {
				if selectedEdges[view.Edges[index].ID] {
					view.Edges[index].Selected = true
				}
			}
			view.SelectedRoute = ADSelectedRoute{SourceAssetID: selectedItem.SourceAssetID, DestinationAssetID: selectedItem.DestinationAssetID, Protocol: selectedItem.Protocol, PlanID: selectedPlanID, CatalogID: selectedItem.CatalogID, Name: selectedItem.Name, Status: selectedItem.Status, NodeIDs: append([]string(nil), selectedItem.LateralInput.RouteNodeIDs...), EdgeIDs: append([]string(nil), selectedItem.LateralInput.RouteEdgeIDs...)}
		} else {
			routeEdgeID := "route:" + shortGraphID(strings.Join([]string{selectedPlanID, selectedItem.CatalogID, sourceID, targetID, selectedItem.Protocol}, "\x00"))
			view.Edges = append(view.Edges, ADGraphEdge{ID: routeEdgeID, Source: sourceID, Target: targetID, Kind: "selected_route", Label: selectedItem.Name, Protocol: selectedItem.Protocol, Directed: true, Status: selectedItem.Status, Selected: true})
			view.SelectedRoute = ADSelectedRoute{SourceAssetID: selectedItem.SourceAssetID, DestinationAssetID: selectedItem.DestinationAssetID, Protocol: selectedItem.Protocol, PlanID: selectedPlanID, CatalogID: selectedItem.CatalogID, Name: selectedItem.Name, Status: selectedItem.Status, NodeIDs: []string{sourceID, targetID}, EdgeIDs: []string{routeEdgeID}}
		}
	} else {
		for _, requirement := range mission.Requirements {
			if requirement.Source == "" || requirement.Target == "" {
				continue
			}
			sourceID := ensureViewNode(&view, "machine", requirement.Source, requirement.Source)
			targetID := ensureViewNode(&view, "machine", requirement.Target, requirement.Target)
			routeEdgeID := "route:" + shortGraphID(strings.Join([]string{mission.ID, sourceID, targetID, requirement.Protocol}, "\x00"))
			view.Edges = append(view.Edges, ADGraphEdge{ID: routeEdgeID, Source: sourceID, Target: targetID, Kind: "selected_route", Label: "mission objective", Protocol: requirement.Protocol, Directed: true, Status: "objective", Selected: true})
			view.SelectedRoute = ADSelectedRoute{SourceAssetID: requirement.Source, DestinationAssetID: requirement.Target, Protocol: requirement.Protocol, Status: "objective", NodeIDs: []string{sourceID, targetID}, EdgeIDs: []string{routeEdgeID}}
			break
		}
	}
	if mission.SelectedRoute != nil && mission.SelectedRoute.Ready && len(mission.SelectedRoute.EdgeIDs) > 0 &&
		strings.Join(observedRemoteRoute(mission.ADGraph, mission.SelectedRoute.SourceAssetID, mission.SelectedRoute.DestinationAssetID, "").EdgeIDs, "\x00") == strings.Join(mission.SelectedRoute.EdgeIDs, "\x00") {
		selected := map[string]bool{}
		for _, id := range mission.SelectedRoute.EdgeIDs {
			selected[id] = true
		}
		for index := range view.Edges {
			view.Edges[index].Selected = selected[view.Edges[index].ID]
		}
		view.SelectedRoute.SourceAssetID = mission.SelectedRoute.SourceAssetID
		view.SelectedRoute.DestinationAssetID = mission.SelectedRoute.DestinationAssetID
		view.SelectedRoute.Protocol = mission.SelectedRoute.Protocol
		view.SelectedRoute.Status = "evidenced"
		view.SelectedRoute.NodeIDs = append([]string(nil), mission.SelectedRoute.NodeIDs...)
		view.SelectedRoute.EdgeIDs = append([]string(nil), mission.SelectedRoute.EdgeIDs...)
	} else if mission.SelectedRoute == nil {
		for _, requirement := range mission.Requirements {
			if requirement.Type != "remote_access_proven" || requirement.Status == "proven" {
				continue
			}
			route := observedRemoteRoute(mission.ADGraph, requirement.Source, requirement.Target, "")
			if !route.Ready {
				continue
			}
			selected := map[string]bool{}
			for _, id := range route.EdgeIDs {
				selected[id] = true
			}
			for index := range view.Edges {
				view.Edges[index].Selected = selected[view.Edges[index].ID]
			}
			view.SelectedRoute = ADSelectedRoute{SourceAssetID: requirement.Source, DestinationAssetID: requirement.Target,
				Protocol: requirement.Protocol, Status: "observed_not_proven", NodeIDs: route.NodeIDs, EdgeIDs: route.EdgeIDs}
			break
		}
	}
	sort.Slice(view.Nodes, func(i, j int) bool {
		return view.Nodes[i].Kind < view.Nodes[j].Kind || (view.Nodes[i].Kind == view.Nodes[j].Kind && view.Nodes[i].Label < view.Nodes[j].Label)
	})
	sort.Slice(view.Edges, func(i, j int) bool {
		return view.Edges[i].Kind < view.Edges[j].Kind || (view.Edges[i].Kind == view.Edges[j].Kind && view.Edges[i].ID < view.Edges[j].ID)
	})
	return view, nil
}
