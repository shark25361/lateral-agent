package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func adEvidenceTestReport() map[string]any {
	return map[string]any{
		"assets": []any{map[string]any{
			"asset_id": "asset-1", "domain": "corp.example",
			"steps": []any{map[string]any{
				"id": "ad-discovery", "action_id": "discover-ad", "success": true,
				"output": map[string]any{
					"machines": []any{
						map[string]any{"asset_id": "asset-1", "hostname": "SOURCE", "domain": "corp.example"},
						map[string]any{"asset_id": "22222222-2222-2222-2222-222222222222", "hostname": "DESTINATION", "domain": "corp.example"},
					},
					"identities":         []any{map[string]any{"name": "alice", "domain": "corp.example", "sid": "S-1-5-21-100"}},
					"groups":             []any{map[string]any{"name": "Domain Admins", "domain": "corp.example", "members": []any{"alice"}}},
					"trusts":             []any{map[string]any{"source_domain": "corp.example", "target_domain": "child.example", "direction": "bidirectional", "trust_type": "forest"}},
					"sessions":           []any{map[string]any{"user": "alice", "domain": "corp.example", "computer": "DESTINATION", "logon_type": "interactive"}},
					"shares":             []any{map[string]any{"host": "DESTINATION", "name": "Engineering", "path": `C:\Engineering`, "accessible_by": []any{"corp.example\\alice"}}},
					"acls":               []any{map[string]any{"principal": "corp.example\\alice", "object": "Domain Admins", "object_type": "group", "rights": "GenericAll"}},
					"delegations":        []any{map[string]any{"principal": "corp.example\\svc-web", "target": "cifs/DESTINATION", "delegation_type": "constrained"}},
					"can_smb":            []any{map[string]any{"principal": "alice", "domain": "corp.example", "destination_asset_id": "22222222-2222-2222-2222-222222222222", "allowed": true}},
					"reachable_services": []any{map[string]any{"source_asset_id": "asset-1", "destination_asset_id": "22222222-2222-2222-2222-222222222222", "protocol": "smb", "port": 445, "reachable": true}},
					"password":           "MUST_NOT_ENTER_GRAPH",
				},
			}},
		}},
	}
}

func edgeKinds(graph ADGraph) map[string]int {
	out := map[string]int{}
	for _, edge := range graph.Edges {
		out[edge.Kind]++
	}
	return out
}

func TestADEvidenceAdapterParsesRelationshipsAndProvenance(t *testing.T) {
	item := ValidatedItem{PlanItem: PlanItem{CatalogID: "ad-discovery-chain"}, Status: "completed", ExecutionID: "execution-ad", ReportObservedAt: time.Date(2026, 9, 22, 1, 2, 3, 0, time.UTC), Report: adEvidenceTestReport()}
	graph := extractADEvidence(item)
	kinds := edgeKinds(graph)
	for _, required := range []string{"member_of_domain", "identity_in_domain", "group_in_domain", "member_of_group", "domain_trust", "session_on", "hosts_share", "can_access_share", "acl", "delegation", "can_smb", "service_on", "service_reachable"} {
		if kinds[required] == 0 {
			t.Fatalf("adapter omitted %s: %+v", required, kinds)
		}
	}
	if len(graph.Nodes) < 10 || len(graph.Evidence) == 0 {
		t.Fatalf("adapter omitted nodes or provenance: %+v", graph)
	}
	machines := 0
	for _, node := range graph.Nodes {
		if node.Kind == "machine" {
			machines++
		}
	}
	if machines != 2 {
		t.Fatalf("asset IDs and hostnames were not merged into canonical machines: %+v", graph.Nodes)
	}
	stepEvidence := false
	for _, evidence := range graph.Evidence {
		if evidence.ExecutionID != "execution-ad" || evidence.CatalogID != "ad-discovery-chain" {
			t.Fatalf("incorrect relationship provenance: %+v", evidence)
		}
		stepEvidence = stepEvidence || evidence.StepID == "ad-discovery"
	}
	if !stepEvidence {
		t.Fatal("step-scoped relationships did not retain their step ID")
	}
	encoded, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "MUST_NOT_ENTER_GRAPH") {
		t.Fatal("unrelated credential material entered the AD graph")
	}
}

func TestADEvidenceAdapterAcceptsJSONStepOutputAndMergesIdempotently(t *testing.T) {
	report := map[string]any{"assets": []any{map[string]any{"asset_id": "source", "steps": []any{map[string]any{"id": "json-step", "success": true, "output": `{"sessions":[{"user":"bob","domain":"lab.example","computer":"server1"}]}`}}}}}
	item := ValidatedItem{PlanItem: PlanItem{CatalogID: "json-chain"}, Status: "completed", ExecutionID: "execution-json", Report: report}
	graph := extractADEvidence(item)
	if edgeKinds(graph)["session_on"] != 1 {
		t.Fatalf("JSON output was not parsed: %+v", graph)
	}
	merged := mergeADGraph(graph, graph)
	if len(merged.Nodes) != len(graph.Nodes) || len(merged.Edges) != len(graph.Edges) || len(merged.Evidence) != len(graph.Evidence) {
		t.Fatalf("graph merge was not idempotent: original=%+v merged=%+v", graph, merged)
	}
}

// Run with: go test -run '^TestReportToADGraphWorkingExample$' -count=1 -v ./internal/app
func TestReportToADGraphWorkingExample(t *testing.T) {
	const source, destination = "demo-source", "demo-destination"
	raw := map[string]any{
		"id": "demo-execution", "chain_id": "demo-discovery", "status": "completed",
		"assets": []any{map[string]any{"asset_id": source, "steps": []any{map[string]any{
			"id": "discovery-step", "success": true,
			"output": map[string]any{"job_id": "demo-job", "output": map[string]any{
				"machines":           []any{map[string]any{"asset_id": source, "hostname": "SOURCE"}, map[string]any{"asset_id": destination, "hostname": "DESTINATION"}},
				"sessions":           []any{map[string]any{"user": "operator", "domain": "lab.example", "asset_id": source}},
				"can_smb":            []any{map[string]any{"principal": "operator", "domain": "lab.example", "destination_asset_id": destination, "allowed": true}},
				"reachable_services": []any{map[string]any{"source_asset_id": source, "destination_asset_id": destination, "protocol": "smb", "port": 445, "reachable": true}},
			}},
		}}}},
	}
	item := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "demo-discovery", AssetIDs: []string{source}},
		Status: "completed", ExecutionID: "demo-execution", Report: reportSummary(raw)}
	graph := extractADEvidence(item)
	kinds := edgeKinds(graph)
	for _, required := range []string{"session_on", "can_smb", "service_on", "service_reachable"} {
		if kinds[required] != 1 {
			t.Fatalf("expected %s edge from structured report: %+v", required, kinds)
		}
	}
	if kinds["remote_access"] != 0 {
		t.Fatal("discovery evidence was misreported as lateral access")
	}
	t.Logf("synthetic FourCore-shaped report: nodes=%d edges=%d edge_kinds=%v remote_access_proven=false", len(graph.Nodes), len(graph.Edges), kinds)
}

func TestADEvidenceUsesOnlySuccessfulProviderSteps(t *testing.T) {
	report := map[string]any{"assets": []any{map[string]any{"asset_id": "source", "steps": []any{
		map[string]any{"id": "failed-by-id", "success": false, "output": map[string]any{"sessions": []any{map[string]any{"user": "false-user", "computer": "source"}}}},
		map[string]any{"id": "unfinished", "success": true, "done": false, "output": map[string]any{"sessions": []any{map[string]any{"user": "unfinished-user", "computer": "source"}}}},
		map[string]any{"id": "parent-failed", "success": false, "action_steps": []any{
			map[string]any{"id": "child-success", "success": true, "output": map[string]any{"output": map[string]any{
				"sessions": []any{map[string]any{"user": "observed-user", "computer": "source"}},
			}}},
		}},
	}}}}
	graph := extractADEvidence(ValidatedItem{Status: "completed", ExecutionID: "step-filter", Report: report})
	if edgeKinds(graph)["session_on"] != 1 {
		t.Fatalf("failed or unfinished steps contributed relationships: %+v", graph.Edges)
	}
	if len(graph.Evidence) != 1 || graph.Evidence[0].StepID != "child-success" {
		t.Fatalf("successful nested action lost its provenance: %+v", graph.Evidence)
	}
}

func TestADEvidenceFailedRunDoesNotTrustUnboundTopLevelClaims(t *testing.T) {
	report := map[string]any{
		"sessions": []any{map[string]any{"user": "unsupported-user", "computer": "source"}},
		"assets": []any{map[string]any{"asset_id": "source", "steps": []any{
			map[string]any{"id": "successful-part", "success": true, "output": map[string]any{"sessions": []any{map[string]any{"user": "observed-user", "computer": "source"}}}},
		}}},
	}
	graph := extractADEvidence(ValidatedItem{Status: "failed", ExecutionID: "partial-run", Report: report})
	if edgeKinds(graph)["session_on"] != 1 || len(graph.Evidence) != 1 || graph.Evidence[0].StepID != "successful-part" {
		t.Fatalf("partial-run evidence was not scoped to its successful step: %+v", graph)
	}
}

func TestADGraphDoesNotTreatDiscoveredHostnameAsAssetID(t *testing.T) {
	report := map[string]any{"assets": []any{map[string]any{"asset_id": "source", "steps": []any{
		map[string]any{"id": "discover", "success": true, "output": map[string]any{"machines": []any{"SERVER-B"}}},
	}}}}
	graph := extractADEvidence(ValidatedItem{Status: "completed", ExecutionID: "host-discovery", Report: report})
	for _, node := range graph.Nodes {
		if node.Label == "SERVER-B" && node.AssetID != "" {
			t.Fatalf("unresolved hostname became an executable asset: %+v", node)
		}
	}
}

func TestADGraphRejectsMismatchedExecutionReport(t *testing.T) {
	report := map[string]any{"id": "wrong-execution", "chain_id": "discovery-chain", "assets": []any{map[string]any{
		"asset_id": "source", "steps": []any{map[string]any{"id": "step", "success": true,
			"output": map[string]any{"sessions": []any{map[string]any{"user": "alice", "computer": "source"}}}}},
	}}}
	item := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "discovery-chain", AssetIDs: []string{"source"}},
		Status: "completed", ExecutionID: "expected-execution", Report: report}
	if graph := extractADEvidence(item); len(graph.Edges) != 0 {
		t.Fatalf("another execution's report entered the graph: %+v", graph.Edges)
	}
	report["id"] = "expected-execution"
	report["chain_id"] = "wrong-chain"
	if graph := extractADEvidence(item); len(graph.Edges) != 0 {
		t.Fatalf("another chain's report entered the graph: %+v", graph.Edges)
	}
}

func TestLateralSimulationGraphRecordsExecutionWithoutInventingDestination(t *testing.T) {
	contract := ActionContract{Produces: []PredicateSpec{{Type: "lateral_movement_validated", Subject: "source"}}}
	item := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "lateral-chain", AssetIDs: []string{"source"}, Contract: &contract}, Name: "Lateral technique simulation", Status: "completed", ExecutionID: "execution-lateral", Report: map[string]any{
		"assets": []any{map[string]any{"asset_id": "source", "steps": []any{map[string]any{"id": "successful-step", "done": true, "success": true}}}},
	}}
	graph := extractADEvidence(item)
	if edgeKinds(graph)["lateral_simulated"] != 1 || edgeKinds(graph)["remote_access"] != 0 {
		t.Fatalf("simulation was missing or promoted to remote access: %+v", graph.Edges)
	}
	if len(graph.Nodes) != 2 || len(graph.Evidence) != 1 || graph.Evidence[0].ExecutionID != item.ExecutionID || graph.Evidence[0].StepID != "successful-step" {
		t.Fatalf("simulation graph omitted source, chain, or provenance: %+v", graph)
	}
	if graph.Edges[0].Status != "simulated" {
		t.Fatalf("simulation edge had an access-proof status: %+v", graph.Edges[0])
	}
	merged := mergeADGraph(graph, graph)
	if len(merged.Edges) != 1 || len(merged.Evidence) != 1 {
		t.Fatalf("replaying the same execution duplicated graph evidence: %+v", merged)
	}
	item.Report = map[string]any{"assets": []any{map[string]any{"asset_id": "source", "steps": []any{map[string]any{"id": "failed-step", "done": true, "success": false}}}}}
	if edgeKinds(extractADEvidence(item))["lateral_simulated"] != 0 {
		t.Fatal("failed chain action was recorded as a completed lateral simulation")
	}
}

func TestMissionSyncPersistsADGraphAndSelectedRoute(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "AD discovery", "T1018")}}
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request: "Discover an AD route",
		Requirements: []Requirement{
			{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1018", Mandatory: true},
			{ID: "R2", Type: "remote_access_proven", Source: "asset-1", Target: "22222222-2222-2222-2222-222222222222", Protocol: "smb", Mandatory: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || planned.Plan == nil {
		t.Fatalf("plan creation failed: %+v %v", planned, err)
	}
	if err := f.svc.Store.UpdatePlan(planned.Plan.ID, func(plan *Plan) error {
		plan.Status = "completed"
		plan.Items[0].Status = "completed"
		plan.Items[0].ExecutionID = "execution-ad"
		plan.Items[0].ReportObservedAt = time.Now().UTC()
		plan.Items[0].Report = adEvidenceTestReport()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := f.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.ADGraph.Nodes) == 0 || len(stored.ADGraph.Edges) == 0 {
		t.Fatalf("mission did not persist AD evidence: %+v", stored.ADGraph)
	}
	if err := f.svc.Store.UpdateMission(mission.ID, func(mission *Mission) error {
		mission.ADGraph = ADGraph{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	view, err := f.svc.MissionADGraph(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := f.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.ADGraph.Nodes) == 0 || len(reloaded.ADGraph.Edges) == 0 {
		t.Fatal("opening the graph did not backfill evidence from an existing stored report")
	}
	if view.SelectedRoute.SourceAssetID != "asset-1" || view.SelectedRoute.DestinationAssetID != "22222222-2222-2222-2222-222222222222" || len(view.SelectedRoute.EdgeIDs) != 1 {
		t.Fatalf("selected mission route was not projected: %+v", view.SelectedRoute)
	}
	selected := false
	for _, edge := range view.Edges {
		selected = selected || edge.Selected
	}
	if !selected {
		t.Fatal("graph view did not mark the selected route")
	}
}

func TestMissionGraphEndpoint(t *testing.T) {
	f := setup(t)
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{Request: "Inspect graph", Requirements: []Requirement{{ID: "R1", Type: "domain_context_observed", Target: "asset-1", Mandatory: true}}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Service: f.svc}).Handler())
	defer server.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/missions/"+mission.ID+"/graph", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+f.svc.Config.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("graph endpoint returned %s", response.Status)
	}
	var view ADGraphView
	if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view.MissionID != mission.ID || len(view.Nodes) == 0 {
		t.Fatalf("graph endpoint returned an incomplete view: %+v", view)
	}
}

func TestReportProjectionRetainsBoundedStructuredADEvidence(t *testing.T) {
	report := reportSummary(map[string]any{"groups": []any{map[string]any{"name": "Domain Admins", "members": []any{"alice"}}}, "assets": []any{map[string]any{"asset_id": "asset-1", "sessions": []any{map[string]any{"user": "alice", "computer": "server1"}}, "can_smb": []any{map[string]any{"principal": "alice", "destination_asset_id": "asset-2", "allowed": true}}}}})
	if report["groups"] == nil {
		t.Fatal("top-level AD evidence was removed from the stored report")
	}
	assets, ok := report["assets"].([]any)
	if !ok || len(assets) != 1 || assets[0].(map[string]any)["sessions"] == nil || assets[0].(map[string]any)["can_smb"] == nil {
		t.Fatalf("asset-scoped AD evidence was removed: %+v", report)
	}
}

func TestADGraphDoesNotPromoteUnprovenReportFields(t *testing.T) {
	report := map[string]any{
		"source_asset_id": "source", "destination_asset_id": "target", "protocol": "smb",
		"assets": []any{map[string]any{"asset_id": "source", "steps": []any{map[string]any{
			"action_id": "failed-discovery", "success": false,
			"output": map[string]any{"sessions": []any{map[string]any{"user": "alice", "computer": "target"}}},
		}}}},
		"can_smb": []any{map[string]any{"principal": "alice", "destination_asset_id": "target"}},
	}
	graph := extractADEvidence(ValidatedItem{ExecutionID: "unproven", Report: report})
	for _, kind := range []string{"service_reachable", "session_on", "can_smb", "remote_access"} {
		if edgeKinds(graph)[kind] != 0 {
			t.Fatalf("unproven %s was promoted to a graph edge: %+v", kind, graph.Edges)
		}
	}
}

func TestADGraphMarksOnlyTrustedDestinationAccessVerified(t *testing.T) {
	report := map[string]any{"route_evidence": map[string]any{
		"source_asset_id": "source", "destination_asset_id": "target", "protocol": "winrm",
		"remote_execution_observed": true, "identity": `LAB\operator`,
	}}
	item := ValidatedItem{ExecutionID: "proof-run", Report: report}
	if edgeKinds(extractADEvidence(item))["remote_access"] != 0 {
		t.Fatal("unsigned provider assertion became verified access")
	}
	item.TrustedDestinationEvidence = true
	graph := extractADEvidence(item)
	if edgeKinds(graph)["remote_access"] != 1 {
		t.Fatalf("signed destination proof was not represented: %+v", graph.Edges)
	}
	for _, edge := range graph.Edges {
		if edge.Kind == "remote_access" && (edge.Status != "verified" || edge.Protocol != "winrm") {
			t.Fatalf("incorrect verified edge: %+v", edge)
		}
	}
}

func TestADGraphKeepsAmbiguousShortHostnamesSeparate(t *testing.T) {
	report := map[string]any{
		"machines": []any{
			map[string]any{"asset_id": "asset-a", "hostname": "SERVER", "domain": "a.example"},
			map[string]any{"asset_id": "asset-b", "hostname": "SERVER", "domain": "b.example"},
		},
		"sessions": []any{map[string]any{"user": "alice", "computer": "SERVER"}},
	}
	graph := extractADEvidence(ValidatedItem{Status: "completed", ExecutionID: "ambiguous", Report: report})
	count := 0
	for _, node := range graph.Nodes {
		if node.Kind == "machine" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("ambiguous short hostname was silently assigned to one domain: %+v", graph.Nodes)
	}
}

func TestADGraphBindsGroupACLToMachineAsset(t *testing.T) {
	report := map[string]any{
		"groups": []any{map[string]any{"name": "Operators", "domain": "lab.example", "members": []any{"alice"}}},
		"acls": []any{map[string]any{
			"principal": `lab.example\Operators`, "principal_type": "group", "object": "SERVER",
			"object_type": "computer", "target_asset_id": "target-asset", "rights": "GenericAll",
		}},
	}
	graph := extractADEvidence(ValidatedItem{Status: "completed", ExecutionID: "acl-run", Report: report})
	matched := false
	for _, edge := range graph.Edges {
		if edge.Kind != "admin_to" {
			continue
		}
		var source, target ADGraphNode
		for _, node := range graph.Nodes {
			if node.ID == edge.Source {
				source = node
			}
			if node.ID == edge.Target {
				target = node
			}
		}
		matched = source.Kind == "group" && target.AssetID == "target-asset"
	}
	if !matched {
		t.Fatalf("group administrator ACL lost its principal or machine binding: %+v", graph)
	}
}
