package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

func fourCoreRemoteTestItem() ValidatedItem {
	contract := ActionContract{Produces: []PredicateSpec{{Type: "lateral_movement_validated", Subject: "source"}}}
	raw := map[string]any{
		"id": "execution-1", "chain_id": "chain-1", "status": "completed",
		"assets": []any{map[string]any{
			"asset_id": "source", "steps": []any{map[string]any{
				"id": "remote-step", "success": true, "source_asset_id": "source",
				"destination_asset_id": "destination", "protocol": "winrm",
				"remote_execution_observed": true, "destination_identity": `LAB\Administrator`, "integrity": "high",
			}},
		}},
	}
	return ValidatedItem{
		PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "chain-1", AssetIDs: []string{"source"}, SourceAssetID: "source", Contract: &contract},
		Status:   "completed", ExecutionID: "execution-1", Report: reportSummary(raw),
	}
}

func TestFourCoreOnlyMissionCanReachReportedDestination(t *testing.T) {
	fixture := setup(t)
	fixture.svc.Config.LateralEnabled = false
	fixture.svc.Lateral = nil
	fixture.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{{
		ID: "c-lateral", Name: "PsExec over SMB", Platforms: []string{"windows"},
		Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}},
	}}}
	mission, err := fixture.svc.CreateMission(context.Background(), "catalogue-only", MissionInput{
		Request:        "Given user access on source, find administrator access on destination",
		StartingAccess: []StartingAccess{{AssetID: "asset-1", AccessLevel: "user"}},
		Requirements:   []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "smb", ExpectedIdentity: "Administrator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || planned.Plan == nil || len(planned.Plan.Items) != 1 || planned.Plan.Items[0].CatalogID != "c-lateral" {
		t.Fatalf("FourCore-only lateral candidate was not planned: %+v %v", planned, err)
	}
	report := reportSummary(map[string]any{
		"id": "execution-1", "chain_id": "c-lateral", "status": "completed",
		"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{
			"id": "remote-step", "success": true, "source_asset_id": "asset-1", "destination_asset_id": lateralTestDestination,
			"protocol": "smb", "remote_execution_observed": true, "destination_identity": `LAB\Administrator`, "integrity": "high",
		}}}},
	})
	if err := fixture.svc.Store.UpdatePlan(planned.Plan.ID, func(p *Plan) error {
		p.Status = "completed"
		p.Items[0].Status = "completed"
		p.Items[0].ExecutionID = "execution-1"
		p.Items[0].Report = report
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	completed, err := fixture.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || !allMandatorySatisfied(completed) {
		t.Fatalf("provider-reported destination was not recognized: %+v", completed.Requirements)
	}
	found := false
	for _, edge := range completed.ADGraph.Edges {
		found = found || edge.Kind == "remote_access" && edge.Status == "observed"
	}
	if !found {
		t.Fatalf("mission graph omitted reported destination: %+v", completed.ADGraph.Edges)
	}
}

func TestFourCoreOnlyMissionTriesNextCatalogueChainAfterSimulationOnly(t *testing.T) {
	fixture := setup(t)
	fixture.svc.Config.LateralEnabled = false
	fixture.svc.Lateral = nil
	fixture.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{
		{ID: "a-lateral", Name: "PsExec over SMB", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}}},
		{ID: "b-lateral", Name: "SMB remote execution", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}}},
	}}
	mission, err := fixture.svc.CreateMission(context.Background(), "catalogue-next", MissionInput{
		Request:      "Prove access from source to destination",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "smb"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || first.Plan == nil || len(first.Plan.Items) != 1 {
		t.Fatalf("first catalogue candidate missing: %+v %v", first, err)
	}
	firstID := first.Plan.Items[0].CatalogID
	if err := fixture.svc.Store.UpdatePlan(first.Plan.ID, func(p *Plan) error {
		p.Status = "completed"
		p.Items[0].Status = "completed"
		p.Items[0].ExecutionID = "simulation-only-1"
		p.Items[0].Report = reportSummary(map[string]any{"id": "simulation-only-1", "chain_id": firstID, "status": "completed", "assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{"id": "step-1", "success": true}}}}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	second, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || second.Plan == nil || len(second.Plan.Items) != 1 || second.Plan.Items[0].CatalogID == firstID {
		t.Fatalf("simulation-only result did not lead to a different reviewed candidate: %+v %v", second, err)
	}
}

func TestFourCoreOnlyMissionExpandsObservedRouteToDestination(t *testing.T) {
	fixture := setup(t)
	fixture.svc.Config.LateralEnabled = false
	fixture.svc.Config.AllowedEndpoint[lateralTestDestination] = true
	fixture.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{{
		ID: "c-lateral", Name: "PsExec over SMB", Platforms: []string{"windows"},
		Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}},
	}}}
	const goal = "goal-machine"
	mission, err := fixture.svc.CreateMission(context.Background(), "route-expansion", MissionInput{
		Request:      "Given access on A, reach B as Administrator",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: goal, Protocol: "smb", ExpectedIdentity: "Administrator"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || first.Plan == nil || first.Plan.Items[0].SourceAssetID != "asset-1" {
		t.Fatalf("initial source plan missing: %+v %v", first, err)
	}
	firstReport := reportSummary(map[string]any{
		"id": "first-hop", "chain_id": "c-lateral", "status": "completed",
		"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{
			"id": "hop-a-c", "success": true, "source_asset_id": "asset-1", "destination_asset_id": lateralTestDestination,
			"protocol": "winrm", "remote_execution_observed": true, "destination_identity": `LAB\user`, "integrity": "medium",
		}}}},
	})
	if err := fixture.svc.Store.UpdatePlan(first.Plan.ID, func(p *Plan) error {
		p.Status, p.Items[0].Status = "completed", "completed"
		p.Items[0].ExecutionID, p.Items[0].Report = "first-hop", firstReport
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	intermediate, _ := fixture.svc.missionByID(mission.ID)
	if intermediate.Status == "completed" || observedRemoteRoute(intermediate.ADGraph, "asset-1", goal, "smb").Ready {
		t.Fatal("intermediate machine was mistaken for the requested destination")
	}
	second, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || second.Plan == nil || second.Plan.Items[0].SourceAssetID != lateralTestDestination || second.Plan.Items[0].DestinationAssetID != goal {
		t.Fatalf("planner did not advance to the evidenced frontier: %+v %v", second, err)
	}
	secondReport := reportSummary(map[string]any{
		"id": "second-hop", "chain_id": "c-lateral", "status": "completed",
		"assets": []any{map[string]any{"asset_id": lateralTestDestination, "steps": []any{map[string]any{
			"id": "hop-c-b", "success": true, "source_asset_id": lateralTestDestination, "destination_asset_id": goal,
			"protocol": "smb", "remote_execution_observed": true, "destination_identity": `LAB\Administrator`, "integrity": "high",
		}}}},
	})
	preview := second.Plan.Items[0]
	preview.Status, preview.ExecutionID, preview.Report = "completed", "second-hop", secondReport
	uncorrelatedGraph := mergeADGraph(intermediate.ADGraph, extractADEvidence(preview))
	uncorrelatedRoute := observedRemoteRoute(uncorrelatedGraph, "asset-1", goal, "")
	if !uncorrelatedRoute.Ready || correlatedObservedRemoteRoute(uncorrelatedGraph, uncorrelatedRoute, "second-hop") {
		t.Fatal("independent A-to-C and C-to-B reports were confused with a correlated pivot")
	}
	secondReport["assets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)["parent_execution_id"] = "first-hop"
	if err := fixture.svc.Store.UpdatePlan(second.Plan.ID, func(p *Plan) error {
		p.Status, p.Items[0].Status = "completed", "completed"
		p.Items[0].ExecutionID, p.Items[0].Report = "second-hop", secondReport
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	completed, _ := fixture.svc.missionByID(mission.ID)
	if completed.Status != "completed" || !allMandatorySatisfied(completed) || completed.SelectedRoute == nil || len(completed.SelectedRoute.EdgeIDs) != 2 {
		t.Fatalf("two observed hops did not complete A-to-B objective: %+v", completed)
	}
	view, err := fixture.svc.MissionADGraph(mission.ID)
	if err != nil || len(view.SelectedRoute.EdgeIDs) != 2 || view.SelectedRoute.Status != "evidenced" {
		t.Fatalf("graph viewer omitted the complete evidenced route: %+v %v", view.SelectedRoute, err)
	}
}

func TestFourCoreOnlyExhaustionIsScopedImpossibleNotRemoteProof(t *testing.T) {
	fixture := setup(t)
	fixture.svc.Config.LateralEnabled = false
	fixture.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{{
		ID: "only-lateral", Name: "PsExec over SMB", Platforms: []string{"windows"},
		Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}},
	}}}
	mission, err := fixture.svc.CreateMission(context.Background(), "catalogue-exhaustion", MissionInput{
		Request:      "Reach the requested destination from asset-1",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "smb"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || first.Plan == nil {
		t.Fatalf("first plan missing: %+v %v", first, err)
	}
	if err := fixture.svc.Store.UpdatePlan(first.Plan.ID, func(p *Plan) error {
		p.Status, p.Items[0].Status = "completed", "completed"
		p.Items[0].ExecutionID = "simulation-only"
		p.Items[0].Report = reportSummary(map[string]any{
			"id": "simulation-only", "chain_id": "only-lateral", "status": "completed",
			"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{"id": "step", "success": true}}}},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mission.Status != "unattainable" || !strings.Contains(result.Mission.BlockingReason, "impossible with the currently permitted catalogue") {
		t.Fatalf("exhaustion was not scoped as impossible: %+v", result)
	}
	report, err := fixture.svc.MissionReport(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Requirements[0].Status == "proven" || !strings.Contains(strings.Join(report.Conclusions, " "), "not proof that no network path exists") {
		t.Fatalf("simulation was mistaken for remote proof: %+v", report)
	}
}

func TestFourCoreOnlyMissionDoesNotRequireDestinationInventory(t *testing.T) {
	fixture := setup(t)
	fixture.svc.Config.LateralEnabled = false
	fixture.svc.Lateral = nil
	fixture.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{{
		ID: "c-lateral", Name: "PsExec over SMB", Platforms: []string{"windows"},
		Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}},
	}}}
	const destination = "unregistered-destination"
	mission, err := fixture.svc.CreateMission(context.Background(), "no-destination-inventory", MissionInput{
		Request:      "Review source-side lateral chain for the requested destination",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: destination, Protocol: "smb"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if assets := missionAssetKinds(mission, false); len(assets) != 1 || assets["asset-1"] != "endpoint" {
		t.Fatalf("catalogue-only mission tried to inventory its unexecuted destination: %+v", assets)
	}
	planned, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || planned.Plan == nil || len(planned.Plan.Items) != 1 || planned.Plan.Items[0].DestinationAssetID != destination {
		t.Fatalf("destination report-matching goal could not be planned: %+v %v", planned, err)
	}
}

func TestFourCoreReportCanProveExplicitRemoteResult(t *testing.T) {
	item := fourCoreRemoteTestItem()
	if observations := fourCoreRemoteObservations(item); len(observations) == 0 {
		t.Fatalf("explicit route observation missing from stored report: %+v", item.Report)
	}
	for _, requirement := range []Requirement{
		{Type: "remote_access_proven", Source: "source", Target: "destination", Protocol: "winrm", ExpectedIdentity: "Administrator"},
		{Type: "identity_observed", Source: "source", Target: "destination", Protocol: "winrm", ExpectedIdentity: "Administrator"},
		{Type: "service_reachable", Source: "source", Target: "destination", Protocol: "winrm"},
	} {
		status, step, detail := evaluateRequirementEvidence(item, requirement)
		if status != "proven" || step != "remote-step" || !strings.Contains(detail, "FourCore execution") {
			t.Fatalf("explicit provider evidence was not accepted for %s: %s %s %s", requirement.Type, status, step, detail)
		}
	}
	graph := extractADEvidence(item)
	found := false
	for _, edge := range graph.Edges {
		if edge.Kind == "remote_access" {
			found = edge.Status == "observed" && edge.Protocol == "winrm" && len(edge.EvidenceIDs) > 0
		}
	}
	if !found {
		t.Fatalf("provider-observed destination edge was not added: %+v", graph.Edges)
	}
}

func TestFourCoreReportDoesNotInferDestinationFromSimulationSuccess(t *testing.T) {
	requirement := Requirement{Type: "remote_access_proven", Source: "source", Target: "destination", Protocol: "winrm", ExpectedIdentity: "Administrator"}
	for _, tc := range []struct {
		name string
		mut  func(*ValidatedItem)
	}{
		{"other destination", func(item *ValidatedItem) {
			item.Report["assets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)["destination_asset_id"] = "other"
		}},
		{"no remote result", func(item *ValidatedItem) {
			delete(item.Report["assets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any), "remote_execution_observed")
		}},
		{"medium integrity", func(item *ValidatedItem) {
			item.Report["assets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)["integrity"] = "medium"
		}},
		{"report ID mismatch", func(item *ValidatedItem) { item.Report["id"] = "another-execution" }},
		{"chain ID mismatch", func(item *ValidatedItem) { item.Report["chain_id"] = "another-chain" }},
		{"source mismatch", func(item *ValidatedItem) { item.Report["assets"].([]any)[0].(map[string]any)["asset_id"] = "other" }},
		{"failed step", func(item *ValidatedItem) {
			item.Report["assets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)["success"] = false
		}},
		{"text only", func(item *ValidatedItem) {
			step := item.Report["assets"].([]any)[0].(map[string]any)["steps"].([]any)[0].(map[string]any)
			delete(step, "destination_asset_id")
			step["output"] = "remote access to destination succeeded"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := fourCoreRemoteTestItem()
			tc.mut(&item)
			status, _, _ := evaluateRequirementEvidence(item, requirement)
			if status == "proven" {
				t.Fatal("insufficient simulation report was promoted to remote-access proof")
			}
		})
	}
}
