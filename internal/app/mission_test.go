package app

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type missionIntakeModel struct{}

func (missionIntakeModel) Name() string { return "mission-intake-test" }
func (missionIntakeModel) GenerateContent(_ context.Context, request *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		last := request.Contents[len(request.Contents)-1]
		for _, part := range last.Parts {
			if part.FunctionResponse != nil {
				yield(&model.LLMResponse{Content: &genai.Content{Role: "model", Parts: []*genai.Part{{Text: "requirements submitted"}}}}, nil)
				return
			}
		}
		input := MissionInput{Request: "Move from source to destination", Requirements: []Requirement{
			{ID: "T1592", Type: "behavior_executed", Target: "11111111-1111-1111-1111-111111111111", Technique: "T1592", Mandatory: true},
			{ID: "R1", Type: "remote_access_proven", Source: "11111111-1111-1111-1111-111111111111", Target: "22222222-2222-2222-2222-222222222222", Protocol: "smb", ExpectedIdentity: "administrator", Mandatory: true},
		}}
		raw, _ := json.Marshal(input)
		var args map[string]any
		_ = json.Unmarshal(raw, &args)
		yield(&model.LLMResponse{Content: &genai.Content{Role: "model", Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{ID: "mission-intake", Name: "submit_mission_requirements", Args: args}}}}}, nil)
	}
}

func TestMissionResumeRefreshesTransientInventoryBlockers(t *testing.T) {
	completedPlan := &Plan{Status: "completed"}
	for _, reason := range []string{
		"asset asset-1 unavailable",
		"asset asset-1 is unavailable or disabled",
		"asset asset-1 is disconnected",
		`FourCore transport failed: Get "https://example.invalid": context canceled`,
	} {
		mission := Mission{Status: "blocked", BlockingReason: reason}
		if route := missionResumeRoute(mission, completedPlan); route != "planning" {
			t.Fatalf("transient inventory blocker %q routed to %q", reason, route)
		}
	}
	mission := Mission{Status: "blocked", BlockingReason: "no compatible catalogue action remains"}
	if route := missionResumeRoute(mission, completedPlan); route != "final" {
		t.Fatalf("non-inventory blocker routed to %q", route)
	}
}

func missionTestCatalog(id, name string, technique string) Catalog {
	return Catalog{ID: id, Name: name, Platforms: []string{"windows"}, Techniques: []map[string]any{{"technique_id": technique}}}
}

func TestMissionIntakeAndCrossHostExpansion(t *testing.T) {
	f := setup(t)
	message := "Test admin access starting with user permissions from 11111111-1111-1111-1111-111111111111 to 22222222-2222-2222-2222-222222222222 over SMB"
	if !shouldAutoMission(message) {
		t.Fatal("action request with exact asset IDs did not enter mission intake")
	}
	input, err := f.svc.ExtractMissionInput(context.Background(), message, missionIntakeModel{})
	if err != nil {
		t.Fatal(err)
	}
	mission, err := normalizeMissionInput(input, "test-session")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, requirement := range mission.Requirements {
		types[requirement.Type] = true
	}
	for _, required := range []string{"remote_access_proven", "identity_observed"} {
		if !types[required] {
			t.Fatalf("cross-host intake omitted %s: %+v", required, mission.Requirements)
		}
	}
	if types["elevated_context_proven"] {
		t.Fatalf("starting as a user incorrectly forced local elevation: %+v", mission.Requirements)
	}
	for _, unnecessary := range []string{"domain_context_observed", "credential_access_validated", "lateral_movement_validated", "service_reachable"} {
		if types[unnecessary] {
			t.Fatalf("remote goal incorrectly forced %s: %+v", unnecessary, mission.Requirements)
		}
	}
	if len(mission.StartingAccess) != 1 || mission.StartingAccess[0].AssetID != "11111111-1111-1111-1111-111111111111" || mission.StartingAccess[0].AccessLevel != "user" {
		t.Fatalf("starting-access assumption was not preserved: %+v", mission.StartingAccess)
	}
	if types["behavior_executed"] {
		t.Fatalf("intake invented reconnaissance requirements: %+v", mission.Requirements)
	}
	for _, requirement := range mission.Requirements {
		if requirement.Type == "domain_context_observed" && !requirement.UserContextOnly {
			t.Fatalf("starting user-context constraint was not propagated to %s: %+v", requirement.ID, requirement)
		}
		if (requirement.Type == "credential_access_validated" || requirement.Type == "lateral_movement_validated") && requirement.UserContextOnly {
			t.Fatalf("starting user context incorrectly prohibited a later post-elevation stage: %+v", requirement)
		}
	}
	if input.Request != message {
		t.Fatalf("intake rewrote the audited operator request: %q", input.Request)
	}
	if shouldAutoMission("Which simulations can I run on 11111111-1111-1111-1111-111111111111?") {
		t.Fatal("an informational catalogue question was routed as an action")
	}
	if !shouldAutoMission("List options and simulate T1057 on 11111111-1111-1111-1111-111111111111") {
		t.Fatal("a mixed request with an explicit simulation was not routed as an action")
	}
	_, err = groundMissionInput(message, MissionInput{Requirements: []Requirement{{Type: "behavior_executed", Target: "33333333-3333-3333-3333-333333333333"}}})
	if err == nil {
		t.Fatal("intake accepted an asset ID that was absent from the operator request")
	}
	grounded, err := groundMissionInput(message, MissionInput{Requirements: []Requirement{
		{Type: "remote_access_proven", Source: "11111111-1111-1111-1111-111111111111", Target: "22222222-2222-2222-2222-222222222222", ExpectedIdentity: "administrator"},
		{Type: "elevated_context_proven", Target: "22222222-2222-2222-2222-222222222222"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(grounded.Requirements) != 1 || normalizeRequirementType(grounded.Requirements[0].Type) != "remote_access_proven" {
		t.Fatalf("redundant direct destination elevation survived grounding: %+v", grounded.Requirements)
	}
}

func TestStructuredStartingAccessIsAnAssumptionNotProof(t *testing.T) {
	source, destination := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	mission, err := normalizeMissionInput(MissionInput{
		Request:        "Given user access on A, find a route to admin on B",
		StartingAccess: []StartingAccess{{AssetID: source, AccessLevel: "user", Identity: `LAB\alice`}},
		Requirements:   []Requirement{{Type: "remote_access_proven", Source: source, Target: destination, ExpectedIdentity: "administrator"}},
	}, "test-session")
	if err != nil {
		t.Fatal(err)
	}
	if !mission.InitialUserContext || len(mission.StartingAccess) != 1 || len(mission.Facts) != 0 {
		t.Fatalf("initial assumption was lost or promoted to evidence: %+v", mission)
	}
	for _, requirement := range mission.Requirements {
		if requirement.Status != "unknown" {
			t.Fatalf("operator assumption proved an outcome: %+v", requirement)
		}
	}
	if _, err := normalizeMissionInput(MissionInput{
		Request: "Reject unrelated starting host", StartingAccess: []StartingAccess{{AssetID: "outside", AccessLevel: "user"}},
		Requirements: []Requirement{{Type: "remote_access_proven", Source: source, Target: destination}},
	}, "test-session"); err == nil {
		t.Fatal("unrelated starting-access asset was accepted")
	}
}

func TestUserPermsPhraseBecomesStartingAssumption(t *testing.T) {
	source, destination := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	message := "Given user perms on " + source + ", find admin access to " + destination
	input, err := groundMissionInput(message, MissionInput{Requirements: []Requirement{{Type: "remote_access_proven", Source: source, Target: destination}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(input.StartingAccess) != 1 || input.StartingAccess[0].AccessLevel != "user" || input.StartingAccess[0].AssetID != source {
		t.Fatalf("operator's starting user access was not captured: %+v", input.StartingAccess)
	}
}

func TestGroundSourceOnlyLateralChainRequest(t *testing.T) {
	const source = "11111111-1111-1111-1111-111111111111"
	message := "Run a lateral movement chain on " + source + " and show whether it executed"
	if !shouldAutoMission(message) {
		t.Fatal("source-only lateral request did not enter mission intake")
	}
	input, err := groundMissionInput(message, MissionInput{Requirements: []Requirement{{Type: "lateral_movement_validated", Target: source}}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := normalizeMissionInput(input, "mission-chat")
	if err != nil {
		t.Fatal(err)
	}
	if m.Request != message || len(m.Requirements) != 1 || m.Requirements[0].Target != source || m.Requirements[0].Source != "" {
		t.Fatalf("source-only intake invented a cross-host path: %+v", m)
	}
}

func TestMissionRequestWorkflowIncludesLLMExtractionNode(t *testing.T) {
	f := setup(t)
	message := "Simulate T1592 starting with user permissions from 11111111-1111-1111-1111-111111111111 to 22222222-2222-2222-2222-222222222222 over SMB"
	result, err := f.svc.RunMissionRequestGraph(context.Background(), "mission-chat", message, missionIntakeModel{})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct{ node, route string }{
		{"workflow_ingress", "extract"},
		{"llm_extracts_structured_mission", "extracted"},
		{"go_validates_mission", "valid"},
		{"create_durable_mission", "created"},
	} {
		if !traceContains(result.Mission, expected.node, expected.route) {
			t.Fatalf("request workflow omitted %s/%s: %+v", expected.node, expected.route, result.Mission.WorkflowTrace)
		}
	}
	if result.Mission.Request != message {
		t.Fatalf("workflow did not preserve the exact operator request: %q", result.Mission.Request)
	}
}

func TestMissionNormalizationMergesDuplicatePredicatesAndPreservesStartingContext(t *testing.T) {
	mission, err := normalizeMissionInput(MissionInput{
		Request: "Start as a standard-user and inspect the domain before testing elevation",
		Requirements: []Requirement{
			{ID: "R1", Type: "domain_context_observed", Target: "asset-1", UserContextOnly: true, Mandatory: true},
			{ID: "R2", Type: "domain_context_observed", Target: "asset-1", TargetKind: "endpoint_chain", Mandatory: true},
			{ID: "R3", Type: "elevated_context_proven", Target: "asset-1", UserContextOnly: true, Mandatory: true},
		},
	}, "mission-chat")
	if err != nil {
		t.Fatal(err)
	}
	if !mission.InitialUserContext || len(mission.Requirements) != 2 {
		t.Fatalf("starting context or semantic deduplication failed: %+v", mission)
	}
	if mission.Requirements[0].Type != "domain_context_observed" || !mission.Requirements[0].UserContextOnly {
		t.Fatalf("merged predicate lost its stricter user-context constraint: %+v", mission.Requirements[0])
	}
}

func TestElevatedRunCapabilityDoesNotProveStartingIdentity(t *testing.T) {
	f := setup(t)
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Start as a standard user and validate local elevation",
		Requirements: []Requirement{{ID: "R1", Type: "elevated_context_proven", Target: "11111111-1111-1111-1111-111111111111", UserContextOnly: true, Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CollectMissionFacts(context.Background(), mission.ID); err != nil {
		t.Fatal(err)
	}
	mission, err = f.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if mission.Requirements[0].Status != "unknown" || factState(mission, "elevated_capability", mission.Requirements[0].Target) != "proven" {
		t.Fatalf("execution capability was confused with starting identity proof: %+v", mission)
	}
}

func TestReusableInventoryFactsRequireExplicitUsableState(t *testing.T) {
	now := time.Now().UTC()
	mission := Mission{Facts: []Fact{
		{Type: "asset_available", Subject: "asset-1", Status: "proven", ObservedAt: now},
		{Type: "asset_connected", Subject: "asset-1", Status: "proven", ObservedAt: now},
		{Type: "platform_windows", Subject: "asset-1", Status: "proven", ObservedAt: now},
	}}
	if !reusableInventoryFacts(mission, "asset-1", "endpoint") {
		t.Fatal("explicit usable endpoint facts were not reusable after a transient refresh error")
	}
	if reusableInventoryFacts(mission, "missing", "endpoint") {
		t.Fatal("missing inventory observations were treated as reusable")
	}
	mission.Facts = append(mission.Facts, Fact{Type: "asset_connected", Subject: "asset-1", Status: "disproven", ObservedAt: now.Add(time.Second)})
	if reusableInventoryFacts(mission, "asset-1", "endpoint") {
		t.Fatal("a later explicit disconnect was ignored")
	}
}

func TestMissionSnapshotValidationReusesCollectedEndpointFacts(t *testing.T) {
	f := setup(t)
	f.svc.Config.AllowElevated = true
	assetID := "11111111-1111-1111-1111-111111111111"
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{{
		ID: "offline-lateral", Name: "SMB lateral movement", Elevated: true,
		Platforms: []string{"windows"}, Techniques: []map[string]any{{"absolute_id": "TA0008.T1021.002"}},
	}}}
	f.svc.FC.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network must not be used while creating the reviewable plan")
	})
	now := time.Now().UTC()
	mission := Mission{Facts: []Fact{
		{Type: "asset_available", Subject: assetID, Status: "proven", ObservedAt: now},
		{Type: "asset_connected", Subject: assetID, Status: "proven", ObservedAt: now},
		{Type: "platform_windows", Subject: assetID, Status: "proven", ObservedAt: now},
		{Type: "elevated_capability", Subject: assetID, Status: "proven", ObservedAt: now},
	}}
	item := PlanItem{Kind: "endpoint_chain", CatalogID: "offline-lateral", AssetIDs: []string{assetID}, Reason: "validate lateral movement", RunElevated: true}
	validated, err := f.svc.validateMissionSnapshot(context.Background(), mission, item)
	if err != nil {
		t.Fatal(err)
	}
	if validated.CatalogID != item.CatalogID || validated.CatalogHash == "" {
		t.Fatalf("snapshot validation did not produce a reviewable item: %+v", validated)
	}
}

func TestExplicitRequirementElevationAllowsHarnessLateralSimulation(t *testing.T) {
	f := setup(t)
	f.svc.Config.AllowElevated = true
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{{
		ID: "lateral-elevated", Name: "Pass-the-Hash SMB remote execution", Elevated: true,
		Platforms: []string{"windows"}, Tags: map[string]any{"category": "Lateral Movement"},
		Techniques: []map[string]any{{"tactic_id": "TA0008", "technique_id": "T1550", "absolute_id": "TA0008.T1550.002"}},
	}}}
	now := time.Now().UTC()
	mission := Mission{
		ID: "mission-elevated-lateral", Status: "unattainable", InitialUserContext: true, CurrentPlanID: "terminal-plan",
		Attempts: []MissionAttempt{{CatalogID: "lateral-elevated", Target: "source", Status: "failed"}},
		Requirements: []Requirement{
			{ID: "R1", Type: "domain_context_observed", Target: "source", TargetKind: "endpoint_chain", Status: "proven", Mandatory: true},
			{ID: "R2", Type: "credential_access_validated", Target: "source", TargetKind: "endpoint_chain", Status: "proven", Mandatory: true},
			{ID: "R3", Type: "lateral_movement_validated", Source: "source", Target: "destination", TargetKind: "endpoint_chain", Protocol: "dcom", Status: "unknown", Mandatory: true},
			{ID: "R4", Type: "remote_access_proven", Source: "source", Target: "destination", TargetKind: "endpoint_chain", Protocol: "dcom", Status: "unknown", Mandatory: true},
			{ID: "R5", Type: "elevated_context_proven", Target: "source", TargetKind: "endpoint_chain", Status: "proven", Mandatory: true},
		},
		Facts: []Fact{
			{Type: "asset_available", Subject: "source", Status: "proven", ObservedAt: now},
			{Type: "asset_connected", Subject: "source", Status: "proven", ObservedAt: now},
			{Type: "platform_windows", Subject: "source", Status: "proven", ObservedAt: now},
			{Type: "elevated_capability", Subject: "source", Status: "proven", ObservedAt: now},
		},
	}
	if err := f.svc.Store.Put("missions", mission.ID, mission); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ConfigureMissionPlan(mission.ID, MissionPlanInput{RunElevatedRequirementIDs: []string{"R3"}, RetryCatalogIDs: []string{"lateral-elevated"}}); err != nil {
		t.Fatal(err)
	}
	configured, err := f.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !configured.Requirements[2].RunElevated || configured.Status != "planning" || configured.CurrentPlanID != "" {
		t.Fatalf("explicit elevated execution was not persisted: %+v", configured)
	}
	if configured.Requirements[2].Protocol != "" || configured.Requirements[3].Protocol != "" {
		t.Fatalf("retry retained a protocol from an unproven lateral plan: %+v", configured.Requirements)
	}
	if len(configured.Attempts) != 0 {
		t.Fatalf("explicit failed catalogue retry did not clear its attempt: %+v", configured.Attempts)
	}
	actions, err := f.svc.candidateActions(context.Background(), configured)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Catalog.ID != "lateral-elevated" || !actions[0].Elevated {
		t.Fatalf("explicit elevated lateral simulation was not admitted: %+v", actions)
	}
	if configured.Requirements[0].Status != "proven" || configured.Requirements[1].Status != "proven" {
		t.Fatal("configuring harness elevation altered prior evidence")
	}
}

func TestFocusedContractsRejectBroadAPTChains(t *testing.T) {
	broad := Catalog{ID: "APT_BROAD", Name: "APT credential theft and remote execution", Tags: map[string]any{"category": "APT"}, Techniques: []map[string]any{{"tactic_id": "TA0006"}, {"tactic_id": "TA0008"}}}
	broadContract := actionContractFor(broad, "endpoint_chain", "source", "source", "destination", "")
	for _, forbidden := range []string{"credential_access_validated", "lateral_movement_validated", "domain_context_observed"} {
		if contractProduces(broadContract, forbidden) {
			t.Fatalf("broad APT chain incorrectly produced %s: %+v", forbidden, broadContract)
		}
	}
	privEsc := Catalog{ID: "PRIVESC", Name: "Print Spooler Privilege Escalation", Tags: map[string]any{"category": "Privilege Escalation"}, Techniques: []map[string]any{{"tactic_id": "TA0004", "technique_id": "T1068"}}}
	privEscContract := actionContractFor(privEsc, "endpoint_chain", "source", "source", "destination", "")
	if !contractProduces(privEscContract, "elevated_context_proven") {
		t.Fatalf("focused privilege-escalation chain did not produce elevation evidence contract: %+v", privEscContract)
	}
	foundDomainPrerequisite := false
	for _, required := range privEscContract.Requires {
		foundDomainPrerequisite = foundDomainPrerequisite || required.Type == "domain_context_observed"
	}
	if !foundDomainPrerequisite {
		t.Fatalf("cross-host privilege escalation did not require discovery first: %+v", privEscContract)
	}
}

func TestProtocolInferencePrefersLateralTechniqueMetadata(t *testing.T) {
	catalog := Catalog{
		ID: "ssh-lateral", Name: "SSH-based lateral movement with RDP credential collection",
		Description: "Dump RDP credentials before SSH remote execution.",
		Tags:        map[string]any{"category": "Lateral Movement"},
		Techniques:  []map[string]any{{"tactic_id": "TA0008", "technique_id": "T1021", "absolute_id": "TA0008.T1021.004"}},
	}
	contract := actionContractFor(catalog, "endpoint_chain", "source", "source", "destination", "")
	if contract.Protocol != "ssh" {
		t.Fatalf("protocol was inferred from incidental prose instead of ATT&CK metadata: %+v", contract)
	}
}

func TestStartingUserMissionStagesFocusedDiscoveryPrivilegeCredentialAndLateralActions(t *testing.T) {
	f := setup(t)
	f.svc.Config.AllowElevated = true
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{
		{ID: "a-domain", Name: "Active Directory domain discovery", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Active Directory Discovery"}, Stages: []map[string]any{{"actions": []any{"discover"}}}},
		{ID: "b-privesc", Name: "UAC bypass privilege escalation", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Privilege Escalation"}, Techniques: []map[string]any{{"tactic_id": "TA0004", "technique_id": "T1548"}}, Stages: []map[string]any{{"actions": []any{"elevate"}}}},
		{ID: "c-credential", Name: "LSASS credential dump", Elevated: true, Platforms: []string{"windows"}, Tags: map[string]any{"category": "Credential Access"}, Techniques: []map[string]any{{"tactic_id": "TA0006", "technique_id": "T1003"}}, Stages: []map[string]any{{"actions": []any{"credential"}}}},
		{ID: "d-lateral", Name: "Pass-the-Hash SMB remote execution", Elevated: true, Platforms: []string{"windows"}, Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008", "technique_id": "T1550"}}, Stages: []map[string]any{{"actions": []any{"lateral"}}}},
		{ID: "bad-apt", Name: "APT credential theft and remote execution", Platforms: []string{"windows"}, Tags: map[string]any{"category": "APT"}, Techniques: []map[string]any{{"tactic_id": "TA0006"}, {"tactic_id": "TA0008"}}},
	}}
	mission, err := normalizeMissionInput(MissionInput{
		Request: "Start as a standard-user and move from source to destination",
		Requirements: []Requirement{
			{ID: "R1", Type: "domain_context_observed", Target: "source", UserContextOnly: true, Mandatory: true},
			{ID: "R2", Type: "elevated_context_proven", Target: "source", UserContextOnly: true, Mandatory: true},
			{ID: "R3", Type: "credential_access_validated", Target: "source", Mandatory: true},
			{ID: "R4", Type: "lateral_movement_validated", Source: "source", Target: "destination", Mandatory: true},
		},
	}, "mission-chat")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, asset := range []string{"source", "destination"} {
		mission.Facts = append(mission.Facts,
			Fact{Type: "asset_available", Subject: asset, Status: "proven", Value: "true", ObservedAt: now},
			Fact{Type: "asset_connected", Subject: asset, Status: "proven", Value: "true", ObservedAt: now},
			Fact{Type: "platform_windows", Subject: asset, Status: "proven", Value: "windows", ObservedAt: now},
		)
	}
	mission.Facts = append(mission.Facts, Fact{Type: "elevated_capability", Subject: "source", Status: "proven", Value: "true", ObservedAt: now})
	decision, err := f.svc.missionPlanningDecision(context.Background(), mission)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Route != "discovery" || len(decision.Selected) != 4 {
		t.Fatalf("expected a four-stage path with a one-action discovery checkpoint: %+v", decision)
	}
	want := []string{"a-domain", "b-privesc", "c-credential", "d-lateral"}
	for index, id := range want {
		if decision.Selected[index].Catalog.ID != id {
			t.Fatalf("unexpected staged path at %d: got=%s want=%s path=%+v", index, decision.Selected[index].Catalog.ID, id, decision.Selected)
		}
	}
	if decision.Selected[3].Protocol != "smb" {
		t.Fatalf("lateral protocol was not derived from the focused action contract: %+v", decision.Selected[3])
	}
}

func TestSourceOnlyLateralSimulationNeedsNoInventedRoutePrerequisites(t *testing.T) {
	f := setup(t)
	f.svc.Config.AllowElevated = true
	catalog := Catalog{
		ID: "lateral-simulation", Name: "Lateral catalogue chain", Elevated: true,
		Platforms: []string{"windows"}, Tags: map[string]any{"category": "Lateral Movement"},
	}
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{catalog}}
	m, err := normalizeMissionInput(MissionInput{Request: "Validate a lateral simulation on source", Requirements: []Requirement{{ID: "R1", Type: "lateral_movement_validated", Target: "source", Mandatory: true}}}, "mission-chat")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Requirements) != 1 || m.Requirements[0].Type != "lateral_movement_validated" {
		t.Fatalf("source-only simulation acquired cross-host prerequisites: %+v", m.Requirements)
	}
	now := time.Now().UTC()
	m.Facts = []Fact{
		{Type: "asset_available", Subject: "source", Status: "proven", ObservedAt: now},
		{Type: "asset_connected", Subject: "source", Status: "proven", ObservedAt: now},
		{Type: "platform_windows", Subject: "source", Status: "proven", ObservedAt: now},
		{Type: "elevated_capability", Subject: "source", Status: "proven", ObservedAt: now},
	}
	actions, err := f.svc.candidateActions(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || actions[0].Catalog.ID != catalog.ID || len(actions[0].PreReqIDs) != 0 {
		t.Fatalf("source-only lateral chain was not selectable: %+v", actions)
	}
	item := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: catalog.ID, AssetIDs: []string{"source"}, Contract: &actions[0].Contract}, Status: "completed", Report: map[string]any{"assets": []any{map[string]any{"asset_id": "source", "steps": []any{map[string]any{"id": "lateral-step", "done": true, "success": true}}}}}}
	status, _, _ := evaluateRequirementEvidence(item, m.Requirements[0])
	if status != "proven" {
		t.Fatalf("successful lateral simulation did not satisfy its simulation predicate: %s", status)
	}
}

func TestElevatedRunRequestDoesNotBypassStartingUserElevationProof(t *testing.T) {
	f := setup(t)
	f.svc.Config.AllowElevated = true
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{
		{ID: "elevated-behavior", Name: "Elevated behavior", Elevated: true, Platforms: []string{"windows"}},
	}}
	now := time.Now().UTC()
	m := Mission{
		InitialUserContext: true,
		Requirements: []Requirement{
			{ID: "elevation", Type: "elevated_context_proven", Target: "source", TargetKind: "endpoint_chain", UserContextOnly: true, Mandatory: true},
			{ID: "behavior", Type: "behavior_executed", Target: "source", TargetKind: "endpoint_chain", RunElevated: true, Mandatory: true},
		},
		Facts: []Fact{
			{Type: "asset_available", Subject: "source", Status: "proven", Value: "true", ObservedAt: now},
			{Type: "asset_connected", Subject: "source", Status: "proven", Value: "true", ObservedAt: now},
			{Type: "platform_windows", Subject: "source", Status: "proven", Value: "windows", ObservedAt: now},
			{Type: "elevated_capability", Subject: "source", Status: "proven", Value: "true", ObservedAt: now},
		},
	}
	actions, err := f.svc.candidateActions(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		if action.Catalog.ID == "elevated-behavior" {
			hasElevationPrerequisite := false
			for _, prerequisite := range action.PreReqIDs {
				hasElevationPrerequisite = hasElevationPrerequisite || prerequisite == "elevation"
			}
			if !hasElevationPrerequisite {
				t.Fatalf("elevated action bypassed source elevation proof: %+v", action)
			}
			return
		}
	}
	t.Fatal("elevated action was not offered with its elevation prerequisite")
}

func TestSelectedLateralProtocolIsPinnedToEveryCrossHostProof(t *testing.T) {
	f := setup(t)
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request: "Validate a reviewed source-to-destination path",
		Requirements: []Requirement{
			{ID: "R1", Type: "lateral_movement_validated", Source: "asset-1", Target: "destination", Mandatory: true},
			{ID: "R2", Type: "remote_access_proven", Source: "asset-1", Target: "destination", Mandatory: true},
			{ID: "R3", Type: "identity_observed", Source: "asset-1", Target: "destination", ExpectedIdentity: "Administrator", Mandatory: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.pinMissionProtocol(mission.ID, "SMB"); err != nil {
		t.Fatal(err)
	}
	mission, err = f.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range mission.Requirements {
		if requirement.Source != "" && requirement.Target != "" && requirement.Protocol != "smb" {
			t.Fatalf("cross-host requirement %s did not inherit the authorized protocol: %+v", requirement.ID, requirement)
		}
	}
}

func TestMissionGraphCreatesReviewedPlan(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}
	result, err := f.svc.RunMissionGraph(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate command execution on the lab endpoint",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Status: "proven", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan == nil || result.Plan.Status != "planned" {
		t.Fatalf("expected a planned reviewable plan: %+v", result)
	}
	if result.Plan.MissionID != result.Mission.ID || result.Mission.Status != "awaiting_authorization" {
		t.Fatalf("mission linkage/status missing: mission=%+v plan=%+v", result.Mission, result.Plan)
	}
	if len(result.Plan.Items) != 1 || result.Plan.Items[0].RequirementIDs[0] != "R1" {
		t.Fatalf("requirement was not linked to plan item: %+v", result.Plan.Items)
	}
}

func TestMissionPlanUsesSnapshotUntilLiveAuthorization(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("snapshot-chain", "Snapshot chain", "T1059")}}
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate command execution from the stored catalogue",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || planned.Plan == nil || len(planned.Plan.Items) != 1 || planned.Plan.Items[0].CatalogID != "snapshot-chain" {
		t.Fatalf("snapshot-backed review plan failed: %+v %v", planned, err)
	}
	if err := f.svc.Authorize(context.Background(), planned.Plan.ID, planned.Plan.Hash, time.Time{}); err == nil {
		t.Fatal("authorization accepted a catalogue entry that FourCore did not confirm live")
	}
}

func TestAdvanceMissionsDoesNotRepeatOperatorGateTrace(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}
	result, err := f.svc.RunMissionGraph(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate command execution",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	traceLength := len(result.Mission.WorkflowTrace)
	if err := f.svc.AdvanceMissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored, err := f.svc.missionByID(result.Mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.WorkflowTrace) != traceLength {
		t.Fatalf("worker repeated an operator-gate transition: before=%d after=%d", traceLength, len(stored.WorkflowTrace))
	}
}

func traceContains(m Mission, node, route string) bool {
	for _, transition := range m.WorkflowTrace {
		if transition.Node == node && (route == "" || transition.Route == route) {
			return true
		}
	}
	return false
}

func TestMissionWorkflowTraversesAuthorizationExecutionEvidenceAndReport(t *testing.T) {
	f := setup(t)
	f.svc.Config.CorrelationWait = 0
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}

	result, err := f.svc.RunMissionGraph(context.Background(), "workflow-chat", MissionInput{
		Request:      "Validate T1059 on the lab endpoint",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct{ node, route string }{
		{"go_validates_mission", "valid"},
		{"create_durable_mission", "created"},
		{"read_live_asset_inventory", "inventory_loaded"},
		{"read_local_fourcore_catalogue", "catalogue_loaded"},
		{"load_evidence_from_prior_attempts", "evidence_loaded"},
		{"build_known_fact_set", "facts_built"},
		{"evaluate_mission_objectives", "objectives_remain"},
		{"build_candidate_action_graph", "candidates_built"},
		{"fully_feasible_path_exists", "full"},
		{"select_shortest_feasible_path", "selected"},
		{"create_immutable_attack_plan", "plan_created"},
		{"user_authorizes_exact_plan_hash", "authorization_required"},
	} {
		if !traceContains(result.Mission, expected.node, expected.route) {
			t.Fatalf("workflow trace omitted %s/%s: %+v", expected.node, expected.route, result.Mission.WorkflowTrace)
		}
	}
	if result.Mission.WorkflowStage != "user_authorizes_exact_plan_hash" || result.Mission.WorkflowVersion != missionWorkflowVersion {
		t.Fatalf("mission did not checkpoint at authorization: %+v", result.Mission)
	}
	if result.Plan == nil {
		t.Fatal("workflow did not create an immutable plan")
	}
	if err := f.svc.Authorize(context.Background(), result.Plan.ID, result.Plan.Hash, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.state = "completed"
	f.mu.Unlock()
	if err := f.svc.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}

	completed, err := f.svc.missionByID(result.Mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != "completed" || completed.Requirements[0].Status != "proven" {
		t.Fatalf("execution evidence did not complete the objective: %+v", completed)
	}
	for _, expected := range []struct{ node, route string }{
		{"user_authorizes_exact_plan_hash", "authorized"},
		{"worker_submits_or_polls_plan", "execution_received"},
		{"execution_id_received", "poll"},
		{"poll_execution_report", "waiting"},
		{"worker_submits_or_polls_plan", "report_ready"},
		{"poll_execution_report", "report_ready"},
		{"apply_evidence_contract", "applied"},
		{"update_facts_and_objective_results", "facts_updated"},
		{"new_facts_produced", "yes"},
		{"evaluate_mission_objectives", "all_satisfied"},
		{"generate_final_report", "complete"},
	} {
		if !traceContains(completed, expected.node, expected.route) {
			t.Fatalf("completed workflow trace omitted %s/%s: %+v", expected.node, expected.route, completed.WorkflowTrace)
		}
	}
	if completed.WorkflowStage != "generate_final_report" || f.posts.Load() != 1 {
		t.Fatalf("workflow did not terminate cleanly or submitted twice: mission=%+v posts=%d", completed, f.posts.Load())
	}
	report, err := f.svc.MissionReport(completed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.WorkflowStage != "generate_final_report" || len(report.WorkflowTrace) == 0 || len(report.AttackPath) != 1 {
		t.Fatalf("mission report omitted workflow or attack path evidence: %+v", report)
	}
}

func TestMissionWorkflowRoutesUncertainExecutionToReconciliation(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}
	result, err := f.svc.RunMissionGraph(context.Background(), "workflow-chat", MissionInput{
		Request:      "Validate T1059 on the lab endpoint",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil || result.Plan == nil {
		t.Fatalf("plan creation failed: %+v %v", result, err)
	}
	if err := f.svc.Store.UpdatePlan(result.Plan.ID, func(p *Plan) error {
		p.Status = "needs_reconciliation"
		p.Items[0].Status = "unknown"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Store.UpdateMission(result.Mission.ID, func(m *Mission) error {
		m.Status = "reconcile"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	resumed, err := f.svc.AdvanceMissionGraph(context.Background(), result.Mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Mission.WorkflowStage != "require_reconciliation" || !traceContains(resumed.Mission, "require_reconciliation", "operator_reconciliation_required") {
		t.Fatalf("uncertain execution did not stop at reconciliation: %+v", resumed.Mission)
	}
}

func TestMissionWorkflowRecordsExactFailureBeforeApplyingEvidence(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}
	result, err := f.svc.RunMissionGraph(context.Background(), "workflow-chat", MissionInput{
		Request:      "Validate T1059 on the lab endpoint",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil || result.Plan == nil {
		t.Fatalf("plan creation failed: %+v %v", result, err)
	}
	if err := f.svc.Store.UpdatePlan(result.Plan.ID, func(p *Plan) error {
		p.Status = "failed"
		p.Items[0].Status = "failed"
		p.Items[0].Error = "FourCore HTTP 403"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Store.UpdateMission(result.Mission.ID, func(m *Mission) error { m.Status = "running"; return nil }); err != nil {
		t.Fatal(err)
	}
	resumed, err := f.svc.AdvanceMissionGraph(context.Background(), result.Mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !traceContains(resumed.Mission, "record_exact_submission_or_execution_failure", "failure_recorded") || !traceContains(resumed.Mission, "apply_evidence_contract", "applied") {
		t.Fatalf("failure did not pass through exact-record and evidence nodes: %+v", resumed.Mission.WorkflowTrace)
	}
	found := false
	for _, transition := range resumed.Mission.WorkflowTrace {
		if transition.Node == "record_exact_submission_or_execution_failure" && strings.Contains(transition.Detail, "FourCore HTTP 403") {
			found = true
		}
	}
	if !found {
		t.Fatalf("exact provider failure was not retained in the workflow trace: %+v", resumed.Mission.WorkflowTrace)
	}
}

func TestMissionWorkflowClarificationBranchDoesNotCreateMission(t *testing.T) {
	f := setup(t)
	before, err := f.svc.Store.Missions()
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RunMissionGraph(context.Background(), "workflow-chat", MissionInput{})
	var workflowErr *MissionWorkflowError
	if !errors.As(err, &workflowErr) || workflowErr.Kind != "clarification" {
		t.Fatalf("empty request did not reach clarification branch: %T %v", err, err)
	}
	after, err := f.svc.Store.Missions()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("clarification branch persisted an invalid mission: before=%d after=%d", len(before), len(after))
	}
}

func TestMissionPlannerChoosesShortestCoveringPath(t *testing.T) {
	reqs := []Requirement{
		{ID: "R1", Mandatory: true},
		{ID: "R2", Mandatory: true},
	}
	actions := []missionAction{
		{Catalog: Catalog{ID: "a"}, ReqIDs: []string{"R1"}, ReqMask: 1},
		{Catalog: Catalog{ID: "b"}, ReqIDs: []string{"R2"}, ReqMask: 2},
		{Catalog: Catalog{ID: "c"}, ReqIDs: []string{"R1", "R2"}, ReqMask: 3},
	}
	selected, reason := chooseActions(Mission{Requirements: reqs}, actions, 5)
	if reason != "" || len(selected) != 1 || selected[0].Catalog.ID != "c" {
		t.Fatalf("planner did not choose shortest covering path: selected=%+v reason=%q", selected, reason)
	}
	ordered, reason := chooseActions(Mission{Requirements: reqs}, []missionAction{
		{Catalog: Catalog{ID: "lateral"}, ReqIDs: []string{"R2"}, ReqMask: 2, PreReqIDs: []string{"R1"}, PreMask: 1},
		{Catalog: Catalog{ID: "credential"}, ReqIDs: []string{"R1"}, ReqMask: 1},
	}, 5)
	if reason != "" || len(ordered) != 2 || ordered[0].Catalog.ID != "credential" || ordered[1].Catalog.ID != "lateral" {
		t.Fatalf("planner ignored action prerequisites: selected=%+v reason=%q", ordered, reason)
	}
}

func TestMissionPlannerSkipsUnaddressableCatalogueIDs(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{
		missionTestCatalog("invalid catalogue id", "Unaddressable chain", "T1059"),
		missionTestCatalog("chain-1", "Addressable chain", "T1059"),
	}}
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate T1059 on the lab endpoint",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Plan == nil || len(planned.Plan.Items) != 1 || planned.Plan.Items[0].CatalogID != "chain-1" {
		t.Fatalf("invalid catalogue ID blocked the valid candidate: %+v", planned)
	}
}

func TestMissionPlannerFiltersIncompatibleCataloguePlatforms(t *testing.T) {
	f := setup(t)
	darwin := missionTestCatalog("a-darwin", "macOS shell discovery", "T1059")
	darwin.Platforms = []string{"darwin"}
	windows := missionTestCatalog("b-windows", "Windows command discovery", "T1059")
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{darwin, windows}}
	mission, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate T1059 on the Windows lab endpoint",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || planned.Plan == nil || len(planned.Plan.Items) != 1 || planned.Plan.Items[0].CatalogID != "b-windows" {
		t.Fatalf("planner selected an incompatible catalogue entry: %+v %v", planned, err)
	}
}

func TestPlannerReturnsMaximalFeasiblePrefix(t *testing.T) {
	reqs := []Requirement{{ID: "R1", Mandatory: true}, {ID: "R2", Mandatory: true}, {ID: "R3", Mandatory: true}}
	actions := []missionAction{
		{Catalog: Catalog{ID: "discovery"}, ReqIDs: []string{"R1"}, ReqMask: 1},
		{Catalog: Catalog{ID: "credential"}, ReqIDs: []string{"R2"}, ReqMask: 2, PreReqIDs: []string{"R1"}, PreMask: 1},
	}
	selected, reason := chooseActions(Mission{Requirements: reqs}, actions, 5)
	if len(selected) != 2 || selected[0].Catalog.ID != "discovery" || selected[1].Catalog.ID != "credential" || reason == "" {
		t.Fatalf("planner did not retain the feasible prefix: selected=%+v reason=%q", selected, reason)
	}
}

func TestPlannerUsesCompleteCatalogueAndActionEffects(t *testing.T) {
	f := setup(t)
	items := make([]Catalog, 30)
	for i := range items {
		items[i] = Catalog{ID: "irrelevant-" + string(rune('a'+i)), Name: "Generic discovery", Platforms: []string{"windows"}, Techniques: []map[string]any{{"tactic_id": "TA0007", "technique_id": "T1057"}}}
	}
	items[29] = missionTestCatalog("chain-1", "Test chain", "T1059")
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: items}
	m, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate T1059",
		Requirements: []Requirement{{Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Plan == nil || len(planned.Plan.Items) != 1 || planned.Plan.Items[0].CatalogID != "chain-1" {
		t.Fatalf("planner did not use the full catalogue/effect contract: %+v", planned)
	}
	if planned.Plan.Items[0].Contract == nil || !contractProduces(*planned.Plan.Items[0].Contract, "behavior_executed") {
		t.Fatalf("plan did not retain the action contract: %+v", planned.Plan.Items[0])
	}
	ad := Catalog{ID: "ad-path", Name: "Active Directory credential and remote execution", Description: "Active Directory credential dumping and pass-the-hash remote execution over SMB", Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0006"}, {"tactic_id": "TA0008"}}}
	contract := actionContractFor(ad, "endpoint_chain", "source", "source", "destination", "smb")
	for _, effect := range []string{"credential_access_validated", "lateral_movement_validated"} {
		if !contractProduces(contract, effect) {
			t.Fatalf("AD action contract omitted %s: %+v", effect, contract)
		}
	}
	if contractProduces(contract, "domain_context_observed") {
		t.Fatalf("a lateral-movement chain was incorrectly treated as focused AD discovery: %+v", contract)
	}
	for _, prerequisite := range contract.Requires {
		if prerequisite.Type == "domain_context_observed" || prerequisite.Type == "credential_access_validated" {
			t.Fatalf("AD lateral action forced unnecessary discovery: %+v", contract)
		}
	}
	if !contractProduces(contract, "remote_access_proven") || !contractProduces(contract, "identity_observed") {
		t.Fatalf("explicit provider report effects were not available: %+v", contract)
	}
	if contract.Protocol != "smb" {
		t.Fatalf("protocol was not retained or inferred: %+v", contract)
	}
}

func TestUserContextADPlanTriesMinimalLateralCandidate(t *testing.T) {
	f := setup(t)
	m, err := normalizeMissionInput(MissionInput{
		Request:      "Start with user permissions and validate lateral movement",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: "destination", ExpectedIdentity: "administrator", UserContextOnly: true, Mandatory: true}},
	}, "mission-chat")
	if err != nil {
		t.Fatal(err)
	}
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{
		{ID: "a-domain", Name: "LDAP Active Directory discovery", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Active Directory Discovery"}},
		{ID: "b-credential", Name: "Credential dump", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Credential Access"}, Techniques: []map[string]any{{"tactic_id": "TA0006"}}},
		{ID: "c-lateral", Name: "PsExec over SMB", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Lateral Movement"}, Techniques: []map[string]any{{"tactic_id": "TA0008"}}},
		{ID: "d-elevated-shortcut", Name: "Elevated AD credential and PsExec chain", Description: "Active Directory credential dump and PsExec over SMB", Elevated: true, Platforms: []string{"windows"}, Tags: map[string]any{"category": "APT"}, Techniques: []map[string]any{{"tactic_id": "TA0006"}, {"tactic_id": "TA0008"}}},
	}}
	actions, err := f.svc.candidateActions(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	selected, reason := chooseActions(m, actions, 5)
	if reason != "" || len(selected) != 1 || selected[0].Catalog.ID != "c-lateral" {
		t.Fatalf("planner did not choose the smallest relevant catalogue candidate: selected=%+v reason=%q", selected, reason)
	}
	if selected[0].Protocol != "smb" || selected[0].Elevated || len(selected[0].ReqIDs) != 2 {
		t.Fatalf("lateral step ignored protocol, objective, or user-context constraint: %+v", selected[0])
	}
}

func TestExplicitDomainDiscoveryPrecedesCredentialAccessRegardlessOfCatalogID(t *testing.T) {
	f := setup(t)
	m, err := normalizeMissionInput(MissionInput{
		Request: "Start with initial domain discovery, then validate credential access",
		Requirements: []Requirement{
			{ID: "R1", Type: "domain_context_observed", Target: "asset-1", Mandatory: true},
			{ID: "R2", Type: "credential_access_validated", Target: "asset-1", Mandatory: true},
		},
	}, "mission-chat")
	if err != nil {
		t.Fatal(err)
	}
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{
		{ID: "a-credential", Name: "Credential discovery", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Credential Access"}, Techniques: []map[string]any{{"tactic_id": "TA0006"}}},
		{ID: "z-domain", Name: "Active Directory domain discovery", Platforms: []string{"windows"}, Tags: map[string]any{"category": "Active Directory Discovery"}, Techniques: []map[string]any{{"tactic_id": "TA0007"}}},
	}}
	actions, err := f.svc.candidateActions(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	selected, reason := chooseActions(m, actions, 5)
	if reason != "" || len(selected) != 2 || selected[0].Catalog.ID != "z-domain" || selected[1].Catalog.ID != "a-credential" {
		t.Fatalf("explicit initial discovery was not ordered first: selected=%+v reason=%q", selected, reason)
	}
}

func TestMissionSyncUsesStrictEvidenceStates(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}
	m, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate command execution",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), m.ID)
	if err != nil || planned.Plan == nil {
		t.Fatalf("plan creation failed: %+v %v", planned, err)
	}
	if err := f.svc.Store.UpdatePlan(planned.Plan.ID, func(p *Plan) error {
		p.Status = "completed"
		p.Items[0].Status = "completed"
		p.Items[0].ExecutionID = "execution-1"
		p.Items[0].Report = map[string]any{"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{"done": true, "success": true}}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SyncMission(m.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.missionByID(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" || got.Requirements[0].Status != "proven" {
		t.Fatalf("successful evidence did not satisfy requirement: %+v", got)
	}
	report, err := f.svc.MissionReport(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AttackPath) != 1 || len(report.Requirements) != 1 || len(report.Conclusions) == 0 || report.AttackPath[0].ExecutionID != "execution-1" {
		t.Fatalf("mission report omitted path or evidence: %+v", report)
	}

	m2, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Prove a remote session",
		Requirements: []Requirement{{ID: "R1", Type: "remote_access_proven", Source: "asset-1", Target: "asset-1", Protocol: "winrm", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned2, err := f.svc.PlanMission(context.Background(), m2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if (planned2.Mission.Status != "blocked" && planned2.Mission.Status != "unattainable") || planned2.Plan != nil {
		t.Fatalf("unsupported remote proof was presented as executable: %+v", planned2)
	}

	detection, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Observe detection for command execution",
		Requirements: []Requirement{{ID: "R1", Type: "detection_observed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	detectionPlan, err := f.svc.PlanMission(context.Background(), detection.ID)
	if err != nil || detectionPlan.Plan == nil {
		t.Fatalf("detection plan creation failed: %+v %v", detectionPlan, err)
	}
	if err := f.svc.Store.UpdatePlan(detectionPlan.Plan.ID, func(p *Plan) error {
		p.Status = "completed"
		p.Items[0].Status = "completed"
		p.Items[0].ExecutionID = "execution-detection"
		p.Items[0].Report = map[string]any{"assets": []any{map[string]any{"steps": []any{map[string]any{"success": true}}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SyncMission(detection.ID); err != nil {
		t.Fatal(err)
	}
	detectionState, err := f.svc.missionByID(detection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detectionState.Requirements[0].Status != "unknown" || detectionState.Status != "planning" {
		t.Fatalf("detection was inferred without explicit detection evidence: %+v", detectionState)
	}

	reconcile, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Recover an uncertain execution",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	reconcilePlan, err := f.svc.PlanMission(context.Background(), reconcile.ID)
	if err != nil || reconcilePlan.Plan == nil {
		t.Fatalf("reconciliation plan creation failed: %+v %v", reconcilePlan, err)
	}
	if err := f.svc.Store.UpdatePlan(reconcilePlan.Plan.ID, func(p *Plan) error {
		p.Status = "needs_reconciliation"
		p.Items[0].Status = "unknown"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Store.UpdateMission(reconcile.ID, func(m *Mission) error { m.Status = "reconcile"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Reconcile(context.Background(), reconcilePlan.Plan.ID, 0, "execution-1"); err != nil {
		t.Fatal(err)
	}
	reconciled, err := f.svc.missionByID(reconcile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Status != "running" {
		t.Fatalf("mission did not resume after reconciliation: %+v", reconciled)
	}
}

func TestRecursiveEvidenceAndExplicitRemoteProof(t *testing.T) {
	report := map[string]any{
		"assets": []any{
			map[string]any{
				"steps": []any{
					map[string]any{
						"id": "parent", "done": true, "success": false,
						"action_steps": []any{map[string]any{"id": "nested", "done": true, "success": true, "detected": true, "output": "evidence"}},
					},
				},
			},
		},
		"route_evidence": map[string]any{
			"source_asset_id": "source", "destination_asset_id": "destination", "protocol": "smb",
			"reachable": true, "remote_execution_observed": true, "proof_token": "harmless-proof", "is_admin": true, "destination_identity": "Administrator",
		},
	}
	if ok, step := reportHasSuccessfulStep(report); !ok || step != "nested" {
		t.Fatalf("nested success was not extracted: ok=%v step=%q", ok, step)
	}
	if ok, step := reportHasDetection(report); !ok || step != "nested" {
		t.Fatalf("nested detection was not extracted: ok=%v step=%q", ok, step)
	}
	requirement := Requirement{Type: "remote_access_proven", Source: "source", Target: "destination", Protocol: "smb", ExpectedIdentity: "administrator"}
	remote, identity, reachable, _ := explicitRouteEvidence(report, requirement)
	if !remote || !identity || !reachable {
		t.Fatalf("explicit route proof was not recognized: remote=%v identity=%v reachable=%v", remote, identity, reachable)
	}
	wrongDestination := requirement
	wrongDestination.Target = "other"
	if remote, _, _, _ := explicitRouteEvidence(report, wrongDestination); remote {
		t.Fatal("route proof was accepted for a different destination")
	}
	contract := ActionContract{Produces: []PredicateSpec{{Type: "credential_access_validated", Subject: "source"}}}
	status, step, _ := evaluateRequirementEvidence(ValidatedItem{PlanItem: PlanItem{CatalogID: "credential-chain", Contract: &contract}, Status: "failed", Report: report}, Requirement{Type: "credential_access_validated", Target: "source"})
	if status != "proven" || step != "nested" {
		t.Fatalf("successful nested step in a failed run was discarded: status=%q step=%q", status, step)
	}
}

func TestElevationRequiresStructuredEvidenceForTheCorrectAsset(t *testing.T) {
	report := map[string]any{"assets": []any{
		map[string]any{"asset_id": "source", "steps": []any{map[string]any{"id": "whoami", "success": true, "identity": `NT AUTHORITY\SYSTEM`, "integrity_level": "system"}}},
		map[string]any{"asset_id": "other", "steps": []any{map[string]any{"id": "admin", "success": true, "is_admin": true}}},
	}}
	contract := ActionContract{Produces: []PredicateSpec{{Type: "elevated_context_proven", Subject: "source"}}}
	item := ValidatedItem{PlanItem: PlanItem{CatalogID: "focused-privesc", Contract: &contract}, Status: "completed", Report: report}
	status, _, detail := evaluateRequirementEvidence(item, Requirement{Type: "elevated_context_proven", Target: "source"})
	if status != "proven" || !strings.Contains(detail, "source") {
		t.Fatalf("structured local elevation evidence was not accepted: status=%q detail=%q", status, detail)
	}
	status, _, _ = evaluateRequirementEvidence(item, Requirement{Type: "elevated_context_proven", Target: "missing"})
	if status != "unknown" {
		t.Fatalf("elevation evidence leaked across assets: %q", status)
	}
	generic := item
	generic.Report = map[string]any{"assets": []any{map[string]any{"asset_id": "source", "steps": []any{map[string]any{"success": true, "output": "generic successful output"}}}}}
	status, _, _ = evaluateRequirementEvidence(generic, Requirement{Type: "elevated_context_proven", Target: "source"})
	if status != "unknown" {
		t.Fatalf("generic successful output was treated as elevation proof: %q", status)
	}
	generic.Report = map[string]any{"assets": []any{map[string]any{"asset_id": "source", "identity": `LAB\Administrator`, "integrity": "medium"}}}
	status, _, _ = evaluateRequirementEvidence(generic, Requirement{Type: "elevated_context_proven", Target: "source"})
	if status != "unknown" {
		t.Fatalf("administrator username with medium integrity was treated as admin proof: %q", status)
	}
}

func TestProvenRequirementKeepsItsProvingEvidence(t *testing.T) {
	first := time.Now().UTC()
	facts := []Fact{
		{Type: "requirement_evidence", Subject: "R1", Value: "proven", Status: "proven", ExecutionID: "proof-run", ObservedAt: first},
		{Type: "requirement_evidence", Subject: "R1", Value: "unknown", Status: "unknown", ExecutionID: "later-run", ObservedAt: first.Add(time.Second)},
	}
	status, evidence := requirementStatus(facts, "R1")
	if status != "proven" || evidence == nil || evidence.ExecutionID != "proof-run" {
		t.Fatalf("proven requirement lost its proving evidence: status=%q evidence=%+v", status, evidence)
	}
}

func TestSkippedPlanItemRemainsEligibleForReplanning(t *testing.T) {
	f := setup(t)
	f.svc.FC.catalog["endpoint_chain"] = catalogCacheEntry{Updated: time.Now().UTC(), Items: []Catalog{missionTestCatalog("chain-1", "Test chain", "T1059")}}
	m, err := f.svc.CreateMission(context.Background(), "mission-chat", MissionInput{
		Request:      "Validate command execution",
		Requirements: []Requirement{{ID: "R1", Type: "behavior_executed", Target: "asset-1", Technique: "T1059", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planned, err := f.svc.PlanMission(context.Background(), m.ID)
	if err != nil || planned.Plan == nil {
		t.Fatalf("plan creation failed: %+v %v", planned, err)
	}
	if err := f.svc.Store.UpdatePlan(planned.Plan.ID, func(p *Plan) error {
		p.Status = "failed"
		p.Items[0].Status = "skipped"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SyncMission(m.ID); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.missionByID(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Attempts) != 0 || got.Requirements[0].Status != "unknown" || got.Status != "planning" {
		t.Fatalf("skipped item was treated as attempted: %+v", got)
	}
	replanned, err := f.svc.PlanMission(context.Background(), m.ID)
	if err != nil || replanned.Plan == nil || replanned.Plan.Items[0].CatalogID != "chain-1" {
		t.Fatalf("skipped catalogue entry was not eligible for replanning: %+v %v", replanned, err)
	}
}
