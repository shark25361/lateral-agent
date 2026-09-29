package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const lateralTestDestination = "22222222-2222-2222-2222-222222222222"

func TestDestinationAdminRequiresHighIntegrity(t *testing.T) {
	for _, tc := range []struct {
		integrity string
		admin     bool
	}{{"medium", false}, {"high", true}, {"system", true}, {"unknown", false}} {
		if got := destinationAdminIntegrity(tc.integrity); got != tc.admin {
			t.Fatalf("integrity %q yielded admin=%v", tc.integrity, got)
		}
	}
}

func lateralTestGraph() ADGraph {
	source := ADGraphNode{ID: "machine:source", Kind: "machine", Label: "attack.test", AssetID: "asset-1"}
	destination := ADGraphNode{ID: "machine:destination", Kind: "machine", Label: "secattack", AssetID: lateralTestDestination}
	service := ADGraphNode{ID: "service:smb", Kind: "service", Label: "secattack:smb:445", Properties: map[string]string{"protocol": "smb", "port": "445"}}
	identity := ADGraphNode{ID: "identity:operator", Kind: "identity", Label: `LAB\operator`}
	decoy := ADGraphNode{ID: "machine:decoy", Kind: "machine", Label: "unused.test", AssetID: "unused"}
	return ADGraph{Nodes: []ADGraphNode{source, destination, service, identity, decoy}, Edges: []ADGraphEdge{
		{ID: "edge:reachable", Source: source.ID, Target: service.ID, Kind: "service_reachable", Protocol: "smb", Port: "445", Directed: true, Status: "observed"},
		{ID: "edge:service", Source: destination.ID, Target: service.ID, Kind: "service_on", Protocol: "smb", Port: "445", Directed: true, Status: "observed"},
		{ID: "edge:session", Source: identity.ID, Target: source.ID, Kind: "session_on", Directed: true, Status: "observed"},
		{ID: "edge:permission", Source: identity.ID, Target: destination.ID, Kind: "can_smb", Protocol: "smb", Port: "445", Directed: true, Status: "observed"},
		{ID: "edge:decoy", Source: source.ID, Target: decoy.ID, Kind: "domain_trust", Directed: true, Status: "observed"},
	}}
}

func TestGoalDirectedRouteUsesShortestRelevantEvidence(t *testing.T) {
	route := goalDirectedADRoute(Mission{ADGraph: lateralTestGraph()}, "asset-1", lateralTestDestination, "smb")
	if !route.Ready || len(route.EdgeIDs) != 2 || route.EdgeIDs[0] != "edge:session" || route.EdgeIDs[1] != "edge:permission" {
		t.Fatalf("unexpected goal-directed route: %+v", route)
	}
}

func TestGoalDirectedRouteUsesProtocolCapability(t *testing.T) {
	source := ADGraphNode{ID: "machine:source", Kind: "machine", AssetID: "asset-1"}
	identity := ADGraphNode{ID: "identity:operator", Kind: "identity", Label: `NORTH\operator`}
	destination := ADGraphNode{ID: "machine:destination", Kind: "machine", AssetID: lateralTestDestination}
	mission := Mission{ADGraph: ADGraph{Nodes: []ADGraphNode{source, identity, destination}, Edges: []ADGraphEdge{
		{ID: "edge:session", Source: identity.ID, Target: source.ID, Kind: "session_on", Directed: true, Status: "observed"},
		{ID: "edge:smb", Source: identity.ID, Target: destination.ID, Kind: "can_smb", Protocol: "smb", Port: "445", Directed: true, Status: "observed"},
		{ID: "edge:rdp", Source: identity.ID, Target: destination.ID, Kind: "can_rdp", Protocol: "rdp", Port: "3389", Directed: true, Status: "observed"},
	}}}
	route := goalDirectedADRoute(mission, "asset-1", lateralTestDestination, "smb")
	if !route.Ready || len(route.EdgeIDs) != 2 || route.EdgeIDs[1] != "edge:smb" {
		t.Fatalf("SMB route did not use the protocol-specific capability: %+v", route)
	}
}

func TestGoalDirectedRouteSkipsShorterUnexecutableTrustEdge(t *testing.T) {
	graph := lateralTestGraph()
	graph.Edges = append(graph.Edges, ADGraphEdge{ID: "trust-only", Source: "machine:source", Target: "machine:destination", Kind: "domain_trust", Directed: true, Status: "observed"})
	route := goalDirectedADRoute(Mission{ADGraph: graph}, "asset-1", lateralTestDestination, "smb")
	if !route.Ready || len(route.EdgeIDs) != 2 || route.EdgeIDs[0] != "edge:session" {
		t.Fatalf("planner chose a non-executable shortcut: %+v", route)
	}
}

func TestGoalDirectedRouteRejectsReachabilityWithoutIdentity(t *testing.T) {
	graph := lateralTestGraph()
	graph.Edges = graph.Edges[:2]
	route := goalDirectedADRoute(Mission{ADGraph: graph}, "asset-1", lateralTestDestination, "smb")
	if route.Ready || len(route.Missing) == 0 {
		t.Fatalf("port reachability was mistaken for lateral permission: %+v", route)
	}
}

func TestGoalDirectedRouteUsesNestedGroupAdminAndReachableService(t *testing.T) {
	graph := lateralTestGraph()
	graph.Edges = graph.Edges[:2]
	graph.Nodes = append(graph.Nodes,
		ADGraphNode{ID: "identity:alice", Kind: "identity", Label: `LAB\alice`},
		ADGraphNode{ID: "group:operators", Kind: "group", Label: `LAB\Operators`},
		ADGraphNode{ID: "group:admins", Kind: "group", Label: `LAB\Server Admins`},
	)
	graph.Edges = append(graph.Edges,
		ADGraphEdge{ID: "session", Source: "identity:alice", Target: "machine:source", Kind: "session_on", Directed: true, Status: "observed"},
		ADGraphEdge{ID: "member-1", Source: "identity:alice", Target: "group:operators", Kind: "member_of_group", Directed: true, Status: "observed"},
		ADGraphEdge{ID: "member-2", Source: "group:operators", Target: "group:admins", Kind: "member_of_group", Directed: true, Status: "observed"},
		ADGraphEdge{ID: "admin", Source: "group:admins", Target: "machine:destination", Kind: "admin_to", Directed: true, Status: "observed"},
	)
	route := goalDirectedADRoute(Mission{ADGraph: graph}, "asset-1", lateralTestDestination, "smb")
	if !route.Ready || len(route.EdgeIDs) != 4 || route.EdgeIDs[3] != "admin" {
		t.Fatalf("nested group control was not usable: %+v", route)
	}
	graph.Edges = graph.Edges[2:]
	route = goalDirectedADRoute(Mission{ADGraph: graph}, "asset-1", lateralTestDestination, "smb")
	if route.Ready {
		t.Fatalf("admin rights were mistaken for network reachability: %+v", route)
	}
}

func TestGoalDirectedRouteAcceptsVerifiedRemoteAccess(t *testing.T) {
	graph := lateralTestGraph()
	graph.Edges = []ADGraphEdge{{ID: "verified-hop", Source: "machine:source", Target: "machine:destination", Kind: "remote_access", Protocol: "smb", Directed: true, Status: "verified"}}
	route := goalDirectedADRoute(Mission{ADGraph: graph}, "asset-1", lateralTestDestination, "smb")
	if !route.Ready || len(route.EdgeIDs) != 1 || route.EdgeIDs[0] != "verified-hop" {
		t.Fatalf("verified remote access was omitted: %+v", route)
	}
}

func TestControlledLabLateralExecutionRequiresSignedDestinationEvidence(t *testing.T) {
	fixture := setup(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialReference := "vault://synthetic/secattack-admin"
	credentialHash := credentialReferenceHash(credentialReference)
	var mu sync.Mutex
	var submitted lateralSubmitRequest
	executor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer lab-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			_ = json.NewEncoder(w).Encode(LateralHealth{Status: "ok", Execute: true, SignedEvidence: true, Protocols: []string{"smb"}, SchemaVersion: "1", CredentialRefs: true, DestinationVerify: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/lateral/executions":
			mu.Lock()
			defer mu.Unlock()
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Error(err)
			}
			fmt.Fprint(w, `{"id":"lab-execution-1","status":"running"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/lateral/executions/lab-execution-1":
			mu.Lock()
			request := submitted
			mu.Unlock()
			evidence := LateralEvidence{ExecutionID: "lab-execution-1", InputHash: request.InputHash, CorrelationID: request.CorrelationID, SourceAssetID: request.SourceAssetID, DestinationAssetID: request.DestinationAssetID, Protocol: request.Protocol, Port: request.Port, ServiceReachable: true, RemoteAccess: true, Identity: `NORTH\Administrator`, Integrity: "high", ObservedAt: time.Now().UTC()}
			canonical, _ := canonicalEvidence(evidence)
			_ = json.NewEncoder(w).Encode(lateralEvidenceEnvelope{Status: "completed", Evidence: evidence, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))})
		default:
			http.NotFound(w, r)
		}
	}))
	defer executor.Close()

	fixture.svc.Config.LateralEnabled = true
	fixture.svc.Config.LateralDestinations = map[string]string{lateralTestDestination: "192.0.2.56"}
	fixture.svc.Config.LateralCredentialRefs = map[string]string{credentialHash: credentialReference}
	fixture.svc.Config.LateralDefaultCredentialRef = credentialHash
	fixture.svc.Lateral = &LateralExecutor{Base: executor.URL, Token: "lab-token", PublicKey: publicKey, HTTP: executor.Client(), Refs: fixture.svc.Config.LateralCredentialRefs}

	mission, err := fixture.svc.CreateMission(context.Background(), "lateral-session", MissionInput{
		Request:      "Prove SMB access from attack.test to secattack",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "smb", ExpectedIdentity: "Administrator", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.Store.UpdateMission(mission.ID, func(stored *Mission) error {
		stored.ADGraph = lateralTestGraph()
		stored.Lateral = &LateralMissionConfiguration{DestinationAssetID: lateralTestDestination, DestinationHost: "192.0.2.56", Protocol: "smb", Port: 445, CredentialRefHash: credentialHash, ExpectedIdentity: "Administrator"}
		for index := range stored.Requirements {
			if stored.Requirements[index].Type != "remote_access_proven" && stored.Requirements[index].Type != "identity_observed" {
				stored.Requirements[index].Status = "proven"
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan == nil || len(result.Plan.Items) != 1 || result.Plan.Items[0].InputHash == "" {
		t.Fatalf("typed lateral plan was not created: %+v", result)
	}
	persistedPlan, err := json.Marshal(result.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(persistedPlan), credentialReference) {
		t.Fatal("opaque credential reference was persisted in the plan")
	}
	if err := fixture.svc.Authorize(context.Background(), result.Plan.ID, result.Plan.Hash, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.svc.processPlanTick(context.Background(), result.Plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.svc.processPlanTick(context.Background(), result.Plan.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	dispatched := submitted
	mu.Unlock()
	if dispatched.CredentialReference != credentialReference || dispatched.DestinationHost != "192.0.2.56" || dispatched.Protocol != "smb" || dispatched.Port != 445 {
		t.Fatalf("unexpected typed executor request: %+v", dispatched)
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	completed, err := fixture.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range completed.Requirements {
		if requirement.Status != "proven" {
			t.Fatalf("requirement %s was not proven: %+v", requirement.ID, requirement)
		}
	}
	if completed.Status != "completed" {
		t.Fatalf("mission did not complete: %+v", completed)
	}
}

func TestDestinationEvidenceRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	planItem := PlanItem{SourceAssetID: "source", DestinationAssetID: "destination", Protocol: "smb", LateralInput: &LateralActionInput{CorrelationID: "correlation", Protocol: "smb", Port: 445}}
	evidence := LateralEvidence{ExecutionID: "execution", InputHash: lateralInputFingerprint(planItem), CorrelationID: "correlation", SourceAssetID: "source", DestinationAssetID: "destination", Protocol: "smb", Port: 445, ServiceReachable: true, RemoteAccess: true, Identity: "Administrator", Integrity: "high", ObservedAt: time.Now().UTC()}
	canonical, _ := canonicalEvidence(evidence)
	envelope := lateralEvidenceEnvelope{Status: "completed", Evidence: evidence, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}
	envelope.Evidence.DestinationAssetID = "other"
	item := ValidatedItem{PlanItem: planItem, ExecutionID: "execution"}
	if err := (&LateralExecutor{PublicKey: publicKey}).verifyEvidence(item, envelope); err == nil {
		t.Fatal("tampered destination evidence was accepted")
	}
}

func TestUnverifiedRouteTokenCannotProveAccess(t *testing.T) {
	report := map[string]any{"route_evidence": map[string]any{
		"source_asset_id": "asset-1", "destination_asset_id": lateralTestDestination,
		"protocol": "winrm", "service_reachable": true,
		"destination_proof": true, "destination_proof_token": "fabricated",
		"remote_execution_observed": true, "destination_identity": `LAB\Operator`,
	}}
	item := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain"}, Status: "completed", Report: report}
	for _, requirement := range []Requirement{
		{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "winrm"},
		{Type: "identity_observed", Source: "asset-1", Target: lateralTestDestination, Protocol: "winrm", ExpectedIdentity: "Operator"},
	} {
		if status, _, _ := evaluateRequirementEvidence(item, requirement); status == "proven" {
			t.Fatalf("unverified generic proof token satisfied %s", requirement.Type)
		}
	}
}

func TestSignedEvidenceMustMatchExecutionHashAndExpectedIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	item := ValidatedItem{PlanItem: PlanItem{SourceAssetID: "asset-1", DestinationAssetID: lateralTestDestination, Protocol: "winrm", LateralInput: &LateralActionInput{CorrelationID: "correlation", Protocol: "winrm", Port: 5985, ExpectedIdentity: "Operator"}}, ExecutionID: "execution-1", SubmittedAt: time.Now().Add(-time.Second)}
	evidence := LateralEvidence{ExecutionID: item.ExecutionID, InputHash: lateralInputFingerprint(item.PlanItem), CorrelationID: "correlation", SourceAssetID: item.SourceAssetID, DestinationAssetID: item.DestinationAssetID, Protocol: "winrm", Port: 5985, RemoteAccess: true, Identity: `LAB\Operator`, ObservedAt: time.Now().UTC()}
	verify := func(value LateralEvidence) error {
		canonical, _ := canonicalEvidence(value)
		return (&LateralExecutor{PublicKey: publicKey}).verifyEvidence(item, lateralEvidenceEnvelope{Status: "completed", Evidence: value, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))})
	}
	if err := verify(evidence); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	canonical, _ := canonicalEvidence(evidence)
	signed := lateralEvidenceEnvelope{Status: "completed", Evidence: evidence, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&LateralExecutor{PublicKey: publicKey, PublicKeys: map[string]ed25519.PublicKey{lateralTestDestination: otherKey}}).verifyEvidence(item, signed); err == nil {
		t.Fatal("global key was accepted despite a different destination-specific key")
	}
	if err := (&LateralExecutor{PublicKeys: map[string]ed25519.PublicKey{lateralTestDestination: publicKey}}).verifyEvidence(item, signed); err != nil {
		t.Fatalf("destination-specific key was rejected: %v", err)
	}
	for _, change := range []func(*LateralEvidence){
		func(value *LateralEvidence) { value.ExecutionID = "execution-2" },
		func(value *LateralEvidence) { value.InputHash = strings.Repeat("f", 64) },
		func(value *LateralEvidence) { value.Identity = `LAB\AnotherUser` },
	} {
		altered := evidence
		change(&altered)
		if err := verify(altered); err == nil {
			t.Fatalf("validly signed but mismatched evidence was accepted: %+v", altered)
		}
	}
}

func TestMultiHopMissionVerifiesFirstHopBeforePlanningSecond(t *testing.T) {
	fixture := setup(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const middle = "11111111-1111-1111-1111-111111111111"
	const reference = "vault://synthetic/multihop"
	var mu sync.Mutex
	requests := map[string]lateralSubmitRequest{}
	count := 0
	executor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			_ = json.NewEncoder(w).Encode(LateralHealth{Status: "ok", Execute: true, SignedEvidence: true, Protocols: []string{"winrm"}, SchemaVersion: "1", CredentialRefs: true, DestinationVerify: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/lateral/executions":
			var request lateralSubmitRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			mu.Lock()
			count++
			id := fmt.Sprintf("hop-%d", count)
			requests[id] = request
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(lateralSubmitResponse{ID: id, Status: "running"})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/lateral/executions/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/lateral/executions/")
			mu.Lock()
			request := requests[id]
			mu.Unlock()
			evidence := LateralEvidence{ExecutionID: id, InputHash: request.InputHash, CorrelationID: request.CorrelationID, SourceAssetID: request.SourceAssetID, DestinationAssetID: request.DestinationAssetID, Protocol: request.Protocol, Port: request.Port, ServiceReachable: true, RemoteAccess: true, Identity: `LAB\Operator`, Integrity: "high", ObservedAt: time.Now().UTC()}
			canonical, _ := canonicalEvidence(evidence)
			_ = json.NewEncoder(w).Encode(lateralEvidenceEnvelope{Status: "completed", Evidence: evidence, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))})
		default:
			http.NotFound(w, r)
		}
	}))
	defer executor.Close()
	fixture.svc.Config.LateralEnabled = true
	fixture.svc.Config.LateralDestinations = map[string]string{middle: "192.0.2.2", lateralTestDestination: "192.0.2.3"}
	fixture.svc.Config.LateralCredentialRefs = map[string]string{credentialReferenceHash(reference): reference}
	fixture.svc.Config.LateralDefaultCredentialRef = credentialReferenceHash(reference)
	fixture.svc.Lateral = &LateralExecutor{Bases: map[string]string{"asset-1": executor.URL, middle: executor.URL}, Token: "lab-token", PublicKey: publicKey, HTTP: executor.Client(), Refs: fixture.svc.Config.LateralCredentialRefs}
	graph := ADGraph{Nodes: []ADGraphNode{
		{ID: "source", Kind: "machine", AssetID: "asset-1"},
		{ID: "mid", Kind: "machine", AssetID: middle},
		{ID: "dest", Kind: "machine", AssetID: lateralTestDestination},
		{ID: "source-operator", Kind: "identity", Label: `LAB\source-operator`},
		{ID: "mid-operator", Kind: "identity", Label: `LAB\mid-operator`},
		{ID: "mid-service", Kind: "service", Properties: map[string]string{"protocol": "winrm", "port": "5985"}},
		{ID: "dest-service", Kind: "service", Properties: map[string]string{"protocol": "winrm", "port": "5985"}},
	}, Edges: []ADGraphEdge{
		{ID: "reach-mid", Source: "source", Target: "mid-service", Kind: "service_reachable", Protocol: "winrm", Port: "5985", Directed: true, Status: "observed"},
		{ID: "service-mid", Source: "mid", Target: "mid-service", Kind: "service_on", Protocol: "winrm", Port: "5985", Directed: true, Status: "observed"},
		{ID: "reach-dest", Source: "mid", Target: "dest-service", Kind: "service_reachable", Protocol: "winrm", Port: "5985", Directed: true, Status: "observed"},
		{ID: "service-dest", Source: "dest", Target: "dest-service", Kind: "service_on", Protocol: "winrm", Port: "5985", Directed: true, Status: "observed"},
		{ID: "session-source", Source: "source-operator", Target: "source", Kind: "session_on", Directed: true, Status: "observed"},
		{ID: "permission-mid", Source: "source-operator", Target: "mid", Kind: "can_winrm", Protocol: "winrm", Directed: true, Status: "observed"},
		{ID: "session-mid", Source: "mid-operator", Target: "mid", Kind: "session_on", Directed: true, Status: "observed"},
		{ID: "permission-dest", Source: "mid-operator", Target: "dest", Kind: "can_winrm", Protocol: "winrm", Directed: true, Status: "observed"},
	}}
	mission, err := fixture.svc.CreateMission(context.Background(), "multi-hop", MissionInput{Request: "Prove WinRM access from attack.test to secattack via source-win", Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "winrm", ExpectedIdentity: "Operator", Mandatory: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.Store.UpdateMission(mission.ID, func(m *Mission) error {
		m.ADGraph = graph
		for index := range m.Requirements {
			if m.Requirements[index].Type != "remote_access_proven" && m.Requirements[index].Type != "identity_observed" {
				m.Requirements[index].Status = "proven"
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || first.Plan == nil {
		t.Fatalf("first hop not planned: %+v %v", first, err)
	}
	if item := first.Plan.Items[0]; item.SourceAssetID != "asset-1" || item.DestinationAssetID != middle {
		t.Fatalf("first hop is not source to intermediate: %+v", item)
	}
	if err := fixture.svc.Authorize(context.Background(), first.Plan.ID, first.Plan.Hash, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := fixture.svc.processPlanTick(context.Background(), first.Plan.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := fixture.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.HopProofs) != 1 || stored.HopProofs[0].DestinationAssetID != middle {
		t.Fatalf("first signed hop proof missing: %+v", stored.HopProofs)
	}
	second, err := fixture.svc.PlanMission(context.Background(), mission.ID)
	if err != nil || second.Plan == nil {
		t.Fatalf("second hop not planned after proof: %+v %v", second, err)
	}
	if item := second.Plan.Items[0]; item.SourceAssetID != middle || item.DestinationAssetID != lateralTestDestination {
		t.Fatalf("second hop is not intermediate to destination: %+v", item)
	}
	if err := fixture.svc.Authorize(context.Background(), second.Plan.ID, second.Plan.Hash, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := fixture.svc.processPlanTick(context.Background(), second.Plan.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.svc.SyncMission(mission.ID); err != nil {
		t.Fatal(err)
	}
	complete, err := fixture.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete.HopProofs) != 2 || complete.Status != "completed" {
		t.Fatalf("the full route was not proven by two signed hops: status=%s proofs=%+v", complete.Status, complete.HopProofs)
	}
}
