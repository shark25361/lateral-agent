package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

func TestHTTPErrorDetailPreservesBoundedValidationMessage(t *testing.T) {
	detail := httpErrorDetail([]byte(`{"detail":"missing required chain input"}`))
	if detail != "missing required chain input" {
		t.Fatalf("unexpected HTTP error detail %q", detail)
	}
	if got := httpErrorDetail([]byte(strings.Repeat("x", 2048))); len(got) > 1040 || !strings.Contains(got, "truncated") {
		t.Fatalf("HTTP error detail was not bounded: %d bytes", len(got))
	}
}

type fixture struct {
	svc                   *Service
	posts                 atomic.Int32
	reads                 atomic.Int32
	assetUnavailableReads atomic.Int32
	state                 string
	mu                    sync.Mutex
	changed               bool
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{state: "running"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret-fourcore" {
			t.Error("missing provider authentication")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/run"):
			f.posts.Add(1)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["disable_cleanup"] != false {
				t.Error("cleanup must be enabled")
			}
			fmt.Fprint(w, `{"id":"execution-1","status":"running"}`)
		case r.URL.Path == "/api/v2/assets":
			f.reads.Add(1)
			fmt.Fprint(w, `[{"id":"asset-1","available":true,"connected":true,"apikey":"MUST_NOT_LEAK","systeminfo":{"hostname":"attack.test","os":"windows","processes":[{"Environ":["SECRET=MUST_NOT_LEAK"]}]}},{"id":"22222222-2222-2222-2222-222222222222","available":true,"connected":true,"systeminfo":{"hostname":"secattack","os":"windows"}}]`)
		case r.URL.Path == "/api/v2/assets/asset-1":
			available := true
			if f.assetUnavailableReads.Load() > 0 {
				f.assetUnavailableReads.Add(-1)
				available = false
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "asset-1", "available": available, "connected": available, "systeminfo": map[string]any{"hostname": "attack.test", "os": "windows"}})
		case r.URL.Path == "/api/v2/assets/asset-linux":
			fmt.Fprint(w, `{"id":"asset-linux","available":true,"connected":true,"systeminfo":{"hostname":"lab-linux","os":"linux"}}`)
		case r.URL.Path == "/api/v2/assets/11111111-1111-1111-1111-111111111111":
			fmt.Fprint(w, `{"id":"11111111-1111-1111-1111-111111111111","available":true,"connected":true,"elevated":true,"systeminfo":{"hostname":"source-win","os":"windows"}}`)
		case r.URL.Path == "/api/v2/assets/22222222-2222-2222-2222-222222222222":
			fmt.Fprint(w, `{"id":"22222222-2222-2222-2222-222222222222","available":true,"connected":true,"elevated":true,"systeminfo":{"hostname":"secattack","os":"windows"}}`)
		case r.URL.Path == "/api/v2/assets/email/email-1":
			fmt.Fprint(w, `{"id":"email-1","email":"lab@example.test","verified":true,"available":true}`)
		case r.URL.Path == "/api/v2/content/chains/chain-1":
			f.mu.Lock()
			name := "Test chain"
			if f.changed {
				name = "Changed chain"
			}
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "chain-1", "name": name, "platforms": []string{"windows"}, "techniques": []any{map[string]any{"technique_id": "T1059"}}})
		case r.URL.Path == "/api/v2/content/email/chains/email-chain":
			fmt.Fprint(w, `{"id":"email-chain","name":"Test email chain"}`)
		case r.URL.Path == "/api/v2/content/packs/pack-1":
			fmt.Fprint(w, `{"id":"pack-1","name":"Test playbook","items":[{"chain":"chain-1","uses":"endpoint"}]}`)
		case r.URL.Path == "/api/v2/content/chains":
			if r.URL.Query().Get("offset") == "100" {
				fmt.Fprint(w, `{"data":[{"id":"chain-1","name":"Test privilege escalation chain","platforms":["windows"],"techniques":[{"technique_id":"T1059"}]}],"total_rows":101}`)
			} else {
				data := make([]map[string]any, 100)
				for n := range data {
					data[n] = map[string]any{"id": fmt.Sprintf("other-%d", n), "name": fmt.Sprintf("Other %d", n)}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "total_rows": 101})
			}
		case r.URL.Path == "/api/v2/executions/execution-1/report":
			f.mu.Lock()
			state := f.state
			f.mu.Unlock()
			status, detail := state, ""
			if state == "fourcore-finished" {
				status = "COMMITTED"
				detail = "FINISHED"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "execution-1", "status": status, "status_state": detail, "total_detected": 1, "chain_id": "chain-1", "assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{"id": "step-1", "success": true, "output": "RAW_STEP_OUTPUT"}}}}, "command": "MUST_NOT_LEAK"})
		default:
			http.Error(w, "not found", 404)
		}
	}))
	t.Cleanup(server.Close)
	store, e := OpenStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	cfg := Config{FourCoreURL: server.URL, FourCoreKey: "secret-fourcore", Token: strings.Repeat("x", 32), MaxItems: 5, MaxAssets: 10, RPM: 60, Execute: true, AllowedEndpoint: map[string]bool{"asset-1": true, "asset-linux": true, "11111111-1111-1111-1111-111111111111": true, "22222222-2222-2222-2222-222222222222": true}, AllowedEmail: map[string]bool{"email-1": true}, Poll: time.Millisecond}
	fc := NewFourCore(cfg)
	fc.interval = 0
	f.svc = &Service{Config: cfg, FC: fc, Store: store}
	return f
}
func input() PlanInput {
	return PlanInput{Objective: "Validate detection", Items: []PlanItem{{Kind: "endpoint_chain", CatalogID: "chain-1", AssetIDs: []string{"asset-1"}, Reason: "Matches technique"}}}
}
func TestAssetRedactionAndSearch(t *testing.T) {
	f := setup(t)
	a, e := f.svc.FC.Assets(context.Background(), "endpoint")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(a)
	if strings.Contains(string(b), "MUST_NOT_LEAK") {
		t.Fatal("asset credentials leaked")
	}
	r, e := f.svc.FC.Search(context.Background(), "endpoint_chain", "Test", 0)
	if e != nil || len(r.Items) != 1 || r.Items[0].ID != "chain-1" || r.More {
		t.Fatalf("full catalogue result: %+v %v", r, e)
	}
}

func TestSearchRanksTechniqueAcrossFullCatalogue(t *testing.T) {
	f := setup(t)
	r, e := f.svc.FC.Search(context.Background(), "endpoint_chain", "T1059 privilege escalation", 0)
	if e != nil || len(r.Items) != 1 || r.Items[0].ID != "chain-1" {
		t.Fatalf("ranked result: %+v %v", r, e)
	}
}

func TestCatalogueSnapshotSupportsOfflineSearchAndDetails(t *testing.T) {
	f := setup(t)
	dir := t.TempDir()
	f.svc.FC.catalogDir = filepath.Join(dir, "catalog")
	if _, e := f.svc.FC.RefreshCatalog(context.Background(), "endpoint_chain"); e != nil {
		t.Fatal(e)
	}

	offline := NewFourCore(Config{FourCoreURL: f.svc.FC.Base, FourCoreKey: "secret-fourcore", DataDir: dir, RPM: 60})
	offline.interval = 0
	offline.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("network must not be used")
	})
	r, e := offline.Search(context.Background(), "endpoint_chain", "T1059", 0)
	if e != nil || len(r.Items) != 1 || r.Items[0].ID != "chain-1" {
		t.Fatalf("offline search failed: %+v %v", r, e)
	}
	detail, e := offline.LocalCatalog(context.Background(), "endpoint_chain", "chain-1")
	if e != nil || detail.Name != "Test privilege escalation chain" {
		t.Fatalf("offline details failed: %+v %v", detail, e)
	}
	if _, e = os.Stat(filepath.Join(dir, "catalog", "endpoint_chain.json")); e != nil {
		t.Fatal(e)
	}
}

func TestMissingCatalogueIDExplainsRecovery(t *testing.T) {
	f := setup(t)
	_, e := f.svc.FC.Catalog(context.Background(), "endpoint_chain", "invented-id")
	if e == nil || !strings.Contains(e.Error(), "was not found") || !strings.Contains(e.Error(), "search_simulations") {
		t.Fatalf("unhelpful missing-ID error: %v", e)
	}
}
func TestValidationRejectsInvalidScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*PlanItem)
	}{{"wrong platform", func(i *PlanItem) { i.AssetIDs = []string{"asset-linux"} }}, {"unauthorized target", func(i *PlanItem) { i.AssetIDs = []string{"outside"} }}, {"cleanup", func(i *PlanItem) { i.DisableCleanup = true }}, {"elevation", func(i *PlanItem) { i.RunElevated = true }}, {"path injection", func(i *PlanItem) { i.CatalogID = "../../admin" }}, {"wrong vector", func(i *PlanItem) { i.Kind = "email_chain" }}, {"WAF unverified", func(i *PlanItem) { i.Kind = "waf_chain" }}} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			in := input()
			tc.mut(&in.Items[0])
			if _, e := f.svc.Propose(context.Background(), "chat", in); e == nil {
				t.Fatal("expected rejection")
			}
			if f.posts.Load() != 0 {
				t.Fatal("validation executed simulation")
			}
		})
	}
}

func TestAssetReadRetriesTransientUnavailableState(t *testing.T) {
	f := setup(t)
	f.assetUnavailableReads.Store(1)
	a, e := f.svc.FC.Asset(context.Background(), "endpoint", "asset-1")
	if e != nil || !a.Available || !a.Connected {
		t.Fatalf("transient state was not retried: %+v %v", a, e)
	}
}

func TestFourCoreGetRetriesTransportFailuresButWritesDoNot(t *testing.T) {
	f := setup(t)
	var getAttempts atomic.Int32
	f.svc.FC.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			if getAttempts.Add(1) < 3 {
				return nil, fmt.Errorf("temporary transport failure")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
		}
		return nil, fmt.Errorf("write transport failure")
	})
	var result map[string]any
	if err := f.svc.FC.Do(context.Background(), http.MethodGet, "/retry", nil, &result); err != nil || result["ok"] != true || getAttempts.Load() != 3 {
		t.Fatalf("safe GET was not retried: attempts=%d result=%+v err=%v", getAttempts.Load(), result, err)
	}
	if err := f.svc.FC.Do(context.Background(), http.MethodPost, "/no-retry", map[string]any{}, nil); err == nil {
		t.Fatal("failed write unexpectedly succeeded")
	}
}
func TestPlaybookExpansion(t *testing.T) {
	f := setup(t)
	in := input()
	in.Items[0].Kind = "playbook"
	in.Items[0].CatalogID = "pack-1"
	p, e := f.svc.Propose(context.Background(), "chat", in)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Items[0].Scope) != 2 {
		t.Fatal("playbook scope not expanded")
	}
}
func TestEmailPlan(t *testing.T) {
	f := setup(t)
	in := input()
	in.Items[0].Kind = "email_chain"
	in.Items[0].CatalogID = "email-chain"
	in.Items[0].AssetIDs = nil
	in.Items[0].EmailAssetIDs = []string{"email-1"}
	if _, e := f.svc.Propose(context.Background(), "chat", in); e != nil {
		t.Fatal(e)
	}
}
func TestPlanLifecycleAndDuplicateSubmission(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	if f.posts.Load() != 0 {
		t.Fatal("unapproved plan executed")
	}
	if e = f.svc.Authorize(ctx, p.ID, "wrong", time.Time{}); e == nil {
		t.Fatal("wrong hash accepted")
	}
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}); e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}); e == nil {
		t.Fatal("duplicate authorization accepted")
	}
	for n := 0; n < 3; n++ {
		if e = f.svc.Tick(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if f.posts.Load() != 1 {
		t.Fatalf("submissions=%d", f.posts.Load())
	}
	f.mu.Lock()
	f.state = "completed"
	f.mu.Unlock()
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.Get("plans", p.ID, &p)
	if p.Status != "completed" {
		t.Fatalf("state %s", p.Status)
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "MUST_NOT_LEAK") {
		t.Fatal("raw report command leaked")
	}
	if !strings.Contains(string(b), "RAW_STEP_OUTPUT") {
		t.Fatal("simulation step output was not stored")
	}
}
func TestChangedCatalogueAndScheduledPlan(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.changed = true
	f.mu.Unlock()
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}); e == nil {
		t.Fatal("changed catalogue accepted")
	}
	f.mu.Lock()
	f.changed = false
	f.mu.Unlock()
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Now().Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	if f.posts.Load() != 0 {
		t.Fatal("scheduled plan ran early")
	}
}
func TestRecoveryNeverResubmits(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.UpdatePlan(p.ID, func(p *Plan) error { p.Status = "running"; p.Items[0].Status = "submitting"; return nil })
	if e = f.svc.Recover(); e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.Get("plans", p.ID, &p)
	if p.Status != "needs_reconciliation" || f.posts.Load() != 0 {
		t.Fatalf("unsafe recovery: %+v", p)
	}
}

func TestUncertainSubmissionIsNotRetried(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}); e != nil {
		t.Fatal(e)
	}
	original := f.svc.FC.HTTP.Transport
	if original == nil {
		original = http.DefaultTransport
	}
	f.svc.FC.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			f.posts.Add(1)
			return nil, fmt.Errorf("connection lost after request may have been accepted")
		}
		return original.RoundTrip(r)
	})
	for n := 0; n < 3; n++ {
		if e = f.svc.Tick(ctx); e != nil {
			t.Fatal(e)
		}
	}
	_ = f.svc.Store.Get("plans", p.ID, &p)
	if p.Status != "needs_reconciliation" || f.posts.Load() != 1 {
		t.Fatalf("unsafe retry: %s, %d", p.Status, f.posts.Load())
	}
	f.svc.FC.HTTP.Transport = original
	if e = f.svc.Reconcile(ctx, p.ID, 0, "execution-1"); e != nil {
		t.Fatal(e)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestConcurrentAuthorization(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("authorized %d times", successes.Load())
	}
}
func TestReportStepRedaction(t *testing.T) {
	raw := map[string]any{"assets": []any{map[string]any{"asset_id": "asset-1", "execute_user": "PRIVATE_USER", "steps": []any{map[string]any{"id": 1, "done": true, "success": false, "detected": true, "output": "RAW_OUTPUT", "correlations": []any{map[string]any{"name": "Detection", "data": "PRIVATE_CORRELATION", "integration_type": "edr"}}}}}}, "route_evidence": map[string]any{"source_asset_id": "source", "destination_asset_id": "destination", "protocol": "smb", "proof_token": "SAFE_PROOF", "credential": "MUST_NOT_LEAK"}}
	b, _ := json.Marshal(reportSummary(raw))
	if strings.Contains(string(b), "PRIVATE_USER") || strings.Contains(string(b), "PRIVATE_CORRELATION") || strings.Contains(string(b), "MUST_NOT_LEAK") || !strings.Contains(string(b), "RAW_OUTPUT") || !strings.Contains(string(b), "Detection") || !strings.Contains(string(b), "SAFE_PROOF") {
		t.Fatalf("incorrect evidence projection: %s", b)
	}
}

func TestReportOutputIsBoundedForModel(t *testing.T) {
	raw := map[string]any{"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{"id": 1, "output": strings.Repeat("x", modelReportOutputBudget+100)}}}}}
	b, _ := json.Marshal(reportForModel(raw))
	if len(b) > modelReportOutputBudget+2000 || !strings.Contains(string(b), `"truncated":true`) || !strings.Contains(string(b), `"original_bytes"`) {
		t.Fatalf("model report was not bounded: bytes=%d", len(b))
	}
}

func TestRawReportEndpointReturnsCompleteUpstreamJSON(t *testing.T) {
	f := setup(t)
	h := (&Server{Service: f.svc}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/reports/execution/execution-1/raw", nil)
	req.Header.Set("Authorization", "Bearer "+f.svc.Config.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "MUST_NOT_LEAK") || !strings.Contains(w.Body.String(), "RAW_STEP_OUTPUT") {
		t.Fatalf("raw endpoint response %d: %s", w.Code, w.Body.String())
	}

	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/reports/execution/execution-1/raw", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("raw endpoint allowed unauthenticated access: %d", unauthorized.Code)
	}
}

func TestDelayedEvidenceCollection(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.svc.Config.CorrelationWait = time.Millisecond * 50
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}); e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.state = "completed"
	f.mu.Unlock()
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.Get("plans", p.ID, &p)
	if p.Items[0].Status != "collecting_evidence" {
		t.Fatal("closed before correlation window")
	}
	time.Sleep(60 * time.Millisecond)
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.Get("plans", p.ID, &p)
	if p.Status != "completed" {
		t.Fatal("correlation window did not finish")
	}
}

func TestFourCoreFinishedStatus(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.svc.Config.CorrelationWait = 0
	p, e := f.svc.Propose(ctx, "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Authorize(ctx, p.ID, p.Hash, time.Time{}); e != nil {
		t.Fatal(e)
	}
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.state = "fourcore-finished"
	f.mu.Unlock()
	if e = f.svc.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.Get("plans", p.ID, &p)
	if p.Status != "completed" {
		t.Fatalf("did not recognize COMMITTED/FINISHED: %+v", p)
	}
}

func TestFinishedCountsOverrideStaleInProgressStatus(t *testing.T) {
	failed := map[string]any{"status": "PREPARED", "status_state": "IN_PROGRESS", "total_attacks": float64(1), "total_finished": float64(1), "total_success": float64(0)}
	if got := terminalReportState(failed); got != "failed" {
		t.Fatalf("stale failed report remained active: %q", got)
	}
	success := map[string]any{"status": "PREPARED", "status_state": "IN_PROGRESS", "total_attacks": float64(2), "total_finished": float64(2), "total_success": float64(2)}
	if got := terminalReportState(success); got != "completed" {
		t.Fatalf("stale successful report remained active: %q", got)
	}
	aborted := map[string]any{"status": "ABORTED", "status_state": "FINISHED", "total_attacks": float64(1), "total_finished": float64(1), "total_success": float64(0)}
	if got := terminalReportState(aborted); got != "aborted" {
		t.Fatalf("aborted report was misclassified: %q", got)
	}
}

func TestReconcileRejectsDifferentScope(t *testing.T) {
	f := setup(t)
	p, e := f.svc.Propose(context.Background(), "chat", input())
	if e != nil {
		t.Fatal(e)
	}
	_ = f.svc.Store.UpdatePlan(p.ID, func(p *Plan) error {
		p.Status = "needs_reconciliation"
		p.Items[0].Status = "unknown"
		p.Items[0].AssetIDs = []string{"asset-linux"}
		return nil
	})
	if e = f.svc.Reconcile(context.Background(), p.ID, 0, "execution-1"); e == nil {
		t.Fatal("accepted mismatched execution targets")
	}
}
func TestHTTPAuthorization(t *testing.T) {
	f := setup(t)
	handler := (&Server{Service: f.svc}).Handler()
	for _, path := range []string{"/api/plans", "/api/config"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Fatal("unauthenticated API exposed")
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/plans", nil)
	r.Header.Set("Authorization", "Bearer "+f.svc.Config.Token)
	handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestOpenRouterToolRoundTrip(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var q map[string]any
		if e := json.NewDecoder(r.Body).Decode(&q); e != nil {
			t.Error(e)
		}
		raw, _ := json.Marshal(q)
		if !strings.Contains(string(raw), `"tool_call_id":"call-1"`) {
			t.Error("tool result lost its ID")
		}
		fmt.Fprint(w, `{"choices":[{"finish_reason":"tool_calls","message":{"content":null,"tool_calls":[{"id":"call-2","function":{"name":"find_assets","arguments":"{\"kind\":\"endpoint\",\"query\":\"lab\"}"}}]}}]}`)
	}))
	defer server.Close()
	m := &OpenRouter{Base: server.URL, Key: "test", Model: "test"}
	req := &model.LLMRequest{Contents: []*genai.Content{{Role: "model", Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{ID: "call-1", Name: "find_assets", Args: map[string]any{}}}}}, {Role: "user", Parts: []*genai.Part{{FunctionResponse: &genai.FunctionResponse{ID: "call-1", Name: "find_assets", Response: map[string]any{"ok": true}}}}}}}
	for v, e := range m.GenerateContent(context.Background(), req, false) {
		if e != nil {
			t.Fatal(e)
		}
		if v.Content.Parts[0].FunctionCall.ID != "call-2" {
			t.Fatal("lost call ID")
		}
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestADKConversationEndToEnd(t *testing.T) {
	f := setup(t)
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), "MUST_NOT_LEAK") {
			t.Error("secrets reached model")
		}
		switch count.Add(1) {
		case 1:
			if _, ok := body["tools"]; !ok {
				t.Error("ADK tools absent")
			}
			fmt.Fprint(w, `{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":"one","function":{"name":"find_assets","arguments":"{\"kind\":\"endpoint\",\"query\":\"lab\"}"}}]}}]}`)
		case 2:
			if !strings.Contains(string(raw), `"tool_call_id":"one"`) {
				t.Error("ADK did not round-trip tool response")
			}
			fmt.Fprint(w, `{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":"two","function":{"name":"get_simulation_details","arguments":"{\"kind\":\"endpoint_chain\",\"id\":\"chain-1\"}"}}]}}]}`)
		case 3:
			if !strings.Contains(string(raw), `"tool_call_id":"two"`) {
				t.Error("ADK did not round-trip detail verification")
			}
			args, _ := json.Marshal(input())
			_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "tool_calls", "message": map[string]any{"tool_calls": []any{map[string]any{"id": "three", "function": map[string]any{"name": "propose_plan", "arguments": string(args)}}}}}}})
		default:
			fmt.Fprint(w, `{"choices":[{"finish_reason":"stop","message":{"content":"The validated plan is ready for review."}}]}`)
		}
	}))
	defer server.Close()
	m := &OpenRouter{Base: server.URL, Key: "fake", Model: "fake"}
	v, e := f.svc.Chat(context.Background(), "test-chat", "Validate T1059 on lab-win", m)
	if e != nil {
		t.Fatal(e)
	}
	if len(v.Plans) != 1 || !strings.Contains(v.Reply, "ready") {
		t.Fatalf("unexpected chat result: %+v", v)
	}
	if f.posts.Load() != 0 {
		t.Fatal("chat executed without authorization")
	}
	var saved Chat
	if e = f.svc.Store.Get("chats", v.SessionID, &saved); e != nil || len(saved.Messages) != 2 {
		t.Fatal("transcript not persisted", e)
	}
	if _, e = f.svc.Chat(context.Background(), v.SessionID, "What next?", m); e != nil {
		t.Fatal("session replay failed", e)
	}
}

func TestChatPlanInputCannotAttachMissionInternals(t *testing.T) {
	var chatInput ChatPlanInput
	err := json.Unmarshal([]byte(`{
		"objective":"reviewed standalone plan",
		"mission_id":"mission-should-be-ignored",
		"items":[{
			"kind":"endpoint_chain",
			"catalog_id":"chain-1",
			"asset_ids":["asset-1"],
			"requirement_ids":["R1"],
			"source_asset_id":"source",
			"destination_asset_id":"destination",
			"contract":{"produces":[{"type":"lateral_movement_validated"}]},
			"reason":"verified alternative",
			"run_elevated":false,
			"disable_cleanup":false
		}]
	}`), &chatInput)
	if err != nil {
		t.Fatal(err)
	}
	input := chatInput.planInput()
	if input.MissionID != "" || len(input.Items) != 1 {
		t.Fatalf("chat proposal retained mission linkage: %+v", input)
	}
	item := input.Items[0]
	if item.Contract != nil || len(item.RequirementIDs) != 0 || item.SourceAssetID != "" || item.DestinationAssetID != "" {
		t.Fatalf("chat proposal retained mission-only fields: %+v", item)
	}
}
