package app

import (
	"context"
	"encoding/json"
	"iter"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type browserModel struct{}

func (browserModel) Name() string { return "mock-browser-model" }
func (browserModel) GenerateContent(_ context.Context, r *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		last := r.Contents[len(r.Contents)-1]
		for _, p := range last.Parts {
			if p.FunctionResponse != nil {
				if p.FunctionResponse.Name == "get_simulation_details" {
					raw, _ := json.Marshal(input())
					var args map[string]any
					_ = json.Unmarshal(raw, &args)
					yield(&model.LLMResponse{Content: &genai.Content{Role: "model", Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{ID: "browser-plan", Name: "propose_plan", Args: args}}}}}, nil)
					return
				}
				yield(&model.LLMResponse{Content: &genai.Content{Role: "model", Parts: []*genai.Part{{Text: "The Test chain plan is ready. Review the scope, then authorize it. Literal text: <img src=x onerror=alert(1)>"}}}}, nil)
				return
			}
		}
		yield(&model.LLMResponse{Content: &genai.Content{Role: "model", Parts: []*genai.Part{{FunctionCall: &genai.FunctionCall{ID: "browser-details", Name: "get_simulation_details", Args: map[string]any{"kind": "endpoint_chain", "id": "chain-1"}}}}}}, nil)
	}
}
func TestBrowserUI(t *testing.T) {
	if os.Getenv("RUN_BROWSER_TEST") != "1" {
		t.Skip("set RUN_BROWSER_TEST=1 to run Playwright")
	}
	f := setup(t)
	f.svc.Config.Model = "mock-browser-model"
	f.state = "completed"
	graphMission, err := f.svc.CreateMission(context.Background(), "browser-graph", MissionInput{
		Request: "Inspect the discovered AD route",
		Requirements: []Requirement{
			{ID: "R1", Type: "domain_context_observed", Target: "asset-1", Mandatory: true},
			{ID: "R2", Type: "remote_access_proven", Source: "asset-1", Target: "22222222-2222-2222-2222-222222222222", Protocol: "smb", Mandatory: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	graphItem := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "chain-1", AssetIDs: []string{"asset-1"}, SourceAssetID: "asset-1", DestinationAssetID: "22222222-2222-2222-2222-222222222222", Protocol: "smb", Reason: "Browser graph fixture"}, Name: "Selected SMB route", Status: "completed", ExecutionID: "execution-graph", ReportObservedAt: time.Now().UTC(), Report: adEvidenceTestReport()}
	simulationContract := ActionContract{Produces: []PredicateSpec{{Type: "lateral_movement_validated", Subject: "asset-1"}}}
	simulationItem := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "lateral-chain", AssetIDs: []string{"asset-1"}, Contract: &simulationContract}, Name: "Lateral chain simulation", Status: "completed", ExecutionID: "execution-simulation", Report: map[string]any{"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{map[string]any{"id": "lateral-step", "done": true, "success": true}}}}}}
	graphPlan := Plan{ID: "browser-graph-plan", MissionID: graphMission.ID, SessionID: "browser-graph", Objective: graphMission.Request, Status: "completed", Created: time.Now().Add(-time.Minute).UTC(), Updated: time.Now().UTC(), Items: []ValidatedItem{graphItem}}
	if err := f.svc.Store.Put("plans", graphPlan.ID, graphPlan); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Store.UpdateMission(graphMission.ID, func(mission *Mission) error {
		mission.CurrentPlanID = graphPlan.ID
		mission.ADGraph = mergeADGraph(extractADEvidence(graphItem), extractADEvidence(simulationItem))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.svc.Worker(ctx) }()
	defer func() { cancel(); <-done }()
	server := httptest.NewServer((&Server{Service: f.svc, Model: browserModel{}}).Handler())
	defer server.Close()
	script := filepath.Join("..", "..", "scripts", "browser_test.py")
	cmd := exec.Command("python", script, server.URL)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("browser test: %v\n%s", e, out)
	}
	t.Log(string(out))
	if f.posts.Load() != 1 {
		t.Fatalf("expected one mock submission, got %d", f.posts.Load())
	}
}

// Optional provider check: only synthetic fixture asset metadata is sent to the
// configured model. This never uses a real FourCore tenant or submits a run.
func TestLiveOpenRouter(t *testing.T) {
	if os.Getenv("RUN_LIVE_MODEL_TEST") != "1" {
		t.Skip("set RUN_LIVE_MODEL_TEST=1 for a billed OpenRouter connectivity check")
	}
	_ = godotenv.Load(filepath.Join("..", "..", ".env"))
	key := os.Getenv("OPENROUTER_API_KEY")
	if key == "" {
		key = os.Getenv("openrouter")
	}
	if key == "" {
		t.Fatal("missing OpenRouter key")
	}
	f := setup(t)
	m := &OpenRouter{Key: key, Model: env("OPENROUTER_MODEL", "deepseek/deepseek-v4.1-flash"), Base: env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")}
	v, e := f.svc.Chat(context.Background(), "live-connectivity", "Use find_assets to list the synthetic endpoint servers attack.test and secattack. State their returned names and availability. Do not create a plan or execute anything.", m)
	if e != nil {
		t.Fatal(e)
	}
	if f.reads.Load() == 0 || strings.TrimSpace(v.Reply) == "" {
		t.Fatalf("model did not complete asset discovery; reply: %s", v.Reply)
	}
	if f.posts.Load() != 0 {
		t.Fatal("unexpected mock execution")
	}
}
