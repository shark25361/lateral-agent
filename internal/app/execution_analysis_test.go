package app

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type latestExecutionModel struct{ sawResolved bool }

func (m *latestExecutionModel) Name() string { return "latest-execution-test" }
func (m *latestExecutionModel) GenerateContent(_ context.Context, request *model.LLMRequest, _ bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		last := request.Contents[len(request.Contents)-1]
		for _, part := range last.Parts {
			if strings.Contains(part.Text, "<resolved_execution_analysis>") && strings.Contains(part.Text, "submission denied") {
				m.sawResolved = true
			}
		}
		yield(&model.LLMResponse{Content: &genai.Content{Role: "model", Parts: []*genai.Part{{Text: "The stored execution failed during submission: submission denied."}}}}, nil)
	}
}

func TestExecutionCandidatePrefersCurrentSessionThenGlobal(t *testing.T) {
	now := time.Now().UTC()
	plans := []Plan{
		{ID: "session-plan", SessionID: "chat-a", Updated: now, Items: []ValidatedItem{{PlanItem: PlanItem{CatalogID: "old"}, Status: "completed", ExecutionID: "exec-old"}}},
		{ID: "global-plan", SessionID: "chat-b", Updated: now.Add(time.Minute), Items: []ValidatedItem{{PlanItem: PlanItem{CatalogID: "new"}, Status: "failed", ExecutionID: "exec-new"}}},
	}
	candidate, selection, err := executionCandidateFromPlans(plans, "chat-a")
	if err != nil || candidate.plan.ID != "session-plan" || !strings.Contains(selection, "current chat") {
		t.Fatalf("current-session execution was not preferred: candidate=%+v selection=%q err=%v", candidate, selection, err)
	}
	candidate, selection, err = executionCandidateFromPlans(plans, "unknown-chat")
	if err != nil || candidate.plan.ID != "global-plan" || !strings.Contains(selection, "local plan history") {
		t.Fatalf("global latest execution fallback failed: candidate=%+v selection=%q err=%v", candidate, selection, err)
	}
}

func TestExecutionCandidateUsesLatestObservationAndIgnoresPendingRecords(t *testing.T) {
	now := time.Now().UTC()
	plans := []Plan{
		{
			ID: "older-plan-update", SessionID: "chat-a", Updated: now.Add(10 * time.Minute),
			Items: []ValidatedItem{{PlanItem: PlanItem{CatalogID: "older"}, Status: "completed", ExecutionID: "exec-older", CompletedAt: now}},
		},
		{
			ID: "newer-observation", SessionID: "chat-a", Updated: now,
			Items: []ValidatedItem{{PlanItem: PlanItem{CatalogID: "newer"}, Status: "failed", ExecutionID: "exec-newer", ReportObservedAt: now.Add(20 * time.Minute)}},
		},
		{
			ID: "pending-plan", SessionID: "chat-a", Updated: now.Add(30 * time.Minute),
			Items: []ValidatedItem{{PlanItem: PlanItem{CatalogID: "pending"}, Status: "pending", Error: "not an execution"}},
		},
	}
	candidate, _, err := executionCandidateFromPlans(plans, "chat-a")
	if err != nil {
		t.Fatal(err)
	}
	if candidate.plan.ID != "newer-observation" {
		t.Fatalf("latest execution observation was not selected: %+v", candidate)
	}
}

func TestLatestExecutionAnalysisExplainsNestedFailureAndOutput(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	plan := Plan{
		ID: "analysis-plan", SessionID: "analysis-chat", Objective: "Analyze execution",
		Status: "failed", Created: now.Add(-time.Minute), Updated: now,
		Items: []ValidatedItem{{
			PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "chain-1", AssetIDs: []string{"asset-1"}, RequirementIDs: []string{"R1"}},
			Name:     "Test chain", Status: "failed", ExecutionID: "execution-analysis",
			Error: "FourCore reported a failed execution",
			Report: map[string]any{
				"status": "failed",
				"assets": []any{
					map[string]any{
						"asset_id": "asset-1",
						"steps": []any{
							map[string]any{
								"id": "parent", "name": "Remote service", "done": true, "success": false,
								"failure_reason": "access denied", "output": "ERROR_ACCESS_DENIED",
								"action_steps": []any{
									map[string]any{"id": "nested", "name": "Host discovery", "done": true, "success": true, "output": "domain=LAB"},
								},
							},
						},
					},
				},
			},
		}},
	}
	if err := f.svc.Store.Put("plans", plan.ID, plan); err != nil {
		t.Fatal(err)
	}
	analysis, err := f.svc.LatestExecutionAnalysis(context.Background(), "analysis-chat")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Execution.PlanID != plan.ID || analysis.SuccessfulSteps != 1 || analysis.FailedSteps != 1 {
		t.Fatalf("execution or step totals were wrong: %+v", analysis)
	}
	if len(analysis.FailureReasons) == 0 || !strings.Contains(strings.Join(analysis.FailureReasons, " "), "access denied") {
		t.Fatalf("explicit failure reason was omitted: %+v", analysis.FailureReasons)
	}
	if len(analysis.Steps) != 2 || analysis.Steps[0].Output == nil || analysis.Steps[1].Output == nil {
		t.Fatalf("nested raw step output was omitted: %+v", analysis.Steps)
	}
	if analysis.ReportSource != "stored sanitized report" || analysis.ReportWarning == "" {
		t.Fatalf("failed live refresh did not fall back to stored evidence: %+v", analysis)
	}
	if analysis.OutcomeCategory != "partial_execution_failure" {
		t.Fatalf("execution failure was misclassified: %+v", analysis)
	}
	if analysis.DetectionState != "unknown_no_explicit_evidence" || analysis.PreventionState != "unknown_no_explicit_evidence" {
		t.Fatalf("missing defensive evidence was not left unknown: %+v", analysis)
	}
}

func TestReportProjectionRetainsFailureMetadata(t *testing.T) {
	report := reportForModel(map[string]any{
		"status": "failed", "failure_reason": "top-level failure", "exit_code": 5,
		"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{
			map[string]any{"id": "step-1", "done": true, "success": false, "error_message": "step failed", "exit_code": 7, "output": "stderr text"},
		}}},
	})
	if report["failure_reason"] != "top-level failure" || report["exit_code"] == nil {
		t.Fatalf("root failure metadata was removed: %+v", report)
	}
	steps := reportSteps(report)
	if len(steps) != 1 || failureText(steps[0].Raw) != "step failed" || steps[0].Raw["output"] == nil {
		t.Fatalf("step failure metadata or output was removed: %+v", steps)
	}
}

func TestExplicitNegativeDefensiveEvidenceIsDistinctFromMissing(t *testing.T) {
	report := map[string]any{
		"total_detected": float64(0),
		"assets": []any{map[string]any{"steps": []any{
			map[string]any{"id": "step-1", "done": true, "success": true, "prevented": false},
		}}},
	}
	if got := detectionEvidenceState(report); got != "explicitly_not_observed" {
		t.Fatalf("explicit zero detection was misclassified as %q", got)
	}
	if got := preventionEvidenceState(report); got != "explicitly_not_observed" {
		t.Fatalf("explicit prevented=false was misclassified as %q", got)
	}
}

func TestChatResolvesLastExecutionBeforeCallingModel(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	plan := Plan{
		ID: "chat-analysis-plan", SessionID: "analysis-chat", Objective: "Test failure analysis",
		Status: "failed", Created: now.Add(-time.Minute), Updated: now,
		Items: []ValidatedItem{{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "chain-1", AssetIDs: []string{"asset-1"}}, Name: "Test chain", Status: "failed", Error: "submission denied", CompletedAt: now}},
	}
	if err := f.svc.Store.Put("plans", plan.ID, plan); err != nil {
		t.Fatal(err)
	}
	model := &latestExecutionModel{}
	result, err := f.svc.Chat(context.Background(), "analysis-chat", "why did my last exec fail?", model)
	if err != nil {
		t.Fatal(err)
	}
	if !model.sawResolved || !strings.Contains(result.Reply, "submission denied") {
		t.Fatalf("chat did not receive the resolved execution: saw=%v result=%+v", model.sawResolved, result)
	}
	if shouldAutoMission("why did the last run on 11111111-1111-1111-1111-111111111111 fail?") {
		t.Fatal("execution-analysis question was misrouted into mission intake")
	}
}

func TestLatestExecutionAnalysisEndpointClassifiesSubmissionFailure(t *testing.T) {
	f := setup(t)
	now := time.Now().UTC()
	plan := Plan{
		ID: "endpoint-analysis-plan", SessionID: "endpoint-chat", Objective: "Test submission failure",
		Status: "failed", Created: now.Add(-time.Minute), Updated: now,
		Items: []ValidatedItem{{
			PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: "chain-1", AssetIDs: []string{"asset-1"}},
			Name:     "Test chain", Status: "failed", Error: "FourCore HTTP 400: invalid resource ID", CompletedAt: now,
		}},
	}
	if err := f.svc.Store.Put("plans", plan.ID, plan); err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Service: f.svc}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/executions/latest/analysis?session_id=endpoint-chat", nil)
	request.Header.Set("Authorization", "Bearer "+f.svc.Config.Token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("analysis endpoint returned %d: %s", response.Code, response.Body.String())
	}
	var analysis ExecutionAnalysis
	if err := json.NewDecoder(response.Body).Decode(&analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.OutcomeCategory != "submission_failed" || analysis.Execution.ExecutionID != "" || !strings.Contains(analysis.Summary, "no simulation run is confirmed") {
		t.Fatalf("submission failure was not represented explicitly: %+v", analysis)
	}
}
