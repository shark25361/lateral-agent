package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/workflowagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/workflow"
	"google.golang.org/genai"
)

const missionWorkflowVersion = 2

// missionWorkflowInput identifies one of the three supported graph entry
// points. A browser request starts at request, the typed HTTP/tool API starts
// at structured, and worker ticks resume an existing durable mission.
type missionWorkflowInput struct {
	Mode        string        `json:"mode"`
	SessionID   string        `json:"session_id,omitempty"`
	UserRequest string        `json:"user_request,omitempty"`
	MissionID   string        `json:"mission_id,omitempty"`
	Structured  *MissionInput `json:"structured,omitempty"`
}

// missionWorkflowState is the value passed between ADK graph nodes during one
// invocation. Long waits never depend on this value: Mission is the durable
// checkpoint used when a later request or worker tick resumes the graph.
type missionWorkflowState struct {
	Input           missionWorkflowInput
	Structured      MissionInput
	Draft           Mission
	Mission         Mission
	MissionID       string
	Plan            *Plan
	Decision        missionPlanningDecision
	Selected        []missionAction
	CatalogueCounts map[string]int
	FactsBefore     int
	FactsAfter      int
	NewFacts        bool
	Reason          string
	ErrorKind       string
	Report          *MissionReport
	PreTrace        []WorkflowTransition
}

// MissionWorkflowError distinguishes a request that needs clarification from
// one that is invalid or outside the implemented mission contract.
type MissionWorkflowError struct {
	Kind   string
	Reason string
}

func (e *MissionWorkflowError) Error() string {
	if e == nil {
		return ""
	}
	return e.Reason
}

func workflowState(input any) (*missionWorkflowState, error) {
	switch value := input.(type) {
	case *missionWorkflowState:
		return value, nil
	case missionWorkflowState:
		copy := value
		return &copy, nil
	default:
		return nil, fmt.Errorf("mission workflow received %T instead of workflow state", input)
	}
}

func missionInputFailureKind(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"request is required",
		"requires 1-32 requirements",
		"needs a target asset id",
		"needs source and target asset ids",
		"no requirements",
		"no grounded requirements",
	} {
		if strings.Contains(message, fragment) {
			return "clarification"
		}
	}
	return "rejected"
}

func (s *Service) recordWorkflowTransition(id, node, route, detail, planID string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	return s.Store.UpdateMission(id, func(m *Mission) error {
		m.WorkflowVersion = missionWorkflowVersion
		m.WorkflowStage = node
		transition := WorkflowTransition{Node: node, Route: route, Detail: detail, PlanID: planID, At: time.Now().UTC()}
		if count := len(m.WorkflowTrace); count > 0 {
			last := m.WorkflowTrace[count-1]
			if last.Node == transition.Node && last.Route == transition.Route && last.Detail == transition.Detail && last.PlanID == transition.PlanID {
				return nil
			}
		}
		m.WorkflowTrace = append(m.WorkflowTrace, transition)
		if len(m.WorkflowTrace) > 256 {
			m.WorkflowTrace = append([]WorkflowTransition(nil), m.WorkflowTrace[len(m.WorkflowTrace)-256:]...)
		}
		return nil
	})
}

func missionCatalogueKinds(m Mission) []string {
	seen := map[string]bool{}
	for _, requirement := range m.Requirements {
		kind := requirement.TargetKind
		if kind == "" {
			kind = "endpoint_chain"
		}
		if kind == "endpoint_chain" || kind == "email_chain" {
			seen[kind] = true
		}
	}
	if len(seen) == 0 {
		seen["endpoint_chain"] = true
	}
	kinds := make([]string, 0, len(seen))
	for _, kind := range []string{"endpoint_chain", "email_chain"} {
		if seen[kind] {
			kinds = append(kinds, kind)
		}
	}
	return kinds
}

func missionResumeRoute(m Mission, p *Plan) string {
	if m.Status == "blocked" && transientInventoryBlocker(m.BlockingReason) {
		// An endpoint can disconnect briefly while a chain finishes or its agent
		// restarts. An explicit replan request must refresh inventory and retain
		// prior evidence instead of making that observation permanently terminal.
		return "planning"
	}
	if m.Status == "completed" || m.Status == "blocked" || m.Status == "unattainable" {
		return "final"
	}
	if m.Status == "reconcile" {
		return "reconcile"
	}
	if p == nil {
		return "planning"
	}
	switch p.Status {
	case "planned":
		return "authorization"
	case "queued", "running":
		return "execute"
	case "needs_reconciliation":
		return "reconcile"
	case "completed":
		if m.Status == "planning" {
			// Evidence has already been synchronized for this terminal plan.
			// A further advance must select the next hop, not replay an old report.
			return "planning"
		}
		return "evidence"
	case "failed", "cancelled":
		return "failure"
	default:
		return "planning"
	}
}

func transientInventoryBlocker(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	return (strings.HasPrefix(reason, "asset ") && (strings.Contains(reason, "unavailable") || strings.Contains(reason, "disconnected"))) ||
		strings.Contains(reason, "fourcore transport failed") || strings.Contains(reason, "context canceled") || strings.Contains(reason, "context deadline exceeded")
}

func missionWorkflowMessage(m Mission, p *Plan) string {
	switch m.Status {
	case "awaiting_authorization":
		return "reviewed plan created; operator authorization of the exact plan hash is required"
	case "queued", "running":
		return "authorized plan is being submitted or monitored"
	case "reconcile":
		return "submission outcome is uncertain; reconcile an independently verified execution ID before continuing"
	case "completed":
		return "all mandatory mission objectives are proven by stored evidence"
	case "blocked":
		return "mission is blocked: " + m.BlockingReason
	case "unattainable":
		return "mission is unattainable with the current assets, catalogue, permissions, and evidence: " + m.BlockingReason
	}
	if p != nil {
		return "mission is waiting at plan " + p.ID
	}
	return "mission is ready for its next planning transition"
}

// runMissionWorkflow builds and invokes the complete ADK graph. Every routed
// node emits a session.Event with Routes, so the workflow package, rather than
// procedural code outside it, owns branch selection and iteration.
func (s *Service) runMissionWorkflow(ctx context.Context, seed missionWorkflowInput, llm model.LLM) (MissionPlanResult, error) {
	var finalState *missionWorkflowState

	newRoutedNode := func(name string, fn func(agent.Context, *missionWorkflowState) (string, error)) workflow.Node {
		return workflow.NewEmittingFunctionNode[any, any](name, func(nodeCtx agent.Context, input any, emit func(*session.Event) error) (any, error) {
			state, err := workflowState(input)
			if err != nil {
				return nil, err
			}
			route, err := fn(nodeCtx, state)
			if err != nil {
				return nil, err
			}
			planID := ""
			if state.Plan != nil {
				planID = state.Plan.ID
			}
			if state.MissionID != "" {
				if err := s.recordWorkflowTransition(state.MissionID, name, route, state.Reason, planID); err != nil {
					return nil, err
				}
			} else {
				state.PreTrace = append(state.PreTrace, WorkflowTransition{Node: name, Route: route, Detail: state.Reason, PlanID: planID, At: time.Now().UTC()})
			}
			event := session.NewEvent(nodeCtx, nodeCtx.InvocationID())
			event.Routes = []string{route}
			event.Output = state
			if err := emit(event); err != nil {
				return nil, err
			}
			return nil, nil
		}, workflow.NodeConfig{})
	}

	newLeafNode := func(name, route string, fn func(agent.Context, *missionWorkflowState) error) workflow.Node {
		return workflow.NewFunctionNode[any, any](name, func(nodeCtx agent.Context, input any) (any, error) {
			state, err := workflowState(input)
			if err != nil {
				return nil, err
			}
			if fn != nil {
				if err := fn(nodeCtx, state); err != nil {
					return nil, err
				}
			}
			planID := ""
			if state.Plan != nil {
				planID = state.Plan.ID
			}
			if state.MissionID != "" {
				if err := s.recordWorkflowTransition(state.MissionID, name, route, state.Reason, planID); err != nil {
					return nil, err
				}
				state.Mission, _ = s.missionByID(state.MissionID)
			}
			finalState = state
			return state, nil
		}, workflow.NodeConfig{})
	}

	ingress := workflow.NewEmittingFunctionNode[any, any]("workflow_ingress", func(nodeCtx agent.Context, input any, emit func(*session.Event) error) (any, error) {
		raw, ok := input.(string)
		if !ok {
			return nil, fmt.Errorf("mission workflow input must be JSON text, got %T", input)
		}
		var parsed missionWorkflowInput
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, fmt.Errorf("decode mission workflow input: %w", err)
		}
		state := &missionWorkflowState{Input: parsed}
		route := parsed.Mode
		switch parsed.Mode {
		case "request":
			route = "extract"
		case "structured":
			if parsed.Structured == nil {
				state.ErrorKind = "clarification"
				state.Reason = "structured mission input is missing"
				route = "clarification"
			} else {
				state.Structured = *parsed.Structured
				route = "validate"
			}
		case "advance":
			state.MissionID = parsed.MissionID
			route = "resume"
		default:
			state.ErrorKind = "rejected"
			state.Reason = "unsupported mission workflow entry mode"
			route = "rejected"
		}
		event := session.NewEvent(nodeCtx, nodeCtx.InvocationID())
		state.PreTrace = append(state.PreTrace, WorkflowTransition{Node: "workflow_ingress", Route: route, Detail: state.Reason, At: time.Now().UTC()})
		event.Routes = []string{route}
		event.Output = state
		if err := emit(event); err != nil {
			return nil, err
		}
		return nil, nil
	}, workflow.NodeConfig{})

	extract := newRoutedNode("llm_extracts_structured_mission", func(nodeCtx agent.Context, state *missionWorkflowState) (string, error) {
		if llm == nil {
			state.ErrorKind = "rejected"
			state.Reason = "mission request extraction requires a configured language model"
			return "rejected", nil
		}
		structured, err := s.ExtractMissionInput(nodeCtx, state.Input.UserRequest, llm)
		if err != nil {
			state.ErrorKind = missionInputFailureKind(err)
			if state.ErrorKind == "" {
				state.ErrorKind = "clarification"
			}
			state.Reason = err.Error()
			return state.ErrorKind, nil
		}
		state.Structured = structured
		state.Reason = "operator request converted into typed objective predicates"
		return "extracted", nil
	})

	validate := newRoutedNode("go_validates_mission", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		draft, err := normalizeMissionInput(state.Structured, state.Input.SessionID)
		if err != nil {
			state.ErrorKind = missionInputFailureKind(err)
			state.Reason = err.Error()
			return state.ErrorKind, nil
		}
		state.Draft = draft
		state.Reason = fmt.Sprintf("validated %d mandatory objective predicates", len(draft.Requirements))
		return "valid", nil
	})

	clarification := newLeafNode("ask_user_for_clarification", "waiting_for_user", func(_ agent.Context, state *missionWorkflowState) error {
		state.ErrorKind = "clarification"
		if state.Reason == "" {
			state.Reason = "the request does not contain enough information to create a mission"
		}
		return nil
	})
	rejected := newLeafNode("reject_with_exact_reason", "rejected", func(_ agent.Context, state *missionWorkflowState) error {
		state.ErrorKind = "rejected"
		if state.Reason == "" {
			state.Reason = "the request is outside the implemented mission contract"
		}
		return nil
	})

	createDurable := newRoutedNode("create_durable_mission", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Draft.WorkflowVersion = missionWorkflowVersion
		state.Draft.WorkflowStage = "create_durable_mission"
		state.Draft.WorkflowTrace = append([]WorkflowTransition(nil), state.PreTrace...)
		if err := s.Store.Put("missions", state.Draft.ID, state.Draft); err != nil {
			return "", err
		}
		state.MissionID = state.Draft.ID
		state.Mission = state.Draft
		state.Reason = "durable mission checkpoint created"
		return "created", nil
	})

	resume := newRoutedNode("resume_durable_mission", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		if strings.TrimSpace(state.MissionID) == "" {
			return "", fmt.Errorf("mission ID is required to resume the workflow")
		}
		mission, err := s.missionByID(state.MissionID)
		if err != nil {
			return "", err
		}
		state.Mission = mission
		state.Plan = nil
		if mission.CurrentPlanID != "" {
			var plan Plan
			if err := s.Store.Get("plans", mission.CurrentPlanID, &plan); err != nil {
				return "", err
			}
			state.Plan = &plan
		}
		route := missionResumeRoute(mission, state.Plan)
		state.Reason = "resumed durable checkpoint at " + route
		return route, nil
	})

	readInventory := newRoutedNode("read_live_asset_inventory", func(nodeCtx agent.Context, state *missionWorkflowState) (string, error) {
		if err := s.CollectMissionFacts(nodeCtx, state.MissionID); err != nil {
			return "", err
		}
		state.Mission, _ = s.missionByID(state.MissionID)
		state.Reason = fmt.Sprintf("read explicit availability, connection, platform, and elevation fields for %d execution assets", len(missionAssetKinds(state.Mission, s.Config.LateralEnabled)))
		return "inventory_loaded", nil
	})

	readCatalogue := newRoutedNode("read_local_fourcore_catalogue", func(nodeCtx agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		state.CatalogueCounts = map[string]int{}
		for _, kind := range missionCatalogueKinds(state.Mission) {
			var items []Catalog
			var err error
			if len(s.Config.LabAssets) > 0 {
				items, err = s.FC.localCatalogItems(kind)
			} else {
				items, err = s.FC.allCatalog(nodeCtx, kind)
			}
			if err != nil {
				return "", err
			}
			state.CatalogueCounts[kind] = len(items)
		}
		parts := make([]string, 0, len(state.CatalogueCounts))
		for _, kind := range missionCatalogueKinds(state.Mission) {
			parts = append(parts, fmt.Sprintf("%s=%d", kind, state.CatalogueCounts[kind]))
		}
		state.Reason = "loaded persisted catalogue snapshot: " + strings.Join(parts, ", ")
		return "catalogue_loaded", nil
	})

	loadEvidence := newRoutedNode("load_evidence_from_prior_attempts", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		state.Reason = fmt.Sprintf("loaded %d prior attempts and %d stored facts", len(state.Mission.Attempts), len(state.Mission.Facts))
		return "evidence_loaded", nil
	})

	buildFacts := newRoutedNode("build_known_fact_set", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		proven, disproven, unknown := 0, 0, 0
		for _, requirement := range state.Mission.Requirements {
			switch requirement.Status {
			case "proven":
				proven++
			case "disproven":
				disproven++
			default:
				unknown++
			}
		}
		state.Reason = fmt.Sprintf("known objective states: proven=%d, disproven=%d, unknown=%d", proven, disproven, unknown)
		return "facts_built", nil
	})

	evaluate := newRoutedNode("evaluate_mission_objectives", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		if blocker := missionAssetBlocker(state.Mission, s.Config.LabAssets, s.Config.LateralEnabled); blocker != "" {
			state.Reason = blocker
			return "blocked", nil
		}
		if allMandatorySatisfied(state.Mission) {
			if err := s.Store.UpdateMission(state.MissionID, func(m *Mission) error {
				m.Status = "completed"
				m.BlockingReason = ""
				return nil
			}); err != nil {
				return "", err
			}
			state.Reason = "all mandatory objective predicates are proven"
			return "all_satisfied", nil
		}
		state.Reason = "mandatory objectives remain"
		return "objectives_remain", nil
	})

	buildCandidates := newRoutedNode("build_candidate_action_graph", func(nodeCtx agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		decision, err := s.missionPlanningDecision(nodeCtx, state.Mission)
		if err != nil {
			return "", err
		}
		state.Decision = decision
		state.Selected = append([]missionAction(nil), decision.Selected...)
		state.Reason = decision.Reason
		if state.Reason == "" {
			state.Reason = fmt.Sprintf("built candidate graph from %d catalogue actions", decision.Actions)
		}
		return "candidates_built", nil
	})

	feasibility := newRoutedNode("fully_feasible_path_exists", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		route := state.Decision.Route
		switch route {
		case "full", "discovery", "unavailable":
		default:
			route = "unavailable"
		}
		if route == "full" {
			state.Reason = fmt.Sprintf("a complete path of %d actions covers the actionable objectives", len(state.Decision.Selected))
		}
		return route, nil
	})

	findBlockers := newRoutedNode("find_unknown_prerequisites_blocking_candidate_paths", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		missing := []string{}
		seen := map[string]bool{}
		for _, action := range state.Decision.Selected {
			for _, id := range action.PreReqIDs {
				if !seen[id] {
					seen[id] = true
					missing = append(missing, id)
				}
			}
		}
		if len(missing) == 0 {
			state.Reason = state.Decision.Reason
		} else {
			state.Reason = "unknown prerequisites: " + strings.Join(missing, ", ")
		}
		return "blockers_identified", nil
	})

	discoveryPermitted := newRoutedNode("permitted_discovery_action_can_resolve_blocker", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		if len(state.Decision.Selected) == 0 {
			state.Reason = "no permitted catalogue action can produce a missing prerequisite"
			return "no", nil
		}
		state.Reason = "a permitted catalogue action can produce prerequisite evidence"
		return "yes", nil
	})

	selectAttack := newRoutedNode("select_shortest_feasible_path", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Selected = append([]missionAction(nil), state.Decision.Selected...)
		state.Reason = fmt.Sprintf("selected the shortest deterministic path with %d actions", len(state.Selected))
		return "selected", nil
	})

	selectDiscovery := newRoutedNode("choose_discovery_action_resolving_most_blockers", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		// chooseActions already orders a shortest feasible prerequisite path.
		// Execute only its first action so later choices are based on evidence,
		// without inventing an information-gain formula.
		state.Selected = append([]missionAction(nil), state.Decision.Selected[:1]...)
		state.Reason = "selected the first action on the shortest prerequisite path"
		return "selected", nil
	})

	createPlanNode := func(name, kind string) workflow.Node {
		return newRoutedNode(name, func(nodeCtx agent.Context, state *missionWorkflowState) (string, error) {
			state.Mission, _ = s.missionByID(state.MissionID)
			result, err := s.createMissionPlan(nodeCtx, state.Mission, state.Selected, state.Decision.Reason, kind)
			if err != nil {
				return "", err
			}
			state.Mission = result.Mission
			state.Plan = result.Plan
			state.Reason = result.Message
			return "plan_created", nil
		})
	}
	createAttack := createPlanNode("create_immutable_attack_plan", "attack")
	createDiscovery := createPlanNode("create_immutable_discovery_plan", "discovery")

	authorization := newLeafNode("user_authorizes_exact_plan_hash", "authorization_required", func(_ agent.Context, state *missionWorkflowState) error {
		state.Mission, _ = s.missionByID(state.MissionID)
		if state.Plan == nil && state.Mission.CurrentPlanID != "" {
			var plan Plan
			if err := s.Store.Get("plans", state.Mission.CurrentPlanID, &plan); err != nil {
				return err
			}
			state.Plan = &plan
		}
		state.Reason = "waiting for operator authorization of the immutable plan hash"
		return nil
	})

	worker := newRoutedNode("worker_submits_or_polls_plan", func(nodeCtx agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		if state.Mission.CurrentPlanID == "" {
			state.Reason = "mission has no current plan"
			return "terminal", nil
		}
		plan, err := s.processPlanTick(nodeCtx, state.Mission.CurrentPlanID)
		if err != nil {
			return "", err
		}
		state.Plan = &plan
		switch plan.Status {
		case "planned":
			state.Reason = "plan has not been authorized"
			return "authorization", nil
		case "queued", "running":
			_ = s.Store.UpdateMission(state.MissionID, func(m *Mission) error { m.Status = "running"; return nil })
			for _, item := range plan.Items {
				if item.ExecutionID != "" && (item.Status == "running" || item.Status == "collecting_evidence" || item.Status == "abort_requested") {
					state.Reason = "execution ID received; report polling remains active"
					return "execution_received", nil
				}
			}
			state.Reason = "scheduled submission or an earlier plan item remains active"
			return "active", nil
		case "needs_reconciliation":
			_ = s.Store.UpdateMission(state.MissionID, func(m *Mission) error {
				m.Status = "reconcile"
				m.BlockingReason = "an execution submission is unresolved; reconcile it before replanning"
				return nil
			})
			state.Reason = "submission outcome is uncertain"
			return "uncertain", nil
		case "failed", "cancelled":
			state.Reason = "plan reached terminal status " + plan.Status
			return "rejected", nil
		default:
			state.Reason = "plan reached terminal status " + plan.Status
			return "report_ready", nil
		}
	})

	executionReceived := newRoutedNode("execution_id_received", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Reason = "a usable execution ID is stored on the immutable plan"
		return "poll", nil
	})

	pollReport := newRoutedNode("poll_execution_report", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		if state.Plan == nil {
			state.Reason = "no plan is available for report polling"
			return "waiting", nil
		}
		switch state.Plan.Status {
		case "completed", "failed", "cancelled":
			state.Reason = "a terminal report snapshot is stored for evidence evaluation"
			return "report_ready", nil
		default:
			state.Reason = "execution report is not terminal; poll again on the next worker tick"
			return "waiting", nil
		}
	})

	recordFailure := newRoutedNode("record_exact_submission_or_execution_failure", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		failures := []string{}
		if state.Plan != nil {
			for index, item := range state.Plan.Items {
				if item.Status == "failed" || item.Status == "aborted" || item.Status == "skipped" {
					detail := item.Error
					if detail == "" {
						detail = item.Status
					}
					failures = append(failures, fmt.Sprintf("item %d (%s): %s", index+1, item.CatalogID, detail))
				}
			}
		}
		if len(failures) > 0 {
			state.Reason = strings.Join(failures, "; ")
		}
		return "failure_recorded", nil
	})

	waitExecution := newLeafNode("wait_for_execution_or_next_poll", "waiting", func(_ agent.Context, state *missionWorkflowState) error {
		state.Reason = "worker will resume this graph on the next polling tick"
		return nil
	})
	reconciliation := newLeafNode("require_reconciliation", "operator_reconciliation_required", func(_ agent.Context, state *missionWorkflowState) error {
		state.Reason = "attach an independently verified execution ID; the uncertain submission will not be retried"
		return nil
	})

	applyEvidence := newRoutedNode("apply_evidence_contract", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		before, err := s.missionByID(state.MissionID)
		if err != nil {
			return "", err
		}
		state.FactsBefore = len(before.Facts)
		if err := s.SyncMission(state.MissionID); err != nil {
			return "", err
		}
		after, err := s.missionByID(state.MissionID)
		if err != nil {
			return "", err
		}
		state.Mission = after
		state.FactsAfter = len(after.Facts)
		state.NewFacts = state.FactsAfter > state.FactsBefore
		state.Reason = fmt.Sprintf("evidence contracts applied; facts before=%d, after=%d", state.FactsBefore, state.FactsAfter)
		return "applied", nil
	})

	updateFacts := newRoutedNode("update_facts_and_objective_results", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		state.Mission, _ = s.missionByID(state.MissionID)
		proven, disproven := 0, 0
		for _, requirement := range state.Mission.Requirements {
			if requirement.Status == "proven" {
				proven++
			} else if requirement.Status == "disproven" {
				disproven++
			}
		}
		state.Reason = fmt.Sprintf("objective results updated: proven=%d, disproven=%d", proven, disproven)
		return "facts_updated", nil
	})

	newFacts := newRoutedNode("new_facts_produced", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		if state.NewFacts {
			state.Reason = "execution produced new explicit facts"
			return "yes", nil
		}
		state.Reason = "the terminal attempt produced no new fact"
		return "no", nil
	})

	markBlocked := newRoutedNode("mark_objective_blocked", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		if state.Reason == "" {
			state.Reason = "a required asset or evidence-producing action is currently unavailable"
		}
		if err := s.Store.UpdateMission(state.MissionID, func(m *Mission) error {
			m.Status = "blocked"
			m.BlockingReason = state.Reason
			return nil
		}); err != nil {
			return "", err
		}
		return "final", nil
	})

	markUnattainable := newRoutedNode("mark_objective_unattainable", func(_ agent.Context, state *missionWorkflowState) (string, error) {
		if state.Reason == "" {
			state.Reason = "no untried permitted catalogue action can satisfy the remaining objectives"
		}
		if err := s.Store.UpdateMission(state.MissionID, func(m *Mission) error {
			m.Status = "unattainable"
			m.BlockingReason = state.Reason
			return nil
		}); err != nil {
			return "", err
		}
		return "final", nil
	})

	finalReport := newLeafNode("generate_final_report", "complete", func(_ agent.Context, state *missionWorkflowState) error {
		report, err := s.MissionReport(state.MissionID)
		if err != nil {
			return err
		}
		state.Report = &report
		state.Mission, _ = s.missionByID(state.MissionID)
		state.Reason = "mission report generated from stored plans, execution evidence, and objective states"
		return nil
	})

	edges := []workflow.Edge{
		{From: workflow.Start, To: ingress},
		{From: ingress, To: extract, Route: workflow.StringRoute("extract")},
		{From: ingress, To: validate, Route: workflow.StringRoute("validate")},
		{From: ingress, To: resume, Route: workflow.StringRoute("resume")},
		{From: ingress, To: clarification, Route: workflow.StringRoute("clarification")},
		{From: ingress, To: rejected, Route: workflow.StringRoute("rejected")},
		{From: extract, To: validate, Route: workflow.StringRoute("extracted")},
		{From: extract, To: clarification, Route: workflow.StringRoute("clarification")},
		{From: extract, To: rejected, Route: workflow.StringRoute("rejected")},
		{From: validate, To: createDurable, Route: workflow.StringRoute("valid")},
		{From: validate, To: clarification, Route: workflow.StringRoute("clarification")},
		{From: validate, To: rejected, Route: workflow.StringRoute("rejected")},
		{From: createDurable, To: readInventory, Route: workflow.StringRoute("created")},
		{From: resume, To: readInventory, Route: workflow.StringRoute("planning")},
		{From: resume, To: authorization, Route: workflow.StringRoute("authorization")},
		{From: resume, To: worker, Route: workflow.StringRoute("execute")},
		{From: resume, To: applyEvidence, Route: workflow.StringRoute("evidence")},
		{From: resume, To: recordFailure, Route: workflow.StringRoute("failure")},
		{From: resume, To: reconciliation, Route: workflow.StringRoute("reconcile")},
		{From: resume, To: finalReport, Route: workflow.StringRoute("final")},
		{From: readInventory, To: readCatalogue, Route: workflow.StringRoute("inventory_loaded")},
		{From: readCatalogue, To: loadEvidence, Route: workflow.StringRoute("catalogue_loaded")},
		{From: loadEvidence, To: buildFacts, Route: workflow.StringRoute("evidence_loaded")},
		{From: buildFacts, To: evaluate, Route: workflow.StringRoute("facts_built")},
		{From: evaluate, To: finalReport, Route: workflow.StringRoute("all_satisfied")},
		{From: evaluate, To: buildCandidates, Route: workflow.StringRoute("objectives_remain")},
		{From: evaluate, To: markBlocked, Route: workflow.StringRoute("blocked")},
		{From: evaluate, To: markUnattainable, Route: workflow.StringRoute("proof_blocked")},
		{From: buildCandidates, To: feasibility, Route: workflow.StringRoute("candidates_built")},
		{From: feasibility, To: selectAttack, Route: workflow.StringRoute("full")},
		{From: feasibility, To: findBlockers, Route: workflow.StringRoute("discovery")},
		{From: feasibility, To: markUnattainable, Route: workflow.StringRoute("unavailable")},
		{From: findBlockers, To: discoveryPermitted, Route: workflow.StringRoute("blockers_identified")},
		{From: discoveryPermitted, To: selectDiscovery, Route: workflow.StringRoute("yes")},
		{From: discoveryPermitted, To: markUnattainable, Route: workflow.StringRoute("no")},
		{From: selectAttack, To: createAttack, Route: workflow.StringRoute("selected")},
		{From: selectDiscovery, To: createDiscovery, Route: workflow.StringRoute("selected")},
		{From: createAttack, To: authorization, Route: workflow.StringRoute("plan_created")},
		{From: createDiscovery, To: authorization, Route: workflow.StringRoute("plan_created")},
		{From: worker, To: authorization, Route: workflow.StringRoute("authorization")},
		{From: worker, To: waitExecution, Route: workflow.StringRoute("active")},
		{From: worker, To: executionReceived, Route: workflow.StringRoute("execution_received")},
		{From: worker, To: reconciliation, Route: workflow.StringRoute("uncertain")},
		{From: worker, To: recordFailure, Route: workflow.StringRoute("rejected")},
		{From: worker, To: pollReport, Route: workflow.StringRoute("report_ready")},
		{From: executionReceived, To: pollReport, Route: workflow.StringRoute("poll")},
		{From: pollReport, To: waitExecution, Route: workflow.StringRoute("waiting")},
		{From: pollReport, To: applyEvidence, Route: workflow.StringRoute("report_ready")},
		{From: recordFailure, To: applyEvidence, Route: workflow.StringRoute("failure_recorded")},
		{From: applyEvidence, To: updateFacts, Route: workflow.StringRoute("applied")},
		{From: updateFacts, To: newFacts, Route: workflow.StringRoute("facts_updated")},
		{From: newFacts, To: buildFacts, Route: workflow.StringRoute("yes")},
		{From: newFacts, To: markBlocked, Route: workflow.StringRoute("no")},
		{From: markBlocked, To: finalReport, Route: workflow.StringRoute("final")},
		{From: markUnattainable, To: finalReport, Route: workflow.StringRoute("final")},
	}

	graph, err := workflowagent.New(workflowagent.Config{
		Name:        "fourcore_mission_workflow",
		Description: "Durable objective-driven FourCore mission workflow with discovery, authorization, execution, evidence, replanning, and reporting.",
		Edges:       edges,
	})
	if err != nil {
		return MissionPlanResult{}, fmt.Errorf("build mission workflow: %w", err)
	}

	raw, err := json.Marshal(seed)
	if err != nil {
		return MissionPlanResult{}, err
	}
	sessions := session.InMemoryService()
	graphSessionID := "mission-workflow-" + newID()
	created, err := sessions.Create(ctx, &session.CreateRequest{AppName: "fourcore-mission", UserID: "operator", SessionID: graphSessionID})
	if err != nil {
		return MissionPlanResult{}, err
	}
	graphRunner, err := runner.New(runner.Config{AppName: "fourcore-mission", Agent: graph, SessionService: sessions})
	if err != nil {
		return MissionPlanResult{}, err
	}
	for event, runErr := range graphRunner.Run(ctx, "operator", created.Session.ID(), &genai.Content{Role: "user", Parts: []*genai.Part{{Text: string(raw)}}}, agent.RunConfig{StreamingMode: agent.StreamingModeNone}) {
		if runErr != nil {
			return MissionPlanResult{}, runErr
		}
		if event.ErrorCode != "" {
			return MissionPlanResult{}, fmt.Errorf("mission workflow event error %s", event.ErrorCode)
		}
	}
	if finalState == nil {
		return MissionPlanResult{}, fmt.Errorf("mission workflow ended without a terminal checkpoint")
	}
	if finalState.ErrorKind != "" {
		return MissionPlanResult{}, &MissionWorkflowError{Kind: finalState.ErrorKind, Reason: finalState.Reason}
	}
	if finalState.MissionID == "" {
		return MissionPlanResult{}, fmt.Errorf("mission workflow completed without a mission ID")
	}
	mission, err := s.missionByID(finalState.MissionID)
	if err != nil {
		return MissionPlanResult{}, err
	}
	var plan *Plan
	if mission.CurrentPlanID != "" {
		var loaded Plan
		if err := s.Store.Get("plans", mission.CurrentPlanID, &loaded); err == nil {
			plan = &loaded
		} else if !errors.Is(err, ErrNotFound) {
			return MissionPlanResult{}, err
		}
	}
	return MissionPlanResult{Mission: mission, Plan: plan, Message: missionWorkflowMessage(mission, plan)}, nil
}

// RunMissionRequestGraph includes LLM extraction as the first graph branch.
func (s *Service) RunMissionRequestGraph(ctx context.Context, sessionID, request string, llm model.LLM) (MissionPlanResult, error) {
	return s.runMissionWorkflow(ctx, missionWorkflowInput{Mode: "request", SessionID: sessionID, UserRequest: request}, llm)
}

// RunMissionGraph starts at the typed-input validation branch.
func (s *Service) RunMissionGraph(ctx context.Context, sessionID string, input MissionInput) (MissionPlanResult, error) {
	return s.runMissionWorkflow(ctx, missionWorkflowInput{Mode: "structured", SessionID: sessionID, Structured: &input}, nil)
}

// AdvanceMissionGraph resumes a durable mission at the correct external gate.
func (s *Service) AdvanceMissionGraph(ctx context.Context, missionID string) (MissionPlanResult, error) {
	s.missionMu.Lock()
	defer s.missionMu.Unlock()
	return s.runMissionWorkflow(ctx, missionWorkflowInput{Mode: "advance", MissionID: missionID}, nil)
}
