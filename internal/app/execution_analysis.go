package app

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	executionHistoryReference = regexp.MustCompile(`(?i)\b(last|latest|previous|recent|most recent)\b`)
	executionHistorySubject   = regexp.MustCompile(`(?i)\b(exec|execution|run|simulation)\b`)
	executionHistoryIntent    = regexp.MustCompile(`(?i)\b(why|fail(?:ed|ure)?|result|output|report|record|evidence|happened|analy[sz]e?|next)\b`)
)

func shouldAutoExecutionAnalysis(message string) bool {
	return executionHistoryReference.MatchString(message) && executionHistorySubject.MatchString(message) && executionHistoryIntent.MatchString(message)
}

type ExecutionReference struct {
	PlanID           string    `json:"plan_id"`
	MissionID        string    `json:"mission_id,omitempty"`
	SessionID        string    `json:"session_id,omitempty"`
	ItemIndex        int       `json:"item_index"`
	Kind             string    `json:"kind"`
	CatalogID        string    `json:"catalog_id"`
	Name             string    `json:"name"`
	Targets          []string  `json:"targets"`
	ExecutionID      string    `json:"execution_id,omitempty"`
	PlanStatus       string    `json:"plan_status"`
	ItemStatus       string    `json:"item_status"`
	ItemError        string    `json:"item_error,omitempty"`
	PlanUpdated      time.Time `json:"plan_updated_at"`
	SubmittedAt      time.Time `json:"submitted_at,omitempty"`
	ReportObservedAt time.Time `json:"report_observed_at,omitempty"`
	CompletedAt      time.Time `json:"completed_at,omitempty"`
	Selection        string    `json:"selection"`
	RunElevated      bool      `json:"run_elevated"`
	Cleanup          bool      `json:"cleanup_enabled"`
	RequirementIDs   []string  `json:"requirement_ids,omitempty"`
}

type ExecutionStepAnalysis struct {
	ID        string `json:"id,omitempty"`
	ActionID  string `json:"action_id,omitempty"`
	Name      string `json:"name,omitempty"`
	Stage     string `json:"stage,omitempty"`
	State     string `json:"state"`
	Detected  *bool  `json:"detected,omitempty"`
	Prevented *bool  `json:"prevented,omitempty"`
	Failure   string `json:"failure,omitempty"`
	Output    any    `json:"output,omitempty"`
}

type ExecutionAnalysis struct {
	Execution        ExecutionReference      `json:"execution"`
	OutcomeCategory  string                  `json:"outcome_category"`
	Summary          string                  `json:"summary"`
	FailureReasons   []string                `json:"failure_reasons,omitempty"`
	Steps            []ExecutionStepAnalysis `json:"steps,omitempty"`
	SuccessfulSteps  int                     `json:"successful_steps"`
	FailedSteps      int                     `json:"failed_steps"`
	DetectionSeen    bool                    `json:"detection_seen"`
	PreventionSeen   bool                    `json:"prevention_seen"`
	DetectionState   string                  `json:"detection_evidence_state"`
	PreventionState  string                  `json:"prevention_evidence_state"`
	ReportSource     string                  `json:"report_source"`
	ReportWarning    string                  `json:"report_warning,omitempty"`
	Report           map[string]any          `json:"report,omitempty"`
	Mission          *MissionReport          `json:"mission,omitempty"`
	Unresolved       []Requirement           `json:"unresolved_requirements,omitempty"`
	ExistingNextPlan string                  `json:"existing_next_plan_id,omitempty"`
	Guidance         []string                `json:"guidance"`
}

type executionCandidate struct {
	plan      Plan
	item      ValidatedItem
	itemIndex int
}

func candidateObservedAt(candidate executionCandidate) time.Time {
	var latest time.Time
	for _, observed := range []time.Time{candidate.item.SubmittedAt, candidate.item.ReportObservedAt, candidate.item.CompletedAt} {
		if observed.After(latest) {
			latest = observed
		}
	}
	if latest.IsZero() {
		latest = candidate.plan.Updated
	}
	if latest.IsZero() {
		latest = candidate.plan.Created
	}
	return latest
}

func finishedExecutionStatus(status string) bool {
	switch status {
	case "completed", "failed", "aborted", "unknown":
		return true
	default:
		return false
	}
}

func executionCandidateFromPlans(plans []Plan, sessionID string) (executionCandidate, string, error) {
	find := func(requireSession bool, terminalOnly bool) (executionCandidate, bool) {
		candidates := []executionCandidate{}
		for _, plan := range plans {
			if requireSession && plan.SessionID != sessionID {
				continue
			}
			for index, item := range plan.Items {
				if item.Status == "pending" || item.Status == "skipped" {
					continue
				}
				if item.ExecutionID == "" && item.Error == "" {
					continue
				}
				if terminalOnly && !finishedExecutionStatus(item.Status) {
					continue
				}
				candidates = append(candidates, executionCandidate{plan: plan, item: item, itemIndex: index})
			}
		}
		if len(candidates) == 0 {
			return executionCandidate{}, false
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			left, right := candidateObservedAt(candidates[i]), candidateObservedAt(candidates[j])
			if !left.Equal(right) {
				return left.After(right)
			}
			return candidates[i].itemIndex > candidates[j].itemIndex
		})
		return candidates[0], true
	}
	if sessionID != "" {
		if candidate, ok := find(true, true); ok {
			return candidate, "latest finished execution attempt in the current chat session", nil
		}
	}
	if candidate, ok := find(false, true); ok {
		return candidate, "latest finished execution attempt in local plan history", nil
	}
	if sessionID != "" {
		if candidate, ok := find(true, false); ok {
			return candidate, "latest active or uncertain execution in the current chat session", nil
		}
	}
	if candidate, ok := find(false, false); ok {
		return candidate, "latest active or uncertain execution in local plan history", nil
	}
	return executionCandidate{}, "", fmt.Errorf("no stored execution records were found")
}

func failureText(node map[string]any) string {
	for _, key := range []string{"failure_reason", "error_message", "error", "reason", "message", "error_code"} {
		if value := strings.TrimSpace(scalarString(node[key])); value != "" {
			return value
		}
	}
	if exit := scalarString(node["exit_code"]); exit != "" && exit != "0" {
		return "non-zero exit code " + exit
	}
	return ""
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func analyzeExecutionSteps(report map[string]any) (steps []ExecutionStepAnalysis, successes, failures int, reasons []string) {
	for _, step := range reportSteps(report) {
		state := "unknown"
		if step.Success != nil {
			if *step.Success {
				state = "succeeded"
				successes++
			} else if step.Done != nil && *step.Done {
				state = "failed"
				failures++
			}
		} else if step.Done != nil {
			if *step.Done {
				state = "finished_without_success_field"
			} else {
				state = "incomplete"
			}
		} else {
			switch strings.ToLower(strings.TrimSpace(step.Status)) {
			case "success", "succeeded", "completed", "finished":
				state = "succeeded"
				successes++
			case "failed", "failure", "error", "aborted":
				state = "failed"
				failures++
			case "running", "pending", "in_progress":
				state = "incomplete"
			}
		}
		failure := ""
		if state == "failed" {
			failure = failureText(step.Raw)
			label := firstNonEmpty(step.Name, step.ActionID, step.ID, "unnamed step")
			if failure == "" {
				reasons = append(reasons, label+" failed without an explicit reason in the report")
			} else {
				reasons = append(reasons, label+": "+failure)
			}
		}
		steps = append(steps, ExecutionStepAnalysis{
			ID: step.ID, ActionID: step.ActionID, Name: step.Name, Stage: step.Stage,
			State: state, Detected: step.Detected, Prevented: step.Prevented,
			Failure: failure, Output: step.Raw["output"],
		})
	}
	return steps, successes, failures, reasons
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func unresolvedMissionRequirements(m Mission) []Requirement {
	unresolved := []Requirement{}
	for i := range m.Requirements {
		if m.Requirements[i].Mandatory && m.Requirements[i].Status != "proven" {
			unresolved = append(unresolved, m.Requirements[i])
		}
	}
	return unresolved
}

func executionOutcome(item ValidatedItem, successes, failures int) (string, string) {
	if item.ExecutionID == "" {
		switch item.Status {
		case "unknown":
			return "submission_uncertain", "FourCore may have accepted the submission, but no execution ID was stored. Reconcile against FourCore execution history before retrying."
		case "failed", "aborted":
			return "submission_failed", "The submission failed before FourCore returned an execution ID, so no simulation run is confirmed."
		default:
			return "pre_execution_record", fmt.Sprintf("No FourCore execution ID is stored; the local item is recorded as %s.", item.Status)
		}
	}
	if item.Status == "unknown" {
		return "execution_status_unknown", "A FourCore execution ID exists, but its final status is unresolved and must be reconciled before retrying."
	}
	if item.Status == "failed" || item.Status == "aborted" || failures > 0 {
		if successes > 0 {
			return "partial_execution_failure", fmt.Sprintf("FourCore ran the simulation with partial results: %d steps succeeded and %d explicitly failed; final status is %s.", successes, failures, item.Status)
		}
		return "terminal_execution_failure", fmt.Sprintf("FourCore ran the simulation and ended with status %s; %d steps succeeded and %d explicitly failed.", item.Status, successes, failures)
	}
	if item.Status == "completed" {
		return "execution_completed", fmt.Sprintf("FourCore completed the simulation with %d explicitly successful report steps.", successes)
	}
	return "execution_in_progress", fmt.Sprintf("The FourCore execution is recorded as %s; %d successful and %d failed steps are explicit so far.", item.Status, successes, failures)
}

func executionReportOverview(report map[string]any) map[string]any {
	overview := map[string]any{}
	for key, value := range report {
		if key == "assets" {
			continue
		}
		overview[key] = value
	}
	return overview
}

func detectionEvidenceState(report map[string]any) string {
	if observed, _ := reportHasDetection(report); observed {
		return "observed"
	}
	if _, ok := report["detected"]; ok {
		return "explicitly_not_observed"
	}
	if _, ok := report["total_detected"]; ok {
		return "explicitly_not_observed"
	}
	for _, step := range reportSteps(report) {
		if step.Detected != nil {
			return "explicitly_not_observed"
		}
	}
	return "unknown_no_explicit_evidence"
}

func preventionEvidenceState(report map[string]any) string {
	if observed, _ := reportWasPrevented(report); observed {
		return "observed"
	}
	if _, ok := report["prevented"]; ok {
		return "explicitly_not_observed"
	}
	for _, step := range reportSteps(report) {
		if step.Prevented != nil {
			return "explicitly_not_observed"
		}
	}
	return "unknown_no_explicit_evidence"
}

func (s *Service) LatestExecutionAnalysis(ctx context.Context, sessionID string) (ExecutionAnalysis, error) {
	plans, err := s.Store.Plans()
	if err != nil {
		return ExecutionAnalysis{}, err
	}
	candidate, selection, err := executionCandidateFromPlans(plans, sessionID)
	if err != nil {
		return ExecutionAnalysis{}, err
	}
	item, plan := candidate.item, candidate.plan
	targets := append([]string(nil), item.AssetIDs...)
	targets = append(targets, item.EmailAssetIDs...)
	analysis := ExecutionAnalysis{Execution: ExecutionReference{
		PlanID: plan.ID, MissionID: plan.MissionID, SessionID: plan.SessionID,
		ItemIndex: candidate.itemIndex, Kind: item.Kind, CatalogID: item.CatalogID,
		Name: item.Name, Targets: targets, ExecutionID: item.ExecutionID,
		PlanStatus: plan.Status, ItemStatus: item.Status, ItemError: item.Error,
		PlanUpdated: plan.Updated, SubmittedAt: item.SubmittedAt, ReportObservedAt: item.ReportObservedAt, CompletedAt: item.CompletedAt,
		Selection: selection, RunElevated: item.RunElevated,
		Cleanup: !item.DisableCleanup, RequirementIDs: append([]string(nil), item.RequirementIDs...),
	}}
	report := reportForModel(item.Report)
	analysis.ReportSource = "stored sanitized report"
	if item.ExecutionID != "" && validID(item.ExecutionID) == nil {
		kind := "execution"
		if item.Kind == "playbook" {
			kind = "playbook"
		}
		if raw, readErr := s.FC.RawReport(ctx, kind, item.ExecutionID); readErr == nil {
			report = reportForModel(raw)
			analysis.ReportSource = "fresh FourCore report"
		} else {
			analysis.ReportWarning = "FourCore refresh failed; analysis uses the last stored report: " + readErr.Error()
		}
	}
	analysis.Steps, analysis.SuccessfulSteps, analysis.FailedSteps, analysis.FailureReasons = analyzeExecutionSteps(report)
	analysis.Report = executionReportOverview(report)
	if item.Error != "" {
		analysis.FailureReasons = append([]string{item.Error}, analysis.FailureReasons...)
	}
	if rootFailure := failureText(report); rootFailure != "" {
		analysis.FailureReasons = append([]string{rootFailure}, analysis.FailureReasons...)
	}
	if (item.Status == "failed" || item.Status == "aborted") && len(analysis.FailureReasons) == 0 {
		analysis.FailureReasons = append(analysis.FailureReasons, "FourCore marked the execution terminal without returning an explicit failure reason")
	}
	analysis.FailureReasons = uniqueStrings(analysis.FailureReasons)
	analysis.OutcomeCategory, analysis.Summary = executionOutcome(item, analysis.SuccessfulSteps, analysis.FailedSteps)
	analysis.DetectionSeen, _ = reportHasDetection(report)
	analysis.PreventionSeen, _ = reportWasPrevented(report)
	analysis.DetectionState = detectionEvidenceState(report)
	analysis.PreventionState = preventionEvidenceState(report)

	if plan.MissionID != "" {
		if missionReport, reportErr := s.MissionReport(plan.MissionID); reportErr == nil {
			analysis.Mission = &missionReport
		}
		if mission, missionErr := s.missionByID(plan.MissionID); missionErr == nil {
			analysis.Unresolved = unresolvedMissionRequirements(mission)
			if mission.CurrentPlanID != "" && mission.CurrentPlanID != plan.ID {
				analysis.ExistingNextPlan = mission.CurrentPlanID
			}
		}
	}
	analysis.Guidance = append(analysis.Guidance,
		"Distinguish submission, execution, simulated behavior, detection, prevention, and destination access; they are separate outcomes.",
		"Use the exact failed step and its output when searching the catalogue for an alternative.",
	)
	if len(analysis.Unresolved) > 0 {
		analysis.Guidance = append(analysis.Guidance, "Ground recommendations in the unresolved requirements, but let the deterministic mission planner enforce prerequisite order before creating a follow-up plan.")
	}
	if analysis.ExistingNextPlan != "" {
		analysis.Guidance = append(analysis.Guidance, "A follow-up reviewed plan already exists; inspect it instead of creating a duplicate.")
	}
	return analysis, nil
}
