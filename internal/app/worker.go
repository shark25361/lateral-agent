package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

func (s *Service) Recover() error {
	plans, e := s.Store.Plans()
	if e != nil {
		return e
	}
	for _, p := range plans {
		if p.Status == "running" || p.Status == "queued" {
			if e = s.Store.UpdatePlan(p.ID, func(p *Plan) error {
				for i := range p.Items {
					if p.Items[i].Status == "submitting" {
						p.Items[i].Status = "unknown"
						p.Items[i].Error = "Process stopped during submission. Reconcile execution history; this item will not be retried."
					}
				}
				return nil
			}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Service) Worker(ctx context.Context) {
	tick := time.NewTicker(s.Config.Poll)
	defer tick.Stop()
	for {
		if err := s.Tick(ctx); err != nil {
			slog.Error("worker", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (s *Service) Tick(ctx context.Context) error {
	plans, e := s.Store.Plans()
	if e != nil {
		return e
	}
	for _, p := range plans {
		// Mission plans are advanced through the ADK graph below. Standalone
		// plans retain the same worker behavior without a mission checkpoint.
		if p.MissionID != "" || (p.Status != "queued" && p.Status != "running") || p.Scheduled.After(time.Now()) {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, e = s.processPlanTick(ctx, p.ID); e != nil {
			return e
		}
	}
	return s.AdvanceMissions(ctx)
}

// processPlanTick performs one idempotent submit-or-poll pass for exactly one
// plan. The mission graph calls it from worker_submits_or_polls_plan, while
// Tick calls it directly only for standalone plans.
func (s *Service) processPlanTick(ctx context.Context, id string) (Plan, error) {
	var p Plan
	if e := s.Store.Get("plans", id, &p); e != nil {
		return Plan{}, e
	}
	if (p.Status != "queued" && p.Status != "running") || p.Scheduled.After(time.Now()) {
		return p, nil
	}
	if ctx.Err() != nil {
		return Plan{}, ctx.Err()
	}
	var e error
	for idx, item := range p.Items {
		if item.Status == "pending" {
			// Submit plan items in order. An uncertain or failed item stops the
			// remainder while already-started runs keep being monitored.
			waiting, blocked := false, false
			for _, previous := range p.Items[:idx] {
				switch previous.Status {
				case "completed":
				case "failed", "unknown", "aborted", "skipped":
					blocked = true
				default:
					waiting = true
				}
			}
			if blocked {
				if e := s.itemUpdate(p.ID, idx, func(i *ValidatedItem) {
					i.Status = "skipped"
					i.Error = "Earlier plan item failed or requires reconciliation"
					i.CompletedAt = time.Now().UTC()
				}); e != nil {
					return Plan{}, e
				}
				continue
			}
			if waiting {
				continue
			}
			if !s.Config.Execute {
				continue
			}
			v, e := s.Validate(ctx, item.PlanItem)
			if e == nil && v.CatalogHash != item.CatalogHash {
				e = fmt.Errorf("catalogue changed since authorization")
			}
			if e == nil && v.InputHash != item.InputHash {
				e = fmt.Errorf("action inputs changed since authorization")
			}
			if e != nil {
				if transientInventoryBlocker(e.Error()) {
					validationErr := e
					if updateErr := s.itemUpdate(p.ID, idx, func(i *ValidatedItem) {
						i.Error = "pre-submission validation deferred: " + validationErr.Error()
					}); updateErr != nil {
						return Plan{}, updateErr
					}
					continue
				}
				validationErr := e
				if updateErr := s.itemUpdate(p.ID, idx, func(i *ValidatedItem) {
					i.Status = "failed"
					i.Error = validationErr.Error()
					i.CompletedAt = time.Now().UTC()
				}); updateErr != nil {
					return Plan{}, updateErr
				}
				continue
			}
			claimed := false
			e = s.Store.UpdatePlan(p.ID, func(p *Plan) error {
				if (p.Status == "queued" || p.Status == "running") && p.Items[idx].Status == "pending" {
					p.Status = "running"
					p.Items[idx].Status = "submitting"
					p.Items[idx].SubmittedAt = time.Now().UTC()
					claimed = true
				}
				return nil
			})
			if e != nil {
				return Plan{}, e
			}
			if !claimed {
				continue
			}
			var raw map[string]any
			var lateralExecutionID string
			if item.Kind == "lab_lateral" {
				lateralExecutionID, raw, e = s.Lateral.Submit(ctx, item.PlanItem)
			} else {
				e = s.FC.Do(ctx, "POST", runPath(item.PlanItem), runBody(item.PlanItem), &raw)
			}
			status, msg, id := "running", "", ""
			if e != nil {
				status = "unknown"
				msg = e.Error()
				var he *HTTPError
				if errors.As(e, &he) && he.Status >= 400 && he.Status < 500 && he.Status != 408 {
					status = "failed"
				}
			} else {
				id = lateralExecutionID
				if id == "" {
					id, _ = raw["id"].(string)
				}
				if validID(id) != nil {
					status = "unknown"
					msg = "Submission returned no usable execution ID; inspect execution history before retrying"
				}
			}
			if e = s.itemUpdate(p.ID, idx, func(i *ValidatedItem) {
				i.Status = status
				i.Error = msg
				i.ExecutionID = id
				i.Report = reportSummary(raw)
				if len(raw) > 0 {
					i.ReportObservedAt = time.Now().UTC()
				}
				if status == "failed" {
					i.CompletedAt = time.Now().UTC()
				}
			}); e != nil {
				return Plan{}, e
			}
		} else if item.Status == "running" || item.Status == "abort_requested" || item.Status == "collecting_evidence" {
			var raw map[string]any
			if item.Kind == "lab_lateral" {
				raw, e = s.Lateral.Report(ctx, item.ExecutionID, item)
			} else {
				e = s.FC.Do(ctx, "GET", reportPath(item.Kind, item.ExecutionID), nil, &raw)
			}
			if e != nil {
				pollErr := e
				if updateErr := s.itemUpdate(p.ID, idx, func(i *ValidatedItem) {
					i.Error = pollErr.Error()
					var verificationError *EvidenceVerificationError
					if errors.As(pollErr, &verificationError) {
						i.Status = "failed"
						i.CompletedAt = time.Now().UTC()
					}
				}); updateErr != nil {
					return Plan{}, updateErr
				}
				continue
			}
			terminal := terminalReportState(raw)
			if e = s.itemUpdate(p.ID, idx, func(i *ValidatedItem) {
				i.Report = reportSummary(raw)
				i.ReportObservedAt = time.Now().UTC()
				i.Error = ""
				if terminal != "" {
					if i.CompletedAt.IsZero() {
						i.CompletedAt = time.Now().UTC()
					}
					if item.Status == "collecting_evidence" {
						i.FinalStatus = terminal
					} else if s.Config.CorrelationWait > 0 {
						i.Status = "collecting_evidence"
						i.FinalStatus = terminal
						i.EvidenceUntil = time.Now().Add(s.Config.CorrelationWait)
					} else {
						i.Status = terminal
					}
				}
				if item.Status == "collecting_evidence" {
					i.Status = "collecting_evidence"
					if !time.Now().Before(item.EvidenceUntil) {
						i.Status = i.FinalStatus
					}
				}
			}); e != nil {
				return Plan{}, e
			}
		}
	}
	if e := s.Store.UpdatePlan(p.ID, func(p *Plan) error {
		if p.Status == "cancelled" {
			return nil
		}
		active, unknown, failed := false, false, false
		for _, i := range p.Items {
			switch i.Status {
			case "pending", "submitting", "running", "abort_requested", "collecting_evidence":
				active = true
			case "unknown":
				unknown = true
			case "failed", "aborted", "skipped":
				failed = true
			}
		}
		if !active {
			p.Status = "completed"
			if failed {
				p.Status = "failed"
			}
			if unknown {
				p.Status = "needs_reconciliation"
			}
		}
		return nil
	}); e != nil {
		return Plan{}, e
	}
	if e := s.Store.Get("plans", id, &p); e != nil {
		return Plan{}, e
	}
	return p, nil
}

func terminalReportState(raw map[string]any) string {
	state, _ := raw["status"].(string)
	stateDetail, _ := raw["status_state"].(string)
	normalizedState := strings.ToLower(strings.TrimSpace(state))
	normalizedDetail := strings.ToLower(strings.TrimSpace(stateDetail))
	switch {
	case normalizedState == "failed", normalizedState == "error":
		return "failed"
	case normalizedState == "aborted", normalizedState == "cancelled", normalizedState == "canceled":
		return "aborted"
	case normalizedState == "completed", normalizedState == "finished", normalizedState == "success":
		return "completed"
	case normalizedDetail == "failed", normalizedDetail == "error":
		return "failed"
	case normalizedDetail == "aborted", normalizedDetail == "cancelled", normalizedDetail == "canceled":
		return "aborted"
	case normalizedDetail == "finished":
		return "completed"
	}
	total, finished, successful := reportInt(raw["total_attacks"]), reportInt(raw["total_finished"]), reportInt(raw["total_success"])
	if total > 0 && finished >= total {
		if successful >= total {
			return "completed"
		}
		return "failed"
	}
	return ""
}

func reportInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case float32:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
func (s *Service) itemUpdate(id string, n int, fn func(*ValidatedItem)) error {
	return s.Store.UpdatePlan(id, func(p *Plan) error { fn(&p.Items[n]); return nil })
}
func (s *Service) Cancel(id string) error {
	return s.Store.UpdatePlan(id, func(p *Plan) error {
		if p.Status != "queued" && p.Status != "planned" {
			return fmt.Errorf("only unstarted plans can be cancelled")
		}
		for _, i := range p.Items {
			if i.Status != "pending" {
				return fmt.Errorf("plan has started")
			}
		}
		p.Status = "cancelled"
		return nil
	})
}
func (s *Service) Abort(ctx context.Context, id string, index int) error {
	var p Plan
	if e := s.Store.Get("plans", id, &p); e != nil {
		return e
	}
	if index < 0 || index >= len(p.Items) {
		return fmt.Errorf("invalid item index")
	}
	i := p.Items[index]
	if i.Kind != "playbook" || i.ExecutionID == "" || i.Status != "running" {
		return fmt.Errorf("only running playbooks support abort")
	}
	if e := s.FC.Do(ctx, "POST", "/api/v2/packs/runs/"+i.ExecutionID+"/abort", nil, nil); e != nil {
		return e
	}
	return s.itemUpdate(id, index, func(i *ValidatedItem) { i.Status = "abort_requested" })
}

// Reconciliation attaches an independently verified execution ID. It never
// resubmits an uncertain request.
func (s *Service) Reconcile(ctx context.Context, id string, index int, execution string) error {
	if e := validID(execution); e != nil {
		return e
	}
	var p Plan
	if e := s.Store.Get("plans", id, &p); e != nil {
		return e
	}
	if index < 0 || index >= len(p.Items) || p.Items[index].Status != "unknown" {
		return fmt.Errorf("item does not require reconciliation")
	}
	var report map[string]any
	item := p.Items[index]
	if item.Kind == "lab_lateral" {
		var e error
		report, e = s.Lateral.Report(ctx, execution, item)
		if e != nil {
			return e
		}
		if item.LateralInput == nil || report["correlation_id"] != item.LateralInput.CorrelationID {
			return fmt.Errorf("lateral execution correlation does not match the authorized plan")
		}
		return s.finishReconciliation(p, index, execution, "Execution ID attached by operator and correlation matched")
	}
	if e := s.FC.Do(ctx, "GET", reportPath(item.Kind, execution), nil, &report); e != nil {
		return e
	}
	if report["id"] != execution {
		return fmt.Errorf("execution report ID mismatch")
	}
	key := "chain_id"
	if item.Kind == "playbook" {
		key = "pack_id"
	}
	if report[key] != item.CatalogID {
		return fmt.Errorf("execution does not match the planned catalogue ID")
	}
	want := map[string]bool{}
	for _, a := range item.AssetIDs {
		want[a] = true
	}
	for _, a := range item.EmailAssetIDs {
		want[a] = true
	}
	actual := map[string]bool{}
	assets, _ := report["assets"].([]any)
	for _, v := range assets {
		if a, ok := v.(map[string]any); ok {
			if id, ok := a["asset_id"].(string); ok {
				actual[id] = true
			}
		} else if id, ok := v.(string); ok {
			actual[id] = true
		}
	}
	if len(actual) != len(want) {
		return fmt.Errorf("execution target scope cannot be verified")
	}
	for id := range want {
		if !actual[id] {
			return fmt.Errorf("execution targets differ from the plan")
		}
	}
	return s.finishReconciliation(p, index, execution, "Execution ID attached by operator and target scope verified")
}

func (s *Service) finishReconciliation(p Plan, index int, execution, detail string) error {
	if err := s.Store.UpdatePlan(p.ID, func(p *Plan) error {
		if p.Items[index].Status != "unknown" {
			return fmt.Errorf("item already reconciled")
		}
		p.Items[index].ExecutionID = execution
		p.Items[index].Status = "running"
		p.Items[index].Error = detail
		p.Status = "running"
		return nil
	}); err != nil {
		return err
	}
	if p.MissionID != "" {
		if err := s.recordWorkflowTransition(p.MissionID, "require_reconciliation", "reconciled", detail, p.ID); err != nil {
			return err
		}
		if err := s.Store.UpdateMission(p.MissionID, func(m *Mission) error {
			if m.Status == "reconcile" {
				m.Status = "running"
				m.BlockingReason = ""
			}
			m.WorkflowStage = "worker_submits_or_polls_plan"
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
