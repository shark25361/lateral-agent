package app

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

type DiagnosticCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass, warning, fail
	Detail string `json:"detail"`
}

type PlanDiagnostics struct {
	PlanID        string             `json:"plan_id"`
	Ready         bool               `json:"ready"`
	ObservedAt    time.Time          `json:"observed_at"`
	Checks        []DiagnosticCheck  `json:"checks"`
	SelectedRoute *GoalDirectedRoute `json:"selected_route,omitempty"`
}

func (d *PlanDiagnostics) add(name, status, detail string) {
	d.Checks = append(d.Checks, DiagnosticCheck{Name: name, Status: status, Detail: detail})
	if status == "fail" {
		d.Ready = false
	}
}

func (s *Service) DiagnosePlan(ctx context.Context, planID string) (PlanDiagnostics, error) {
	diagnostics := PlanDiagnostics{PlanID: planID, Ready: true, ObservedAt: time.Now().UTC()}
	var plan Plan
	if err := s.Store.Get("plans", planID, &plan); err != nil {
		return diagnostics, err
	}
	if !s.Config.Execute {
		diagnostics.add("execution_gate", "fail", "EXECUTION_ENABLED is false")
	} else {
		diagnostics.add("execution_gate", "pass", "execution is enabled; exact-hash authorization is still required")
	}
	if plan.Status != "planned" {
		diagnostics.add("plan_state", "warning", "plan is already "+plan.Status)
	} else if time.Since(plan.Created) > 24*time.Hour {
		diagnostics.add("plan_state", "fail", "plan is older than 24 hours")
	} else {
		diagnostics.add("plan_state", "pass", "plan is reviewable and unexpired")
	}
	var mission Mission
	if plan.MissionID != "" {
		loaded, err := s.missionByID(plan.MissionID)
		if err != nil {
			diagnostics.add("mission", "fail", err.Error())
		} else {
			mission = loaded
		}
	}
	for index, item := range plan.Items {
		prefix := fmt.Sprintf("item_%d", index+1)
		validated, err := s.Validate(ctx, item.PlanItem)
		if err != nil {
			diagnostics.add(prefix+"_live_validation", "fail", err.Error())
			continue
		}
		if item.Kind == "lab_lateral" {
			if len(s.Config.LabAssets) > 0 {
				diagnostics.add(prefix+"_scope_validation", "pass", "source and destination are declared in the local lab registry and allowlisted; this does not establish connectivity or access")
			} else {
				diagnostics.add(prefix+"_live_validation", "pass", "source and destination are allowlisted, available and connected according to FourCore; the destination binding and typed inputs are valid")
			}
		} else {
			diagnostics.add(prefix+"_live_validation", "pass", "targets are available and the live catalogue entry is executable for the reviewed scope")
			if item.Kind == "endpoint_chain" && item.SourceAssetID != "" && item.DestinationAssetID != "" {
				diagnostics.add(prefix+"_destination_binding", "warning", "FourCore chain-run receives the source asset only; the requested destination is a report-matching objective, not a runtime input to this chain")
			}
		}
		if validated.CatalogHash != item.CatalogHash || validated.InputHash != item.InputHash {
			diagnostics.add(prefix+"_fingerprint", "fail", "catalogue or typed action inputs changed")
		} else {
			diagnostics.add(prefix+"_fingerprint", "pass", "catalogue and typed input hashes match the reviewed plan")
		}
		if item.Kind != "lab_lateral" {
			diagnostics.add(prefix+"_execute_permission", "warning", "FourCore exposes no safe execute-permission preflight; permission is enforced at the single authorized submission")
			continue
		}
		if mission.ID == "" {
			diagnostics.add(prefix+"_route", "fail", "lateral execution requires a durable mission")
			continue
		}
		route := goalDirectedADRoute(mission, item.SourceAssetID, item.DestinationAssetID, item.Protocol)
		diagnostics.SelectedRoute = &route
		if !route.Ready || item.LateralInput == nil || hash(route.EdgeIDs) != hash(item.LateralInput.RouteEdgeIDs) {
			diagnostics.add(prefix+"_route", "fail", route.Reason)
		} else {
			diagnostics.add(prefix+"_route", "pass", route.Reason)
		}
		keyConfigured := s.Lateral != nil && len(s.Lateral.PublicKey) == ed25519.PublicKeySize
		if s.Lateral != nil && len(s.Lateral.PublicKeys) > 0 {
			keyConfigured = len(s.Lateral.PublicKeys[item.DestinationAssetID]) == ed25519.PublicKeySize
		}
		if !keyConfigured {
			diagnostics.add(prefix+"_signed_evidence", "fail", "destination evidence verifier is not configured")
			continue
		}
		diagnostics.add(prefix+"_signed_evidence", "pass", "an Ed25519 destination-evidence verification key is configured")
		health, err := s.Lateral.HealthForSource(ctx, item.SourceAssetID)
		if err != nil {
			diagnostics.add(prefix+"_executor", "fail", err.Error())
			continue
		}
		if !health.Execute || !health.SignedEvidence || !health.DestinationVerify || !health.CredentialRefs || health.SchemaVersion != "1" {
			diagnostics.add(prefix+"_executor", "fail", "executor lacks execution, credential-reference, schema-v1, or signed destination-verification capability")
			continue
		}
		diagnostics.add(prefix+"_executor_capabilities", "pass", "executor authorizes typed execution, opaque credential references, schema v1, and signed destination verification")
		protocolSupported := false
		for _, protocol := range health.Protocols {
			protocolSupported = protocolSupported || strings.EqualFold(protocol, item.Protocol)
		}
		if !protocolSupported {
			diagnostics.add(prefix+"_protocol", "fail", "executor does not advertise "+item.Protocol)
		} else {
			diagnostics.add(prefix+"_executor", "pass", "executor is reachable and advertises the authorized protocol with signed destination evidence")
		}
	}
	for _, status := range s.FC.CatalogStatuses() {
		if !status.Available {
			continue
		}
		age := time.Since(status.Updated)
		if age > 24*time.Hour {
			diagnostics.add("catalogue_"+status.Kind, "warning", fmt.Sprintf("snapshot is %.0f hours old; authorization still performs a live fingerprint check", age.Hours()))
		}
	}
	return diagnostics, nil
}
