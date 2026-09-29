package app

import (
	"fmt"
	"sort"
	"strings"
)

type RequirementOutcome struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	Source           string `json:"source,omitempty"`
	Target           string `json:"target"`
	Technique        string `json:"technique,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	ExpectedIdentity string `json:"expected_identity,omitempty"`
	UserContextOnly  bool   `json:"user_context_only,omitempty"`
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	Evidence         []Fact `json:"evidence,omitempty"`
}

type AttackPathStep struct {
	PlanID                 string   `json:"plan_id"`
	CatalogID              string   `json:"catalog_id"`
	Name                   string   `json:"name"`
	Targets                []string `json:"targets"`
	SourceAssetID          string   `json:"source_asset_id,omitempty"`
	DestinationAssetID     string   `json:"destination_asset_id,omitempty"`
	Protocol               string   `json:"protocol,omitempty"`
	RequirementIDs         []string `json:"requirement_ids"`
	Status                 string   `json:"status"`
	ExecutionID            string   `json:"execution_id,omitempty"`
	EvidenceInterpretation string   `json:"evidence_interpretation"`
}

type MissionReport struct {
	MissionID       string               `json:"mission_id"`
	Request         string               `json:"request"`
	Status          string               `json:"status"`
	BlockingReason  string               `json:"blocking_reason,omitempty"`
	WorkflowStage   string               `json:"workflow_stage,omitempty"`
	WorkflowVersion int                  `json:"workflow_version,omitempty"`
	WorkflowTrace   []WorkflowTransition `json:"workflow_trace,omitempty"`
	Requirements    []RequirementOutcome `json:"requirements"`
	StartingAccess  []StartingAccess     `json:"starting_access,omitempty"`
	AttackPath      []AttackPathStep     `json:"attack_path"`
	Conclusions     []string             `json:"conclusions"`
	ADGraph         ADGraph              `json:"ad_graph,omitempty"`
	SelectedRoute   *GoalDirectedRoute   `json:"selected_route,omitempty"`
	HopProofs       []LateralHopProof    `json:"hop_proofs,omitempty"`
}

func evidenceInterpretation(item ValidatedItem) string {
	if item.Status == "unknown" {
		return "Submission outcome is uncertain and requires reconciliation; no retry was issued."
	}
	if item.Status == "aborted" || item.Status == "failed" || item.Status == "skipped" {
		return "The simulation did not complete. Successful intermediate steps remain recorded separately."
	}
	if item.Status != "completed" {
		return "Execution evidence is still being collected."
	}
	success, _ := reportHasSuccessfulStep(item.Report)
	detected, _ := reportHasDetection(item.Report)
	prevented, _ := reportWasPrevented(item.Report)
	parts := []string{}
	if success {
		parts = append(parts, "at least one simulated action succeeded")
	} else {
		parts = append(parts, "no successful action was explicitly reported")
	}
	for _, observed := range fourCoreRemoteObservations(item) {
		parts = append(parts, fmt.Sprintf("FourCore reported remote execution %s -> %s over %s as %s", observed.Source, observed.Destination, observed.Protocol, observed.Identity))
	}
	if prevented {
		parts = append(parts, "prevention was explicitly observed")
	}
	if detected {
		parts = append(parts, "detection was explicitly observed")
	} else {
		parts = append(parts, "no detection evidence was present in the stored correlation snapshot")
	}
	return strings.Join(parts, "; ") + "."
}

func (s *Service) MissionReport(id string) (MissionReport, error) {
	m, err := s.missionByID(id)
	if err != nil {
		return MissionReport{}, err
	}
	report := MissionReport{MissionID: m.ID, Request: m.Request, Status: m.Status, BlockingReason: m.BlockingReason, WorkflowStage: m.WorkflowStage, WorkflowVersion: m.WorkflowVersion, WorkflowTrace: append([]WorkflowTransition(nil), m.WorkflowTrace...), StartingAccess: append([]StartingAccess(nil), m.StartingAccess...), ADGraph: m.ADGraph, SelectedRoute: m.SelectedRoute, HopProofs: append([]LateralHopProof(nil), m.HopProofs...)}
	for _, requirement := range m.Requirements {
		outcome := RequirementOutcome{ID: requirement.ID, Type: requirement.Type, Source: requirement.Source, Target: requirement.Target, Technique: requirement.Technique, Protocol: requirement.Protocol, ExpectedIdentity: requirement.ExpectedIdentity, UserContextOnly: requirement.UserContextOnly, Status: requirement.Status, Reason: requirement.Reason}
		for _, fact := range m.Facts {
			if fact.Type == "requirement_evidence" && fact.Subject == requirement.ID {
				outcome.Evidence = append(outcome.Evidence, fact)
			}
		}
		report.Requirements = append(report.Requirements, outcome)
	}
	plans, err := s.Store.Plans()
	if err != nil {
		return MissionReport{}, err
	}
	for _, plan := range plans {
		if plan.MissionID != id {
			continue
		}
		for _, item := range plan.Items {
			targets := append([]string(nil), item.AssetIDs...)
			targets = append(targets, item.EmailAssetIDs...)
			report.AttackPath = append(report.AttackPath, AttackPathStep{PlanID: plan.ID, CatalogID: item.CatalogID, Name: item.Name, Targets: targets, SourceAssetID: item.SourceAssetID, DestinationAssetID: item.DestinationAssetID, Protocol: item.Protocol, RequirementIDs: item.RequirementIDs, Status: item.Status, ExecutionID: item.ExecutionID, EvidenceInterpretation: evidenceInterpretation(item)})
		}
	}
	for _, requirement := range report.Requirements {
		subject := requirement.Target
		if requirement.Source != "" {
			subject = requirement.Source + " -> " + requirement.Target
		}
		switch requirement.Status {
		case "proven":
			report.Conclusions = append(report.Conclusions, fmt.Sprintf("%s on %s was proven by explicit stored evidence.", requirement.Type, subject))
		case "disproven":
			report.Conclusions = append(report.Conclusions, fmt.Sprintf("%s on %s was not achieved by the attempted simulation.", requirement.Type, subject))
		default:
			report.Conclusions = append(report.Conclusions, fmt.Sprintf("%s on %s remains unknown; it must not be inferred from adjacent successful steps.", requirement.Type, subject))
		}
	}
	if m.Status == "unattainable" {
		for _, requirement := range report.Requirements {
			if requirement.Type == "remote_access_proven" && requirement.Status != "proven" {
				report.Conclusions = append(report.Conclusions, fmt.Sprintf("Objective impossible with the currently permitted catalogue actions and allowlisted assets: no evidence-backed route to %s was completed. This is not proof that no network path exists.", requirement.Target))
			}
		}
	}
	sort.Strings(report.Conclusions)
	return report, nil
}

func formatMissionPlanResult(result MissionPlanResult) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Mission `%s` was created with status `%s`.\n\n", result.Mission.ID, result.Mission.Status)
	if result.Plan != nil && result.Mission.Status == "awaiting_authorization" {
		fmt.Fprintf(&out, "Reviewed plan `%s` is ready for authorization. It has not been executed.\n", result.Plan.ID)
		for index, item := range result.Plan.Items {
			fmt.Fprintf(&out, "\n%d. %s (`%s`) on `%s`\n   %s", index+1, item.Name, item.CatalogID, itemTarget(item), item.Reason)
			if item.SourceAssetID != "" && item.DestinationAssetID != "" {
				fmt.Fprintf(&out, "\n   Context: `%s` -> `%s`", item.SourceAssetID, item.DestinationAssetID)
				if item.Protocol != "" {
					fmt.Fprintf(&out, " over `%s`", item.Protocol)
				}
			}
		}
	}
	if result.Message != "" {
		fmt.Fprintf(&out, "\n\n%s", result.Message)
	}
	unknownProof := []string{}
	for _, requirement := range result.Mission.Requirements {
		if proofOnlyRequirement(requirement.Type) && requirement.Status != "proven" {
			unknownProof = append(unknownProof, requirement.ID+" ("+requirement.Type+")")
		}
	}
	if len(unknownProof) > 0 {
		fmt.Fprintf(&out, "\n\nThe following outcomes still require an explicit destination-specific successful provider report step or signed destination evidence and will not be inferred from simulation success: %s.", strings.Join(unknownProof, ", "))
	}
	return strings.TrimSpace(out.String())
}
