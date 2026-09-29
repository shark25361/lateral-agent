package app

import (
	"context"
	"encoding/json"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"time"
)

// MissionInput is the structured form produced by the conversational agent.
// Execution sources are FourCore asset IDs. A catalogue-only remote destination
// is an exact operator-supplied ID used for report matching, not a run input.
type MissionInput struct {
	Request        string           `json:"request"`
	Requirements   []Requirement    `json:"requirements"`
	StartingAccess []StartingAccess `json:"starting_access,omitempty"`
}

// StartingAccess is an operator assumption used to constrain planning. It is
// never inserted into Facts or treated as observed AD/remote-access evidence.
type StartingAccess struct {
	AssetID     string `json:"asset_id"`
	AccessLevel string `json:"access_level"` // user or administrator
	Identity    string `json:"identity,omitempty"`
}

type MissionPlanInput struct {
	RunElevatedRequirementIDs []string                  `json:"run_elevated_requirement_ids,omitempty"`
	RetryCatalogIDs           []string                  `json:"retry_catalog_ids,omitempty"`
	Lateral                   *LateralPlanConfiguration `json:"lateral,omitempty"`
}

type LateralPlanConfiguration struct {
	DestinationAssetID  string `json:"destination_asset_id"`
	Protocol            string `json:"protocol,omitempty"`
	CredentialReference string `json:"credential_reference,omitempty"`
	ExpectedIdentity    string `json:"expected_identity,omitempty"`
}

type LateralMissionConfiguration struct {
	DestinationAssetID string `json:"destination_asset_id"`
	DestinationHost    string `json:"destination_host"`
	Protocol           string `json:"protocol"`
	Port               int    `json:"port"`
	CredentialRefHash  string `json:"credential_reference_hash"`
	ExpectedIdentity   string `json:"expected_identity,omitempty"`
}

type Requirement struct {
	ID               string `json:"id,omitempty"`
	Type             string `json:"type"`
	Source           string `json:"source,omitempty"`
	Target           string `json:"target"`
	TargetKind       string `json:"target_kind,omitempty"`
	Technique        string `json:"technique,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	ExpectedIdentity string `json:"expected_identity,omitempty"`
	UserContextOnly  bool   `json:"user_context_only,omitempty"`
	RunElevated      bool   `json:"run_elevated,omitempty"`
	Mandatory        bool   `json:"mandatory,omitempty"`
	Status           string `json:"status,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

type Fact struct {
	Type        string    `json:"type"`
	Subject     string    `json:"subject,omitempty"`
	Object      string    `json:"object,omitempty"`
	Value       string    `json:"value,omitempty"`
	Status      string    `json:"status"` // proven, disproven, unknown
	ExecutionID string    `json:"execution_id,omitempty"`
	StepID      string    `json:"step_id,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	ObservedAt  time.Time `json:"observed_at"`
}

type MissionAttempt struct {
	PlanID       string    `json:"plan_id"`
	CatalogID    string    `json:"catalog_id"`
	Target       string    `json:"target,omitempty"`
	Status       string    `json:"status"`
	ExecutionIDs []string  `json:"execution_ids,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// WorkflowTransition is the durable audit trail of the ADK mission graph.
// The graph runner itself is intentionally short lived; these records are the
// checkpoint that lets a later worker tick resume after authorization,
// execution polling, or operator reconciliation.
type WorkflowTransition struct {
	Node   string    `json:"node"`
	Route  string    `json:"route"`
	Detail string    `json:"detail,omitempty"`
	PlanID string    `json:"plan_id,omitempty"`
	At     time.Time `json:"at"`
}

type Mission struct {
	ID                 string                       `json:"id"`
	SessionID          string                       `json:"session_id"`
	Request            string                       `json:"request"`
	Requirements       []Requirement                `json:"requirements"`
	StartingAccess     []StartingAccess             `json:"starting_access,omitempty"`
	InitialUserContext bool                         `json:"initial_user_context,omitempty"`
	Facts              []Fact                       `json:"facts,omitempty"`
	Attempts           []MissionAttempt             `json:"attempts,omitempty"`
	CurrentPlanID      string                       `json:"current_plan_id,omitempty"`
	Status             string                       `json:"status"`
	BlockingReason     string                       `json:"blocking_reason,omitempty"`
	Iteration          int                          `json:"iteration"`
	WorkflowStage      string                       `json:"workflow_stage,omitempty"`
	WorkflowTrace      []WorkflowTransition         `json:"workflow_trace,omitempty"`
	ADGraph            ADGraph                      `json:"ad_graph,omitempty"`
	SelectedRoute      *GoalDirectedRoute           `json:"selected_route,omitempty"`
	HopProofs          []LateralHopProof            `json:"hop_proofs,omitempty"`
	Lateral            *LateralMissionConfiguration `json:"lateral,omitempty"`
	WorkflowVersion    int                          `json:"workflow_version,omitempty"`
	Created            time.Time                    `json:"created_at"`
	Updated            time.Time                    `json:"updated_at"`
}

type LateralHopProof struct {
	SourceAssetID      string    `json:"source_asset_id"`
	DestinationAssetID string    `json:"destination_asset_id"`
	Protocol           string    `json:"protocol"`
	ExecutionID        string    `json:"execution_id"`
	InputHash          string    `json:"input_hash"`
	EvidenceDigest     string    `json:"evidence_digest"`
	Identity           string    `json:"identity"`
	Integrity          string    `json:"integrity"`
	ObservedAt         time.Time `json:"observed_at"`
}

func provenHop(m Mission, hop MachineHop) bool {
	for _, proof := range m.HopProofs {
		if proof.SourceAssetID == hop.SourceAssetID && proof.DestinationAssetID == hop.DestinationAssetID && strings.EqualFold(proof.Protocol, hop.Protocol) && proof.ExecutionID != "" {
			return true
		}
	}
	return false
}

type MissionPlanResult struct {
	Mission Mission `json:"mission"`
	Plan    *Plan   `json:"plan,omitempty"`
	Message string  `json:"message"`
}

type missionAction struct {
	Kind        string
	Catalog     Catalog
	Contract    ActionContract
	ReqMask     uint64
	PreMask     uint64
	ReqIDs      []string
	PreReqIDs   []string
	Target      string
	Source      string
	Destination string
	Protocol    string
	Elevated    bool
}

func normalizeRequirementType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch t {
	case "behavior", "behavior_executed", "technique_executed":
		return "behavior_executed"
	case "credential", "credential_access", "credential_access_validated":
		return "credential_access_validated"
	case "lateral_movement", "lateral_movement_validated":
		return "lateral_movement_validated"
	case "remote_access", "remote_access_proven":
		return "remote_access_proven"
	case "detection", "detection_observed", "detection_validated":
		return "detection_observed"
	case "prevention", "behavior_prevented", "prevention_observed":
		return "behavior_prevented"
	case "domain", "domain_context", "domain_context_observed":
		return "domain_context_observed"
	case "identity", "identity_observed", "administrator_identity_observed":
		return "identity_observed"
	case "elevated_context", "elevated_context_proven":
		return "elevated_context_proven"
	case "service_reachable", "reachability":
		return "service_reachable"
	default:
		return t
	}
}

func requirementSemanticKey(r Requirement) string {
	targetKind := r.TargetKind
	if targetKind == "" {
		targetKind = "endpoint_chain"
	}
	return strings.Join([]string{
		normalizeRequirementType(r.Type), r.Source, r.Target,
		targetKind, strings.ToLower(r.Protocol), strings.ToUpper(r.Technique), strings.ToLower(r.ExpectedIdentity),
	}, "\x00")
}

func mergeMissionRequirements(input []Requirement) []Requirement {
	out := make([]Requirement, 0, len(input))
	positions := map[string]int{}
	for _, requirement := range input {
		requirement.Type = normalizeRequirementType(requirement.Type)
		key := requirementSemanticKey(requirement)
		if position, exists := positions[key]; exists {
			existing := &out[position]
			existing.UserContextOnly = existing.UserContextOnly || requirement.UserContextOnly
			existing.RunElevated = existing.RunElevated || requirement.RunElevated
			existing.Mandatory = existing.Mandatory || requirement.Mandatory
			if existing.ID == "" {
				existing.ID = requirement.ID
			}
			continue
		}
		positions[key] = len(out)
		out = append(out, requirement)
	}
	return out
}

func expandMissionRequirements(input []Requirement) []Requirement {
	out := append([]Requirement(nil), input...)
	seen := map[string]bool{}
	for i := range out {
		out[i].Type = normalizeRequirementType(out[i].Type)
		seen[requirementSemanticKey(out[i])] = true
	}
	appendRequirement := func(r Requirement) {
		r.Type = normalizeRequirementType(r.Type)
		key := requirementSemanticKey(r)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, r)
	}
	original := append([]Requirement(nil), out...)
	for _, r := range original {
		switch r.Type {
		case "remote_access_proven":
			// A remote objective is fulfilled by an explicit remote result, not by
			// completing a fixed checklist of source-side simulations. Add only
			// the separately requested destination identity predicate.
			if r.ExpectedIdentity != "" {
				appendRequirement(Requirement{Type: "identity_observed", Source: r.Source, Target: r.Target, TargetKind: "endpoint_chain", Protocol: r.Protocol, ExpectedIdentity: r.ExpectedIdentity, Mandatory: true})
			}
		case "lateral_movement_validated":
			executionTarget := r.Source
			if executionTarget == "" {
				executionTarget = r.Target
			}
			// A source-only lateral-chain validation is a simulation objective,
			// not a claim that a route to a second asset exists. Do not require
			// AD or credential discovery merely to run that source-side chain.
			if r.Source != "" && r.Target != "" && r.Source != r.Target {
				appendRequirement(Requirement{Type: "credential_access_validated", Target: executionTarget, TargetKind: "endpoint_chain", Mandatory: true})
				appendRequirement(Requirement{Type: "domain_context_observed", Target: executionTarget, TargetKind: "endpoint_chain", UserContextOnly: r.UserContextOnly, Mandatory: true})
			}
		}
	}
	return out
}

func normalizeMissionInput(in MissionInput, session string) (Mission, error) {
	if strings.TrimSpace(in.Request) == "" {
		return Mission{}, fmt.Errorf("request is required")
	}
	if len(in.Requirements) == 0 || len(in.Requirements) > 32 {
		return Mission{}, fmt.Errorf("mission requires 1-32 requirements")
	}
	if len(in.StartingAccess) > 1 {
		return Mission{}, fmt.Errorf("mission accepts one starting-access assumption for its initial machine")
	}
	startingAssets := map[string]bool{}
	for index := range in.StartingAccess {
		access := &in.StartingAccess[index]
		access.AssetID = strings.TrimSpace(access.AssetID)
		access.AccessLevel = strings.ToLower(strings.TrimSpace(access.AccessLevel))
		access.Identity = strings.TrimSpace(access.Identity)
		if validID(access.AssetID) != nil || (access.AccessLevel != "user" && access.AccessLevel != "administrator") || len(access.Identity) > 128 || strings.ContainsAny(access.Identity, "\r\n\x00") {
			return Mission{}, fmt.Errorf("starting_access requires an asset ID, user or administrator access level, and an optional short identity label")
		}
		if startingAssets[access.AssetID] {
			return Mission{}, fmt.Errorf("duplicate starting-access asset %s", access.AssetID)
		}
		startingAssets[access.AssetID] = true
		mentioned := false
		for _, requirement := range in.Requirements {
			mentioned = mentioned || requirement.Source == access.AssetID || requirement.Target == access.AssetID
		}
		if !mentioned {
			return Mission{}, fmt.Errorf("starting-access asset %s is not in the mission requirements", access.AssetID)
		}
		if access.AccessLevel == "user" {
			for requirementIndex := range in.Requirements {
				requirement := &in.Requirements[requirementIndex]
				if requirement.Source == access.AssetID && normalizeRequirementType(requirement.Type) == "remote_access_proven" ||
					requirement.Target == access.AssetID && (normalizeRequirementType(requirement.Type) == "domain_context_observed" || normalizeRequirementType(requirement.Type) == "elevated_context_proven") {
					requirement.UserContextOnly = true
				}
			}
		}
	}
	in.Requirements = mergeMissionRequirements(expandMissionRequirements(in.Requirements))
	initialUserContext := false
	for _, access := range in.StartingAccess {
		initialUserContext = initialUserContext || access.AccessLevel == "user"
	}
	for _, requirement := range in.Requirements {
		initialUserContext = initialUserContext || requirement.UserContextOnly
	}
	reserved := map[string]bool{}
	for _, requirement := range in.Requirements {
		if requirement.ID != "" {
			reserved[requirement.ID] = true
		}
	}
	seen := map[string]bool{}
	nextID := 1
	for i := range in.Requirements {
		r := &in.Requirements[i]
		if r.ID == "" {
			for seen[fmt.Sprintf("R%d", nextID)] || reserved[fmt.Sprintf("R%d", nextID)] {
				nextID++
			}
			r.ID = fmt.Sprintf("R%d", nextID)
			nextID++
		}
		if seen[r.ID] {
			return Mission{}, fmt.Errorf("duplicate requirement ID %q", r.ID)
		}
		seen[r.ID] = true
		r.Type = normalizeRequirementType(r.Type)
		if r.Type == "" {
			return Mission{}, fmt.Errorf("requirement %s has no type", r.ID)
		}
		if !supportedRequirementType(r.Type) {
			return Mission{}, fmt.Errorf("requirement %s has unsupported type %q", r.ID, r.Type)
		}
		// Requirement state is evidence-derived. Never accept a caller-provided
		// proven/disproven value at mission creation time.
		r.Status = "unknown"
		if !r.Mandatory {
			// The MVP treats every stated requirement as mandatory. Keep the field
			// in the wire format so optional requirements can be added deliberately.
			r.Mandatory = true
		}
		if r.Type != "remote_access_proven" && r.Type != "service_reachable" && strings.TrimSpace(r.Target) == "" {
			return Mission{}, fmt.Errorf("requirement %s needs a target asset ID", r.ID)
		}
		if r.Type == "remote_access_proven" || r.Type == "service_reachable" {
			if strings.TrimSpace(r.Source) == "" || strings.TrimSpace(r.Target) == "" {
				return Mission{}, fmt.Errorf("requirement %s needs source and target asset IDs", r.ID)
			}
		}
	}
	return Mission{ID: newID(), SessionID: session, Request: strings.TrimSpace(in.Request), Requirements: in.Requirements, StartingAccess: in.StartingAccess, InitialUserContext: initialUserContext, Status: "planning", WorkflowStage: "validate_mission", WorkflowVersion: 2, Created: time.Now().UTC(), Updated: time.Now().UTC()}, nil
}

func supportedRequirementType(t string) bool {
	switch t {
	case "behavior_executed", "credential_access_validated", "lateral_movement_validated", "remote_access_proven", "detection_observed", "behavior_prevented", "domain_context_observed", "identity_observed", "elevated_context_proven", "service_reachable":
		return true
	default:
		return false
	}
}

func (s *Service) CreateMission(_ context.Context, session string, in MissionInput) (Mission, error) {
	m, err := normalizeMissionInput(in, session)
	if err != nil {
		return Mission{}, err
	}
	if err = s.Store.Put("missions", m.ID, m); err != nil {
		return Mission{}, err
	}
	return m, nil
}

func (s *Service) missionByID(id string) (Mission, error) {
	var m Mission
	if err := s.Store.Get("missions", id, &m); err != nil {
		return Mission{}, err
	}
	return m, nil
}

func (s *Service) PlanMission(ctx context.Context, id string) (MissionPlanResult, error) {
	s.missionMu.Lock()
	defer s.missionMu.Unlock()
	return s.runMissionWorkflow(ctx, missionWorkflowInput{Mode: "advance", MissionID: id}, nil)
}

func (s *Service) ConfigureAndPlanMission(ctx context.Context, id string, input MissionPlanInput) (MissionPlanResult, error) {
	s.missionMu.Lock()
	defer s.missionMu.Unlock()
	if err := s.ConfigureMissionPlan(id, input); err != nil {
		return MissionPlanResult{}, err
	}
	return s.runMissionWorkflow(ctx, missionWorkflowInput{Mode: "advance", MissionID: id}, nil)
}

func (s *Service) ConfigureMissionPlan(id string, input MissionPlanInput) error {
	if len(input.RunElevatedRequirementIDs) == 0 && len(input.RetryCatalogIDs) == 0 && input.Lateral == nil {
		return nil
	}
	wanted := map[string]bool{}
	for _, requirementID := range input.RunElevatedRequirementIDs {
		requirementID = strings.TrimSpace(requirementID)
		if requirementID == "" {
			return fmt.Errorf("run_elevated requirement ID cannot be empty")
		}
		wanted[requirementID] = true
	}
	return s.Store.UpdateMission(id, func(mission *Mission) error {
		matched := map[string]bool{}
		routeSource, routeDestination := "", ""
		for index := range mission.Requirements {
			requirement := &mission.Requirements[index]
			if !wanted[requirement.ID] {
				continue
			}
			if proofOnlyRequirement(requirement.Type) || requirement.Status == "proven" {
				return fmt.Errorf("requirement %s cannot request elevated execution", requirement.ID)
			}
			requirement.RunElevated = true
			if requirement.Type == "lateral_movement_validated" {
				routeSource, routeDestination = requirement.Source, requirement.Target
			}
			matched[requirement.ID] = true
		}
		for requirementID := range wanted {
			if !matched[requirementID] {
				return fmt.Errorf("mission requirement %s was not found", requirementID)
			}
		}
		if len(input.RetryCatalogIDs) > 0 {
			retry := map[string]bool{}
			for _, catalogID := range input.RetryCatalogIDs {
				catalogID = strings.TrimSpace(catalogID)
				if validID(catalogID) != nil {
					return fmt.Errorf("invalid retry catalogue ID")
				}
				retry[catalogID] = true
			}
			found := map[string]bool{}
			kept := mission.Attempts[:0]
			for _, attempt := range mission.Attempts {
				if retry[attempt.CatalogID] && (attempt.Status == "failed" || attempt.Status == "aborted" || attempt.Status == "cancelled") {
					found[attempt.CatalogID] = true
					continue
				}
				kept = append(kept, attempt)
			}
			for catalogID := range retry {
				if !found[catalogID] {
					return fmt.Errorf("catalogue %s has no failed mission attempt to retry", catalogID)
				}
			}
			mission.Attempts = kept
		}
		if routeSource != "" && routeDestination != "" {
			for index := range mission.Requirements {
				requirement := &mission.Requirements[index]
				if requirement.Status != "proven" && requirement.Source == routeSource && requirement.Target == routeDestination {
					requirement.Protocol = ""
				}
			}
		}
		if input.Lateral != nil {
			configuration := input.Lateral
			if !s.Config.LateralEnabled || s.Lateral == nil {
				return fmt.Errorf("controlled-lab lateral executor is disabled")
			}
			var routeRequirement *Requirement
			for index := range mission.Requirements {
				requirement := &mission.Requirements[index]
				if requirement.Type == "remote_access_proven" && (configuration.DestinationAssetID == "" || requirement.Target == configuration.DestinationAssetID) {
					routeRequirement = requirement
					break
				}
			}
			if routeRequirement == nil {
				return fmt.Errorf("mission has no matching remote-access objective")
			}
			destinationHost := s.Config.LateralDestinations[routeRequirement.Target]
			if destinationHost == "" {
				return fmt.Errorf("destination asset %s has no allowlisted lateral binding", routeRequirement.Target)
			}
			protocol := strings.ToLower(strings.TrimSpace(configuration.Protocol))
			if protocol == "" {
				protocol = strings.ToLower(strings.TrimSpace(routeRequirement.Protocol))
			}
			if !validLateralProtocol(protocol) {
				return fmt.Errorf("lateral protocol must be smb, winrm, rdp, or ssh")
			}
			credentialHash := s.Config.LateralDefaultCredentialRef
			if configuration.CredentialReference != "" {
				credentialHash = credentialReferenceHash(configuration.CredentialReference)
			}
			if s.Config.LateralCredentialRefs[credentialHash] == "" {
				return fmt.Errorf("credential reference is not configured")
			}
			expectedIdentity := strings.TrimSpace(configuration.ExpectedIdentity)
			if expectedIdentity == "" {
				expectedIdentity = routeRequirement.ExpectedIdentity
			}
			mission.Lateral = &LateralMissionConfiguration{DestinationAssetID: routeRequirement.Target, DestinationHost: destinationHost, Protocol: protocol, Port: protocolPort(protocol), CredentialRefHash: credentialHash, ExpectedIdentity: expectedIdentity}
			for index := range mission.Requirements {
				requirement := &mission.Requirements[index]
				if requirement.Source == routeRequirement.Source && requirement.Target == routeRequirement.Target && requirement.Protocol == "" {
					requirement.Protocol = protocol
				}
			}
		}
		mission.Status = "planning"
		mission.BlockingReason = ""
		mission.CurrentPlanID = ""
		mission.WorkflowStage = "read_live_asset_inventory"
		return nil
	})
}

type missionPlanningDecision struct {
	Route    string
	Selected []missionAction
	Reason   string
	Actions  int
}

func (s *Service) missionPlanningDecision(ctx context.Context, m Mission) (missionPlanningDecision, error) {
	if blocker := missionAssetBlocker(m, s.Config.LabAssets, s.Config.LateralEnabled); blocker != "" {
		return missionPlanningDecision{Route: "blocked", Reason: blocker}, nil
	}
	if allMandatorySatisfied(m) {
		return missionPlanningDecision{Route: "satisfied", Reason: "all mandatory requirements are proven"}, nil
	}
	proofPending, actionablePending := false, false
	for _, requirement := range m.Requirements {
		if !requirement.Mandatory || requirement.Status == "proven" {
			continue
		}
		if proofOnlyRequirement(requirement.Type) {
			proofPending = true
		} else {
			actionablePending = true
		}
	}
	actions, err := s.candidateActions(ctx, m)
	if err != nil {
		return missionPlanningDecision{}, err
	}
	for _, action := range actions {
		if action.Kind != "lab_lateral" || len(action.ReqIDs) != 0 {
			continue
		}
		ready := true
		for _, id := range action.PreReqIDs {
			for _, requirement := range m.Requirements {
				if requirement.ID == id && requirement.Status != "proven" {
					ready = false
				}
			}
		}
		if ready {
			return missionPlanningDecision{Route: "full", Selected: []missionAction{action}, Reason: "execute and verify the next machine hop before replanning", Actions: len(actions)}, nil
		}
	}
	selected, reason := chooseActions(m, actions, s.Config.MaxItems)
	if len(selected) == 0 {
		if proofPending && !actionablePending {
			if len(actions) == 0 {
				return missionPlanningDecision{Route: "proof_blocked", Reason: "objective impossible with the currently permitted catalogue actions and allowlisted source assets: no untried action remains that can establish destination-specific proof; this does not establish that the network path is impossible", Actions: 0}, nil
			}
			return missionPlanningDecision{Route: "proof_blocked", Reason: unresolvedProofReason(m), Actions: len(actions)}, nil
		}
		return missionPlanningDecision{Route: "unavailable", Reason: reason, Actions: len(actions)}, nil
	}
	route := "full"
	if reason != "" || len(selected) > 1 {
		route = "discovery"
		if reason == "" {
			reason = fmt.Sprintf("staged path contains %d actions; execute one prerequisite action and reevaluate evidence before selecting the next", len(selected))
		}
	}
	return missionPlanningDecision{Route: route, Selected: selected, Reason: reason, Actions: len(actions)}, nil
}

func (s *Service) createMissionPlan(ctx context.Context, m Mission, selected []missionAction, reason, planKind string) (MissionPlanResult, error) {
	selectedProtocol := ""
	for _, action := range selected {
		if contractProduces(action.Contract, "lateral_movement_validated") && action.Protocol != "" {
			selectedProtocol = action.Protocol
			break
		}
	}
	if selectedProtocol != "" {
		if err := s.pinMissionProtocol(m.ID, selectedProtocol); err != nil {
			return MissionPlanResult{}, err
		}
		m, _ = s.missionByID(m.ID)
	}
	in := PlanInput{Objective: m.Request, MissionID: m.ID}
	for _, a := range selected {
		contract := a.Contract
		item := PlanItem{Kind: a.Kind, CatalogID: a.Catalog.ID, RequirementIDs: a.ReqIDs, SourceAssetID: a.Source, DestinationAssetID: a.Destination, Protocol: a.Protocol, Contract: &contract, Reason: actionReason(a), RunElevated: a.Elevated, DisableCleanup: false}
		if a.Kind == "lab_lateral" {
			route := goalDirectedADRoute(m, a.Source, a.Destination, a.Protocol)
			configuration := s.lateralConfiguration(m, a.Source, a.Destination, a.Protocol)
			schema := lateralInputSchema()
			item.Executor = "controlled_lab"
			item.InputSchema = &schema
			item.LateralInput = &LateralActionInput{DestinationHost: configuration.DestinationHost, Protocol: configuration.Protocol, Port: configuration.Port, CredentialRefHash: configuration.CredentialRefHash, ExpectedIdentity: configuration.ExpectedIdentity, CorrelationID: newID(), RouteNodeIDs: route.NodeIDs, RouteEdgeIDs: route.EdgeIDs}
			item.AssetIDs = []string{a.Source, a.Destination}
			in.Items = append(in.Items, item)
			continue
		}
		if a.Kind == "email_chain" {
			item.EmailAssetIDs = []string{a.Target}
		} else {
			item.AssetIDs = []string{a.Target}
		}
		in.Items = append(in.Items, item)
	}
	// The candidate graph was built from the complete persisted catalogue.
	// Create the reviewable plan from that same immutable snapshot. The exact
	// entry is re-fetched live by Authorize and again before submission, so a
	// changed or removed entry still cannot execute.
	p, err := s.proposeMission(ctx, m.SessionID, in)
	if err != nil {
		_ = s.Store.UpdateMission(m.ID, func(m *Mission) error {
			if transientInventoryBlocker(err.Error()) {
				m.Status = "planning"
				m.BlockingReason = ""
				return nil
			}
			m.Status = "blocked"
			m.BlockingReason = err.Error()
			return nil
		})
		return MissionPlanResult{}, err
	}
	if err = s.Store.UpdateMission(m.ID, func(m *Mission) error {
		for _, action := range selected {
			if action.Kind != "lab_lateral" || m.SelectedRoute != nil {
				continue
			}
			for _, objective := range m.Requirements {
				if objective.Type == "remote_access_proven" && objective.Status != "proven" {
					route := goalDirectedADRoute(*m, objective.Source, objective.Target, action.Protocol)
					if route.Ready {
						m.SelectedRoute = &route
					}
					break
				}
			}
		}
		m.CurrentPlanID = p.ID
		m.Status = "awaiting_authorization"
		m.Iteration++
		m.BlockingReason = ""
		m.WorkflowStage = "user_authorizes_exact_plan_hash"
		return nil
	}); err != nil {
		return MissionPlanResult{}, err
	}
	m, _ = s.missionByID(m.ID)
	message := planKind + " plan created; operator authorization is required"
	if reason != "" {
		message += "; " + reason
	}
	return MissionPlanResult{Mission: m, Plan: &p, Message: message}, nil
}

func (s *Service) pinMissionProtocol(missionID, protocol string) error {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return nil
	}
	return s.Store.UpdateMission(missionID, func(stored *Mission) error {
		for index := range stored.Requirements {
			requirement := &stored.Requirements[index]
			if requirement.Source == "" || requirement.Target == "" || requirement.Protocol != "" {
				continue
			}
			switch requirement.Type {
			case "lateral_movement_validated", "remote_access_proven", "identity_observed", "service_reachable":
				requirement.Protocol = protocol
			}
		}
		return nil
	})
}

func actionReason(a missionAction) string {
	if len(a.ReqIDs) == 0 {
		return "Selected by the deterministic mission planner"
	}
	reason := "Satisfies requirements: " + strings.Join(a.ReqIDs, ", ")
	if len(a.PreReqIDs) > 0 {
		reason += "; requires prior evidence from: " + strings.Join(a.PreReqIDs, ", ")
	}
	return reason
}

func (s *Service) candidateActions(ctx context.Context, m Mission) ([]missionAction, error) {
	tried := map[string]bool{}
	for _, a := range m.Attempts {
		if a.Target == "" {
			tried[a.CatalogID] = true
		} else {
			tried[actionKey(a.CatalogID, a.Target)] = true
		}
	}
	targetKinds := map[string]string{}
	frontier := map[string]Requirement{}
	for _, r := range m.Requirements {
		if r.Status == "proven" || (proofOnlyRequirement(r.Type) && r.Type != "service_reachable" && r.Type != "remote_access_proven" && r.Type != "identity_observed") {
			continue
		}
		kind := r.TargetKind
		if kind == "" {
			kind = "endpoint_chain"
		}
		if kind != "endpoint_chain" && kind != "email_chain" {
			return nil, fmt.Errorf("requirement %s has unsupported target kind %q", r.ID, kind)
		}
		targetKinds[actionKey(kind, requirementExecutionTarget(r))] = kind
		if !s.Config.LateralEnabled && r.Type == "remote_access_proven" && r.Source != "" && r.Target != "" {
			for _, reached := range observedRemoteFrontier(m.ADGraph, r.Source, "") {
				if reached == r.Target || !s.Config.AllowedEndpoint[reached] || validID(reached) != nil {
					continue
				}
				asset, err := s.FC.Asset(ctx, "endpoint", reached)
				if err != nil {
					return nil, err
				}
				if asset.ID != reached || asset.Disabled || !asset.Available || !asset.Connected || !strings.EqualFold(platform(asset.Platform), "windows") {
					continue
				}
				targetKinds[actionKey("endpoint_chain", reached)] = "endpoint_chain"
				frontier[reached] = r
			}
		}
	}
	byID := map[string]missionAction{}
	for targetKey, kind := range targetKinds {
		target := strings.SplitN(targetKey, "\x00", 2)[1]
		var catalogue []Catalog
		var err error
		if len(s.Config.LabAssets) > 0 {
			catalogue, err = s.FC.localCatalogItems(kind)
		} else {
			catalogue, err = s.FC.allCatalog(ctx, kind)
		}
		if err != nil {
			return nil, err
		}
		source, destination, protocol := missionContext(m, target)
		if objective, ok := frontier[target]; ok {
			source, destination, protocol = target, objective.Target, strings.ToLower(objective.Protocol)
		}
		for _, c := range catalogue {
			// Some tenants contain historical catalogue IDs with spaces or other
			// characters that cannot be addressed safely through the run API.
			// Ignore them here so one unusable entry cannot block the whole mission.
			if c.Deprecated || validID(c.ID) != nil || tried[c.ID] || tried[actionKey(c.ID, target)] {
				continue
			}
			// Endpoint missions currently require a Windows asset. Filter on the
			// persisted catalogue metadata before graph search so a shorter macOS
			// or Linux chain cannot win and then fail during plan validation.
			if kind == "endpoint_chain" && !compatible(c, Asset{Platform: "windows"}) {
				continue
			}
			contract := actionContractFor(c, kind, target, source, destination, protocol)
			a := missionAction{Kind: kind, Catalog: c, Contract: contract, Target: target, Source: source, Destination: destination, Protocol: contract.Protocol, Elevated: c.Elevated}
			for _, r := range m.Requirements {
				frontierObjective, isFrontier := frontier[target]
				frontierRequirement := isFrontier && r.Source == frontierObjective.Source && r.Target == frontierObjective.Target &&
					(r.Type == "remote_access_proven" || r.Type == "identity_observed")
				if r.Status == "proven" || (proofOnlyRequirement(r.Type) && r.Type != "remote_access_proven" && r.Type != "identity_observed") ||
					(requirementExecutionTarget(r) != target && !frontierRequirement) {
					continue
				}
				requirementKind := r.TargetKind
				if requirementKind == "" {
					requirementKind = "endpoint_chain"
				}
				covers := contractCoversRequirement(c, contract, r)
				if frontierRequirement {
					covers = contractProduces(contract, r.Type) &&
						(r.Protocol == "" || strings.EqualFold(r.Protocol, contract.Protocol)) &&
						(r.Technique == "" || strings.Contains(catalogText(c), strings.ToLower(r.Technique)))
				}
				if requirementKind != kind || !covers {
					continue
				}
				if r.UserContextOnly && c.Elevated {
					continue
				}
				a.ReqIDs = append(a.ReqIDs, r.ID)
				a.Elevated = a.Elevated || r.RunElevated
			}
			if len(a.ReqIDs) == 0 {
				continue
			}
			if a.Elevated {
				capability := factState(m, "elevated_capability", target)
				if capability == "" {
					// Backward compatibility for missions created before the inventory
					// fact was renamed to distinguish capability from identity proof.
					capability = factState(m, "elevated_session", target)
				}
				if !s.Config.AllowElevated || capability != "proven" {
					continue
				}
				if m.InitialUserContext {
					elevationRequirement, elevationProven := missionElevationRequirement(m, target)
					if elevationRequirement == "" {
						continue
					}
					if !elevationProven {
						a.PreReqIDs = append(a.PreReqIDs, elevationRequirement)
					}
				}
			}
			if m.InitialUserContext && !contractProduces(contract, "elevated_context_proven") &&
				(contractProduces(contract, "credential_access_validated") || contractProduces(contract, "lateral_movement_validated")) {
				elevationRequirement, elevationProven := missionElevationRequirement(m, target)
				if elevationRequirement != "" && !elevationProven {
					a.PreReqIDs = append(a.PreReqIDs, elevationRequirement)
				}
			}
			// If domain discovery is an explicit objective for this host, later
			// credential and lateral stages must consume that evidence. Otherwise
			// catalogue ID ordering could let a credential chain run before the
			// operator's requested initial information-gathering checkpoint.
			if contractProduces(contract, "credential_access_validated") || contractProduces(contract, "lateral_movement_validated") {
				for _, requirement := range m.Requirements {
					if requirement.Type == "domain_context_observed" && requirementExecutionTarget(requirement) == target && requirement.Status != "proven" {
						a.PreReqIDs = append(a.PreReqIDs, requirement.ID)
					}
				}
			}
			missingPrerequisite := false
			for _, required := range contract.Requires {
				if !supportedRequirementType(required.Type) {
					continue
				}
				matchedRequirement := false
				for _, r := range m.Requirements {
					if !requirementMatchesPredicate(r, required) {
						continue
					}
					matchedRequirement = true
					if r.Status != "proven" {
						a.PreReqIDs = append(a.PreReqIDs, r.ID)
					}
				}
				if !matchedRequirement {
					missingPrerequisite = true
				}
			}
			if missingPrerequisite {
				continue
			}
			sort.Strings(a.ReqIDs)
			a.PreReqIDs = uniqueStrings(a.PreReqIDs)
			sort.Strings(a.PreReqIDs)
			key := actionKey(c.ID, target)
			byID[key] = a
		}
	}
	actions := make([]missionAction, 0, len(byID))
	for _, a := range byID {
		a.ReqMask = requirementMask(m.Requirements, a.ReqIDs)
		a.PreMask = requirementMask(m.Requirements, a.PreReqIDs)
		actions = append(actions, a)
	}
	if action, ok := s.goalDirectedLateralAction(m, tried); ok {
		action.ReqMask = requirementMask(m.Requirements, action.ReqIDs)
		action.PreMask = requirementMask(m.Requirements, action.PreReqIDs)
		actions = append(actions, action)
	}
	sort.Slice(actions, func(i, j int) bool {
		if len(actions[i].PreReqIDs) != len(actions[j].PreReqIDs) {
			return len(actions[i].PreReqIDs) < len(actions[j].PreReqIDs)
		}
		if actions[i].Elevated != actions[j].Elevated {
			return !actions[i].Elevated
		}
		_, leftFrontier := frontier[actions[i].Target]
		_, rightFrontier := frontier[actions[j].Target]
		if leftFrontier != rightFrontier {
			return leftFrontier
		}
		leftActions, rightActions := catalogActionCount(actions[i].Catalog), catalogActionCount(actions[j].Catalog)
		if leftActions != rightActions {
			return leftActions < rightActions
		}
		if len(actions[i].Catalog.Stages) != len(actions[j].Catalog.Stages) {
			return len(actions[i].Catalog.Stages) < len(actions[j].Catalog.Stages)
		}
		if len(actions[i].Catalog.Techniques) != len(actions[j].Catalog.Techniques) {
			return len(actions[i].Catalog.Techniques) < len(actions[j].Catalog.Techniques)
		}
		if len(actions[i].Contract.Produces) != len(actions[j].Contract.Produces) {
			return len(actions[i].Contract.Produces) < len(actions[j].Contract.Produces)
		}
		if actions[i].Catalog.ID != actions[j].Catalog.ID {
			return actions[i].Catalog.ID < actions[j].Catalog.ID
		}
		return actions[i].Target < actions[j].Target
	})
	return actions, nil
}

func (s *Service) lateralConfiguration(m Mission, source, destination, protocol string) LateralMissionConfiguration {
	if m.Lateral != nil && m.Lateral.DestinationAssetID == destination {
		return *m.Lateral
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	return LateralMissionConfiguration{DestinationAssetID: destination, DestinationHost: s.Config.LateralDestinations[destination], Protocol: protocol, Port: protocolPort(protocol), CredentialRefHash: s.Config.LateralDefaultCredentialRef, ExpectedIdentity: missionExpectedIdentity(m, source, destination)}
}

func missionExpectedIdentity(m Mission, source, destination string) string {
	for _, requirement := range m.Requirements {
		if requirement.Type == "identity_observed" && requirement.Source == source && requirement.Target == destination {
			return requirement.ExpectedIdentity
		}
	}
	return ""
}

func frontierRequirementCovered(m Mission, item PlanItem, requirement Requirement, catalog Catalog, contract ActionContract) bool {
	if item.Kind != "endpoint_chain" || item.SourceAssetID == "" || item.SourceAssetID == requirement.Source ||
		item.SourceAssetID != contract.Source || item.DestinationAssetID != requirement.Target ||
		item.DestinationAssetID != contract.Destination || !containsString(item.AssetIDs, item.SourceAssetID) ||
		(requirement.Type != "remote_access_proven" && requirement.Type != "identity_observed") ||
		!contractProduces(contract, requirement.Type) ||
		(requirement.Technique != "" && !strings.Contains(catalogText(catalog), strings.ToLower(requirement.Technique))) ||
		(requirement.Protocol != "" && !strings.EqualFold(requirement.Protocol, contract.Protocol)) {
		return false
	}
	return observedRemoteRoute(m.ADGraph, requirement.Source, item.SourceAssetID, "").Ready
}

func missionFrontierAsset(m Mission, assetID string) bool {
	for _, requirement := range m.Requirements {
		if requirement.Type == "remote_access_proven" && requirement.Status != "proven" && assetID != requirement.Target &&
			observedRemoteRoute(m.ADGraph, requirement.Source, assetID, "").Ready {
			return true
		}
	}
	return false
}

func (s *Service) goalDirectedLateralAction(m Mission, tried map[string]bool) (missionAction, bool) {
	if !s.Config.LateralEnabled || s.Lateral == nil {
		return missionAction{}, false
	}
	for _, objective := range m.Requirements {
		if objective.Type != "remote_access_proven" || objective.Status == "proven" {
			continue
		}
		protocol := objective.Protocol
		if m.Lateral != nil && m.Lateral.DestinationAssetID == objective.Target {
			protocol = m.Lateral.Protocol
		}
		if !validLateralProtocol(protocol) {
			continue
		}
		route := goalDirectedADRoute(m, objective.Source, objective.Target, protocol)
		if m.SelectedRoute != nil && m.SelectedRoute.Ready {
			route = *m.SelectedRoute
		}
		for _, hop := range machineHops(m.ADGraph, route) {
			if provenHop(m, hop) {
				continue
			}
			if !executableHop(m.ADGraph, hop) {
				break
			}
			configuration := s.lateralConfiguration(m, hop.SourceAssetID, hop.DestinationAssetID, protocol)
			if configuration.DestinationHost == "" || configuration.CredentialRefHash == "" || s.Config.LateralCredentialRefs[configuration.CredentialRefHash] == "" || s.Lateral.endpoint(hop.SourceAssetID) == "" || tried[actionKey(lateralCatalogID, hop.SourceAssetID)] {
				break
			}
			catalog := lateralCatalog()
			contract := lateralContract(hop.SourceAssetID, hop.DestinationAssetID, protocol)
			action := missionAction{Kind: "lab_lateral", Catalog: catalog, Contract: contract, Target: hop.SourceAssetID, Source: hop.SourceAssetID, Destination: hop.DestinationAssetID, Protocol: protocol}
			for _, requirement := range m.Requirements {
				if requirement.Status == "proven" || requirement.Source != hop.SourceAssetID || requirement.Target != hop.DestinationAssetID {
					continue
				}
				if contractCoversRequirement(catalog, contract, requirement) {
					action.ReqIDs = append(action.ReqIDs, requirement.ID)
				}
			}
			for _, requirement := range m.Requirements {
				if requirement.Status == "proven" {
					continue
				}
				if (requirement.Type == "domain_context_observed" || requirement.Type == "credential_access_validated" || requirement.Type == "elevated_context_proven") && requirementExecutionTarget(requirement) == objective.Source {
					action.PreReqIDs = append(action.PreReqIDs, requirement.ID)
				}
			}
			action.ReqIDs = uniqueStrings(action.ReqIDs)
			action.PreReqIDs = uniqueStrings(action.PreReqIDs)
			sort.Strings(action.ReqIDs)
			sort.Strings(action.PreReqIDs)
			return action, true
		}
	}
	return missionAction{}, false
}

func missionElevationRequirement(m Mission, target string) (string, bool) {
	for _, requirement := range m.Requirements {
		if requirement.Type == "elevated_context_proven" && requirementExecutionTarget(requirement) == target {
			return requirement.ID, requirement.Status == "proven"
		}
	}
	return "", false
}

func catalogActionCount(c Catalog) int {
	total := 0
	for _, stage := range c.Stages {
		actions, ok := stage["actions"].([]any)
		if ok {
			total += len(actions)
			continue
		}
		if stringsValue, ok := stage["actions"].([]string); ok {
			total += len(stringsValue)
		}
	}
	return total
}

func actionKey(catalogID, target string) string {
	return catalogID + "\x00" + target
}

func catalogText(c Catalog) string {
	b, _ := json.Marshal(c)
	return strings.ToLower(string(b))
}

func requirementMask(reqs []Requirement, ids []string) uint64 {
	var mask uint64
	for i, r := range reqs {
		if containsString(ids, r.ID) {
			mask |= uint64(1) << i
		}
	}
	return mask
}

func mandatoryMask(reqs []Requirement, actions []missionAction) uint64 {
	var coverable uint64
	for _, action := range actions {
		coverable |= action.ReqMask
	}
	var mask uint64
	for i, r := range reqs {
		bit := uint64(1) << i
		if r.Mandatory && r.Status != "proven" && (!proofOnlyRequirement(r.Type) || coverable&bit != 0) {
			mask |= bit
		}
	}
	return mask
}

func chooseActions(m Mission, actions []missionAction, maxItems int) ([]missionAction, string) {
	goal := mandatoryMask(m.Requirements, actions)
	if goal == 0 {
		return nil, "all mandatory requirements are already proven"
	}
	if len(actions) == 0 {
		return nil, "no catalogue action matches the remaining requirements"
	}
	if len(m.Requirements) > 63 {
		return nil, "mission has more than 63 requirements; split it into smaller missions"
	}
	if maxItems <= 0 {
		maxItems = 5
	}
	type state struct {
		mask uint64
		path []int
	}
	queue := []state{{}}
	seen := map[uint64]bool{0: true}
	best := state{}
	bestCovered := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if covered := bits.OnesCount64(cur.mask & goal); covered > bestCovered {
			best = cur
			bestCovered = covered
		}
		if cur.mask&goal == goal {
			selected := make([]missionAction, 0, len(cur.path))
			for _, i := range cur.path {
				selected = append(selected, actions[i])
			}
			return selected, ""
		}
		if len(cur.path) >= maxItems {
			continue
		}
		for i, a := range actions {
			if cur.mask&a.PreMask != a.PreMask {
				continue
			}
			next := cur.mask | a.ReqMask
			if next == cur.mask || seen[next] {
				continue
			}
			seen[next] = true
			path := append(append([]int(nil), cur.path...), i)
			queue = append(queue, state{mask: next, path: path})
		}
	}
	if len(best.path) > 0 {
		selected := make([]missionAction, 0, len(best.path))
		for _, i := range best.path {
			selected = append(selected, actions[i])
		}
		return selected, fmt.Sprintf("partial feasible plan covers %d of %d currently actionable requirements; the remainder will be reassessed from execution evidence", bestCovered, bits.OnesCount64(goal))
	}
	return nil, "catalogue actions do not cover every mandatory requirement"
}

func allMandatorySatisfied(m Mission) bool {
	for _, r := range m.Requirements {
		if r.Mandatory && r.Status != "proven" {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func (s *Service) SyncMission(id string) error {
	m, err := s.missionByID(id)
	if err != nil {
		return err
	}
	if m.CurrentPlanID == "" {
		return nil
	}
	var p Plan
	if err = s.Store.Get("plans", m.CurrentPlanID, &p); err != nil {
		return err
	}
	return s.Store.UpdateMission(id, func(m *Mission) error {
		for _, item := range p.Items {
			if item.Status == "pending" || item.Status == "submitting" || item.Status == "running" || item.Status == "collecting_evidence" {
				continue
			}
			// A skipped item was never dispatched. Keep its requirements unknown so
			// the next planning iteration may select it again when appropriate.
			if item.Status == "skipped" {
				continue
			}
			if item.Kind == "lab_lateral" && item.Status == "completed" {
				if err := s.Lateral.VerifyStoredReport(item); err != nil {
					return fmt.Errorf("destination evidence verification failed for execution %s: %w", item.ExecutionID, err)
				}
				item.TrustedDestinationEvidence = true
				var envelope lateralEvidenceEnvelope
				encoded, _ := json.Marshal(item.Report["signed_evidence"])
				if err := json.Unmarshal(encoded, &envelope); err != nil {
					return err
				}
				found := false
				for _, proof := range m.HopProofs {
					if proof.ExecutionID == item.ExecutionID {
						found = true
					}
				}
				if !found {
					evidence := envelope.Evidence
					m.HopProofs = append(m.HopProofs, LateralHopProof{SourceAssetID: evidence.SourceAssetID, DestinationAssetID: evidence.DestinationAssetID, Protocol: evidence.Protocol, ExecutionID: evidence.ExecutionID, InputHash: evidence.InputHash, EvidenceDigest: evidenceDigest(evidence), Identity: evidence.Identity, Integrity: evidence.Integrity, ObservedAt: evidence.ObservedAt})
				}
			}
			attempted := false
			for _, a := range m.Attempts {
				if a.PlanID == p.ID && a.CatalogID == item.CatalogID && a.Target == itemTarget(item) {
					attempted = true
					break
				}
			}
			if !attempted {
				m.Attempts = append(m.Attempts, MissionAttempt{PlanID: p.ID, CatalogID: item.CatalogID, Target: itemTarget(item), Status: item.Status, ExecutionIDs: nonEmptyExecutionIDs(item), ObservedAt: time.Now().UTC()})
			}
			if item.Status == "unknown" {
				m.Status = "reconcile"
				m.BlockingReason = "an execution submission is unresolved; reconcile it before replanning"
				continue
			}
			if item.Status == "failed" || item.Status == "aborted" || item.Status == "cancelled" {
				for _, requirementID := range item.RequirementIDs {
					for index := range m.Requirements {
						requirement := &m.Requirements[index]
						if requirement.ID != requirementID || requirement.Type != "lateral_movement_validated" || requirement.Status == "proven" {
							continue
						}
						for linkedIndex := range m.Requirements {
							linked := &m.Requirements[linkedIndex]
							if linked.Status != "proven" && linked.Source == requirement.Source && linked.Target == requirement.Target {
								linked.Protocol = ""
							}
						}
					}
				}
			}
			for _, fact := range stepFacts(item) {
				m.Facts = appendFact(m.Facts, fact)
			}
			// Translate structured AD discovery output into durable graph entities
			// and evidence-backed relationships. Repeated worker ticks are safe:
			// graph nodes, edges, and evidence use stable IDs and merge idempotently.
			m.ADGraph = mergeADGraph(m.ADGraph, extractADEvidence(item))
			requirementIDs := append([]string(nil), item.RequirementIDs...)
			for _, requirement := range m.Requirements {
				if proofOnlyRequirement(requirement.Type) && !containsString(requirementIDs, requirement.ID) {
					requirementIDs = append(requirementIDs, requirement.ID)
				}
			}
			for _, reqID := range requirementIDs {
				var requirement *Requirement
				for i := range m.Requirements {
					if m.Requirements[i].ID == reqID {
						requirement = &m.Requirements[i]
						break
					}
				}
				if requirement == nil {
					continue
				}
				status, stepID, detail := evaluateRequirementEvidence(item, *requirement)
				m.Facts = appendFact(m.Facts, Fact{Type: "requirement_evidence", Subject: reqID, Object: item.CatalogID, Value: status, Status: status, ExecutionID: item.ExecutionID, StepID: stepID, Detail: detail, ObservedAt: time.Now().UTC()})
			}
		}
		applyCompletedLateralRoute(m)
		applyObservedRemoteRoute(m, p.Items)
		for i := range m.Requirements {
			r := &m.Requirements[i]
			if status, fact := requirementStatus(m.Facts, r.ID); fact != nil {
				r.Status = status
				r.Reason = "Evidence from execution " + fact.ExecutionID
			}
		}
		if allMandatorySatisfied(*m) {
			m.Status = "completed"
			m.BlockingReason = ""
		} else if m.Status != "reconcile" {
			m.Status = "planning"
			m.BlockingReason = ""
		}
		return nil
	})
}

// A FourCore report can complete a multi-hop objective only after every hop
// has its own explicit remote observation. The final report must also provide
// the requested destination identity; a graph relationship cannot invent it.
func applyObservedRemoteRoute(m *Mission, items []ValidatedItem) {
	for _, objective := range m.Requirements {
		if objective.Type != "remote_access_proven" || objective.Status == "proven" {
			continue
		}
		route := observedRemoteRoute(m.ADGraph, objective.Source, objective.Target, "")
		if !route.Ready || len(route.NodeIDs) < 3 {
			continue // Direct hops are handled by evaluateRequirementEvidence.
		}
		nodes := map[string]ADGraphNode{}
		for _, node := range m.ADGraph.Nodes {
			nodes[node.ID] = node
		}
		lastSource := nodes[route.NodeIDs[len(route.NodeIDs)-2]].AssetID
		for _, item := range items {
			observed, ok := matchingFourCoreRemoteObservation(item, Requirement{
				Source: lastSource, Target: objective.Target, Protocol: objective.Protocol,
				ExpectedIdentity: objective.ExpectedIdentity,
			})
			if !ok || !correlatedObservedRemoteRoute(m.ADGraph, route, item.ExecutionID) {
				continue
			}
			for _, requirement := range m.Requirements {
				if requirement.Status == "proven" || requirement.Source != objective.Source || requirement.Target != objective.Target ||
					(requirement.Type != "remote_access_proven" && requirement.Type != "identity_observed") ||
					(requirement.ExpectedIdentity != "" && !identityMatches(observed.Identity, requirement.ExpectedIdentity)) {
					continue
				}
				m.Facts = appendFact(m.Facts, Fact{Type: "requirement_evidence", Subject: requirement.ID,
					Object: "observed_remote_route", Value: "proven", Status: "proven", ExecutionID: item.ExecutionID,
					StepID: observed.StepID, Detail: fmt.Sprintf("%d explicit provider-reported remote hops connect %s to %s; final identity=%s", len(route.EdgeIDs), objective.Source, objective.Target, observed.Identity),
					ObservedAt: time.Now().UTC()})
			}
			route.Protocol = objective.Protocol
			m.SelectedRoute = &route
			break
		}
	}
}

func applyCompletedLateralRoute(m *Mission) {
	if m.SelectedRoute == nil {
		return
	}
	hops := machineHops(m.ADGraph, *m.SelectedRoute)
	if len(hops) == 0 {
		return
	}
	for _, hop := range hops {
		if !provenHop(*m, hop) {
			return
		}
	}
	last := hops[len(hops)-1]
	var finalProof *LateralHopProof
	for index := range m.HopProofs {
		proof := &m.HopProofs[index]
		if proof.SourceAssetID == last.SourceAssetID && proof.DestinationAssetID == last.DestinationAssetID && strings.EqualFold(proof.Protocol, last.Protocol) {
			finalProof = proof
		}
	}
	if finalProof == nil {
		return
	}
	for _, requirement := range m.Requirements {
		if requirement.Source != m.SelectedRoute.SourceAssetID || requirement.Target != m.SelectedRoute.DestinationAssetID || requirement.Status == "proven" {
			continue
		}
		switch requirement.Type {
		case "remote_access_proven", "service_reachable", "lateral_movement_validated":
		case "identity_observed":
			if requirement.ExpectedIdentity != "" && !identityMatches(finalProof.Identity, requirement.ExpectedIdentity) {
				continue
			}
		default:
			continue
		}
		m.Facts = appendFact(m.Facts, Fact{Type: "requirement_evidence", Subject: requirement.ID, Object: "verified_lateral_route", Value: "proven", Status: "proven", ExecutionID: finalProof.ExecutionID, Detail: fmt.Sprintf("%d signed destination hop records prove the route; final identity=%s", len(hops), finalProof.Identity), ObservedAt: finalProof.ObservedAt})
	}
}

func appendFact(facts []Fact, fact Fact) []Fact {
	for _, existing := range facts {
		if existing.Type == fact.Type && existing.Subject == fact.Subject && existing.Object == fact.Object && existing.ExecutionID == fact.ExecutionID {
			return facts
		}
	}
	return append(facts, fact)
}

func requirementStatus(facts []Fact, id string) (string, *Fact) {
	var latest *Fact
	var latestProven *Fact
	for i := range facts {
		if facts[i].Type != "requirement_evidence" || facts[i].Subject != id {
			continue
		}
		if facts[i].Value == "proven" && (latestProven == nil || facts[i].ObservedAt.After(latestProven.ObservedAt)) {
			latestProven = &facts[i]
		}
		if latest == nil || facts[i].ObservedAt.After(latest.ObservedAt) {
			latest = &facts[i]
		}
	}
	if latest == nil {
		return "", nil
	}
	if latestProven != nil {
		return "proven", latestProven
	}
	return latest.Value, latest
}

func nonEmptyExecutionIDs(item ValidatedItem) []string {
	if item.ExecutionID == "" {
		return nil
	}
	return []string{item.ExecutionID}
}

func itemTarget(item ValidatedItem) string {
	if len(item.AssetIDs) > 0 {
		return item.AssetIDs[0]
	}
	if len(item.EmailAssetIDs) > 0 {
		return item.EmailAssetIDs[0]
	}
	return ""
}

func (s *Service) AdvanceMissions(ctx context.Context) error {
	missions, err := s.Store.Missions()
	if err != nil {
		return err
	}
	for _, m := range missions {
		// These stages are explicit operator gates. Re-entering their leaf nodes
		// on every worker tick only grows the durable trace; it cannot advance the
		// mission until the operator authorizes or reconciles it.
		if m.Status == "awaiting_authorization" || m.Status == "reconcile" || m.WorkflowStage == "user_authorizes_exact_plan_hash" || m.WorkflowStage == "require_reconciliation" {
			continue
		}
		if (m.Status == "completed" || m.Status == "blocked" || m.Status == "unattainable") && m.WorkflowStage == "generate_final_report" {
			continue
		}
		if _, err := s.AdvanceMissionGraph(ctx, m.ID); err != nil {
			return err
		}
	}
	return nil
}
