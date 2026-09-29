package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type PlanInput struct {
	Objective string     `json:"objective"`
	Items     []PlanItem `json:"items"`
	MissionID string     `json:"mission_id,omitempty"`
}
type PlanItem struct {
	Kind               string              `json:"kind"`
	CatalogID          string              `json:"catalog_id"`
	AssetIDs           []string            `json:"asset_ids"`
	EmailAssetIDs      []string            `json:"email_asset_ids,omitempty"`
	RequirementIDs     []string            `json:"requirement_ids,omitempty"`
	SourceAssetID      string              `json:"source_asset_id,omitempty"`
	DestinationAssetID string              `json:"destination_asset_id,omitempty"`
	Protocol           string              `json:"protocol,omitempty"`
	Contract           *ActionContract     `json:"contract,omitempty"`
	Reason             string              `json:"reason"`
	RunElevated        bool                `json:"run_elevated"`
	DisableCleanup     bool                `json:"disable_cleanup"`
	Executor           string              `json:"executor,omitempty"`
	InputSchema        *ActionInputSchema  `json:"input_schema,omitempty"`
	LateralInput       *LateralActionInput `json:"lateral_input,omitempty"`
}
type ValidatedItem struct {
	PlanItem
	TrustedDestinationEvidence bool           `json:"-"`
	Name                       string         `json:"name"`
	CatalogHash                string         `json:"catalog_hash"`
	InputHash                  string         `json:"input_hash,omitempty"`
	Scope                      []Catalog      `json:"scope"`
	Status                     string         `json:"status"`
	ExecutionID                string         `json:"execution_id,omitempty"`
	Error                      string         `json:"error,omitempty"`
	Report                     map[string]any `json:"report,omitempty"`
	EvidenceUntil              time.Time      `json:"evidence_until,omitempty"`
	FinalStatus                string         `json:"final_status,omitempty"`
	SubmittedAt                time.Time      `json:"submitted_at,omitempty"`
	ReportObservedAt           time.Time      `json:"report_observed_at,omitempty"`
	CompletedAt                time.Time      `json:"completed_at,omitempty"`
}
type Plan struct {
	ID           string          `json:"id"`
	SessionID    string          `json:"session_id"`
	MissionID    string          `json:"mission_id,omitempty"`
	Objective    string          `json:"objective"`
	Hash         string          `json:"hash"`
	Status       string          `json:"status"`
	Created      time.Time       `json:"created_at"`
	Updated      time.Time       `json:"updated_at"`
	Scheduled    time.Time       `json:"scheduled_at"`
	AuthorizedAt time.Time       `json:"authorized_at,omitempty"`
	AuthorizedBy string          `json:"authorized_by,omitempty"`
	Items        []ValidatedItem `json:"items"`
}
type Service struct {
	Config    Config
	FC        *FourCore
	Lateral   *LateralExecutor
	Store     *Store
	missionMu sync.Mutex
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func platform(s string) string {
	s = strings.ToLower(s)
	if strings.Contains(s, "windows") {
		return "windows"
	}
	if strings.Contains(s, "darwin") || strings.Contains(s, "mac") {
		return "darwin"
	}
	if strings.Contains(s, "linux") {
		return "linux"
	}
	return s
}
func compatible(c Catalog, a Asset) bool {
	ps := c.Platforms
	if len(ps) == 0 && c.Platform != "" {
		ps = []string{c.Platform}
	}
	for _, p := range ps {
		if platform(p) == platform(a.Platform) {
			return true
		}
	}
	return false
}

type catalogLookup func(context.Context, string, string) (Catalog, error)
type assetLookup func(context.Context, string, string) (Asset, error)

func (s *Service) Validate(ctx context.Context, item PlanItem) (ValidatedItem, error) {
	return s.validate(ctx, item, s.FC.Catalog, s.FC.Asset)
}

// validateFromSnapshot is used only while creating a reviewable mission plan.
// Authorization and submission call Validate and therefore still require the
// selected catalogue content to match FourCore live before anything can run.
func (s *Service) validateFromSnapshot(ctx context.Context, item PlanItem) (ValidatedItem, error) {
	return s.validate(ctx, item, s.FC.LocalCatalog, s.FC.Asset)
}

func (s *Service) validateMissionSnapshot(ctx context.Context, mission Mission, item PlanItem) (ValidatedItem, error) {
	assets := func(ctx context.Context, kind, id string) (Asset, error) {
		if kind == "email" {
			// Email verification is not represented by the endpoint mission facts,
			// so retain the live check for email plans.
			return s.FC.Asset(ctx, kind, id)
		}
		if !reusableInventoryFacts(mission, id, kind) {
			if !missionFrontierAsset(mission, id) {
				return Asset{}, fmt.Errorf("mission has no reusable inventory evidence for asset %s", id)
			}
			// A newly observed hop can make a different source eligible. Verify
			// that source live before proposing its first reviewed plan.
			return s.FC.Asset(ctx, kind, id)
		}
		asset := Asset{ID: id, Platform: "windows", Available: true, Connected: true}
		asset.Elevated = factState(mission, "elevated_capability", id) == "proven"
		return asset, nil
	}
	lookup := s.FC.LocalCatalog
	if len(s.Config.LabAssets) > 0 {
		lookup = func(_ context.Context, kind, id string) (Catalog, error) {
			return s.FC.LocalCatalogStrict(kind, id)
		}
	}
	return s.validate(ctx, item, lookup, assets)
}

func (s *Service) validate(ctx context.Context, item PlanItem, lookup catalogLookup, assets assetLookup) (ValidatedItem, error) {
	v := ValidatedItem{PlanItem: item, Status: "pending"}
	if item.DisableCleanup {
		return v, fmt.Errorf("cleanup must remain enabled")
	}
	if item.RunElevated && !s.Config.AllowElevated {
		return v, fmt.Errorf("elevated execution is disabled by configuration")
	}
	if len(item.AssetIDs)+len(item.EmailAssetIDs) == 0 || len(item.AssetIDs)+len(item.EmailAssetIDs) > s.Config.MaxAssets {
		return v, fmt.Errorf("target count must be between 1 and %d", s.Config.MaxAssets)
	}
	if item.Reason == "" {
		return v, fmt.Errorf("each selection requires a reason")
	}
	if item.Kind == "lab_lateral" {
		return s.validateLateral(ctx, item, assets)
	}
	if item.Kind != "endpoint_chain" && item.Kind != "email_chain" && item.Kind != "playbook" {
		return v, fmt.Errorf("execution supports endpoint chains, email chains and validated endpoint/email playbooks; WAF and firewall execution require missing API contracts")
	}
	if item.Kind == "endpoint_chain" && (len(item.AssetIDs) == 0 || len(item.EmailAssetIDs) > 0) {
		return v, fmt.Errorf("endpoint chains require endpoint targets only")
	}
	if item.Kind == "email_chain" && (len(item.EmailAssetIDs) == 0 || len(item.AssetIDs) > 0 || item.RunElevated) {
		return v, fmt.Errorf("email chains require email targets only, without elevation")
	}
	c, e := lookup(ctx, item.Kind, item.CatalogID)
	if e != nil {
		return v, e
	}
	v.Name = c.Name
	v.Scope = []Catalog{c}
	endpoints, emails := []Catalog{}, []Catalog{}
	switch item.Kind {
	case "endpoint_chain":
		endpoints = append(endpoints, c)
	case "email_chain":
		emails = append(emails, c)
	case "playbook":
		if len(c.Items) == 0 || len(c.Items) > s.Config.MaxItems {
			return v, fmt.Errorf("playbook has zero or more than %d chains", s.Config.MaxItems)
		}
		for _, p := range c.Items {
			kind := ""
			switch p.Uses {
			case "endpoint":
				kind = "endpoint_chain"
			case "email":
				kind = "email_chain"
			default:
				return v, fmt.Errorf("unverified playbook vector %q; execution blocked", p.Uses)
			}
			child, e := lookup(ctx, kind, p.Chain)
			if e != nil {
				return v, e
			}
			v.Scope = append(v.Scope, child)
			if kind == "endpoint_chain" {
				endpoints = append(endpoints, child)
			} else {
				emails = append(emails, child)
			}
		}
	}
	if item.Contract != nil && item.Kind != "playbook" {
		target := ""
		if len(item.AssetIDs) > 0 {
			target = item.AssetIDs[0]
		} else if len(item.EmailAssetIDs) > 0 {
			target = item.EmailAssetIDs[0]
		}
		contract := actionContractFor(c, item.Kind, target, item.SourceAssetID, item.DestinationAssetID, item.Protocol)
		v.Contract = &contract
	}
	if (len(endpoints) > 0) != (len(item.AssetIDs) > 0) || (len(emails) > 0) != (len(item.EmailAssetIDs) > 0) {
		return v, fmt.Errorf("target types must match every vector in the selected simulation")
	}
	seen := map[string]bool{}
	for kind, ids := range map[string][]string{"endpoint": item.AssetIDs, "email": item.EmailAssetIDs} {
		for _, id := range ids {
			if seen[id] {
				return v, fmt.Errorf("duplicate asset ID")
			}
			seen[id] = true
			allow := s.Config.AllowedEndpoint
			if kind == "email" {
				allow = s.Config.AllowedEmail
			}
			if !allow[id] {
				return v, fmt.Errorf("asset %s is outside configured execution scope", id)
			}
			a, e := assets(ctx, kind, id)
			if e != nil {
				return v, e
			}
			if a.ID != id || a.Disabled || !a.Available {
				return v, fmt.Errorf("asset %s unavailable", id)
			}
			if kind == "endpoint" {
				if !a.Connected {
					return v, fmt.Errorf("asset %s disconnected", id)
				}
				if item.RunElevated && !a.Elevated {
					return v, fmt.Errorf("asset %s has no elevated session", id)
				}
				for _, ch := range endpoints {
					if !compatible(ch, a) {
						return v, fmt.Errorf("chain %s incompatible with asset %s", ch.ID, id)
					}
				}
			} else if !a.Verified {
				return v, fmt.Errorf("email asset %s is not verified", id)
			}
		}
	}
	for _, ch := range v.Scope {
		if ch.Deprecated {
			return v, fmt.Errorf("deprecated catalogue entry")
		}
		if ch.Elevated && !item.RunElevated {
			return v, fmt.Errorf("chain requires elevated execution")
		}
	}
	// Exclude mutable run counters from the fingerprint: Catalog contains only
	// selection metadata and expanded chain content.
	v.CatalogHash = hash(v.Scope)
	return v, nil
}

func (s *Service) validateLateral(ctx context.Context, item PlanItem, assets assetLookup) (ValidatedItem, error) {
	v := ValidatedItem{PlanItem: item, Status: "pending"}
	if !s.Config.LateralEnabled || s.Lateral == nil {
		return v, fmt.Errorf("controlled-lab lateral executor is disabled")
	}
	if s.Lateral.endpoint(item.SourceAssetID) == "" {
		return v, fmt.Errorf("source asset has no configured lab executor")
	}
	if item.CatalogID != lateralCatalogID || item.Executor != "controlled_lab" || item.LateralInput == nil {
		return v, fmt.Errorf("invalid controlled-lab lateral action")
	}
	if item.SourceAssetID == "" || item.DestinationAssetID == "" || item.SourceAssetID == item.DestinationAssetID {
		return v, fmt.Errorf("lateral action requires distinct source and destination assets")
	}
	if len(item.AssetIDs) != 2 || item.AssetIDs[0] != item.SourceAssetID || item.AssetIDs[1] != item.DestinationAssetID || len(item.EmailAssetIDs) != 0 {
		return v, fmt.Errorf("lateral action scope must contain its source and destination exactly once")
	}
	input := item.LateralInput
	if !strings.EqualFold(input.Protocol, item.Protocol) || !validLateralProtocol(input.Protocol) || input.Port != protocolPort(input.Protocol) {
		return v, fmt.Errorf("unsupported or inconsistent lateral protocol and port")
	}
	if s.Config.LateralDestinations[item.DestinationAssetID] != input.DestinationHost {
		return v, fmt.Errorf("destination host is not bound to the authorized destination asset")
	}
	if s.Config.LateralCredentialRefs[input.CredentialRefHash] == "" {
		return v, fmt.Errorf("credential reference is not configured")
	}
	if validID(input.CorrelationID) != nil || len(input.RouteNodeIDs) < 2 || len(input.RouteEdgeIDs) == 0 {
		return v, fmt.Errorf("lateral action requires a correlated evidence-backed route")
	}
	seen := map[string]bool{}
	for _, assetID := range item.AssetIDs {
		if seen[assetID] || !s.Config.AllowedEndpoint[assetID] {
			return v, fmt.Errorf("asset %s is outside configured execution scope", assetID)
		}
		seen[assetID] = true
		if len(s.Config.LabAssets) > 0 {
			if asset, registered := s.Config.LabAssets[assetID]; !registered || asset.ID != assetID || asset.Platform != "windows" {
				return v, fmt.Errorf("asset %s is not in the local lab asset registry", assetID)
			}
		} else {
			asset, err := assets(ctx, "endpoint", assetID)
			if err != nil {
				return v, err
			}
			if asset.ID != assetID || asset.Disabled || !asset.Available || !asset.Connected {
				return v, fmt.Errorf("asset %s unavailable or disconnected", assetID)
			}
		}
	}
	catalog := lateralCatalog()
	v.Name = catalog.Name
	v.Scope = []Catalog{catalog}
	contract := lateralContract(item.SourceAssetID, item.DestinationAssetID, strings.ToLower(item.Protocol))
	v.Contract = &contract
	schema := lateralInputSchema()
	v.InputSchema = &schema
	v.InputHash = lateralInputFingerprint(v.PlanItem)
	v.CatalogHash = hash(catalog)
	return v, nil
}
func (s *Service) Propose(ctx context.Context, session string, in PlanInput) (Plan, error) {
	return s.propose(ctx, session, in, s.Validate)
}

func (s *Service) proposeMission(ctx context.Context, session string, in PlanInput) (Plan, error) {
	mission, err := s.missionByID(in.MissionID)
	if err != nil {
		return Plan{}, err
	}
	return s.propose(ctx, session, in, func(ctx context.Context, item PlanItem) (ValidatedItem, error) {
		return s.validateMissionSnapshot(ctx, mission, item)
	})
}

func (s *Service) propose(ctx context.Context, session string, in PlanInput, validate func(context.Context, PlanItem) (ValidatedItem, error)) (Plan, error) {
	p := Plan{ID: newID(), SessionID: session, MissionID: in.MissionID, Objective: in.Objective, Status: "planned", Created: time.Now().UTC(), Updated: time.Now().UTC(), Items: []ValidatedItem{}}
	if strings.TrimSpace(in.Objective) == "" || len(in.Items) == 0 || len(in.Items) > s.Config.MaxItems {
		return p, fmt.Errorf("objective and 1-%d items required", s.Config.MaxItems)
	}
	var mission *Mission
	if in.MissionID != "" {
		loaded, e := s.missionByID(in.MissionID)
		if e != nil {
			return p, e
		}
		mission = &loaded
	}
	total := 0
	seen := map[string]bool{}
	for _, item := range in.Items {
		total += len(item.AssetIDs) + len(item.EmailAssetIDs)
		if total > s.Config.MaxAssets {
			return p, fmt.Errorf("plan exceeds total asset-run limit %d", s.Config.MaxAssets)
		}
		key := hash(item)
		if seen[key] {
			return p, fmt.Errorf("duplicate plan item")
		}
		seen[key] = true
		v, e := validate(ctx, item)
		if e != nil {
			return p, e
		}
		if mission != nil {
			if v.Contract == nil || len(v.Scope) == 0 {
				return p, fmt.Errorf("mission plan item %s has no validated action contract", item.CatalogID)
			}
			for _, requirementID := range item.RequirementIDs {
				matched := false
				for _, requirement := range mission.Requirements {
					if requirement.ID == requirementID && (contractCoversRequirement(v.Scope[0], *v.Contract, requirement) ||
						frontierRequirementCovered(*mission, item, requirement, v.Scope[0], *v.Contract)) {
						matched = true
						break
					}
				}
				if !matched {
					return p, fmt.Errorf("live catalogue entry %s no longer satisfies requirement %s", item.CatalogID, requirementID)
				}
			}
		}
		p.Items = append(p.Items, v)
	}
	p.Hash = hash(struct {
		Objective string
		Items     []ValidatedItem
	}{p.Objective, p.Items})
	return p, s.Store.Put("plans", p.ID, p)
}
func (s *Service) Authorize(ctx context.Context, id, digest string, when time.Time) error {
	if !s.Config.Execute {
		return fmt.Errorf("EXECUTION_ENABLED is false")
	}
	var p Plan
	if e := s.Store.Get("plans", id, &p); e != nil {
		return e
	}
	if p.Hash != digest {
		return fmt.Errorf("plan hash mismatch")
	}
	if p.Status != "planned" {
		return fmt.Errorf("plan already authorized or submitted")
	}
	if time.Since(p.Created) > 24*time.Hour {
		return fmt.Errorf("plan expired; generate a fresh plan")
	}
	for _, item := range p.Items {
		if item.Kind == "lab_lateral" {
			diagnostics, e := s.DiagnosePlan(ctx, p.ID)
			if e != nil {
				return e
			}
			if !diagnostics.Ready {
				return fmt.Errorf("lateral authorization preflight failed")
			}
			break
		}
	}
	for _, item := range p.Items {
		v, e := s.Validate(ctx, item.PlanItem)
		if e != nil {
			return e
		}
		if v.CatalogHash != item.CatalogHash {
			return fmt.Errorf("catalogue changed; generate a fresh plan")
		}
		if v.InputHash != item.InputHash {
			return fmt.Errorf("action inputs changed; generate a fresh plan")
		}
	}
	if p.MissionID != "" {
		mission, e := s.missionByID(p.MissionID)
		if e != nil {
			return e
		}
		for _, item := range p.Items {
			if item.Kind == "endpoint_chain" && item.SourceAssetID != "" {
				for _, requirementID := range item.RequirementIDs {
					for _, requirement := range mission.Requirements {
						if requirement.ID == requirementID && requirement.Source != "" && requirement.Source != item.SourceAssetID &&
							!missionFrontierAsset(mission, item.SourceAssetID) {
							return fmt.Errorf("the observed remote route to source %s is no longer available; generate a fresh plan", item.SourceAssetID)
						}
					}
				}
			}
			if item.Kind != "lab_lateral" || item.LateralInput == nil {
				continue
			}
			route := goalDirectedADRoute(mission, item.SourceAssetID, item.DestinationAssetID, item.Protocol)
			if !route.Ready || hash(route.EdgeIDs) != hash(item.LateralInput.RouteEdgeIDs) {
				return fmt.Errorf("the evidence-backed lateral route changed; generate a fresh plan")
			}
		}
	}
	if err := s.Store.UpdatePlan(id, func(p *Plan) error {
		if p.Status != "planned" || p.Hash != digest {
			return fmt.Errorf("plan changed or already authorized")
		}
		p.Status = "queued"
		p.AuthorizedAt = time.Now().UTC()
		p.AuthorizedBy = "operator"
		p.Scheduled = when
		return nil
	}); err != nil {
		return err
	}
	if p.MissionID != "" {
		if err := s.recordWorkflowTransition(p.MissionID, "user_authorizes_exact_plan_hash", "authorized", "operator authorized the exact immutable plan hash", p.ID); err != nil {
			return err
		}
		if err := s.Store.UpdateMission(p.MissionID, func(m *Mission) error {
			m.Status = "queued"
			m.BlockingReason = ""
			m.WorkflowStage = "worker_submits_or_polls_plan"
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
func runPath(i PlanItem) string {
	switch i.Kind {
	case "email_chain":
		return "/api/v2/email/chain/" + i.CatalogID + "/run"
	case "playbook":
		return "/api/v2/packs/" + i.CatalogID + "/run"
	default:
		return "/api/v2/chains/" + i.CatalogID + "/run"
	}
}
func runBody(i PlanItem) map[string]any {
	b := map[string]any{"disable_cleanup": false, "run_elevated": i.RunElevated}
	if len(i.AssetIDs) > 0 {
		b["assets"] = i.AssetIDs
	}
	if len(i.EmailAssetIDs) > 0 {
		b["email_assets"] = i.EmailAssetIDs
	}
	return b
}
