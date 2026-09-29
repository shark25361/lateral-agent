package app

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const cachedInventoryRefreshTimeout = 10 * time.Second

func upsertFact(facts []Fact, fact Fact) []Fact {
	for i := range facts {
		if facts[i].Type == fact.Type && facts[i].Subject == fact.Subject && facts[i].Object == fact.Object && facts[i].ExecutionID == fact.ExecutionID {
			facts[i] = fact
			return facts
		}
	}
	return append(facts, fact)
}

func missionAssetKinds(m Mission, includeRouteDestinations bool) map[string]string {
	assets := map[string]string{}
	for _, requirement := range m.Requirements {
		kind := "endpoint"
		if requirement.TargetKind == "email_chain" {
			kind = "email"
		}
		remoteOnlyDestination := !includeRouteDestinations && requirement.Source != "" && requirement.Target != requirement.Source && requirementExecutionTarget(requirement) == requirement.Source
		if requirement.Target != "" && !remoteOnlyDestination {
			assets[requirement.Target] = kind
		}
		if requirement.Source != "" {
			assets[requirement.Source] = "endpoint"
		}
	}
	routes := []GoalDirectedRoute{}
	if includeRouteDestinations {
		if m.SelectedRoute != nil {
			routes = append(routes, *m.SelectedRoute)
		} else {
			for _, requirement := range m.Requirements {
				if requirement.Type == "remote_access_proven" {
					routes = append(routes, goalDirectedADRoute(m, requirement.Source, requirement.Target, requirement.Protocol))
				}
			}
		}
	}
	selected := map[string]bool{}
	for _, route := range routes {
		for _, id := range route.NodeIDs {
			selected[id] = true
		}
	}
	for _, node := range m.ADGraph.Nodes {
		if selected[node.ID] && node.Kind == "machine" && node.AssetID != "" {
			assets[node.AssetID] = "endpoint"
		}
	}
	return assets
}

// CollectMissionFacts performs only the inventory checks needed by the current
// requirements. It records explicit API fields and does not infer domain or
// remote-access state from host names or catalogue descriptions.
func (s *Service) CollectMissionFacts(ctx context.Context, id string) error {
	m, err := s.missionByID(id)
	if err != nil {
		return err
	}
	observed := []Fact{}
	for assetID, kind := range missionAssetKinds(m, s.Config.LateralEnabled) {
		if _, registered := s.Config.LabAssets[assetID]; s.Config.LateralEnabled && kind == "endpoint" && registered {
			observed = append(observed, Fact{
				Type: "lab_asset_registered", Subject: assetID, Value: "true", Status: "proven",
				ObservedAt: time.Now().UTC(),
				Detail:     "operator-declared local lab asset; availability, connectivity, platform, and identity have not been verified",
			})
			continue
		}
		assetCtx := ctx
		cancel := func() {}
		if reusableInventoryFacts(m, assetID, kind) {
			// Planning may reuse prior explicit endpoint state after a bounded
			// refresh. Submission still performs an unabridged live validation.
			assetCtx, cancel = context.WithTimeout(ctx, cachedInventoryRefreshTimeout)
		}
		asset, readErr := s.FC.Asset(assetCtx, kind, assetID)
		cancel()
		if readErr != nil {
			if reusableInventoryFacts(m, assetID, kind) {
				observed = append(observed, Fact{Type: "inventory_refresh", Subject: assetID, Value: "cached", Status: "unknown", ObservedAt: time.Now().UTC(), Detail: "live inventory refresh failed; retained prior explicit inventory facts: " + readErr.Error()})
				continue
			}
			return fmt.Errorf("read mission asset %s: %w", assetID, readErr)
		}
		now := time.Now().UTC()
		status := func(ok bool) string {
			if ok {
				return "proven"
			}
			return "disproven"
		}
		observed = append(observed,
			Fact{Type: "asset_available", Subject: assetID, Value: fmt.Sprint(asset.Available && !asset.Disabled), Status: status(asset.Available && !asset.Disabled), ObservedAt: now, Detail: "FourCore asset inventory"},
			Fact{Type: "asset_connected", Subject: assetID, Value: fmt.Sprint(asset.Connected), Status: status(kind == "email" || asset.Connected), ObservedAt: now, Detail: "FourCore asset inventory"},
			Fact{Type: "platform_" + platform(asset.Platform), Subject: assetID, Value: asset.Platform, Status: "proven", ObservedAt: now, Detail: "FourCore asset inventory"},
			Fact{Type: "elevated_capability", Subject: assetID, Value: fmt.Sprint(asset.Elevated), Status: status(asset.Elevated), ObservedAt: now, Detail: "FourCore reports whether the endpoint agent can accept run_elevated; this is not proof of the mission's starting identity"},
		)
	}
	return s.Store.UpdateMission(id, func(m *Mission) error {
		for _, fact := range observed {
			m.Facts = upsertFact(m.Facts, fact)
		}
		return nil
	})
}

func reusableInventoryFacts(m Mission, assetID, kind string) bool {
	if factState(m, "asset_available", assetID) != "proven" {
		return false
	}
	if kind == "endpoint" {
		return factState(m, "asset_connected", assetID) == "proven" && factState(m, "platform_windows", assetID) == "proven"
	}
	return true
}

func factState(m Mission, kind, subject string) string {
	latest := ""
	var at time.Time
	for _, fact := range m.Facts {
		if fact.Type == kind && fact.Subject == subject && (at.IsZero() || fact.ObservedAt.After(at)) {
			latest = fact.Status
			at = fact.ObservedAt
		}
	}
	return latest
}

func missionHasInventoryFacts(m Mission, includeRouteDestinations bool) bool {
	for assetID := range missionAssetKinds(m, includeRouteDestinations) {
		if factState(m, "asset_available", assetID) == "" && factState(m, "lab_asset_registered", assetID) != "proven" {
			return false
		}
	}
	return true
}

func missionAssetBlocker(m Mission, labAssets map[string]LabAsset, includeRouteDestinations bool) string {
	for assetID, kind := range missionAssetKinds(m, includeRouteDestinations) {
		if _, registered := labAssets[assetID]; kind == "endpoint" && registered && factState(m, "lab_asset_registered", assetID) == "proven" {
			// Registration permits lab planning only. Live readiness is checked
			// by the executor; remote access requires signed destination proof.
			continue
		}
		if factState(m, "asset_available", assetID) == "disproven" {
			return "asset " + assetID + " is unavailable or disabled"
		}
		if kind == "endpoint" && factState(m, "asset_connected", assetID) == "disproven" {
			return "asset " + assetID + " is disconnected"
		}
		if kind == "endpoint" && factState(m, "platform_windows", assetID) != "proven" {
			return "asset " + assetID + " is not a verified Windows endpoint"
		}
	}
	return ""
}

func missionContext(m Mission, target string) (source, destination, protocol string) {
	for _, requirement := range m.Requirements {
		if requirementExecutionTarget(requirement) != target {
			continue
		}
		if requirement.Source != "" && requirement.Target != "" {
			source = requirement.Source
			destination = requirement.Target
			protocol = strings.ToLower(requirement.Protocol)
			return
		}
	}
	return
}

func unresolvedProofReason(m Mission) string {
	missing := []string{}
	for _, requirement := range m.Requirements {
		if !requirement.Mandatory || requirement.Status == "proven" || !proofOnlyRequirement(requirement.Type) {
			continue
		}
		switch requirement.Type {
		case "remote_access_proven":
			missing = append(missing, "remote access from "+requirement.Source+" to "+requirement.Target+" requires a successful FourCore report step explicitly naming that destination, protocol and remote identity, or signed destination-side proof")
		case "identity_observed":
			identity := requirement.ExpectedIdentity
			if identity == "" {
				identity = "requested identity"
			}
			missing = append(missing, identity+" identity on "+requirement.Target+" requires an explicit successful provider report step or signed destination-side identity evidence")
		case "elevated_context_proven":
			missing = append(missing, "elevated context on "+requirement.Target+" requires explicit identity or integrity evidence")
		case "service_reachable":
			missing = append(missing, "service reachability requires explicit source, destination, protocol, and reachable=true evidence")
		}
	}
	if len(missing) == 0 {
		return "remaining proof requirements cannot be established by the available report fields"
	}
	return strings.Join(missing, "; ")
}
