package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type reportStep struct {
	ID        string
	ActionID  string
	Name      string
	Stage     string
	Status    string
	Done      *bool
	Success   *bool
	Detected  *bool
	Prevented *bool
	HasOutput bool
	Raw       map[string]any
}

func boolPointer(value any) *bool {
	v, ok := value.(bool)
	if !ok {
		return nil
	}
	return &v
}

func scalarString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	default:
		return ""
	}
}

func outputPresent(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(v) != ""
	case map[string]any:
		if nested, ok := v["output"]; ok {
			return outputPresent(nested)
		}
		if truncated, ok := v["truncated"].(bool); ok && truncated {
			return strings.TrimSpace(scalarString(v["raw_json_prefix"])) != ""
		}
		for _, nested := range v {
			if outputPresent(nested) {
				return true
			}
		}
		return false
	case []any:
		return len(v) > 0
	default:
		return true
	}
}

func collectReportSteps(value any, out *[]reportStep, stepContext bool) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			collectReportSteps(child, out, stepContext)
		}
	case map[string]any:
		looksLikeStep := node["success"] != nil || node["done"] != nil || node["action_id"] != nil || node["stage_name"] != nil || node["action_steps"] != nil
		if stepContext && (node["status"] != nil || node["error"] != nil || node["error_message"] != nil || node["failure_reason"] != nil) {
			looksLikeStep = true
		}
		if looksLikeStep {
			*out = append(*out, reportStep{
				ID:        scalarString(node["id"]),
				ActionID:  scalarString(node["action_id"]),
				Name:      scalarString(node["name"]),
				Stage:     scalarString(node["stage_name"]),
				Status:    scalarString(node["status"]),
				Done:      boolPointer(node["done"]),
				Success:   boolPointer(node["success"]),
				Detected:  boolPointer(node["detected"]),
				Prevented: boolPointer(node["prevented"]),
				HasOutput: outputPresent(node["output"]),
				Raw:       node,
			})
		}
		for _, key := range []string{"assets", "steps", "action_steps", "executions"} {
			if child, ok := node[key]; ok {
				collectReportSteps(child, out, key == "steps" || key == "action_steps")
			}
		}
	}
}

func reportSteps(report map[string]any) []reportStep {
	steps := []reportStep{}
	collectReportSteps(report, &steps, false)
	return steps
}

func positiveNumber(value any) bool {
	switch v := value.(type) {
	case float64:
		return v > 0
	case int:
		return v > 0
	case int64:
		return v > 0
	case jsonNumber:
		n, _ := strconv.ParseFloat(string(v), 64)
		return n > 0
	}
	return false
}

// jsonNumber is kept local to avoid changing the decoder used by the API.
type jsonNumber string

func reportHasSuccessfulStep(report map[string]any) (bool, string) {
	if success, ok := report["success"].(bool); ok && success {
		return true, ""
	}
	if positiveNumber(report["total_success"]) {
		return true, ""
	}
	for _, step := range reportSteps(report) {
		if step.Success != nil && *step.Success {
			return true, step.ID
		}
		if step.Success == nil && (strings.EqualFold(step.Status, "success") || strings.EqualFold(step.Status, "succeeded") || strings.EqualFold(step.Status, "completed")) {
			return true, step.ID
		}
	}
	return false, ""
}

func reportHasDetection(report map[string]any) (bool, string) {
	if detected, ok := report["detected"].(bool); ok && detected {
		return true, ""
	}
	if positiveNumber(report["total_detected"]) || positiveNumber(report["detected"]) {
		return true, ""
	}
	for _, step := range reportSteps(report) {
		if step.Detected != nil && *step.Detected {
			return true, step.ID
		}
		if correlations, ok := step.Raw["correlations"].([]any); ok && len(correlations) > 0 {
			return true, step.ID
		}
	}
	return false, ""
}

func reportWasPrevented(report map[string]any) (bool, string) {
	if prevented, ok := report["prevented"].(bool); ok && prevented {
		return true, ""
	}
	for _, step := range reportSteps(report) {
		if step.Prevented != nil && *step.Prevented {
			return true, step.ID
		}
	}
	return false, ""
}

func reportHasMeaningfulOutput(report map[string]any) bool {
	for _, step := range reportSteps(report) {
		if step.HasOutput {
			return true
		}
	}
	return false
}

func stringField(node map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := node[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func boolField(node map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := node[key].(bool); ok && value {
			return true
		}
	}
	return false
}

func collectMaps(value any, out *[]map[string]any) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			collectMaps(child, out)
		}
	case map[string]any:
		*out = append(*out, node)
		for _, child := range node {
			collectMaps(child, out)
		}
	}
}

func explicitRouteEvidence(report map[string]any, requirement Requirement) (remote, identity, reachable bool, detail string) {
	maps := []map[string]any{}
	collectMaps(report, &maps)
	for _, node := range maps {
		source := stringField(node, "source_asset_id", "source_id")
		destination := stringField(node, "destination_asset_id", "destination_id", "target_asset_id")
		protocol := stringField(node, "protocol", "remote_protocol")
		if (requirement.Source != "" && source != requirement.Source) || destination != requirement.Target {
			continue
		}
		if strings.TrimSpace(protocol) == "" {
			continue
		}
		if requirement.Protocol != "" && !strings.EqualFold(protocol, requirement.Protocol) {
			continue
		}
		observedReachable := boolField(node, "reachable", "service_reachable")
		proof := boolField(node, "destination_proof", "remote_execution_observed") || stringField(node, "proof_token", "destination_proof_token") != ""
		observedRemote := proof && (observedReachable || boolField(node, "remote_execution_observed"))
		observedIdentity := stringField(node, "remote_identity", "destination_identity", "identity", "principal", "run_as")
		observedIdentityMatches := observedIdentity != ""
		if requirement.ExpectedIdentity != "" {
			observedIdentityMatches = identityMatches(observedIdentity, requirement.ExpectedIdentity)
		}
		reachable = reachable || observedReachable
		if observedRemote {
			remote = true
			identity = observedIdentityMatches
			detail = fmt.Sprintf("explicit route evidence source=%s destination=%s protocol=%s identity=%s", source, destination, protocol, observedIdentity)
			return
		}
	}
	return
}

func identityMatches(observed, expected string) bool {
	observed = strings.ToLower(strings.TrimSpace(observed))
	expected = strings.ToLower(strings.TrimSpace(expected))
	if observed == "" || expected == "" {
		return false
	}
	if observed == expected {
		return true
	}
	return !strings.ContainsAny(expected, `\@`) && strings.HasSuffix(observed, `\`+expected)
}

// A FourCore report can support a remote-access claim only when one successful
// source-asset step states a concrete destination, protocol, remote execution
// result, and observed identity. Catalogue metadata or free-text output alone
// cannot establish a cross-host result.
type providerRemoteObservation struct {
	Source, Destination, Protocol, Identity, Integrity, StepID, ParentExecutionID string
}

func fourCoreRemoteObservations(item ValidatedItem) []providerRemoteObservation {
	if item.Kind != "endpoint_chain" || item.Status != "completed" || item.ExecutionID == "" ||
		item.Contract == nil || !contractProduces(*item.Contract, "lateral_movement_validated") ||
		stringField(item.Report, "id") != item.ExecutionID {
		return nil
	}
	if reportedChain := stringField(item.Report, "chain_id"); reportedChain != "" && reportedChain != item.CatalogID {
		return nil
	}
	source := item.SourceAssetID
	if source == "" && len(item.AssetIDs) == 1 {
		source = item.AssetIDs[0]
	}
	if source == "" || len(item.AssetIDs) != 1 || item.AssetIDs[0] != source {
		return nil
	}
	assets, _ := item.Report["assets"].([]any)
	observations := []providerRemoteObservation{}
	for _, rawAsset := range assets {
		asset, ok := rawAsset.(map[string]any)
		if !ok || stringField(asset, "asset_id") != source {
			continue
		}
		var walk func(any, int)
		walk = func(value any, depth int) {
			if depth > 4 {
				return
			}
			steps, _ := value.([]any)
			for _, rawStep := range steps {
				step, ok := rawStep.(map[string]any)
				if !ok {
					continue
				}
				stepSource := stringField(step, "source_asset_id")
				if stepSource == "" {
					stepSource = source
				}
				protocol := strings.ToLower(stringField(step, "protocol"))
				destination := stringField(step, "destination_asset_id")
				identity := stringField(step, "destination_identity", "remote_identity", "identity")
				if stepSource == source && destination != "" && destination != source && validLateralProtocol(protocol) &&
					identity != "" && boolField(step, "success") && boolField(step, "remote_execution_observed") {
					observations = append(observations, providerRemoteObservation{
						Source: source, Destination: destination, Protocol: protocol, Identity: identity,
						Integrity: stringField(step, "integrity"), StepID: scalarString(step["id"]),
						ParentExecutionID: stringField(step, "parent_execution_id", "pivot_execution_id"),
					})
				}
				walk(step["action_steps"], depth+1)
			}
		}
		walk(asset["steps"], 0)
	}
	return observations
}

func matchingFourCoreRemoteObservation(item ValidatedItem, requirement Requirement) (providerRemoteObservation, bool) {
	for _, observed := range fourCoreRemoteObservations(item) {
		if observed.Source != requirement.Source || observed.Destination != requirement.Target ||
			(requirement.Protocol != "" && !strings.EqualFold(observed.Protocol, requirement.Protocol)) {
			continue
		}
		if requirement.ExpectedIdentity != "" && !identityMatches(observed.Identity, requirement.ExpectedIdentity) {
			continue
		}
		if identityMatches(observed.Identity, "administrator") || identityMatches(observed.Identity, "system") {
			if !destinationAdminIntegrity(observed.Integrity) {
				continue
			}
		}
		return observed, true
	}
	return providerRemoteObservation{}, false
}

func explicitLocalElevationEvidence(value any, target, inheritedAsset string) (bool, string) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			if proven, detail := explicitLocalElevationEvidence(child, target, inheritedAsset); proven {
				return true, detail
			}
		}
	case map[string]any:
		assetID := stringField(node, "asset_id", "endpoint_id")
		if assetID == "" {
			assetID = inheritedAsset
		}
		if assetID == target {
			identity := stringField(node, "identity", "principal", "run_as", "username", "user")
			integrity := strings.ToLower(stringField(node, "integrity_level", "integrity", "security_context"))
			isElevated := boolField(node, "is_admin", "administrator", "elevated", "high_integrity") ||
				integrity == "high" || integrity == "system"
			if isElevated {
				return true, fmt.Sprintf("explicit local elevation evidence asset=%s identity=%s integrity=%s", assetID, identity, integrity)
			}
		}
		for _, child := range node {
			if proven, detail := explicitLocalElevationEvidence(child, target, assetID); proven {
				return true, detail
			}
		}
	}
	return false, ""
}

func evaluateRequirementEvidence(item ValidatedItem, requirement Requirement) (status, stepID, detail string) {
	terminalFailure := item.Status == "failed" || item.Status == "aborted"
	if item.Status != "completed" && !terminalFailure {
		return "unknown", "", "execution is not terminal"
	}
	success, successfulStep := reportHasSuccessfulStep(item.Report)
	switch requirement.Type {
	case "detection_observed":
		if detected, step := reportHasDetection(item.Report); detected {
			return "proven", step, "explicit detection evidence was present"
		}
		if terminalFailure {
			return "unknown", "", "execution ended without explicit detection evidence"
		}
		return "unknown", "", "no explicit detection flag, count, or correlation was present"
	case "behavior_prevented":
		if prevented, step := reportWasPrevented(item.Report); prevented {
			return "proven", step, "explicit prevention evidence was present"
		}
		if terminalFailure {
			return "unknown", "", "execution ended without explicit prevention evidence"
		}
		return "unknown", "", "no explicit prevented=true evidence was present"
	case "elevated_context_proven":
		if elevated, elevationDetail := explicitLocalElevationEvidence(item.Report, requirement.Target, ""); elevated {
			return "proven", "", elevationDetail
		}
		if terminalFailure {
			return "unknown", "", "execution ended without structured local administrator, SYSTEM, or high-integrity evidence"
		}
		return "unknown", "", "the report did not contain structured local administrator, SYSTEM, or high-integrity evidence"
	case "remote_access_proven", "service_reachable", "identity_observed":
		if observed, ok := matchingFourCoreRemoteObservation(item, requirement); ok {
			return "proven", observed.StepID, fmt.Sprintf("FourCore execution %s reported successful remote execution from %s to %s over %s as %s (integrity=%s)", item.ExecutionID, observed.Source, observed.Destination, observed.Protocol, observed.Identity, observed.Integrity)
		}
		remote, identity, reachable, routeDetail := explicitRouteEvidence(item.Report, requirement)
		switch requirement.Type {
		case "remote_access_proven":
			if item.TrustedDestinationEvidence && remote {
				return "proven", "", routeDetail
			}
		case "service_reachable":
			if reachable {
				return "proven", "", routeDetail
			}
		default:
			if item.TrustedDestinationEvidence && remote && identity {
				return "proven", "", routeDetail
			}
		}
		if terminalFailure {
			return "unknown", "", "execution ended without a matching destination-specific provider result or signed destination proof"
		}
		return "unknown", "", "the report did not contain a matching destination-specific provider result or signed destination proof"
	case "domain_context_observed":
		if success && item.Contract != nil && contractProduces(*item.Contract, requirement.Type) && reportHasMeaningfulOutput(item.Report) {
			return "proven", successfulStep, "an AD/domain discovery action succeeded and returned output"
		}
		if terminalFailure {
			return "disproven", successfulStep, "the matching domain discovery action ended without successful output"
		}
		return "unknown", successfulStep, "domain context requires a successful matching discovery action with output"
	case "credential_access_validated":
		if success && item.Contract != nil && contractProduces(*item.Contract, requirement.Type) {
			return "proven", successfulStep, "credential-access simulation behavior completed; usable credential material was not inferred"
		}
		if terminalFailure {
			return "disproven", successfulStep, "the matching credential-access simulation ended without a successful action step"
		}
		return "unknown", successfulStep, "no successful credential-access action was evidenced"
	case "lateral_movement_validated":
		if success && item.Contract != nil && contractProduces(*item.Contract, requirement.Type) {
			if requirement.Source == "" {
				return "proven", successfulStep, "a FourCore lateral-category chain completed with a successful action; no destination or cross-host access was inferred"
			}
			return "proven", successfulStep, "lateral-movement simulation behavior completed; cross-host access remains a separate predicate"
		}
		if terminalFailure {
			return "disproven", successfulStep, "the matching lateral-movement simulation ended without a successful action step"
		}
		return "unknown", successfulStep, "no successful lateral-movement action was evidenced"
	default:
		if success {
			return "proven", successfulStep, "a simulation action completed successfully"
		}
		if terminalFailure {
			return "disproven", "", "the planned simulation ended without a successful action step"
		}
		return "unknown", "", "the report contained no successful action step"
	}
}

func stepFacts(item ValidatedItem) []Fact {
	facts := []Fact{}
	for _, step := range reportSteps(item.Report) {
		if step.Success == nil && step.Done == nil && step.Status == "" {
			continue
		}
		status := "unknown"
		value := "incomplete"
		if step.Success != nil {
			if *step.Success {
				status, value = "proven", "success"
			} else if step.Done != nil && *step.Done {
				status, value = "disproven", "failed"
			}
		}
		if step.Success == nil {
			switch strings.ToLower(strings.TrimSpace(step.Status)) {
			case "success", "succeeded", "completed", "finished":
				status, value = "proven", "success"
			case "failed", "failure", "error", "aborted":
				status, value = "disproven", "failed"
			}
		}
		subject := step.ActionID
		if subject == "" {
			subject = step.Name
		}
		facts = append(facts, Fact{Type: "step_execution", Subject: subject, Object: item.CatalogID, Value: value, Status: status, ExecutionID: item.ExecutionID, StepID: step.ID, Detail: strings.TrimSpace(step.Stage + ": " + step.Name), ObservedAt: time.Now().UTC()})
	}
	return facts
}
