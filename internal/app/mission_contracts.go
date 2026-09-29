package app

import (
	"sort"
	"strings"
)

// PredicateSpec describes a machine-checkable state used by the mission
// planner. It intentionally contains no confidence or probability score.
type PredicateSpec struct {
	Type     string `json:"type"`
	Subject  string `json:"subject,omitempty"`
	Object   string `json:"object,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// ActionContract is the deterministic interpretation of a FourCore catalogue
// entry. The catalogue remains the source of executable content; this contract
// only states prerequisites, possible effects, and the evidence needed to
// claim those effects.
type ActionContract struct {
	ExecutionRole string          `json:"execution_role"`
	Source        string          `json:"source_asset_id,omitempty"`
	Destination   string          `json:"destination_asset_id,omitempty"`
	Protocol      string          `json:"protocol,omitempty"`
	Requires      []PredicateSpec `json:"requires,omitempty"`
	Produces      []PredicateSpec `json:"produces,omitempty"`
	EvidenceRules []string        `json:"evidence_rules"`
}

func techniqueIDs(c Catalog) map[string]bool {
	out := map[string]bool{}
	for _, technique := range c.Techniques {
		for _, key := range []string{"absolute_id", "technique_id", "tactic_id"} {
			if value, ok := technique[key].(string); ok && value != "" {
				out[strings.ToUpper(value)] = true
			}
		}
	}
	return out
}

func hasTactic(ids map[string]bool, tactic string) bool {
	return ids[strings.ToUpper(tactic)]
}

func containsAny(text string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(text, strings.ToLower(term)) {
			return true
		}
	}
	return false
}

func catalogCategory(c Catalog) string {
	if c.Tags == nil {
		return ""
	}
	category, _ := c.Tags["category"].(string)
	return strings.ToLower(strings.TrimSpace(category))
}

// Semantic mission predicates are intentionally restricted to focused
// catalogue content. A large APT or kill-chain entry may mention credentials,
// domains, and remote services without being the minimal action represented by
// any of those predicates.
func focusedCatalogPurpose(c Catalog, purpose string) bool {
	category := catalogCategory(c)
	label := strings.ToLower(c.ID + " " + c.Name)
	switch purpose {
	case "domain":
		return containsAny(category, "discovery", "information gathering") &&
			containsAny(label, "active directory", "domain", "ldap", "adfind", "host profiling")
	case "credential":
		return containsAny(category, "credential access", "credential", "lateral movement") &&
			containsAny(label, "credential", "lsass", "kerberoast", "password", "hash", "sam", "ntds", "secret", "mimikatz")
	case "lateral":
		return strings.Contains(category, "lateral movement")
	case "privilege_escalation":
		return strings.Contains(category, "privilege escalation") ||
			(strings.Contains(category, "discovery") && containsAny(label, " lpe", "uac bypass", "fodhelper", "computerdefaults", "sdclt"))
	default:
		return false
	}
}

func appendPredicate(values []PredicateSpec, value PredicateSpec) []PredicateSpec {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func actionContractFor(c Catalog, kind, target, source, destination, protocol string) ActionContract {
	text := catalogText(c)
	label := strings.ToLower(c.ID + " " + c.Name)
	ids := techniqueIDs(c)
	protocol = inferredCatalogProtocol(c, protocol)
	contract := ActionContract{
		ExecutionRole: "target",
		Source:        source,
		Destination:   destination,
		Protocol:      protocol,
		EvidenceRules: []string{
			"A completed report and an explicit successful action step are required for behavior claims.",
			"Detection and prevention require their own explicit report fields.",
		},
	}
	if source != "" && destination != "" {
		contract.ExecutionRole = "source"
	}
	contract.Requires = appendPredicate(contract.Requires, PredicateSpec{Type: "asset_available", Subject: target})
	if kind != "email_chain" {
		contract.Requires = appendPredicate(contract.Requires, PredicateSpec{Type: "asset_connected", Subject: target})
		contract.Requires = appendPredicate(contract.Requires, PredicateSpec{Type: "platform_windows", Subject: target})
	}
	if c.Elevated && kind != "email_chain" {
		contract.Requires = appendPredicate(contract.Requires, PredicateSpec{Type: "elevated_session", Subject: target})
	}

	contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "behavior_executed", Subject: target})
	credentialFocused := hasTactic(ids, "TA0006") && focusedCatalogPurpose(c, "credential")
	if credentialFocused {
		contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "credential_access_validated", Subject: target})
	}
	remoteLateral := hasTactic(ids, "TA0008") && focusedCatalogPurpose(c, "lateral") && containsAny(text, "t1021", "t1550.002", "pass-the-hash", "remote execution", "psexec", "winrm", "smb exec", "wmi remote", "lateral movement")
	sourceOnlySimulation := source == "" && destination == "" && focusedCatalogPurpose(c, "lateral")
	if remoteLateral || sourceOnlySimulation {
		// FourCore runs this behavior on the source endpoint; its run API does not
		// select a real destination. A source-only objective can validate a chain
		// in the lateral catalogue without claiming any remote technique worked.
		// Destination access remains a separate, stronger proof predicate.
		contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "lateral_movement_validated", Subject: target, Protocol: contract.Protocol})
		if source != "" && destination != "" && contract.Protocol != "" {
			// Conditional effect: chain success alone cannot establish it.
			contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "remote_access_proven", Subject: source, Object: destination, Protocol: contract.Protocol})
			contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "identity_observed", Subject: source, Object: destination, Protocol: contract.Protocol})
			contract.EvidenceRules = append(contract.EvidenceRules, "Remote access requires a successful report step explicitly naming the destination, protocol, remote execution result, and observed identity.")
		}
	}
	networkDiscovery := (ids["T1046"] || ids["TA0007.T1046"] || ids["T1018"] || ids["TA0007.T1018"]) && containsAny(text, "network service", "port scan", "remote system", "host discovery", "service discovery")
	if networkDiscovery && source != "" && destination != "" && contract.Protocol != "" {
		contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "service_reachable", Subject: source, Object: destination, Protocol: contract.Protocol})
		contract.EvidenceRules = append(contract.EvidenceRules, "Reachability is proven only when the report explicitly identifies the requested source, destination, and protocol.")
	}
	if focusedCatalogPurpose(c, "domain") && containsAny(label, "active directory", "kerberos", "domain account", "domain computer", "domain profiling", "ldap", "adfind", "delegation", "adminsdholder", "host profiling") {
		contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "domain_context_observed", Subject: target})
	}
	privilegeFocused := hasTactic(ids, "TA0004") && focusedCatalogPurpose(c, "privilege_escalation")
	if privilegeFocused {
		contract.Produces = appendPredicate(contract.Produces, PredicateSpec{Type: "elevated_context_proven", Subject: target})
		contract.EvidenceRules = append(contract.EvidenceRules, "Elevation requires a structured administrator, SYSTEM, high-integrity, or elevated-context field from the execution report; catalogue metadata and generic step success are insufficient.")
		if source != "" && destination != "" {
			contract.Requires = appendPredicate(contract.Requires, PredicateSpec{Type: "domain_context_observed", Subject: target})
		}
	}

	// Domain and credential discovery are optional unless explicitly requested
	// or required by a selected action's typed input contract.
	sort.Slice(contract.Requires, func(i, j int) bool { return predicateKey(contract.Requires[i]) < predicateKey(contract.Requires[j]) })
	sort.Slice(contract.Produces, func(i, j int) bool { return predicateKey(contract.Produces[i]) < predicateKey(contract.Produces[j]) })
	return contract
}

func inferredCatalogProtocol(c Catalog, requested string) string {
	if protocol := strings.ToLower(strings.TrimSpace(requested)); protocol != "" {
		return protocol
	}
	ids := techniqueIDs(c)
	for _, candidate := range []struct {
		technique string
		protocol  string
	}{
		{"TA0008.T1021.006", "winrm"},
		{"TA0008.T1021.001", "rdp"},
		{"TA0008.T1021.002", "smb"},
		{"TA0008.T1021.003", "dcom"},
		{"TA0008.T1021.004", "ssh"},
		{"T1021.006", "winrm"},
		{"T1021.001", "rdp"},
		{"T1021.002", "smb"},
		{"T1021.003", "dcom"},
		{"T1021.004", "ssh"},
	} {
		if ids[candidate.technique] {
			return candidate.protocol
		}
	}
	return inferredProtocol(catalogText(c), "")
}

func inferredProtocol(text, requested string) string {
	if protocol := strings.ToLower(strings.TrimSpace(requested)); protocol != "" {
		return protocol
	}
	switch {
	case containsAny(text, "t1021.006", "winrm"):
		return "winrm"
	case containsAny(text, "t1021.001", "remote desktop", " rdp"):
		return "rdp"
	case containsAny(text, "t1021.002", "psexec", "smb exec", "admin share", "smb"):
		return "smb"
	case containsAny(text, "t1021.003", "dcom"):
		return "dcom"
	case containsAny(text, "t1021.004", " ssh"):
		return "ssh"
	case strings.Contains(text, "wmi remote"):
		return "wmi"
	default:
		return ""
	}
}

func predicateKey(p PredicateSpec) string {
	return strings.Join([]string{p.Type, p.Subject, p.Object, strings.ToLower(p.Protocol)}, "\x00")
}

func contractProduces(contract ActionContract, kind string) bool {
	for _, predicate := range contract.Produces {
		if predicate.Type == kind {
			return true
		}
	}
	return false
}

func proofOnlyRequirement(kind string) bool {
	switch kind {
	case "remote_access_proven", "identity_observed", "service_reachable":
		return true
	default:
		return false
	}
}

func requirementExecutionTarget(r Requirement) string {
	if (r.Type == "lateral_movement_validated" || r.Type == "remote_access_proven" || r.Type == "identity_observed" || r.Type == "service_reachable") && r.Source != "" {
		return r.Source
	}
	return r.Target
}

func requirementMatchesPredicate(r Requirement, predicate PredicateSpec) bool {
	if r.Type != predicate.Type {
		return false
	}
	switch r.Type {
	case "lateral_movement_validated", "remote_access_proven", "service_reachable", "identity_observed":
		if r.Type == "lateral_movement_validated" && r.Source == "" && r.Target == predicate.Subject && predicate.Object == "" {
			return predicate.Protocol == "" || r.Protocol == "" || strings.EqualFold(r.Protocol, predicate.Protocol)
		}
		if predicate.Subject != "" && r.Source != predicate.Subject {
			return false
		}
		if predicate.Object != "" && r.Target != predicate.Object {
			return false
		}
		if predicate.Protocol != "" && r.Protocol != "" && !strings.EqualFold(r.Protocol, predicate.Protocol) {
			return false
		}
		return true
	default:
		return predicate.Subject == "" || r.Target == predicate.Subject
	}
}

func contractCoversRequirement(c Catalog, contract ActionContract, r Requirement) bool {
	text := catalogText(c)
	if r.Technique != "" && !strings.Contains(text, strings.ToLower(r.Technique)) {
		return false
	}
	switch r.Type {
	case "detection_observed", "behavior_prevented":
		return true
	case "behavior_executed":
		return contractProduces(contract, "behavior_executed")
	case "credential_access_validated", "lateral_movement_validated", "domain_context_observed", "elevated_context_proven", "remote_access_proven", "service_reachable", "identity_observed":
		for _, produced := range contract.Produces {
			if requirementMatchesPredicate(r, produced) {
				if r.Type == "lateral_movement_validated" && r.Source != "" && r.Target != "" && contract.Protocol == "" {
					return false
				}
				if proofOnlyRequirement(r.Type) && r.Type != "service_reachable" && c.ID != lateralCatalogID &&
					!((r.Type == "remote_access_proven" || r.Type == "identity_observed") && contractProduces(contract, "lateral_movement_validated")) {
					return false
				}
				return true
			}
		}
	}
	return false
}
