package app

import "testing"

func TestKnownDiscoveryTextCreatesOnlyObservedADRelationships(t *testing.T) {
	const chain = "CHAIN_TI067_TERMINALFIX_DISCOVERY_TTPS"
	step := func(id, name, output string, success bool) map[string]any {
		return map[string]any{"id": id, "name": name, "done": true, "success": success, "output": map[string]any{"output": output}}
	}
	item := ValidatedItem{PlanItem: PlanItem{Kind: "endpoint_chain", CatalogID: chain, AssetIDs: []string{"asset-1"}}, Status: "completed", ExecutionID: "execution-1", Report: map[string]any{
		"id": "execution-1", "chain_id": chain,
		"assets": []any{map[string]any{"asset_id": "asset-1", "steps": []any{
			step("host", "Multilingual System Information Discovery using Systeminfo and Findstr", "Host Name: IRONHOLD\nDomain: sevenkingdoms.local", true),
			step("trust", "Domain Trust Enumeration via NLTEST", "0: NORTH north.sevenkingdoms.local (Direct Outbound) (Direct Inbound)\n1: SEVENKINGDOMS sevenkingdoms.local (Primary Domain)", true),
			step("admins", "Domain Administrators Enumeration via Net.exe", "The request will be processed at a domain controller for domain sevenkingdoms.local.\nGroup name Domain Admins\nMembers\n-----\nAdministrator     cersei.lannister\nThe command completed successfully.", true),
			step("failed", "Domain Trust Enumeration via NLTEST", "0: EVIL evil.local (Direct Outbound)\n1: SEVENKINGDOMS sevenkingdoms.local (Primary Domain)", false),
		}}},
	}}
	graph := extractADEvidence(item)
	kinds := map[string]int{}
	for _, edge := range graph.Edges {
		kinds[edge.Kind]++
		if edge.Kind == "remote_access" || edge.Kind == "can_smb" {
			t.Fatalf("discovery must not imply lateral access: %+v", edge)
		}
	}
	if kinds["member_of_domain"] != 1 || kinds["domain_trust"] != 1 || kinds["group_in_domain"] != 1 || kinds["member_of_group"] != 2 {
		t.Fatalf("unexpected relationships: %+v", kinds)
	}
	for _, node := range graph.Nodes {
		if node.Label == "evil.local" {
			t.Fatal("failed step contributed a domain")
		}
	}
	merged := mergeADGraph(ADGraph{Nodes: []ADGraphNode{{ID: graphNodeID("machine", "asset-1"), Kind: "machine", Label: "asset-1", AssetID: "asset-1"}}}, graph)
	for _, node := range merged.Nodes {
		if node.AssetID == "asset-1" && node.Label != "IRONHOLD" {
			t.Fatalf("observed hostname did not replace the placeholder: %+v", node)
		}
	}
}
