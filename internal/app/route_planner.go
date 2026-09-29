package app

import (
	"fmt"
	"sort"
	"strings"
)

// GoalDirectedRoute is deliberately mission-scoped. It searches only the
// evidence already collected for the requested source and destination; it does
// not enumerate the directory or construct an organization-wide attack graph.
type GoalDirectedRoute struct {
	SourceAssetID      string   `json:"source_asset_id"`
	DestinationAssetID string   `json:"destination_asset_id"`
	Protocol           string   `json:"protocol"`
	Ready              bool     `json:"ready"`
	NodeIDs            []string `json:"node_ids,omitempty"`
	EdgeIDs            []string `json:"edge_ids,omitempty"`
	Missing            []string `json:"missing,omitempty"`
	Reason             string   `json:"reason"`
}

type MachineHop struct {
	SourceAssetID      string   `json:"source_asset_id"`
	DestinationAssetID string   `json:"destination_asset_id"`
	Protocol           string   `json:"protocol"`
	NodeIDs            []string `json:"node_ids"`
	EdgeIDs            []string `json:"edge_ids"`
}

// machineHops projects a relationship path onto the machine transitions that
// must each receive their own authorized execution and destination proof.
func machineHops(graph ADGraph, route GoalDirectedRoute) []MachineHop {
	if !route.Ready || len(route.NodeIDs) < 2 || len(route.EdgeIDs) != len(route.NodeIDs)-1 {
		return nil
	}
	nodes := map[string]ADGraphNode{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	positions := []int{}
	for index, id := range route.NodeIDs {
		if node := nodes[id]; node.Kind == "machine" && node.AssetID != "" {
			positions = append(positions, index)
		}
	}
	if len(positions) < 2 {
		return nil
	}
	hops := []MachineHop{}
	for index := 0; index+1 < len(positions); index++ {
		start, end := positions[index], positions[index+1]
		source, destination := nodes[route.NodeIDs[start]].AssetID, nodes[route.NodeIDs[end]].AssetID
		if source == destination {
			continue
		}
		hops = append(hops, MachineHop{
			SourceAssetID: source, DestinationAssetID: destination, Protocol: route.Protocol,
			NodeIDs: append([]string(nil), route.NodeIDs[start:end+1]...),
			EdgeIDs: append([]string(nil), route.EdgeIDs[start:end]...),
		})
	}
	return hops
}

// A reachable port is not an executable transition. Require an identity
// observed on the source and a matching permission on the destination, or a
// previously verified remote-access result for this exact hop.
func executableHop(graph ADGraph, hop MachineHop) bool {
	edges := map[string]ADGraphEdge{}
	nodes := map[string]ADGraphNode{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	for _, edge := range graph.Edges {
		edges[edge.ID] = edge
	}
	usablePrincipals := map[string]bool{}
	protocolPermission := false
	adminPermission := false
	for _, id := range hop.EdgeIDs {
		edge := edges[id]
		if edge.Status != "observed" && edge.Status != "verified" {
			continue
		}
		if edge.Kind == "remote_access" && edge.Status == "verified" &&
			nodes[edge.Source].AssetID == hop.SourceAssetID && nodes[edge.Target].AssetID == hop.DestinationAssetID &&
			strings.EqualFold(edge.Protocol, hop.Protocol) {
			return true
		}
		if edge.Kind == "session_on" && nodes[edge.Target].AssetID == hop.SourceAssetID && nodes[edge.Source].Kind == "identity" {
			usablePrincipals[edge.Source] = true
		}
		if edge.Kind == "member_of_group" && usablePrincipals[edge.Source] {
			usablePrincipals[edge.Target] = true
		}
		if edge.Kind == "can_"+strings.ToLower(hop.Protocol) &&
			nodes[edge.Target].AssetID == hop.DestinationAssetID && usablePrincipals[edge.Source] {
			protocolPermission = true
		}
		if edge.Kind == "admin_to" && nodes[edge.Target].AssetID == hop.DestinationAssetID && usablePrincipals[edge.Source] {
			adminPermission = true
		}
	}
	if len(usablePrincipals) == 0 {
		return false
	}
	if protocolPermission {
		return true
	}
	if !adminPermission {
		return false
	}
	// Admin rights do not imply a usable transport. Both sides of the same
	// observed service must be bound to this source and destination.
	for _, reachable := range graph.Edges {
		if reachable.Kind != "service_reachable" || reachable.Status != "observed" ||
			nodes[reachable.Source].AssetID != hop.SourceAssetID || !strings.EqualFold(reachable.Protocol, hop.Protocol) {
			continue
		}
		for _, hosted := range graph.Edges {
			if hosted.Kind == "service_on" && hosted.Status == "observed" && hosted.Target == reachable.Target &&
				nodes[hosted.Source].AssetID == hop.DestinationAssetID {
				return true
			}
		}
	}
	return false
}

func routeMachineNode(graph ADGraph, assetID string) string {
	for _, node := range graph.Nodes {
		if node.Kind == "machine" && (node.AssetID == assetID || strings.EqualFold(node.Label, assetID)) {
			return node.ID
		}
	}
	return ""
}

func routeEdgeAllowed(edge ADGraphEdge, nodes map[string]ADGraphNode, protocol string) bool {
	if edge.Status != "observed" && edge.Status != "verified" {
		return false
	}
	if edge.Protocol != "" && protocol != "" && !strings.EqualFold(edge.Protocol, protocol) {
		return false
	}
	switch edge.Kind {
	case "service_reachable", "service_on", "session_on", "member_of_group", "admin_to", "delegation", "domain_trust", "remote_access",
		"can_smb", "can_rdp", "can_winrm", "can_ssh":
		if strings.HasPrefix(edge.Kind, "can_") && !strings.EqualFold(strings.TrimPrefix(edge.Kind, "can_"), protocol) {
			return false
		}
		return true
	case "acl":
		label := strings.ToLower(edge.Label)
		target := nodes[edge.Target]
		return target.Kind == "machine" && containsAny(label, "admin", "genericall", "full control", "writeall", "write_dacl", "write owner")
	default:
		return false
	}
}

type routeHop struct {
	to     string
	edgeID string
}

// observedRemoteRoute searches only completed, destination-specific remote
// observations. Relationship and simulation edges cannot establish a reached
// machine. It is separate from the prospective AD permission route above.
func observedRemoteRoute(graph ADGraph, source, destination, protocol string) GoalDirectedRoute {
	route := GoalDirectedRoute{SourceAssetID: source, DestinationAssetID: destination, Protocol: strings.ToLower(strings.TrimSpace(protocol))}
	start, goal := routeMachineNode(graph, source), routeMachineNode(graph, destination)
	if start == "" || goal == "" || start == goal {
		return route
	}
	nodes := map[string]ADGraphNode{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = node
	}
	adjacency := map[string][]routeHop{}
	for _, edge := range graph.Edges {
		if edge.Kind != "remote_access" || (edge.Status != "observed" && edge.Status != "verified") ||
			(protocol != "" && !strings.EqualFold(edge.Protocol, protocol)) ||
			nodes[edge.Source].Kind != "machine" || nodes[edge.Target].Kind != "machine" ||
			nodes[edge.Source].AssetID == "" || nodes[edge.Target].AssetID == "" {
			continue
		}
		adjacency[edge.Source] = append(adjacency[edge.Source], routeHop{to: edge.Target, edgeID: edge.ID})
	}
	for id := range adjacency {
		sort.Slice(adjacency[id], func(i, j int) bool {
			if adjacency[id][i].to != adjacency[id][j].to {
				return adjacency[id][i].to < adjacency[id][j].to
			}
			return adjacency[id][i].edgeID < adjacency[id][j].edgeID
		})
	}
	type path struct{ nodes, edges []string }
	queue := []path{{nodes: []string{start}}}
	seen := map[string]bool{start: true}
	for len(queue) > 0 && len(seen) <= 256 {
		current := queue[0]
		queue = queue[1:]
		last := current.nodes[len(current.nodes)-1]
		if last == goal {
			route.Ready, route.NodeIDs, route.EdgeIDs = true, current.nodes, current.edges
			route.Reason = fmt.Sprintf("%d destination-specific remote observations connect source to destination", len(current.edges))
			return route
		}
		for _, hop := range adjacency[last] {
			if seen[hop.to] {
				continue
			}
			seen[hop.to] = true
			queue = append(queue, path{nodes: append(append([]string(nil), current.nodes...), hop.to), edges: append(append([]string(nil), current.edges...), hop.edgeID)})
		}
	}
	return route
}

func observedRemoteFrontier(graph ADGraph, source, protocol string) []string {
	frontier := []string{}
	seen := map[string]bool{}
	for _, node := range graph.Nodes {
		if node.Kind != "machine" || node.AssetID == "" || node.AssetID == source || seen[node.AssetID] {
			continue
		}
		if observedRemoteRoute(graph, source, node.AssetID, protocol).Ready {
			seen[node.AssetID] = true
			frontier = append(frontier, node.AssetID)
		}
	}
	sort.Strings(frontier)
	return frontier
}

// Separate endpoint runs do not establish a pivot. Every later report must
// explicitly identify the execution that obtained its source access.
func correlatedObservedRemoteRoute(graph ADGraph, route GoalDirectedRoute, finalExecutionID string) bool {
	if !route.Ready || len(route.EdgeIDs) == 0 || finalExecutionID == "" {
		return false
	}
	edges := map[string]ADGraphEdge{}
	evidence := map[string]ADGraphEvidence{}
	for _, edge := range graph.Edges {
		edges[edge.ID] = edge
	}
	for _, record := range graph.Evidence {
		evidence[record.ID] = record
	}
	previous := map[string]bool{}
	for index, edgeID := range route.EdgeIDs {
		edge, exists := edges[edgeID]
		if !exists || edge.Kind != "remote_access" || (edge.Status != "observed" && edge.Status != "verified") {
			return false
		}
		next := map[string]bool{}
		for _, evidenceID := range edge.EvidenceIDs {
			record := evidence[evidenceID]
			if record.ExecutionID != "" && (index == 0 || previous[record.ParentExecutionID]) {
				next[record.ExecutionID] = true
			}
		}
		if len(next) == 0 {
			return false
		}
		previous = next
	}
	return previous[finalExecutionID]
}

func goalDirectedADRoute(mission Mission, source, destination, protocol string) GoalDirectedRoute {
	route := GoalDirectedRoute{SourceAssetID: source, DestinationAssetID: destination, Protocol: strings.ToLower(strings.TrimSpace(protocol))}
	if source == "" || destination == "" {
		route.Missing = []string{"source and destination asset IDs"}
		route.Reason = "the lateral objective does not identify both endpoints"
		return route
	}
	if !validLateralProtocol(route.Protocol) {
		route.Missing = []string{"supported protocol (smb, winrm, rdp, or ssh)"}
		route.Reason = "the route has no supported protocol"
		return route
	}
	nodes := map[string]ADGraphNode{}
	for _, node := range mission.ADGraph.Nodes {
		nodes[node.ID] = node
	}
	start, goal := routeMachineNode(mission.ADGraph, source), routeMachineNode(mission.ADGraph, destination)
	if start == "" {
		route.Missing = append(route.Missing, "source machine evidence")
	}
	if goal == "" {
		route.Missing = append(route.Missing, "destination machine evidence")
	}
	if len(route.Missing) > 0 {
		route.Reason = "goal-directed graph needs " + strings.Join(route.Missing, " and ")
		return route
	}
	adjacency := map[string][]routeHop{}
	for _, edge := range mission.ADGraph.Edges {
		if !routeEdgeAllowed(edge, nodes, route.Protocol) {
			continue
		}
		switch edge.Kind {
		case "session_on":
			// A session observed on the source makes that identity relevant to the
			// goal. Traverse from the machine to the identity, not vice versa.
			adjacency[edge.Target] = append(adjacency[edge.Target], routeHop{to: edge.Source, edgeID: edge.ID})
		case "service_on":
			// service_reachable ends on the service node; service_on identifies
			// which destination machine owns it.
			adjacency[edge.Target] = append(adjacency[edge.Target], routeHop{to: edge.Source, edgeID: edge.ID})
		default:
			adjacency[edge.Source] = append(adjacency[edge.Source], routeHop{to: edge.Target, edgeID: edge.ID})
			if !edge.Directed {
				adjacency[edge.Target] = append(adjacency[edge.Target], routeHop{to: edge.Source, edgeID: edge.ID})
			}
		}
	}
	for nodeID := range adjacency {
		sort.Slice(adjacency[nodeID], func(i, j int) bool {
			if adjacency[nodeID][i].to != adjacency[nodeID][j].to {
				return adjacency[nodeID][i].to < adjacency[nodeID][j].to
			}
			return adjacency[nodeID][i].edgeID < adjacency[nodeID][j].edgeID
		})
	}
	type path struct {
		nodes       []string
		edges       []string
		machineHops int
	}
	queue := []path{{nodes: []string{start}}}
	expanded := 0
	for len(queue) > 0 {
		if expanded >= 4096 {
			break
		}
		// Minimize machine transitions first, then relationship count. A
		// two-hop route must never outrank a feasible direct hop merely
		// because its directory representation has fewer edges.
		sort.SliceStable(queue, func(i, j int) bool {
			if queue[i].machineHops != queue[j].machineHops {
				return queue[i].machineHops < queue[j].machineHops
			}
			return len(queue[i].edges) < len(queue[j].edges)
		})
		current := queue[0]
		queue = queue[1:]
		expanded++
		last := current.nodes[len(current.nodes)-1]
		if last == goal {
			route.NodeIDs = current.nodes
			route.EdgeIDs = current.edges
			hops := machineHops(mission.ADGraph, GoalDirectedRoute{Ready: true, Protocol: route.Protocol, NodeIDs: current.nodes, EdgeIDs: current.edges})
			compatible := len(hops) > 0
			for _, hop := range hops {
				compatible = compatible && executableHop(mission.ADGraph, hop)
			}
			if compatible {
				route.Ready = true
				route.Reason = fmt.Sprintf("shortest identity-and-protocol-evidenced route uses %d machine hops and %d relationships; action compatibility still requires preflight", len(hops), len(current.edges))
				return route
			}
			continue
		}
		for _, hop := range adjacency[last] {
			if containsString(current.nodes, hop.to) {
				continue
			}
			machineHops := current.machineHops
			if nodes[hop.to].Kind == "machine" && nodes[hop.to].AssetID != "" && hop.to != start {
				machineHops++
			}
			queue = append(queue, path{nodes: append(append([]string(nil), current.nodes...), hop.to), edges: append(append([]string(nil), current.edges...), hop.edgeID), machineHops: machineHops})
		}
	}
	route.NodeIDs, route.EdgeIDs = nil, nil
	route.Missing = []string{"a source session/identity with destination permission (or verified access) on every hop"}
	route.Reason = "no identity-bound, executable evidence route connects the requested source to destination"
	return route
}
