package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/session"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"
	"google.golang.org/genai"
)

var (
	exactAssetIDPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	actionIntentPattern = regexp.MustCompile(`(?i)\b(test|simulate|validate|execute|run|start|trigger|perform|launch|attempt|gain|obtain|move|access|prove)\b`)
	strongActionPattern = regexp.MustCompile(`(?i)\b(test|simulate|validate|execute|start|trigger|perform|launch|attempt|gain|obtain|move|prove)\b`)
	informationPrefix   = regexp.MustCompile(`(?i)^\s*(what|which|why|how|list|show|find|tell|explain)\b`)
	techniquePattern    = regexp.MustCompile(`(?i)\bT\d{4}(?:\.\d{3})?\b`)
	userContextPattern  = regexp.MustCompile(`(?i)\b(user (?:permissions?|perms?|context)|ordinary user|standard[- ]user|non[- ]elevated|low[- ]privilege(?:d)?)\b`)
	adminContextPattern = regexp.MustCompile(`(?i)\b(start(?:ing)? (?:as|with)|given|already have)\s+(?:an?\s+)?(?:admin(?:istrator)?|elevated|system)\b`)
)

func shouldAutoMission(message string) bool {
	if !exactAssetIDPattern.MatchString(message) || !actionIntentPattern.MatchString(message) {
		return false
	}
	if informationPrefix.MatchString(message) {
		return strongActionPattern.MatchString(message)
	}
	return true
}

func groundMissionInput(message string, input MissionInput) (MissionInput, error) {
	allowed := map[string]string{}
	for _, id := range exactAssetIDPattern.FindAllString(message, -1) {
		allowed[strings.ToLower(id)] = id
	}
	explicitTechniques := map[string]bool{}
	for _, technique := range techniquePattern.FindAllString(message, -1) {
		explicitTechniques[strings.ToUpper(technique)] = true
	}
	userContextOnly := userContextPattern.MatchString(message)
	grounded := make([]Requirement, 0, len(input.Requirements))
	for index := range input.Requirements {
		requirement := input.Requirements[index]
		requirement.ID = ""
		if userContextOnly {
			switch normalizeRequirementType(requirement.Type) {
			case "domain_context_observed", "elevated_context_proven", "behavior_executed", "remote_access_proven":
				requirement.UserContextOnly = true
			}
		}
		if normalizeRequirementType(requirement.Type) == "behavior_executed" && requirement.Technique != "" && !explicitTechniques[strings.ToUpper(requirement.Technique)] {
			// The intake model may structure an explicitly named technique, but it
			// may not invent a blanket reconnaissance checklist.
			continue
		}
		for field, value := range map[string]*string{"source": &requirement.Source, "target": &requirement.Target} {
			id := strings.TrimSpace(*value)
			if id == "" {
				continue
			}
			canonical, ok := allowed[strings.ToLower(id)]
			if exactAssetIDPattern.FindString(id) != id || !ok {
				return MissionInput{}, fmt.Errorf("requirement %d %s asset ID %q was not present in the operator request", index+1, field, id)
			}
			*value = canonical
		}
		grounded = append(grounded, requirement)
	}
	if len(grounded) == 0 {
		return MissionInput{}, fmt.Errorf("mission intake returned no grounded requirements")
	}
	// A requested administrator identity on a remote destination is proved by
	// remote_access_proven plus identity_observed. A direct elevation action on
	// that destination would run through its existing FourCore agent and cannot
	// prove that the source reached it laterally, so discard that redundant LLM
	// interpretation before it enters the deterministic planner.
	remoteDestinations := map[string]bool{}
	for _, requirement := range grounded {
		if normalizeRequirementType(requirement.Type) == "remote_access_proven" && requirement.Source != "" && requirement.Target != "" && requirement.Source != requirement.Target {
			remoteDestinations[requirement.Target] = true
		}
	}
	filtered := grounded[:0]
	for _, requirement := range grounded {
		if normalizeRequirementType(requirement.Type) == "elevated_context_proven" && remoteDestinations[requirement.Target] {
			continue
		}
		filtered = append(filtered, requirement)
	}
	grounded = filtered
	// A standard-user foothold is a starting assumption, not a mandatory
	// source-elevation objective. An observed user-level permission may already
	// permit the shortest path to the destination.
	starting := []StartingAccess{}
	seenStarting := map[string]bool{}
	for _, access := range input.StartingAccess {
		id := strings.TrimSpace(access.AssetID)
		canonical, ok := allowed[strings.ToLower(id)]
		if !ok || exactAssetIDPattern.FindString(id) != id {
			return MissionInput{}, fmt.Errorf("starting-access asset ID %q was not present in the operator request", id)
		}
		level := strings.ToLower(strings.TrimSpace(access.AccessLevel))
		if (level == "user" && !userContextOnly) || (level == "administrator" && !adminContextPattern.MatchString(message)) {
			return MissionInput{}, fmt.Errorf("starting-access level %q was not stated by the operator", access.AccessLevel)
		}
		if access.Identity != "" && !strings.Contains(strings.ToLower(message), strings.ToLower(access.Identity)) {
			return MissionInput{}, fmt.Errorf("starting-access identity was not stated by the operator")
		}
		access.AssetID = canonical
		starting = append(starting, access)
		seenStarting[canonical] = true
	}
	if userContextOnly {
		for _, requirement := range grounded {
			if normalizeRequirementType(requirement.Type) == "remote_access_proven" && requirement.Source != "" && !seenStarting[requirement.Source] {
				starting = append(starting, StartingAccess{AssetID: requirement.Source, AccessLevel: "user"})
				seenStarting[requirement.Source] = true
			}
		}
	}
	input.Requirements = grounded
	input.StartingAccess = starting
	// The persisted objective is always the operator's exact text. The model is
	// allowed to structure the request, not rewrite the audit record.
	input.Request = strings.TrimSpace(message)
	return input, nil
}

const missionIntakeInstruction = `Convert the operator's security-validation request into machine-readable requirements and call submit_mission_requirements exactly once.
Do not choose catalogue IDs, simulations, commands, payloads, or attack tools. Preserve the original request in request.
Use only exact asset IDs appearing in the request. Every requirement is mandatory and starts unknown.
Supported requirement types: behavior_executed, domain_context_observed, credential_access_validated, lateral_movement_validated, remote_access_proven, identity_observed, elevated_context_proven, service_reachable, detection_observed, behavior_prevented.
For a named MITRE technique, create behavior_executed with that technique and its target. Create behavior_executed only for MITRE technique IDs explicitly written by the operator. Never invent reconnaissance technique IDs from phrases such as information gathering, discovery, or reconnaissance. For an AD lateral objective, represent minimal information gathering as domain_context_observed; the server will order it before credential access and lateral movement.
If the operator asks only to execute or validate a lateral-movement chain on one source asset, create lateral_movement_validated with target set to that source asset ID and no source or destination. This proves only that the matching simulation action executed; do not invent a remote machine, credentials, or an administrator requirement.
If the operator explicitly asks to prove access to a second machine, create remote_access_proven with source and destination asset IDs, protocol when stated, and expected_identity when stated. The server will deterministically expand its prerequisites. Do not turn a request for chain execution alone into remote_access_proven.
When the operator states a starting context, put it in starting_access with the exact source asset ID and access_level=user or administrator. This is an assumption, not a proven fact. For starting user context also set user_context_only=true on starting discovery, explicit privilege-escalation, and remote-access requirements; do not constrain later credential or lateral stages to user context. Do not invent a source-side elevated_context_proven objective merely because the user starts with ordinary permissions: a user-level route may already exist. Do not add destination-side elevated_context_proven merely because the desired destination identity is administrator.
Use endpoint_chain unless the request explicitly targets an email asset.
Do not mark anything proven and do not claim that a credential, session, identity, detection, or prevention exists.`

func (s *Service) ExtractMissionInput(ctx context.Context, message string, llm model.LLM) (MissionInput, error) {
	var captured MissionInput
	submit, err := functiontool.New(functiontool.Config{
		Name:        "submit_mission_requirements",
		Description: "Submit the typed objective predicates extracted from the operator request. This does not execute anything.",
	}, func(_ agent.Context, input MissionInput) (map[string]any, error) {
		captured = input
		return map[string]any{"accepted": true}, nil
	})
	if err != nil {
		return MissionInput{}, err
	}
	intake, err := llmagent.New(llmagent.Config{
		Name:        "mission_intake",
		Description: "Extract typed security-validation objectives without selecting attacks.",
		Model:       llm,
		Instruction: missionIntakeInstruction,
		Tools:       []tool.Tool{submit},
	})
	if err != nil {
		return MissionInput{}, err
	}
	sessions := session.InMemoryService()
	sessionID := "mission-intake-" + newID()
	created, err := sessions.Create(ctx, &session.CreateRequest{AppName: "fourcore-mission-intake", UserID: "operator", SessionID: sessionID})
	if err != nil {
		return MissionInput{}, err
	}
	r, err := runner.New(runner.Config{AppName: "fourcore-mission-intake", Agent: intake, SessionService: sessions})
	if err != nil {
		return MissionInput{}, err
	}
	runCtx, cancel := context.WithTimeout(modelBudget(ctx), 2*time.Minute)
	defer cancel()
	for event, runErr := range r.Run(runCtx, "operator", created.Session.ID(), &genai.Content{Role: "user", Parts: []*genai.Part{{Text: message}}}, agent.RunConfig{StreamingMode: agent.StreamingModeNone}) {
		if runErr != nil {
			return MissionInput{}, runErr
		}
		if event.ErrorCode != "" {
			return MissionInput{}, fmt.Errorf("mission intake error: %s", event.ErrorCode)
		}
	}
	if len(captured.Requirements) == 0 {
		return MissionInput{}, fmt.Errorf("mission intake returned no requirements")
	}
	return groundMissionInput(message, captured)
}

func (s *Service) autoMissionChat(ctx context.Context, id, message string, llm model.LLM) (ChatResult, error) {
	result, err := s.RunMissionRequestGraph(ctx, id, message, llm)
	reply := ""
	if err != nil {
		var workflowErr *MissionWorkflowError
		if !errors.As(err, &workflowErr) {
			return ChatResult{SessionID: id}, fmt.Errorf("could not run mission workflow: %w", err)
		}
		if workflowErr.Kind == "clarification" {
			reply = "I need clarification before I can create a mission: " + workflowErr.Reason
		} else {
			reply = "The mission was rejected: " + workflowErr.Reason
		}
	} else {
		reply = formatMissionPlanResult(result)
	}
	chat := Chat{ID: id, Messages: []ChatMessage{}}
	if err := s.Store.Get("chats", id, &chat); err != nil && err != ErrNotFound {
		return ChatResult{SessionID: id}, err
	}
	now := time.Now().UTC()
	chat.Messages = append(chat.Messages, ChatMessage{Role: "user", Text: message, At: now}, ChatMessage{Role: "assistant", Text: reply, At: now})
	if len(chat.Messages) > 100 {
		chat.Messages = chat.Messages[len(chat.Messages)-100:]
	}
	if err := s.Store.Put("chats", id, chat); err != nil {
		return ChatResult{SessionID: id}, err
	}
	plans, err := s.Store.Plans()
	if err != nil {
		return ChatResult{SessionID: id}, err
	}
	sessionPlans := []Plan{}
	for _, plan := range plans {
		if plan.SessionID == id {
			sessionPlans = append(sessionPlans, plan)
		}
	}
	return ChatResult{SessionID: id, Reply: reply, Plans: sessionPlans}, nil
}
