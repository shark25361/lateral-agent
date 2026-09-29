package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const lateralCatalogID = "LAB_LATERAL_V1"

type ActionInputField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required"`
	Description string   `json:"description,omitempty"`
	Allowed     []string `json:"allowed,omitempty"`
}

type ActionInputSchema struct {
	Version string             `json:"version"`
	Fields  []ActionInputField `json:"fields"`
}

type LateralActionInput struct {
	DestinationHost   string   `json:"destination_host"`
	Protocol          string   `json:"protocol"`
	Port              int      `json:"port"`
	CredentialRefHash string   `json:"credential_reference_hash"`
	ExpectedIdentity  string   `json:"expected_identity,omitempty"`
	CorrelationID     string   `json:"correlation_id"`
	RouteNodeIDs      []string `json:"route_node_ids,omitempty"`
	RouteEdgeIDs      []string `json:"route_edge_ids,omitempty"`
}

func lateralInputSchema() ActionInputSchema {
	return ActionInputSchema{Version: "1", Fields: []ActionInputField{
		{Name: "destination_host", Type: "host", Required: true, Description: "Destination bound to an allowlisted asset ID."},
		{Name: "protocol", Type: "enum", Required: true, Allowed: []string{"smb", "winrm", "rdp", "ssh"}},
		{Name: "port", Type: "integer", Required: true},
		{Name: "credential_reference", Type: "opaque_reference", Required: true, Description: "Resolved only at dispatch; credential material is never persisted."},
		{Name: "expected_identity", Type: "string", Required: false},
		{Name: "correlation_id", Type: "identifier", Required: true},
	}}
}

func protocolPort(protocol string) int {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "smb":
		return 445
	case "winrm":
		return 5985
	case "rdp":
		return 3389
	case "ssh":
		return 22
	default:
		return 0
	}
}

func validLateralProtocol(protocol string) bool { return protocolPort(protocol) != 0 }

func lateralCatalog() Catalog {
	return Catalog{ID: lateralCatalogID, Name: "Goal-directed controlled-lab lateral access", Platforms: []string{"windows"}, Tags: map[string]any{"category": "lateral movement", "executor": "controlled_lab", "schema_version": "1"}}
}

func lateralContract(source, destination, protocol string) ActionContract {
	return ActionContract{
		ExecutionRole: "source",
		Source:        source,
		Destination:   destination,
		Protocol:      protocol,
		Requires: []PredicateSpec{
			{Type: "domain_context_observed", Subject: source},
			{Type: "credential_access_validated", Subject: source},
			{Type: "service_reachable", Subject: source, Object: destination, Protocol: protocol},
		},
		Produces: []PredicateSpec{
			{Type: "lateral_movement_validated", Subject: source, Object: destination, Protocol: protocol},
			{Type: "service_reachable", Subject: source, Object: destination, Protocol: protocol},
			{Type: "remote_access_proven", Subject: source, Object: destination, Protocol: protocol},
			{Type: "identity_observed", Subject: source, Object: destination, Protocol: protocol},
		},
		EvidenceRules: []string{
			"The destination evidence must have a valid Ed25519 signature.",
			"Correlation, source, destination, protocol, and observation time must match the authorized input hash.",
			"Remote access and identity are proven only by destination-side fields, never by executor acceptance alone.",
		},
	}
}

type lateralSubmitRequest struct {
	InputHash           string `json:"input_hash"`
	CorrelationID       string `json:"correlation_id"`
	SourceAssetID       string `json:"source_asset_id"`
	DestinationAssetID  string `json:"destination_asset_id"`
	DestinationHost     string `json:"destination_host"`
	Protocol            string `json:"protocol"`
	Port                int    `json:"port"`
	CredentialReference string `json:"credential_reference"`
	ExpectedIdentity    string `json:"expected_identity,omitempty"`
}

type lateralSubmitResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// LateralEvidence is the canonical destination-side statement. Signature is
// excluded from the signed JSON and is carried separately in the envelope.
type LateralEvidence struct {
	ExecutionID        string    `json:"execution_id"`
	InputHash          string    `json:"input_hash"`
	CorrelationID      string    `json:"correlation_id"`
	SourceAssetID      string    `json:"source_asset_id"`
	DestinationAssetID string    `json:"destination_asset_id"`
	Protocol           string    `json:"protocol"`
	Port               int       `json:"port"`
	ServiceReachable   bool      `json:"service_reachable"`
	RemoteAccess       bool      `json:"remote_access"`
	Identity           string    `json:"identity"`
	Integrity          string    `json:"integrity"`
	ObservedAt         time.Time `json:"observed_at"`
}

type lateralEvidenceEnvelope struct {
	Status    string          `json:"status"`
	Error     string          `json:"error,omitempty"`
	Evidence  LateralEvidence `json:"evidence"`
	Signature string          `json:"signature"`
}

type LateralHealth struct {
	Status            string   `json:"status"`
	Execute           bool     `json:"execute"`
	SignedEvidence    bool     `json:"signed_evidence"`
	Protocols         []string `json:"protocols"`
	SchemaVersion     string   `json:"schema_version"`
	CredentialRefs    bool     `json:"credential_references"`
	DestinationVerify bool     `json:"destination_verification"`
}

type LateralExecutor struct {
	Base       string
	Bases      map[string]string
	Token      string
	PublicKey  ed25519.PublicKey
	PublicKeys map[string]ed25519.PublicKey
	HTTP       *http.Client
	Refs       map[string]string
}

type EvidenceVerificationError struct{ Detail string }

func (e *EvidenceVerificationError) Error() string {
	return "destination evidence rejected: " + e.Detail
}

func NewLateralExecutor(config Config) *LateralExecutor {
	if !config.LateralEnabled {
		return nil
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(config.LateralEvidencePublicKey))
	keys := map[string]ed25519.PublicKey{}
	for destination, encoded := range config.LateralEvidencePublicKeys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil && len(key) == ed25519.PublicKeySize {
			keys[destination] = ed25519.PublicKey(key)
		}
	}
	return &LateralExecutor{
		Base: strings.TrimRight(config.LateralExecutorURL, "/"), Bases: config.LateralSourceExecutors, Token: config.LateralExecutorToken,
		PublicKey: ed25519.PublicKey(raw), PublicKeys: keys, Refs: config.LateralCredentialRefs,
		HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (l *LateralExecutor) client() *http.Client {
	if l.HTTP != nil {
		return l.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (l *LateralExecutor) do(ctx context.Context, method, path string, body any, out any) error {
	return l.doAt(ctx, l.Base, method, path, body, out)
}

func (l *LateralExecutor) endpoint(sourceAssetID string) string {
	if l == nil {
		return ""
	}
	if len(l.Bases) > 0 {
		return strings.TrimRight(l.Bases[sourceAssetID], "/")
	}
	return l.Base
}

func (l *LateralExecutor) doAt(ctx context.Context, base, method, path string, body any, out any) error {
	if l == nil || base == "" {
		return fmt.Errorf("controlled-lab lateral executor is not configured")
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+l.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := l.client().Do(req)
	if err != nil {
		return fmt.Errorf("lateral executor transport failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return fmt.Errorf("lateral executor response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Status: resp.StatusCode, Detail: httpErrorDetail(raw)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid lateral executor response: %w", err)
	}
	return nil
}

func (l *LateralExecutor) Health(ctx context.Context) (LateralHealth, error) {
	var health LateralHealth
	err := l.doAt(ctx, l.Base, http.MethodGet, "/v1/health", nil, &health)
	return health, err
}

func (l *LateralExecutor) HealthForSource(ctx context.Context, sourceAssetID string) (LateralHealth, error) {
	var health LateralHealth
	base := l.endpoint(sourceAssetID)
	if err := l.doAt(ctx, base, http.MethodGet, "/v1/health", nil, &health); err != nil {
		return health, err
	}
	return health, nil
}

func (l *LateralExecutor) Submit(ctx context.Context, item PlanItem) (string, map[string]any, error) {
	if item.LateralInput == nil {
		return "", nil, fmt.Errorf("lateral action input is missing")
	}
	credentialReference := l.Refs[item.LateralInput.CredentialRefHash]
	if credentialReference == "" {
		return "", nil, fmt.Errorf("authorized credential reference is no longer configured")
	}
	request := lateralSubmitRequest{
		InputHash:     lateralInputFingerprint(item),
		CorrelationID: item.LateralInput.CorrelationID, SourceAssetID: item.SourceAssetID,
		DestinationAssetID: item.DestinationAssetID, DestinationHost: item.LateralInput.DestinationHost,
		Protocol: item.LateralInput.Protocol, Port: item.LateralInput.Port,
		CredentialReference: credentialReference, ExpectedIdentity: item.LateralInput.ExpectedIdentity,
	}
	var response lateralSubmitResponse
	if err := l.doAt(ctx, l.endpoint(item.SourceAssetID), http.MethodPost, "/v1/lateral/executions", request, &response); err != nil {
		return "", nil, err
	}
	if validID(response.ID) != nil {
		return "", nil, fmt.Errorf("lateral executor returned no usable execution ID")
	}
	return response.ID, map[string]any{"id": response.ID, "status": response.Status, "correlation_id": request.CorrelationID}, nil
}

func canonicalEvidence(evidence LateralEvidence) ([]byte, error) { return json.Marshal(evidence) }

func evidenceDigest(evidence LateralEvidence) string {
	raw, _ := canonicalEvidence(evidence)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (l *LateralExecutor) verifyEvidence(item ValidatedItem, envelope lateralEvidenceEnvelope) error {
	publicKey := l.PublicKey
	if len(l.PublicKeys) > 0 {
		publicKey = l.PublicKeys[item.DestinationAssetID]
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("destination evidence public key is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("destination evidence signature is invalid")
	}
	canonical, err := canonicalEvidence(envelope.Evidence)
	if err != nil || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("destination evidence signature verification failed")
	}
	input := item.LateralInput
	if input == nil || envelope.Evidence.CorrelationID != input.CorrelationID || envelope.Evidence.SourceAssetID != item.SourceAssetID || envelope.Evidence.DestinationAssetID != item.DestinationAssetID || !strings.EqualFold(envelope.Evidence.Protocol, input.Protocol) || envelope.Evidence.Port != input.Port || envelope.Evidence.InputHash != lateralInputFingerprint(item.PlanItem) || envelope.Evidence.ExecutionID != item.ExecutionID {
		return fmt.Errorf("destination evidence does not match the authorized route")
	}
	if input.ExpectedIdentity != "" && !identityMatches(envelope.Evidence.Identity, input.ExpectedIdentity) {
		return fmt.Errorf("destination identity does not match the authorized expected identity")
	}
	if envelope.Evidence.ObservedAt.IsZero() || envelope.Evidence.ObservedAt.After(time.Now().Add(5*time.Minute)) || (!item.SubmittedAt.IsZero() && envelope.Evidence.ObservedAt.Before(item.SubmittedAt.Add(-time.Minute))) {
		return fmt.Errorf("destination evidence observation time is outside the authorized execution window")
	}
	return nil
}

func (l *LateralExecutor) Report(ctx context.Context, executionID string, item ValidatedItem) (map[string]any, error) {
	if validID(executionID) != nil {
		return nil, fmt.Errorf("invalid lateral execution ID")
	}
	var envelope lateralEvidenceEnvelope
	if err := l.doAt(ctx, l.endpoint(item.SourceAssetID), http.MethodGet, "/v1/lateral/executions/"+url.PathEscape(executionID), nil, &envelope); err != nil {
		return nil, err
	}
	status := strings.ToLower(strings.TrimSpace(envelope.Status))
	if status == "failed" || status == "aborted" {
		return map[string]any{"id": executionID, "status": status, "error": envelope.Error, "correlation_id": item.LateralInput.CorrelationID}, nil
	}
	if status != "completed" {
		return map[string]any{"id": executionID, "status": status, "correlation_id": item.LateralInput.CorrelationID}, nil
	}
	if err := l.verifyEvidence(item, envelope); err != nil {
		return nil, &EvidenceVerificationError{Detail: err.Error()}
	}
	if !envelope.Evidence.RemoteAccess {
		return map[string]any{"id": executionID, "status": "failed", "error": "destination verifier did not observe remote access", "correlation_id": item.LateralInput.CorrelationID, "signed_evidence": envelope}, nil
	}
	evidence := envelope.Evidence
	// A username containing Administrator is not sufficient: a filtered
	// medium-integrity Windows token does not demonstrate administrator rights.
	isAdmin := destinationAdminIntegrity(evidence.Integrity)
	success := status == "completed" && evidence.RemoteAccess
	return map[string]any{
		"id": executionID, "status": status, "status_state": strings.ToUpper(status), "success": success,
		"correlation_id": evidence.CorrelationID, "evidence_digest": evidenceDigest(evidence),
		"signed_evidence": envelope,
		"route_evidence": map[string]any{
			"correlation_id": evidence.CorrelationID, "source_asset_id": evidence.SourceAssetID,
			"destination_asset_id": evidence.DestinationAssetID, "protocol": strings.ToLower(evidence.Protocol),
			"port": evidence.Port, "reachable": evidence.ServiceReachable, "service_reachable": evidence.ServiceReachable,
			"remote_execution_observed": evidence.RemoteAccess, "destination_proof": true,
			"destination_proof_token": "ed25519:" + evidenceDigest(evidence), "destination_identity": evidence.Identity,
			"integrity": evidence.Integrity, "is_admin": isAdmin, "observed_at": evidence.ObservedAt,
		},
		"assets": []any{map[string]any{"asset_id": evidence.DestinationAssetID, "identity": evidence.Identity, "integrity": evidence.Integrity, "is_admin": isAdmin, "steps": []any{map[string]any{"id": "destination-verification", "name": "Signed destination-side verification", "done": true, "success": success}}}},
	}, nil
}

func destinationAdminIntegrity(integrity string) bool {
	switch strings.ToLower(strings.TrimSpace(integrity)) {
	case "high", "system":
		return true
	default:
		return false
	}
}

// VerifyStoredReport rechecks the signed destination statement when persisted
// reports are converted into mission facts. A projected report field is never
// trusted as a substitute for this signature check.
func (l *LateralExecutor) VerifyStoredReport(item ValidatedItem) error {
	if l == nil {
		return fmt.Errorf("destination verifier is unavailable")
	}
	raw, ok := item.Report["signed_evidence"]
	if !ok {
		return fmt.Errorf("stored report has no signed destination evidence")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var envelope lateralEvidenceEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return err
	}
	if envelope.Status != "completed" || !envelope.Evidence.RemoteAccess {
		return fmt.Errorf("signed destination evidence does not report completed access")
	}
	return l.verifyEvidence(item, envelope)
}

func lateralInputFingerprint(item PlanItem) string {
	if item.LateralInput == nil {
		return ""
	}
	return hash(struct {
		Schema      ActionInputSchema
		Kind        string
		CatalogID   string
		Source      string
		Destination string
		Input       LateralActionInput
	}{lateralInputSchema(), item.Kind, item.CatalogID, item.SourceAssetID, item.DestinationAssetID, *item.LateralInput})
}

func portString(port int) string {
	if port == 0 {
		return ""
	}
	return strconv.Itoa(port)
}
