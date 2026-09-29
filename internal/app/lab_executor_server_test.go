package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type signedLabRunner struct {
	key   ed25519.PrivateKey
	calls atomic.Int32
}

func (r *signedLabRunner) Run(_ context.Context, request LabRunRequest) (lateralEvidenceEnvelope, error) {
	r.calls.Add(1)
	evidence := LateralEvidence{
		ExecutionID: request.ExecutionID, InputHash: request.InputHash,
		CorrelationID: request.CorrelationID, SourceAssetID: request.SourceAssetID,
		DestinationAssetID: request.DestinationAssetID, Protocol: request.Protocol,
		Port: request.Port, ServiceReachable: true, RemoteAccess: true,
		Identity: `LAB\Operator`, Integrity: "high", ObservedAt: time.Now().UTC(),
	}
	canonical, _ := canonicalEvidence(evidence)
	return lateralEvidenceEnvelope{Status: "completed", Evidence: evidence, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(r.key, canonical))}, nil
}

func TestLabExecutorAllowlistAndSignedResult(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := currentLabIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runner := &signedLabRunner{key: private}
	server, err := NewLabExecutorServer(LabExecutorConfig{
		SourceAssetID: "asset-1", Destinations: map[string]string{lateralTestDestination: "192.0.2.56"},
		Profiles: map[string]string{"vault://lab/operator": identity}, Token: strings.Repeat("x", 24),
		PublicKeys: map[string]ed25519.PublicKey{lateralTestDestination: public}, DataDir: t.TempDir(),
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	api := httptest.NewTLSServer(server.Handler())
	defer api.Close()
	client := api.Client()
	request := lateralSubmitRequest{
		InputHash: strings.Repeat("a", 64), CorrelationID: "lab-correlation-1",
		SourceAssetID: "asset-1", DestinationAssetID: lateralTestDestination,
		DestinationHost: "192.0.2.56", Protocol: "winrm", Port: 5985,
		CredentialReference: "vault://lab/operator", ExpectedIdentity: "Operator",
	}
	submit := func(value lateralSubmitRequest, token string) (int, lateralSubmitResponse) {
		t.Helper()
		body, _ := json.Marshal(value)
		httpRequest, err := http.NewRequest(http.MethodPost, api.URL+"/v1/lateral/executions", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result lateralSubmitResponse
		_ = json.NewDecoder(response.Body).Decode(&result)
		return response.StatusCode, result
	}
	if status, _ := submit(request, "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("bad bearer token: %d", status)
	}
	wrongDestination := request
	wrongDestination.DestinationHost = "192.0.2.57"
	if status, _ := submit(wrongDestination, strings.Repeat("x", 24)); status != http.StatusBadRequest {
		t.Fatalf("unallowlisted destination: %d", status)
	}
	status, accepted := submit(request, strings.Repeat("x", 24))
	if status != http.StatusAccepted || accepted.ID == "" {
		t.Fatalf("request not accepted: %d %+v", status, accepted)
	}
	if status, repeated := submit(request, strings.Repeat("x", 24)); status != http.StatusAccepted || repeated.ID != accepted.ID {
		t.Fatalf("idempotent submit failed: %d %+v", status, repeated)
	}
	changed := request
	changed.InputHash = strings.Repeat("b", 64)
	if status, _ := submit(changed, strings.Repeat("x", 24)); status != http.StatusConflict {
		t.Fatalf("reused correlation accepted: %d", status)
	}
	var envelope lateralEvidenceEnvelope
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		httpRequest, _ := http.NewRequest(http.MethodGet, api.URL+"/v1/lateral/executions/"+accepted.ID, nil)
		httpRequest.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 24))
		response, err := client.Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if envelope.Status != "completed" || envelope.Evidence.ExecutionID != accepted.ID || runner.calls.Load() != 1 {
		t.Fatalf("signed job did not complete once: %+v calls=%d", envelope, runner.calls.Load())
	}
	canonical, _ := canonicalEvidence(envelope.Evidence)
	signature, _ := base64.StdEncoding.DecodeString(envelope.Signature)
	if !ed25519.Verify(public, canonical, signature) {
		t.Fatal("destination signature did not verify")
	}
}

func TestDestinationKeypairDoesNotOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "keys")
	private, public, err := GenerateVerifierKeypair(directory)
	if err != nil {
		t.Fatal(err)
	}
	if private == "" || public == "" {
		t.Fatal("key paths were empty")
	}
	if _, _, err := GenerateVerifierKeypair(directory); err == nil {
		t.Fatal("existing destination key was overwritten")
	}
}

func TestSourceExecutorBindingsRequireScopedHTTPS(t *testing.T) {
	bindings, err := sourceExecutorBindings("asset-1=https://attack.test:9443,asset-2=https://secattack:9443")
	if err != nil || len(bindings) != 2 {
		t.Fatalf("valid source-scoped endpoints rejected: %v %+v", err, bindings)
	}
	for _, raw := range []string{"asset-1=http://attack.test", "asset-1=https://user:pass@attack.test", "asset-1=https://attack.test/path", "invalid id=https://attack.test"} {
		if _, err := sourceExecutorBindings(raw); err == nil {
			t.Fatalf("invalid source binding accepted: %s", raw)
		}
	}
}

func TestDestinationPublicKeyBindings(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(public)
	bindings, err := publicKeyBindings(lateralTestDestination + "=" + encoded)
	if err != nil || bindings[lateralTestDestination] != encoded {
		t.Fatalf("destination key mapping was rejected: %v", err)
	}
	if _, err := publicKeyBindings(lateralTestDestination + "=not-a-key"); err == nil {
		t.Fatal("invalid verifier key was accepted")
	}
}

func TestDestinationVerifierSignsLocalWindowsToken(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("destination token verification requires Windows")
	}
	privatePath, publicPath, err := GenerateVerifierKeypair(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(string(publicBytes))
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	invocation := VerifierInvocation{ExecutionID: "local-execution", InputHash: strings.Repeat("a", 64), CorrelationID: "local-correlation", SourceAssetID: "asset-1", DestinationAssetID: lateralTestDestination, Protocol: "winrm", Port: 5985}
	input, _ := json.Marshal(invocation)
	var output bytes.Buffer
	if err := RunDestinationVerifier(LabVerifierConfig{DestinationAssetID: lateralTestDestination, Hostname: hostname, AllowedSources: map[string]bool{"asset-1": true}, PrivateKeyPath: privatePath}, bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var signed lateralEvidenceEnvelope
	if err := json.Unmarshal(output.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	canonical, _ := canonicalEvidence(signed.Evidence)
	signature, _ := base64.StdEncoding.DecodeString(signed.Signature)
	if !signed.Evidence.RemoteAccess || signed.Evidence.Identity == "" || !ed25519.Verify(publicKey, canonical, signature) {
		t.Fatalf("local verifier did not produce a valid token-bound statement: %+v", signed.Evidence)
	}
}
