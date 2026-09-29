package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VerifierInvocation is supplied to a fixed executable already installed on
// the destination. The program is launched through a WinRM session, so its
// local Windows token is the remote execution identity being proved.
type VerifierInvocation struct {
	ExecutionID        string `json:"execution_id"`
	InputHash          string `json:"input_hash"`
	CorrelationID      string `json:"correlation_id"`
	SourceAssetID      string `json:"source_asset_id"`
	DestinationAssetID string `json:"destination_asset_id"`
	Protocol           string `json:"protocol"`
	Port               int    `json:"port"`
}

type LabVerifierConfig struct {
	DestinationAssetID string
	Hostname           string
	AllowedSources     map[string]bool
	PrivateKeyPath     string
}

func SignDestinationInvocation(config LabVerifierConfig, invocation VerifierInvocation) (lateralEvidenceEnvelope, error) {
	if invocation.DestinationAssetID != config.DestinationAssetID || !config.AllowedSources[invocation.SourceAssetID] || invocation.Protocol != "winrm" || invocation.Port != 5985 || validID(invocation.ExecutionID) != nil || validID(invocation.CorrelationID) != nil || len(invocation.InputHash) != 64 {
		return lateralEvidenceEnvelope{}, fmt.Errorf("verifier invocation is outside configured lab scope")
	}
	if config.Hostname != "" {
		host, err := os.Hostname()
		if err != nil || !strings.EqualFold(host, config.Hostname) {
			return lateralEvidenceEnvelope{}, fmt.Errorf("verifier is not running on its configured destination")
		}
	}
	identity, elevated, err := destinationProcessIdentity()
	if err != nil || identity == "" {
		return lateralEvidenceEnvelope{}, fmt.Errorf("could not observe destination Windows identity: %w", err)
	}
	privateFile, err := os.ReadFile(config.PrivateKeyPath)
	if err != nil {
		return lateralEvidenceEnvelope{}, err
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateFile)))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return lateralEvidenceEnvelope{}, fmt.Errorf("destination signing key is invalid")
	}
	integrity := "medium"
	if elevated {
		integrity = "high"
	}
	evidence := LateralEvidence{
		ExecutionID: invocation.ExecutionID, InputHash: invocation.InputHash,
		CorrelationID: invocation.CorrelationID, SourceAssetID: invocation.SourceAssetID,
		DestinationAssetID: invocation.DestinationAssetID, Protocol: invocation.Protocol,
		Port: invocation.Port, ServiceReachable: true, RemoteAccess: true,
		Identity: identity, Integrity: integrity, ObservedAt: time.Now().UTC(),
	}
	canonical, err := canonicalEvidence(evidence)
	if err != nil {
		return lateralEvidenceEnvelope{}, err
	}
	return lateralEvidenceEnvelope{Status: "completed", Evidence: evidence, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))}, nil
}

func RunDestinationVerifier(config LabVerifierConfig, input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 16<<10))
	decoder.DisallowUnknownFields()
	var invocation VerifierInvocation
	if err := decoder.Decode(&invocation); err != nil {
		return err
	}
	envelope, err := SignDestinationInvocation(config, invocation)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(envelope)
}

// GenerateVerifierKeypair creates a destination-local keypair without
// overwriting an existing private key. Restrict the file ACL to the verifier
// endpoint account before enabling remote execution.
func GenerateVerifierKeypair(directory string) (string, string, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", "", err
	}
	privatePath := filepath.Join(directory, "destination-ed25519.key")
	publicPath := filepath.Join(directory, "destination-ed25519.pub")
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Stat(path); err == nil {
			return "", "", fmt.Errorf("key file already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return "", "", err
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0644); err != nil {
		return "", "", err
	}
	return privatePath, publicPath, nil
}
