package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf16"
)

// The script is fixed application code. Destination, verifier path and the
// signed challenge travel as typed stdin JSON/ArgumentList values. No request
// field is interpreted as a script or PowerShell command.
const fixedWinRMScript = `$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$result = Invoke-Command -ComputerName $request.destination_host -Authentication Kerberos -ScriptBlock {
  param([string]$verifierPath, [string]$challenge)
  $challenge | & $verifierPath
  if ($LASTEXITCODE -ne 0) { throw 'destination verifier failed' }
} -ArgumentList $request.verifier_path, $request.challenge
if ($result -is [array]) { $result = $result -join '' }
[Console]::Out.Write([string]$result)
`

type WinRMRunner struct {
	PowerShellPath string
	VerifierPath   string
}

func encodedPowerShell(script string) string {
	runes := utf16.Encode([]rune(script))
	data := make([]byte, len(runes)*2)
	for index, value := range runes {
		binary.LittleEndian.PutUint16(data[index*2:], value)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func (runner WinRMRunner) Run(ctx context.Context, request LabRunRequest) (lateralEvidenceEnvelope, error) {
	if runtime.GOOS != "windows" {
		return lateralEvidenceEnvelope{}, fmt.Errorf("WinRM execution requires a Windows source machine")
	}
	if request.Protocol != "winrm" || request.Port != 5985 || runner.VerifierPath == "" {
		return lateralEvidenceEnvelope{}, fmt.Errorf("only the configured WinRM verifier action is supported")
	}
	powershell := runner.PowerShellPath
	if powershell == "" {
		powershell = "powershell.exe"
	}
	challenge, err := json.Marshal(VerifierInvocation{
		ExecutionID: request.ExecutionID, InputHash: request.InputHash,
		CorrelationID: request.CorrelationID, SourceAssetID: request.SourceAssetID,
		DestinationAssetID: request.DestinationAssetID, Protocol: request.Protocol, Port: request.Port,
	})
	if err != nil {
		return lateralEvidenceEnvelope{}, err
	}
	input, err := json.Marshal(struct {
		DestinationHost string `json:"destination_host"`
		VerifierPath    string `json:"verifier_path"`
		Challenge       string `json:"challenge"`
	}{request.DestinationHost, runner.VerifierPath, string(challenge)})
	if err != nil {
		return lateralEvidenceEnvelope{}, err
	}
	command := exec.CommandContext(ctx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(fixedWinRMScript))
	command.Stdin = bytes.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return lateralEvidenceEnvelope{}, fmt.Errorf("fixed WinRM verifier action failed: %w: %s", err, boundedLabError(output))
	}
	if len(output) > 1<<20 {
		return lateralEvidenceEnvelope{}, fmt.Errorf("destination verifier output exceeds limit")
	}
	var envelope lateralEvidenceEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(output), &envelope); err != nil {
		return lateralEvidenceEnvelope{}, fmt.Errorf("destination verifier did not return signed JSON: %w", err)
	}
	return envelope, nil
}

func boundedLabError(raw []byte) string {
	message := strings.TrimSpace(string(raw))
	if len(message) > 500 {
		message = message[:500] + "..."
	}
	return message
}
