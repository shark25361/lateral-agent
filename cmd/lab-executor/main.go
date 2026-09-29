package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fourcore-agent/internal/app"
)

func required(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func bindings(raw string) map[string]string {
	result := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			log.Fatal("invalid lab executor binding")
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result
}

func main() {
	if runtime.GOOS != "windows" {
		log.Fatal("the WinRM lab executor must run on the source Windows machine")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("LAB_EXECUTOR_EVIDENCE_PUBLIC_KEY")))
	keyMap := map[string]ed25519.PublicKey{}
	if raw := strings.TrimSpace(os.Getenv("LAB_EXECUTOR_EVIDENCE_PUBLIC_KEYS")); raw != "" {
		for destination, encoded := range bindings(raw) {
			key, decodeErr := base64.StdEncoding.DecodeString(encoded)
			if decodeErr != nil || len(key) != ed25519.PublicKeySize {
				log.Fatalf("invalid evidence public key for destination %s", destination)
			}
			keyMap[destination] = ed25519.PublicKey(key)
		}
	}
	if (err != nil || len(keyBytes) != ed25519.PublicKeySize) && len(keyMap) == 0 {
		log.Fatal("configure LAB_EXECUTOR_EVIDENCE_PUBLIC_KEY or LAB_EXECUTOR_EVIDENCE_PUBLIC_KEYS")
	}
	verifierPath := required("LAB_EXECUTOR_VERIFIER_PATH")
	if !filepath.IsAbs(verifierPath) {
		log.Fatal("LAB_EXECUTOR_VERIFIER_PATH must be an absolute destination-local path")
	}
	config := app.LabExecutorConfig{
		SourceAssetID: required("LAB_EXECUTOR_SOURCE_ASSET_ID"), SourceHostname: required("LAB_EXECUTOR_SOURCE_HOSTNAME"),
		Destinations: bindings(required("LAB_EXECUTOR_DESTINATIONS")), Profiles: bindings(required("LAB_EXECUTOR_CREDENTIAL_PROFILES")),
		Token: required("LAB_EXECUTOR_TOKEN"), PublicKey: ed25519.PublicKey(keyBytes), PublicKeys: keyMap,
		VerifierPath: verifierPath, PowerShellPath: strings.TrimSpace(os.Getenv("LAB_EXECUTOR_POWERSHELL_PATH")),
		DataDir: required("LAB_EXECUTOR_DATA_DIR"),
	}
	server, err := app.NewLabExecutorServer(config, app.WinRMRunner{PowerShellPath: config.PowerShellPath, VerifierPath: verifierPath})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	listen := strings.TrimSpace(os.Getenv("LAB_EXECUTOR_LISTEN"))
	if listen == "" {
		listen = "127.0.0.1:9443"
	}
	httpServer := &http.Server{Addr: listen, Handler: server.Handler(), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Print(fmt.Sprintf("lab executor ready on %s", listen))
	log.Fatal(httpServer.ListenAndServeTLS(required("LAB_EXECUTOR_TLS_CERT"), required("LAB_EXECUTOR_TLS_KEY")))
}
