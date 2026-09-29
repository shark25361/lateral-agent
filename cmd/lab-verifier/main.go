package main

import (
	"log"
	"os"
	"strings"

	"fourcore-agent/internal/app"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "keygen" {
		privatePath, publicPath, err := app.GenerateVerifierKeypair(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("private key: %s; public key: %s", privatePath, publicPath)
		return
	}
	sources := map[string]bool{}
	for _, source := range strings.Split(os.Getenv("LAB_VERIFIER_ALLOWED_SOURCE_IDS"), ",") {
		if source = strings.TrimSpace(source); source != "" {
			sources[source] = true
		}
	}
	config := app.LabVerifierConfig{
		DestinationAssetID: strings.TrimSpace(os.Getenv("LAB_VERIFIER_ASSET_ID")),
		Hostname:           strings.TrimSpace(os.Getenv("LAB_VERIFIER_HOSTNAME")),
		AllowedSources:     sources, PrivateKeyPath: strings.TrimSpace(os.Getenv("LAB_VERIFIER_PRIVATE_KEY_PATH")),
	}
	if config.DestinationAssetID == "" || config.Hostname == "" || config.PrivateKeyPath == "" || len(sources) == 0 {
		log.Fatal("LAB_VERIFIER_ASSET_ID, LAB_VERIFIER_HOSTNAME, LAB_VERIFIER_ALLOWED_SOURCE_IDS and LAB_VERIFIER_PRIVATE_KEY_PATH are required")
	}
	if err := app.RunDestinationVerifier(config, os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}
