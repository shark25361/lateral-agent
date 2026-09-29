package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalLabInventoryDecouplesOnlyLabValidation(t *testing.T) {
	fixture := setup(t)
	fixture.svc.FC.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("FourCore network must not be used")
	})
	fixture.svc.Config.LateralEnabled = true
	fixture.svc.Config.LabAssets = map[string]LabAsset{
		"asset-1":              {ID: "asset-1", Name: "source", Platform: "windows"},
		lateralTestDestination: {ID: lateralTestDestination, Name: "destination", Platform: "windows"},
	}
	fixture.svc.Config.LateralDestinations = map[string]string{lateralTestDestination: "destination.test"}
	ref := "vault://synthetic/operator"
	refHash := credentialReferenceHash(ref)
	fixture.svc.Config.LateralCredentialRefs = map[string]string{refHash: ref}
	fixture.svc.Lateral = &LateralExecutor{Base: "https://executor.example.test"}

	mission, err := fixture.svc.CreateMission(context.Background(), "offline-lab", MissionInput{
		Request:      "Review lab access evidence",
		Requirements: []Requirement{{Type: "remote_access_proven", Source: "asset-1", Target: lateralTestDestination, Protocol: "winrm", Mandatory: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.svc.CollectMissionFacts(context.Background(), mission.ID); err != nil {
		t.Fatal(err)
	}
	mission, err = fixture.svc.missionByID(mission.ID)
	if err != nil {
		t.Fatal(err)
	}
	if factState(mission, "lab_asset_registered", "asset-1") != "proven" || factState(mission, "asset_connected", "asset-1") != "" || factState(mission, "elevated_capability", "asset-1") != "" {
		t.Fatalf("registration was mistaken for live connectivity or elevation: %+v", mission.Facts)
	}
	if blocker := missionAssetBlocker(mission, fixture.svc.Config.LabAssets, fixture.svc.Config.LateralEnabled); blocker != "" {
		t.Fatalf("local lab planning was blocked: %s", blocker)
	}
	item := PlanItem{
		Kind: "lab_lateral", CatalogID: lateralCatalogID, Executor: "controlled_lab", Reason: "Review configured lab route",
		AssetIDs: []string{"asset-1", lateralTestDestination}, SourceAssetID: "asset-1", DestinationAssetID: lateralTestDestination,
		Protocol: "winrm", LateralInput: &LateralActionInput{
			DestinationHost: "destination.test", Protocol: "winrm", Port: 5985, CredentialRefHash: refHash,
			CorrelationID: "local-test-1", RouteNodeIDs: []string{"source", "destination"}, RouteEdgeIDs: []string{"edge-1"},
		},
	}
	if _, err := fixture.svc.Validate(context.Background(), item); err != nil {
		t.Fatalf("lab validation must not call FourCore: %v", err)
	}
	delete(fixture.svc.Config.LabAssets, lateralTestDestination)
	if _, err := fixture.svc.Validate(context.Background(), item); err == nil || !strings.Contains(err.Error(), "local lab asset registry") {
		t.Fatalf("unregistered destination was accepted: %v", err)
	}
}

func TestLoadLabAssetsRejectsOutOfScopeAndDuplicateEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assets.json")
	allowed := map[string]bool{"source": true}
	for _, tc := range []struct {
		name, body string
		wantOK     bool
	}{
		{"valid", `[{"id":"source","name":"Source","platform":"windows"}]`, true},
		{"out of scope", `[{"id":"destination","name":"Dest","platform":"windows"}]`, false},
		{"duplicate", `[{"id":"source","name":"A","platform":"windows"},{"id":"source","name":"B","platform":"windows"}]`, false},
		{"false platform", `[{"id":"source","name":"A","platform":"linux"}]`, false},
		{"unknown field", `[{"id":"source","name":"A","platform":"windows","connected":true}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadLabAssets(path, allowed)
			if (err == nil) != tc.wantOK {
				t.Fatalf("unexpected registry result: %v", err)
			}
		})
	}
}

func TestStrictLocalCatalogueNeverRefreshesMissingSnapshot(t *testing.T) {
	provider := NewFourCore(Config{FourCoreURL: "https://attack.test.fourcore.io", FourCoreKey: "synthetic", DataDir: t.TempDir(), RPM: 60})
	provider.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("local catalogue lookup attempted a network request")
		return nil, fmt.Errorf("unexpected network request")
	})
	if _, err := provider.SearchLocal("endpoint_chain", "", 0); err == nil || !strings.Contains(err.Error(), "snapshot unavailable") {
		t.Fatalf("missing snapshot did not fail closed: %v", err)
	}
	if _, err := provider.LocalCatalogStrict("endpoint_chain", "synthetic"); err == nil || !strings.Contains(err.Error(), "snapshot unavailable") {
		t.Fatalf("missing catalogue detail did not fail closed: %v", err)
	}
}
