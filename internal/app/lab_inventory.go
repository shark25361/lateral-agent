package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// LabAsset is an operator declaration, not evidence that an endpoint is live,
// reachable, privileged, or controlled by the configured executor.
type LabAsset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
}

func loadLabAssets(path string, allowed map[string]bool) (map[string]LabAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open LAB_ASSETS_FILE: %w", err)
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || info.Size() > 1<<20 {
		return nil, fmt.Errorf("LAB_ASSETS_FILE must be a readable file no larger than 1 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var assets []LabAsset
	if err := decoder.Decode(&assets); err != nil {
		return nil, fmt.Errorf("decode LAB_ASSETS_FILE: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("LAB_ASSETS_FILE must contain exactly one JSON array")
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("LAB_ASSETS_FILE must list at least one asset")
	}
	registry := make(map[string]LabAsset, len(assets))
	for _, asset := range assets {
		asset.ID = strings.TrimSpace(asset.ID)
		asset.Name = strings.TrimSpace(asset.Name)
		asset.Platform = strings.ToLower(strings.TrimSpace(asset.Platform))
		if validID(asset.ID) != nil || asset.Name == "" || asset.Platform != "windows" {
			return nil, fmt.Errorf("LAB_ASSETS_FILE entries require an ID, name, and windows platform")
		}
		if !allowed[asset.ID] {
			return nil, fmt.Errorf("lab asset %s is outside ALLOWED_ENDPOINT_ASSETS", asset.ID)
		}
		if _, exists := registry[asset.ID]; exists {
			return nil, fmt.Errorf("duplicate lab asset %s", asset.ID)
		}
		registry[asset.ID] = asset
	}
	return registry, nil
}
