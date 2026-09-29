package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	OpenRouterKey, Model, OpenRouterURL, FourCoreKey, FourCoreURL string
	Token, Listen, DataDir                                        string
	Execute, AllowElevated                                        bool
	AllowedEndpoint, AllowedEmail                                 map[string]bool
	LateralEnabled                                                bool
	LateralExecutorURL, LateralExecutorToken                      string
	LateralEvidencePublicKey                                      string
	LateralEvidencePublicKeys                                     map[string]string
	LateralDestinations                                           map[string]string
	LateralSourceExecutors                                        map[string]string
	LateralCredentialRefs                                         map[string]string
	LateralDefaultCredentialRef                                   string
	LabAssets                                                     map[string]LabAsset
	MaxItems, MaxAssets, RPM                                      int
	Poll                                                          time.Duration
	CorrelationWait                                               time.Duration
}

func LoadConfig() (Config, error) {
	c := Config{OpenRouterKey: os.Getenv("OPENROUTER_API_KEY"), Model: os.Getenv("OPENROUTER_MODEL"), OpenRouterURL: env("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"), FourCoreKey: os.Getenv("FOURCORE_API_KEY"), FourCoreURL: env("FOURCORE_BASE_URL", "https://prod.fourcore.io"), Token: os.Getenv("APP_TOKEN"), Listen: env("LISTEN_ADDR", "127.0.0.1:8080"), DataDir: env("DATA_DIR", "data"), AllowedEndpoint: set(os.Getenv("ALLOWED_ENDPOINT_ASSETS")), AllowedEmail: set(os.Getenv("ALLOWED_EMAIL_ASSETS")), LateralExecutorURL: os.Getenv("LATERAL_EXECUTOR_BASE_URL"), LateralExecutorToken: os.Getenv("LATERAL_EXECUTOR_TOKEN"), LateralEvidencePublicKey: os.Getenv("LATERAL_EVIDENCE_PUBLIC_KEY"), LateralDefaultCredentialRef: strings.TrimSpace(os.Getenv("LATERAL_DEFAULT_CREDENTIAL_REF"))}
	// Preserve compatibility with the existing workspace's original key name.
	if c.OpenRouterKey == "" {
		c.OpenRouterKey = os.Getenv("openrouter")
	}
	var err error
	if c.Execute, err = strconv.ParseBool(env("EXECUTION_ENABLED", "false")); err != nil {
		return c, fmt.Errorf("EXECUTION_ENABLED: %w", err)
	}
	if c.AllowElevated, err = strconv.ParseBool(env("ALLOW_ELEVATED", "false")); err != nil {
		return c, err
	}
	if c.LateralEnabled, err = strconv.ParseBool(env("LATERAL_EXECUTOR_ENABLED", "false")); err != nil {
		return c, fmt.Errorf("LATERAL_EXECUTOR_ENABLED: %w", err)
	}
	if c.LateralDestinations, err = destinationBindings(os.Getenv("LATERAL_ALLOWED_DESTINATIONS")); err != nil {
		return c, err
	}
	if c.LateralSourceExecutors, err = sourceExecutorBindings(os.Getenv("LATERAL_SOURCE_EXECUTORS")); err != nil {
		return c, err
	}
	if c.LateralEvidencePublicKeys, err = publicKeyBindings(os.Getenv("LATERAL_EVIDENCE_PUBLIC_KEYS")); err != nil {
		return c, err
	}
	for source, endpoint := range c.LateralSourceExecutors {
		u, parseErr := url.Parse(endpoint)
		if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("invalid HTTPS lateral executor URL for source %s", source)
		}
	}
	c.LateralCredentialRefs = credentialReferences(os.Getenv("LATERAL_CREDENTIAL_REFS"))
	if file := strings.TrimSpace(os.Getenv("LAB_ASSETS_FILE")); file != "" {
		c.LabAssets, err = loadLabAssets(file, c.AllowedEndpoint)
		if err != nil {
			return c, err
		}
	}
	if c.LateralDefaultCredentialRef != "" {
		digest := credentialReferenceHash(c.LateralDefaultCredentialRef)
		if c.LateralCredentialRefs[digest] == "" {
			return c, fmt.Errorf("LATERAL_DEFAULT_CREDENTIAL_REF must be listed in LATERAL_CREDENTIAL_REFS")
		}
		c.LateralDefaultCredentialRef = digest
	}
	for _, v := range []struct {
		name          string
		target        *int
		def, min, max int
	}{{"MAX_PLAN_ITEMS", &c.MaxItems, 5, 1, 50}, {"MAX_PLAN_ASSETS", &c.MaxAssets, 10, 1, 100}, {"FOURCORE_RPM", &c.RPM, 60, 1, 90}} {
		n, e := strconv.Atoi(env(v.name, strconv.Itoa(v.def)))
		if e != nil || n < v.min || n > v.max {
			return c, fmt.Errorf("invalid %s", v.name)
		}
		*v.target = n
	}
	p, e := strconv.Atoi(env("POLL_INTERVAL_SECONDS", "30"))
	if e != nil || p < 5 {
		return c, fmt.Errorf("POLL_INTERVAL_SECONDS must be at least 5")
	}
	c.Poll = time.Duration(p) * time.Second
	wait, e := strconv.Atoi(env("CORRELATION_WAIT_SECONDS", "120"))
	if e != nil || wait < 0 || wait > 3600 {
		return c, fmt.Errorf("CORRELATION_WAIT_SECONDS must be between 0 and 3600")
	}
	c.CorrelationWait = time.Duration(wait) * time.Second
	missing := []string{}
	if c.OpenRouterKey == "" {
		missing = append(missing, "OPENROUTER_API_KEY (or openrouter)")
	}
	if c.Model == "" {
		missing = append(missing, "OPENROUTER_MODEL")
	}
	if c.FourCoreKey == "" {
		missing = append(missing, "FOURCORE_API_KEY")
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("set %s in .env", strings.Join(missing, ", "))
	}
	if len(c.Token) < 24 {
		return c, fmt.Errorf("APP_TOKEN must contain at least 24 characters")
	}
	for _, s := range []string{c.OpenRouterURL, c.FourCoreURL} {
		u, e := url.Parse(s)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return c, fmt.Errorf("provider URLs must be HTTPS URLs without credentials, query or fragment")
		}
	}
	if c.LateralEnabled {
		for assetID := range c.LateralDestinations {
			if !c.AllowedEndpoint[assetID] {
				return c, fmt.Errorf("lateral destination %s must be in ALLOWED_ENDPOINT_ASSETS", assetID)
			}
		}
		for assetID := range c.LateralSourceExecutors {
			if !c.AllowedEndpoint[assetID] {
				return c, fmt.Errorf("lateral source %s must be in ALLOWED_ENDPOINT_ASSETS", assetID)
			}
		}
		if (c.LateralExecutorURL == "" && len(c.LateralSourceExecutors) == 0) || c.LateralExecutorToken == "" || (c.LateralEvidencePublicKey == "" && len(c.LateralEvidencePublicKeys) == 0) {
			return c, fmt.Errorf("enabled lateral executor requires a source HTTPS URL, LATERAL_EXECUTOR_TOKEN, and destination evidence public key(s)")
		}
		if c.LateralExecutorURL != "" {
			u, e := url.Parse(c.LateralExecutorURL)
			if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return c, fmt.Errorf("LATERAL_EXECUTOR_BASE_URL must be an HTTPS URL without credentials, query or fragment")
			}
		}
		if len(c.LateralDestinations) == 0 || len(c.LateralCredentialRefs) == 0 || c.LateralDefaultCredentialRef == "" {
			return c, fmt.Errorf("enabled lateral executor requires allowlisted destinations and a default credential reference")
		}
		if c.LateralEvidencePublicKey != "" {
			publicKey, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(c.LateralEvidencePublicKey))
			if decodeErr != nil || len(publicKey) != ed25519.PublicKeySize {
				return c, fmt.Errorf("LATERAL_EVIDENCE_PUBLIC_KEY must be a base64-encoded Ed25519 public key")
			}
		}
		if len(c.LateralEvidencePublicKeys) > 0 {
			for destination := range c.LateralDestinations {
				if c.LateralEvidencePublicKeys[destination] == "" {
					return c, fmt.Errorf("destination %s has no configured evidence public key", destination)
				}
			}
		}
	}
	return c, nil
}

func sourceExecutorBindings(raw string) (map[string]string, error) {
	bindings := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || validID(strings.TrimSpace(parts[0])) != nil {
			return nil, fmt.Errorf("invalid LATERAL_SOURCE_EXECUTORS entry")
		}
		assetID, endpoint := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, fmt.Errorf("invalid HTTPS lateral executor URL for source %s", assetID)
		}
		bindings[assetID] = strings.TrimRight(endpoint, "/")
	}
	return bindings, nil
}

func publicKeyBindings(raw string) (map[string]string, error) {
	bindings := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || validID(strings.TrimSpace(parts[0])) != nil {
			return nil, fmt.Errorf("invalid LATERAL_EVIDENCE_PUBLIC_KEYS entry")
		}
		assetID := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid destination evidence public key for asset %s", assetID)
		}
		bindings[assetID] = value
	}
	return bindings, nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			m[v] = true
		}
	}
	return m
}

func credentialReferenceHash(reference string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(reference)))
	return hex.EncodeToString(digest[:])
}

func credentialReferences(raw string) map[string]string {
	refs := map[string]string{}
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			refs[credentialReferenceHash(value)] = value
		}
	}
	return refs
}

func destinationBindings(raw string) (map[string]string, error) {
	bindings := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || validID(strings.TrimSpace(parts[0])) != nil {
			return nil, fmt.Errorf("invalid LATERAL_ALLOWED_DESTINATIONS entry")
		}
		assetID, host := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if net.ParseIP(host) == nil {
			if len(host) > 253 || strings.ContainsAny(host, "/:@?#") {
				return nil, fmt.Errorf("invalid lateral destination host for asset %s", assetID)
			}
			for _, label := range strings.Split(host, ".") {
				if label == "" || len(label) > 63 {
					return nil, fmt.Errorf("invalid lateral destination host for asset %s", assetID)
				}
				for _, char := range label {
					if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
						return nil, fmt.Errorf("invalid lateral destination host for asset %s", assetID)
					}
				}
			}
		}
		bindings[assetID] = host
	}
	return bindings, nil
}
