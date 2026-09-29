package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type HTTPError struct {
	Status int
	Retry  time.Duration
	Detail string
}

func (e *HTTPError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("FourCore HTTP %d: %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("FourCore HTTP %d", e.Status)
}

func httpErrorDetail(raw []byte) string {
	var payload map[string]any
	if json.Unmarshal(raw, &payload) == nil {
		for _, key := range []string{"detail", "message", "error"} {
			if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
				raw = []byte(value)
				break
			}
		}
	}
	detail := strings.Join(strings.Fields(string(raw)), " ")
	if len(detail) > 1024 {
		detail = detail[:1024] + "...[truncated]"
	}
	return detail
}

type FourCore struct {
	Base, Key  string
	HTTP       *http.Client
	mu         sync.Mutex
	next       time.Time
	interval   time.Duration
	catalogMu  sync.Mutex
	refreshMu  sync.Mutex
	catalog    map[string]catalogCacheEntry
	catalogDir string
}

func NewFourCore(c Config) *FourCore {
	catalogDir := ""
	if c.DataDir != "" {
		catalogDir = filepath.Join(c.DataDir, "catalog")
	}
	return &FourCore{Base: strings.TrimRight(c.FourCoreURL, "/"), Key: c.FourCoreKey, HTTP: &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, interval: time.Minute / time.Duration(c.RPM), catalog: map[string]catalogCacheEntry{}, catalogDir: catalogDir}
}
func (f *FourCore) wait(ctx context.Context) error {
	f.mu.Lock()
	n := time.Now()
	if f.next.After(n) {
		n = f.next
	}
	f.next = n.Add(f.interval)
	f.mu.Unlock()
	t := time.NewTimer(time.Until(n))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func (f *FourCore) Do(ctx context.Context, method, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	attempts := 1
	if method == http.MethodGet {
		attempts = 3
	}
	for i := 0; i < attempts; i++ {
		if err = f.wait(ctx); err != nil {
			return err
		}
		req, e := http.NewRequestWithContext(ctx, method, f.Base+path, bytes.NewReader(b))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+f.Key)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		r, e := f.HTTP.Do(req)
		if e != nil {
			// GETs are safe to repeat. A dropped connection or read timeout must not
			// turn a transient provider failure into a terminal planning result.
			// Writes remain single-attempt because the provider may have accepted a
			// request before the connection failed.
			if method == http.MethodGet && i+1 < attempts && ctx.Err() == nil {
				delay := time.Duration(1<<i) * 100 * time.Millisecond
				t := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					t.Stop()
					return ctx.Err()
				case <-t.C:
				}
				continue
			}
			return fmt.Errorf("FourCore transport failed: %w", e)
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, 8<<20+1))
		r.Body.Close()
		if e != nil {
			return e
		}
		if len(raw) > 8<<20 {
			return fmt.Errorf("FourCore response exceeds limit")
		}
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			if out == nil {
				return nil
			}
			return json.Unmarshal(raw, out)
		}
		delay := time.Duration(1<<i) * time.Second
		for _, h := range []string{"Retry-After", "x-ratelimit-retry-after"} {
			if n, e := strconv.Atoi(r.Header.Get(h)); e == nil && n > 0 {
				delay = time.Duration(n) * time.Second
			}
		}
		if r.StatusCode == 429 {
			f.mu.Lock()
			until := time.Now().Add(delay)
			if until.After(f.next) {
				f.next = until
			}
			f.mu.Unlock()
		}
		if (r.StatusCode == 429 || r.StatusCode >= 500) && i+1 < attempts {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
			continue
		}
		return &HTTPError{Status: r.StatusCode, Retry: delay, Detail: httpErrorDetail(raw)}
	}
	return fmt.Errorf("request failed")
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$`)

func validID(id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid resource ID")
	}
	return nil
}

type Asset struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Platform  string         `json:"platform"`
	Available bool           `json:"available"`
	Connected bool           `json:"connected"`
	Disabled  bool           `json:"disabled"`
	Verified  bool           `json:"verified"`
	Elevated  bool           `json:"elevated"`
	Tags      map[string]any `json:"tags,omitempty"`
}
type rawAsset struct {
	ID        string         `json:"id"`
	Email     string         `json:"email"`
	Available bool           `json:"available"`
	Connected bool           `json:"connected"`
	Disabled  bool           `json:"disabled"`
	Verified  bool           `json:"verified"`
	Elevated  bool           `json:"elevated"`
	Tags      map[string]any `json:"tags"`
	System    struct {
		Hostname string `json:"hostname"`
		OS       string `json:"os"`
	} `json:"systeminfo"`
}

func (a rawAsset) safe() Asset {
	name := a.System.Hostname
	if a.Email != "" {
		name = a.Email
	}
	return Asset{ID: a.ID, Name: name, Platform: a.System.OS, Available: a.Available, Connected: a.Connected, Disabled: a.Disabled, Verified: a.Verified, Elevated: a.Elevated, Tags: a.Tags}
}
func (f *FourCore) Assets(ctx context.Context, kind string) ([]Asset, error) {
	path := "/api/v2/assets"
	if kind == "email" {
		path += "/email"
	} else if kind != "endpoint" {
		return nil, fmt.Errorf("asset kind must be endpoint or email")
	}
	var rows []rawAsset
	if err := f.Do(ctx, "GET", path, nil, &rows); err != nil {
		return nil, err
	}
	out := make([]Asset, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.safe())
	}
	return out, nil
}
func (f *FourCore) Asset(ctx context.Context, kind, id string) (Asset, error) {
	if err := validID(id); err != nil {
		return Asset{}, err
	}
	p := "/api/v2/assets/"
	if kind == "email" {
		p += "email/"
	}
	var a rawAsset
	for attempt := 0; attempt < 3; attempt++ {
		if err := f.Do(ctx, http.MethodGet, p+id, nil, &a); err != nil {
			return Asset{}, err
		}
		ready := a.Available && !a.Disabled
		if kind == "email" {
			ready = ready && a.Verified
		} else {
			ready = ready && a.Connected
		}
		if ready || attempt == 2 {
			return a.safe(), nil
		}
		t := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return Asset{}, ctx.Err()
		case <-t.C:
		}
	}
	return a.safe(), nil
}

type Catalog struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Platforms   []string         `json:"platforms"`
	Platform    string           `json:"platform"`
	Elevated    bool             `json:"elevated"`
	Deprecated  bool             `json:"deprecated"`
	Techniques  []map[string]any `json:"techniques"`
	Stages      []map[string]any `json:"stages,omitempty"`
	Items       []PackItem       `json:"items,omitempty"`
	Tags        map[string]any   `json:"tags,omitempty"`
}
type PackItem struct {
	Chain string `json:"chain"`
	Uses  string `json:"uses"`
}

func catalogPath(kind string) (string, error) {
	switch kind {
	case "endpoint_chain":
		return "/api/v2/content/chains", nil
	case "email_chain":
		return "/api/v2/content/email/chains", nil
	case "firewall_chain":
		return "/api/v2/content/firewall/chains", nil
	case "playbook":
		return "/api/v2/content/packs", nil
	}
	return "", fmt.Errorf("unsupported catalogue kind %q; WAF chain discovery is absent from the published API", kind)
}
func (f *FourCore) Catalog(ctx context.Context, kind, id string) (Catalog, error) {
	p, e := catalogPath(kind)
	if e != nil {
		return Catalog{}, e
	}
	if e = validID(id); e != nil {
		return Catalog{}, e
	}
	var c Catalog
	e = f.Do(ctx, "GET", p+"/"+id, nil, &c)
	var httpErr *HTTPError
	if errors.As(e, &httpErr) && httpErr.Status == http.StatusNotFound {
		return c, fmt.Errorf("catalogue ID %q was not found in %s; call search_simulations and use an exact returned ID", id, kind)
	}
	if e == nil && c.ID != id {
		return c, fmt.Errorf("catalogue ID mismatch")
	}
	return c, e
}

type SearchResult struct {
	Items      []Catalog `json:"items"`
	NextOffset int       `json:"next_offset"`
	More       bool      `json:"more"`
}

type catalogCacheEntry struct {
	Updated time.Time
	Items   []Catalog
	Raw     []json.RawMessage
}

type CatalogStatus struct {
	Kind      string    `json:"kind"`
	Available bool      `json:"available"`
	Count     int       `json:"count"`
	Updated   time.Time `json:"updated_at,omitempty"`
}

type catalogSnapshot struct {
	Version int               `json:"version"`
	Kind    string            `json:"kind"`
	Updated time.Time         `json:"updated_at"`
	Items   []json.RawMessage `json:"items"`
}

const (
	catalogPageSize = 100
	catalogLimit    = 5000
	searchPageSize  = 25
)

func (f *FourCore) allCatalog(ctx context.Context, kind string) ([]Catalog, error) {
	if _, err := catalogPath(kind); err != nil {
		return nil, err
	}
	f.catalogMu.Lock()
	cached, ok := f.catalog[kind]
	if ok {
		items := append([]Catalog(nil), cached.Items...)
		f.catalogMu.Unlock()
		return items, nil
	}
	f.catalogMu.Unlock()
	if cached, err := f.loadCatalog(kind); err == nil {
		f.catalogMu.Lock()
		f.catalog[kind] = cached
		f.catalogMu.Unlock()
		return append([]Catalog(nil), cached.Items...), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return f.RefreshCatalog(ctx, kind)
}

// localCatalogItems never refreshes over the network. A missing snapshot is
// an explicit planning limitation, not permission to contact another tenant.
func (f *FourCore) localCatalogItems(kind string) ([]Catalog, error) {
	if _, err := catalogPath(kind); err != nil {
		return nil, err
	}
	f.catalogMu.Lock()
	cached, ok := f.catalog[kind]
	f.catalogMu.Unlock()
	if !ok {
		var err error
		cached, err = f.loadCatalog(kind)
		if err != nil {
			return nil, fmt.Errorf("local %s catalogue snapshot unavailable: %w", kind, err)
		}
		f.catalogMu.Lock()
		f.catalog[kind] = cached
		f.catalogMu.Unlock()
	}
	return append([]Catalog(nil), cached.Items...), nil
}

func (f *FourCore) RefreshCatalog(ctx context.Context, kind string) ([]Catalog, error) {
	f.refreshMu.Lock()
	defer f.refreshMu.Unlock()
	p, err := catalogPath(kind)
	if err != nil {
		return nil, err
	}
	items := []Catalog{}
	rawItems := []json.RawMessage{}
	for len(items) < catalogLimit {
		q := url.Values{"size": {strconv.Itoa(catalogPageSize)}, "offset": {strconv.Itoa(len(items))}}
		var page struct {
			Data  []json.RawMessage `json:"data"`
			Total int               `json:"total_rows"`
		}
		if err = f.Do(ctx, http.MethodGet, p+"?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		for _, raw := range page.Data {
			var item Catalog
			if err = json.Unmarshal(raw, &item); err != nil {
				return nil, fmt.Errorf("invalid %s catalogue entry: %w", kind, err)
			}
			if item.ID == "" {
				return nil, fmt.Errorf("%s catalogue contains an entry without an ID", kind)
			}
			items = append(items, item)
			rawItems = append(rawItems, append(json.RawMessage(nil), raw...))
		}
		if len(page.Data) == 0 || (page.Total > 0 && len(items) >= page.Total) || len(page.Data) < catalogPageSize {
			break
		}
	}
	if len(items) >= catalogLimit {
		return nil, fmt.Errorf("%s catalogue exceeds the %d-item safety limit", kind, catalogLimit)
	}
	entry := catalogCacheEntry{Updated: time.Now().UTC(), Items: items, Raw: rawItems}
	if err = f.saveCatalog(kind, entry); err != nil {
		return nil, err
	}
	f.catalogMu.Lock()
	f.catalog[kind] = entry
	f.catalogMu.Unlock()
	return append([]Catalog(nil), items...), nil
}

func (f *FourCore) LocalCatalog(ctx context.Context, kind, id string) (Catalog, error) {
	if err := validID(id); err != nil {
		return Catalog{}, err
	}
	items, err := f.allCatalog(ctx, kind)
	if err != nil {
		return Catalog{}, err
	}
	return catalogByID(items, kind, id)
}

func (f *FourCore) LocalCatalogStrict(kind, id string) (Catalog, error) {
	if err := validID(id); err != nil {
		return Catalog{}, err
	}
	items, err := f.localCatalogItems(kind)
	if err != nil {
		return Catalog{}, err
	}
	return catalogByID(items, kind, id)
}

func catalogByID(items []Catalog, kind, id string) (Catalog, error) {
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return Catalog{}, fmt.Errorf("catalogue ID %q was not found in the local %s snapshot; refresh the catalogue and use an exact returned ID", id, kind)
}

func (f *FourCore) loadCatalog(kind string) (catalogCacheEntry, error) {
	if f.catalogDir == "" {
		return catalogCacheEntry{}, os.ErrNotExist
	}
	b, err := os.ReadFile(filepath.Join(f.catalogDir, kind+".json"))
	if err != nil {
		return catalogCacheEntry{}, err
	}
	if len(b) > 64<<20 {
		return catalogCacheEntry{}, fmt.Errorf("local %s catalogue snapshot exceeds limit", kind)
	}
	var snapshot catalogSnapshot
	if err = json.Unmarshal(b, &snapshot); err != nil {
		return catalogCacheEntry{}, fmt.Errorf("invalid local %s catalogue snapshot: %w", kind, err)
	}
	if snapshot.Version != 1 || snapshot.Kind != kind {
		return catalogCacheEntry{}, fmt.Errorf("invalid local %s catalogue snapshot metadata", kind)
	}
	items := make([]Catalog, 0, len(snapshot.Items))
	for _, raw := range snapshot.Items {
		var item Catalog
		if err = json.Unmarshal(raw, &item); err != nil || item.ID == "" {
			return catalogCacheEntry{}, fmt.Errorf("invalid entry in local %s catalogue snapshot", kind)
		}
		items = append(items, item)
	}
	return catalogCacheEntry{Updated: snapshot.Updated, Items: items, Raw: snapshot.Items}, nil
}

func (f *FourCore) saveCatalog(kind string, entry catalogCacheEntry) error {
	if f.catalogDir == "" {
		return nil
	}
	if err := os.MkdirAll(f.catalogDir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(catalogSnapshot{Version: 1, Kind: kind, Updated: entry.Updated, Items: entry.Raw}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(f.catalogDir, kind+".json")
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		if err = os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

func (f *FourCore) CatalogStatuses() []CatalogStatus {
	kinds := []string{"endpoint_chain", "email_chain", "firewall_chain", "playbook"}
	out := make([]CatalogStatus, 0, len(kinds))
	for _, kind := range kinds {
		f.catalogMu.Lock()
		entry, ok := f.catalog[kind]
		f.catalogMu.Unlock()
		if !ok {
			var err error
			entry, err = f.loadCatalog(kind)
			ok = err == nil
		}
		out = append(out, CatalogStatus{Kind: kind, Available: ok, Count: len(entry.Items), Updated: entry.Updated})
	}
	return out
}

func (f *FourCore) Search(ctx context.Context, kind, query string, offset int) (SearchResult, error) {
	if offset < 0 {
		return SearchResult{}, fmt.Errorf("invalid offset")
	}
	all, err := f.allCatalog(ctx, kind)
	if err != nil {
		return SearchResult{}, err
	}
	return searchCatalog(all, query, offset), nil
}

func (f *FourCore) SearchLocal(kind, query string, offset int) (SearchResult, error) {
	if offset < 0 {
		return SearchResult{}, fmt.Errorf("invalid offset")
	}
	all, err := f.localCatalogItems(kind)
	if err != nil {
		return SearchResult{}, err
	}
	return searchCatalog(all, query, offset), nil
}

func searchCatalog(all []Catalog, query string, offset int) SearchResult {
	type match struct {
		item  Catalog
		score int
	}
	matches := []match{}
	for _, c := range all {
		b, _ := json.Marshal(c)
		score := searchScore(strings.ToLower(string(b)), query)
		if query != "" && score == 0 {
			continue
		}
		// Fetch expanded stage/pack details only after shortlisting.
		c.Stages = nil
		c.Items = nil
		c.Tags = nil
		if len(c.Description) > 2000 {
			c.Description = c.Description[:2000] + "..."
		}
		matches = append(matches, match{item: c, score: score})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score == matches[j].score {
			return strings.ToLower(matches[i].item.Name) < strings.ToLower(matches[j].item.Name)
		}
		return matches[i].score > matches[j].score
	})
	if offset > len(matches) {
		offset = len(matches)
	}
	end := offset + searchPageSize
	if end > len(matches) {
		end = len(matches)
	}
	items := make([]Catalog, 0, end-offset)
	for _, m := range matches[offset:end] {
		items = append(items, m.item)
	}
	return SearchResult{Items: items, NextOffset: end, More: end < len(matches)}
}

func searchScore(haystack, query string) int {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return 1
	}
	score := 0
	if strings.Contains(haystack, query) {
		score += 20
	}
	seen := map[string]bool{}
	for _, term := range strings.FieldsFunc(query, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '.' && r != '_'
	}) {
		if len(term) < 3 || seen[term] || term == "and" || term == "the" || term == "for" || term == "with" {
			continue
		}
		seen[term] = true
		if strings.Contains(haystack, term) {
			score++
			if strings.HasPrefix(term, "t") && len(term) >= 5 {
				score += 4
			}
		}
	}
	return score
}
func reportPath(kind, id string) string {
	if kind == "playbook" {
		return "/api/v2/packs/runs/" + id
	}
	return "/api/v2/executions/" + id + "/report"
}

const (
	storedReportOutputBudget = 256 << 10
	modelReportOutputBudget  = 48 << 10
)

// reportSummary keeps raw simulation step output while omitting unrelated host,
// credential, and integration fields. The complete response is available through
// RawReport; this stored projection is bounded to protect the local database.
func reportSummary(raw map[string]any) map[string]any {
	budget := storedReportOutputBudget
	return reportProjection(raw, &budget)
}

// reportForModel has a smaller bound because it becomes part of an OpenRouter
// request. Report output is untrusted evidence and never instructions.
func reportForModel(raw map[string]any) map[string]any {
	budget := modelReportOutputBudget
	return reportProjection(raw, &budget)
}

func reportProjection(raw map[string]any, budget *int) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"id", "chain_id", "attack_name", "name", "status", "status_state", "progress", "total_attacks", "total_finished", "total_success", "total_detected", "detected", "prevented", "score", "created_at", "updated_at", "total", "success", "error", "error_code", "error_message", "message", "reason", "failure_reason", "exit_code", "correlation_id", "evidence_digest", "source_asset_id", "destination_asset_id", "protocol", "port", "reachable", "service_reachable", "remote_execution_observed", "destination_proof", "proof_token", "destination_proof_token", "remote_identity", "destination_identity", "identity", "principal", "run_as", "integrity", "observed_at", "is_admin", "administrator", "elevated", "domain"} {
		if v, ok := raw[k]; ok {
			out[k] = v
		}
	}
	adFields := []string{"ad_evidence", "domains", "domain_memberships", "machines", "computers", "users", "identities", "groups", "group_memberships", "trusts", "sessions", "shares", "acls", "delegations", "services", "reachable_services", "can_smb", "can_rdp", "can_winrm", "can_ssh", "protocol_access", "remote_access_rights"}
	for _, k := range adFields {
		if v, ok := raw[k]; ok {
			out[k] = boundedRawOutput(v, budget)
		}
	}
	if assets, ok := raw["assets"].([]any); ok {
		safe := []any{}
		for _, v := range assets {
			if a, ok := v.(map[string]any); ok {
				row := pick(a, "asset_id", "platform", "status", "progress", "total_attacks", "total_finished", "total_success", "total_detected", "source_asset_id", "destination_asset_id", "protocol", "reachable", "service_reachable", "remote_execution_observed", "destination_proof", "proof_token", "destination_proof_token", "remote_identity", "destination_identity", "identity", "principal", "run_as", "integrity", "is_admin", "administrator", "elevated", "domain")
				for _, k := range adFields {
					if value, exists := a[k]; exists {
						row[k] = boundedRawOutput(value, budget)
					}
				}
				row["steps"] = safeSteps(a["steps"], 0, budget)
				safe = append(safe, row)
			} else if id, ok := v.(string); ok {
				safe = append(safe, id)
			}
		}
		out["assets"] = safe
	}
	if runs, ok := raw["executions"].([]any); ok {
		safe := []any{}
		for _, v := range runs {
			if a, ok := v.(map[string]any); ok {
				safe = append(safe, pick(a, "id", "attack_name", "status", "progress", "total_attacks", "total_finished", "total_success", "total_detected"))
			}
		}
		out["executions"] = safe
	}
	if route, ok := raw["route_evidence"].(map[string]any); ok {
		out["route_evidence"] = pick(route, "correlation_id", "source_asset_id", "source_id", "destination_asset_id", "destination_id", "target_asset_id", "protocol", "remote_protocol", "port", "reachable", "service_reachable", "remote_execution_observed", "destination_proof", "proof_token", "destination_proof_token", "remote_identity", "destination_identity", "identity", "principal", "run_as", "integrity", "observed_at", "is_admin", "administrator", "elevated")
	}
	if signed, ok := raw["signed_evidence"].(lateralEvidenceEnvelope); ok {
		out["signed_evidence"] = signed
	}
	out["interpretation"] = "Execution, prevention and detection are separate outcomes. Missing detection counts do not prove a detection failure."
	return out
}

func (f *FourCore) RawReport(ctx context.Context, kind, id string) (map[string]any, error) {
	if err := validID(id); err != nil {
		return nil, err
	}
	if kind != "execution" && kind != "playbook" {
		return nil, fmt.Errorf("kind must be execution or playbook")
	}
	pathKind := "endpoint_chain"
	if kind == "playbook" {
		pathKind = "playbook"
	}
	var raw map[string]any
	if err := f.Do(ctx, http.MethodGet, reportPath(pathKind, id), nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
func pick(v map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if x, ok := v[k]; ok {
			out[k] = x
		}
	}
	return out
}
func safeSteps(v any, depth int, budget *int) []any {
	out := []any{}
	if depth > 4 {
		return out
	}
	items, _ := v.([]any)
	for n, x := range items {
		if n >= 200 {
			break
		}
		a, ok := x.(map[string]any)
		if !ok {
			continue
		}
		row := pick(a, "id", "action_id", "name", "stage_name", "status", "done", "success", "detected", "prevented", "severity", "start_time", "finish_time", "error", "error_code", "error_message", "message", "reason", "failure_reason", "exit_code", "source_asset_id", "destination_asset_id", "parent_execution_id", "pivot_execution_id", "protocol", "reachable", "service_reachable", "remote_execution_observed", "destination_proof", "proof_token", "destination_proof_token", "remote_identity", "destination_identity", "identity", "principal", "run_as", "integrity", "is_admin", "administrator", "elevated", "domain")
		for _, k := range []string{"ad_evidence", "domains", "domain_memberships", "machines", "computers", "users", "identities", "groups", "group_memberships", "trusts", "sessions", "shares", "acls", "delegations", "services", "reachable_services", "can_smb", "can_rdp", "can_winrm", "can_ssh", "protocol_access", "remote_access_rights"} {
			if value, exists := a[k]; exists {
				row[k] = boundedRawOutput(value, budget)
			}
		}
		if output, ok := a["output"]; ok {
			row["output"] = boundedRawOutput(output, budget)
		}
		if a["action_steps"] != nil {
			row["action_steps"] = safeSteps(a["action_steps"], depth+1, budget)
		}
		if correlations, ok := a["correlations"].([]any); ok {
			safe := []any{}
			for _, x := range correlations {
				if c, ok := x.(map[string]any); ok {
					safe = append(safe, pick(c, "id", "name", "integration_type", "correlation_type", "detection_time", "severity"))
				}
			}
			row["correlations"] = safe
		}
		out = append(out, row)
	}
	return out
}

func boundedRawOutput(v any, budget *int) any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"unavailable": true, "error": "output could not be encoded"}
	}
	if *budget >= len(b) {
		*budget -= len(b)
		return v
	}
	available := *budget
	*budget = 0
	if available > len(b) {
		available = len(b)
	}
	return map[string]any{
		"truncated":       true,
		"original_bytes":  len(b),
		"raw_json_prefix": string(b[:available]),
	}
}
