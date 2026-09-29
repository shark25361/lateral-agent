package app

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/adk/v2/model"
)

//go:embed web/*
var web embed.FS

type Server struct {
	Service *Service
	Model   model.LLM
	chatMu  sync.Mutex
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		inventorySource := "fourcore_live"
		if len(s.Service.Config.LabAssets) > 0 {
			inventorySource = "operator_declared_lab"
		}
		writeJSON(w, 200, map[string]any{"execution_enabled": s.Service.Config.Execute, "lateral_executor_enabled": s.Service.Config.LateralEnabled, "inventory_source": inventorySource, "lab_asset_count": len(s.Service.Config.LabAssets), "model": s.Service.Config.Model, "supported_execution": []string{"endpoint_chain", "email_chain", "playbook", "lab_lateral"}, "max_items": s.Service.Config.MaxItems, "max_assets": s.Service.Config.MaxAssets})
	})
	mux.HandleFunc("GET /api/catalog/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.Service.FC.CatalogStatuses())
	})
	mux.HandleFunc("POST /api/catalog/refresh", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Kind string `json:"kind"`
		}
		if !decode(w, r, &q) {
			return
		}
		kinds := []string{q.Kind}
		if q.Kind == "all" {
			kinds = []string{"endpoint_chain", "email_chain", "firewall_chain", "playbook"}
		}
		for _, kind := range kinds {
			if _, e := s.Service.FC.RefreshCatalog(r.Context(), kind); e != nil {
				fail(w, e)
				return
			}
		}
		writeJSON(w, 200, s.Service.FC.CatalogStatuses())
	})
	mux.HandleFunc("POST /api/missions", func(w http.ResponseWriter, r *http.Request) {
		var q MissionInput
		if !decode(w, r, &q) {
			return
		}
		m, e := s.Service.RunMissionGraph(r.Context(), "api", q)
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 201, m)
	})
	mux.HandleFunc("GET /api/missions", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.Store.Missions()
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/missions/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.missionByID(r.PathValue("id"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/missions/{id}/plan", func(w http.ResponseWriter, r *http.Request) {
		var q MissionPlanInput
		if r.ContentLength != 0 && !decode(w, r, &q) {
			return
		}
		v, e := s.Service.ConfigureAndPlanMission(r.Context(), r.PathValue("id"), q)
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/missions/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.MissionReport(r.PathValue("id"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/missions/{id}/graph", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.MissionADGraph(r.PathValue("id"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/executions/latest/analysis", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.LatestExecutionAnalysis(r.Context(), r.URL.Query().Get("session_id"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/chat", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Session string `json:"session_id"`
			Message string `json:"message"`
		}
		if !decode(w, r, &q) {
			return
		}
		if len(q.Message) > 12000 || strings.TrimSpace(q.Message) == "" {
			fail(w, errors.New("message must contain 1-12000 characters"))
			return
		}
		if !s.chatMu.TryLock() {
			writeJSON(w, 429, map[string]string{"error": "An agent turn is already running; try again when it finishes"})
			return
		}
		defer s.chatMu.Unlock()
		v, e := s.Service.Chat(r.Context(), q.Session, q.Message, s.Model)
		if e != nil {
			slog.Error("agent chat request failed", "session_id", v.SessionID, "error", e)
			_ = s.Service.RecordChatFailure(v.SessionID, q.Message, e)
			writeJSON(w, 502, map[string]string{"error": e.Error(), "session_id": v.SessionID})
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/plans", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.Store.Plans()
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/plans/{id}", func(w http.ResponseWriter, r *http.Request) {
		var p Plan
		if e := s.Service.Store.Get("plans", r.PathValue("id"), &p); e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, p)
	})
	mux.HandleFunc("GET /api/plans/{id}/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.DiagnosePlan(r.Context(), r.PathValue("id"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("GET /api/reports/{kind}/{id}/raw", func(w http.ResponseWriter, r *http.Request) {
		v, e := s.Service.FC.RawReport(r.Context(), r.PathValue("kind"), r.PathValue("id"))
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, v)
	})
	mux.HandleFunc("POST /api/plans/{id}/authorize", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Hash      string    `json:"hash"`
			Scheduled time.Time `json:"scheduled_at"`
		}
		if !decode(w, r, &q) {
			return
		}
		if e := s.Service.Authorize(r.Context(), r.PathValue("id"), q.Hash, q.Scheduled); e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 202, map[string]string{"status": "queued"})
	})
	mux.HandleFunc("POST /api/plans/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if e := s.Service.Cancel(r.PathValue("id")); e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "cancelled"})
	})
	mux.HandleFunc("POST /api/plans/{id}/abort", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Index int `json:"item_index"`
		}
		if !decode(w, r, &q) {
			return
		}
		if e := s.Service.Abort(r.Context(), r.PathValue("id"), q.Index); e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "abort_requested"})
	})
	mux.HandleFunc("POST /api/plans/{id}/reconcile", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Index     int    `json:"item_index"`
			Execution string `json:"execution_id"`
		}
		if !decode(w, r, &q) {
			return
		}
		if e := s.Service.Reconcile(r.Context(), r.PathValue("id"), q.Index, q.Execution); e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "running"})
	})
	mux.HandleFunc("GET /api/chats/{id}", func(w http.ResponseWriter, r *http.Request) {
		var c Chat
		if e := s.Service.Store.Get("chats", r.PathValue("id"), &c); e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, c)
	})
	mux.HandleFunc("GET /api/chats", func(w http.ResponseWriter, r *http.Request) {
		chats, e := s.Service.Store.Chats()
		if e != nil {
			fail(w, e)
			return
		}
		writeJSON(w, 200, chats)
	})
	root, _ := fs.Sub(web, "web")
	mux.Handle("GET /", http.FileServer(http.FS(root)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if len(s.Service.Config.Token) < 24 || subtle.ConstantTimeCompare([]byte(got), []byte(s.Service.Config.Token)) != 1 {
				writeJSON(w, 401, map[string]string{"error": "Valid APP_TOKEN required"})
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		writeJSON(w, 400, map[string]string{"error": "Invalid JSON request"})
		return false
	}
	if e := d.Decode(new(any)); e != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "Expected one JSON value"})
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, e error) {
	status := 400
	if errors.Is(e, ErrNotFound) {
		status = 404
	}
	writeJSON(w, status, map[string]string{"error": e.Error()})
}
