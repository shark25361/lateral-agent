package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

// LabExecutorConfig is deliberately source scoped. One instance runs on one
// Windows source under an already provisioned service identity. A credential
// reference selects that identity; no password is passed to PowerShell.
type LabExecutorConfig struct {
	SourceAssetID  string
	SourceHostname string
	Destinations   map[string]string
	Profiles       map[string]string // opaque reference -> expected process identity
	Token          string
	PublicKey      ed25519.PublicKey
	PublicKeys     map[string]ed25519.PublicKey
	VerifierPath   string
	PowerShellPath string
	DataDir        string
}

type LabRunRequest struct {
	ExecutionID string
	lateralSubmitRequest
}

type LabRemoteRunner interface {
	Run(context.Context, LabRunRequest) (lateralEvidenceEnvelope, error)
}

type labJob struct {
	ID          string                   `json:"id"`
	InputHash   string                   `json:"input_hash"`
	Correlation string                   `json:"correlation_id"`
	Status      string                   `json:"status"`
	Error       string                   `json:"error,omitempty"`
	Envelope    *lateralEvidenceEnvelope `json:"envelope,omitempty"`
	UpdatedAt   time.Time                `json:"updated_at"`
}

type LabExecutorServer struct {
	config LabExecutorConfig
	runner LabRemoteRunner
	db     *bbolt.DB
}

func NewLabExecutorServer(config LabExecutorConfig, runner LabRemoteRunner) (*LabExecutorServer, error) {
	if validID(config.SourceAssetID) != nil || len(config.Token) < 24 || (len(config.PublicKey) != ed25519.PublicKeySize && len(config.PublicKeys) == 0) || len(config.Destinations) == 0 || len(config.Profiles) == 0 || config.DataDir == "" || runner == nil {
		return nil, fmt.Errorf("lab executor requires a source ID, bearer token, verifier key, destination bindings, identity profiles, data directory, and runner")
	}
	if len(config.PublicKeys) > 0 {
		for destination := range config.Destinations {
			if len(config.PublicKeys[destination]) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("destination %s has no valid verifier key", destination)
			}
		}
	}
	if runtime.GOOS != "windows" && config.SourceHostname != "" {
		return nil, fmt.Errorf("the WinRM lab executor must run on Windows")
	}
	if config.SourceHostname != "" {
		host, err := os.Hostname()
		if err != nil || !strings.EqualFold(host, config.SourceHostname) {
			return nil, fmt.Errorf("lab executor is not running on configured source host")
		}
	}
	if err := os.MkdirAll(config.DataDir, 0700); err != nil {
		return nil, err
	}
	db, err := bbolt.Open(filepath.Join(config.DataDir, "lab-executor.db"), 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	server := &LabExecutorServer{config: config, runner: runner, db: db}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, name := range []string{"jobs", "correlations"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		// A process restart never replays a write that may have reached WinRM.
		return tx.Bucket([]byte("jobs")).ForEach(func(k, v []byte) error {
			var job labJob
			if err := json.Unmarshal(v, &job); err != nil {
				return err
			}
			if job.Status != "running" {
				return nil
			}
			job.Status, job.Error, job.UpdatedAt = "failed", "executor restarted while the remote outcome was uncertain; inspect destination evidence before another attempt", time.Now().UTC()
			encoded, _ := json.Marshal(job)
			return tx.Bucket([]byte("jobs")).Put(k, encoded)
		})
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return server, nil
}

func (s *LabExecutorServer) Close() error { return s.db.Close() }

func currentLabIdentity() (string, error) {
	identity, err := user.Current()
	if err != nil {
		return "", err
	}
	return identity.Username, nil
}

func (s *LabExecutorServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, LateralHealth{Status: "ok", Execute: true, SignedEvidence: true, Protocols: []string{"winrm"}, SchemaVersion: "1", CredentialRefs: true, DestinationVerify: true})
	})
	mux.HandleFunc("POST /v1/lateral/executions", s.submit)
	mux.HandleFunc("GET /v1/lateral/executions/{id}", s.report)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		given := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(given), []byte(s.config.Token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *LabExecutorServer) submit(w http.ResponseWriter, r *http.Request) {
	var request lateralSubmitRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid typed request"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request must contain one JSON object"})
		return
	}
	if request.SourceAssetID != s.config.SourceAssetID || request.SourceAssetID == request.DestinationAssetID || s.config.Destinations[request.DestinationAssetID] != request.DestinationHost || request.Protocol != "winrm" || request.Port != 5985 || validID(request.CorrelationID) != nil || len(request.InputHash) != 64 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "route is outside configured lab scope"})
		return
	}
	if _, err := hex.DecodeString(request.InputHash); err != nil || s.config.Profiles[request.CredentialReference] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "input hash or credential profile is invalid"})
		return
	}
	identity, err := currentLabIdentity()
	if err != nil || !strings.EqualFold(identity, s.config.Profiles[request.CredentialReference]) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "executor process identity does not match selected credential profile"})
		return
	}
	var job labJob
	created := false
	err = s.db.Update(func(tx *bbolt.Tx) error {
		jobs, correlations := tx.Bucket([]byte("jobs")), tx.Bucket([]byte("correlations"))
		if existing := correlations.Get([]byte(request.CorrelationID)); existing != nil {
			if err := json.Unmarshal(jobs.Get(existing), &job); err != nil {
				return err
			}
			if job.InputHash != request.InputHash {
				return fmt.Errorf("correlation ID was already used for different inputs")
			}
			return nil
		}
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		job = labJob{ID: hex.EncodeToString(bytes), InputHash: request.InputHash, Correlation: request.CorrelationID, Status: "running", UpdatedAt: time.Now().UTC()}
		encoded, _ := json.Marshal(job)
		if err := jobs.Put([]byte(job.ID), encoded); err != nil {
			return err
		}
		if err := correlations.Put([]byte(request.CorrelationID), []byte(job.ID)); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if created {
		go s.run(LabRunRequest{ExecutionID: job.ID, lateralSubmitRequest: request})
	}
	writeJSON(w, http.StatusAccepted, lateralSubmitResponse{ID: job.ID, Status: job.Status})
}

func (s *LabExecutorServer) run(request LabRunRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	envelope, runErr := s.runner.Run(ctx, request)
	if runErr == nil {
		// The executor cannot recompute the whole application route hash; it
		// checks the signed value against the exact submitted input hash.
		if envelope.Status != "completed" || !envelope.Evidence.RemoteAccess || envelope.Evidence.Identity == "" || (request.ExpectedIdentity != "" && !identityMatches(envelope.Evidence.Identity, request.ExpectedIdentity)) || envelope.Evidence.ObservedAt.IsZero() || envelope.Evidence.ObservedAt.After(time.Now().Add(5*time.Minute)) || envelope.Evidence.ObservedAt.Before(time.Now().Add(-3*time.Minute)) || envelope.Evidence.InputHash != request.InputHash || envelope.Evidence.ExecutionID != request.ExecutionID || envelope.Evidence.CorrelationID != request.CorrelationID || envelope.Evidence.SourceAssetID != request.SourceAssetID || envelope.Evidence.DestinationAssetID != request.DestinationAssetID || envelope.Evidence.Protocol != request.Protocol || envelope.Evidence.Port != request.Port {
			runErr = fmt.Errorf("destination verifier returned mismatched evidence")
		} else {
			canonical, _ := canonicalEvidence(envelope.Evidence)
			signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
			publicKey := s.config.PublicKey
			if len(s.config.PublicKeys) > 0 {
				publicKey = s.config.PublicKeys[request.DestinationAssetID]
			}
			if err != nil || !ed25519.Verify(publicKey, canonical, signature) {
				runErr = fmt.Errorf("destination verifier signature is invalid")
			}
		}
	}
	_ = s.db.Update(func(tx *bbolt.Tx) error {
		jobs := tx.Bucket([]byte("jobs"))
		var job labJob
		if err := json.Unmarshal(jobs.Get([]byte(request.ExecutionID)), &job); err != nil {
			return err
		}
		job.UpdatedAt = time.Now().UTC()
		if runErr != nil {
			job.Status = "failed"
			job.Error = runErr.Error()
		} else {
			job.Status = "completed"
			job.Envelope = &envelope
		}
		encoded, _ := json.Marshal(job)
		return jobs.Put([]byte(job.ID), encoded)
	})
}

func (s *LabExecutorServer) report(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if validID(id) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid execution ID"})
		return
	}
	var job labJob
	err := s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket([]byte("jobs")).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &job)
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "execution not found"})
		return
	}
	if job.Envelope != nil {
		writeJSON(w, 200, job.Envelope)
		return
	}
	writeJSON(w, 200, map[string]string{"status": job.Status, "error": job.Error})
}
