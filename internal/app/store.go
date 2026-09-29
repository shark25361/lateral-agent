package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var ErrNotFound = errors.New("record not found")

type Store struct{ db *bolt.DB }

func OpenStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	dbPath := filepath.Join(dir, "agent.db")
	d, e := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		if errors.Is(e, bolt.ErrTimeout) {
			return nil, fmt.Errorf("data store %q is locked by another FourCore agent process; stop that process or use the already-running agent", dbPath)
		}
		return nil, e
	}
	s := &Store{d}
	e = d.Update(func(tx *bolt.Tx) error {
		for _, b := range []string{"plans", "chats", "missions", "audit"} {
			if _, e := tx.CreateBucketIfNotExists([]byte(b)); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		d.Close()
	}
	return s, e
}
func (s *Store) Close() error { return s.db.Close() }
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (s *Store) Put(bucket, id string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(bucket)).Put([]byte(id), b) })
}
func (s *Store) Get(bucket, id string, v any) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket)).Get([]byte(id))
		if b == nil {
			return ErrNotFound
		}
		return json.Unmarshal(b, v)
	})
}
func (s *Store) Plans() ([]Plan, error) {
	out := []Plan{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("plans")).ForEach(func(_, v []byte) error {
			var p Plan
			if e := json.Unmarshal(v, &p); e != nil {
				return e
			}
			out = append(out, p)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, err
}

type ChatSummary struct {
	ID           string    `json:"id"`
	Preview      string    `json:"preview"`
	MessageCount int       `json:"message_count"`
	Updated      time.Time `json:"updated_at"`
}

func (s *Store) Chats() ([]ChatSummary, error) {
	out := []ChatSummary{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("chats")).ForEach(func(_, v []byte) error {
			var c Chat
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			summary := ChatSummary{ID: c.ID, MessageCount: len(c.Messages)}
			for _, message := range c.Messages {
				if message.At.After(summary.Updated) {
					summary.Updated = message.At
				}
				if summary.Preview == "" && message.Role == "user" {
					summary.Preview = message.Text
				}
			}
			if len(summary.Preview) > 120 {
				summary.Preview = summary.Preview[:120] + "…"
			}
			out = append(out, summary)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	return out, err
}
func (s *Store) UpdatePlan(id string, fn func(*Plan) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plans"))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var p Plan
		if e := json.Unmarshal(raw, &p); e != nil {
			return e
		}
		if e := fn(&p); e != nil {
			return e
		}
		p.Updated = time.Now().UTC()
		raw, e := json.Marshal(p)
		if e != nil {
			return e
		}
		if e = b.Put([]byte(id), raw); e != nil {
			return e
		}
		a, _ := json.Marshal(map[string]any{"plan_id": id, "status": p.Status, "time": p.Updated})
		return tx.Bucket([]byte("audit")).Put([]byte(newID()), a)
	})
}

func (s *Store) Missions() ([]Mission, error) {
	out := []Mission{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("missions")).ForEach(func(_, v []byte) error {
			var m Mission
			if e := json.Unmarshal(v, &m); e != nil {
				return e
			}
			out = append(out, m)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, err
}

func (s *Store) UpdateMission(id string, fn func(*Mission) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("missions"))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var m Mission
		if e := json.Unmarshal(raw, &m); e != nil {
			return e
		}
		if e := fn(&m); e != nil {
			return e
		}
		m.Updated = time.Now().UTC()
		raw, e := json.Marshal(m)
		if e != nil {
			return e
		}
		if e = b.Put([]byte(id), raw); e != nil {
			return e
		}
		a, _ := json.Marshal(map[string]any{"mission_id": id, "status": m.Status, "time": m.Updated})
		return tx.Bucket([]byte("audit")).Put([]byte(newID()), a)
	})
}
