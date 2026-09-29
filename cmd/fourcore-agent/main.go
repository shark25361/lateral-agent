package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"fourcore-agent/internal/app"
	"github.com/joho/godotenv"
)

func main() {
	if e := run(); e != nil {
		slog.Error("agent stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	_ = godotenv.Load()
	cfg, e := app.LoadConfig()
	if e != nil {
		return e
	}
	store, e := app.OpenStore(cfg.DataDir)
	if e != nil {
		return e
	}
	defer store.Close()
	svc := &app.Service{Config: cfg, FC: app.NewFourCore(cfg), Lateral: app.NewLateralExecutor(cfg), Store: store}
	if e = svc.Recover(); e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		for _, status := range svc.FC.CatalogStatuses() {
			if status.Available {
				continue
			}
			items, err := svc.FC.RefreshCatalog(ctx, status.Kind)
			if err != nil {
				slog.Warn("catalogue snapshot unavailable", "kind", status.Kind, "error", err)
				continue
			}
			slog.Info("catalogue snapshot stored", "kind", status.Kind, "items", len(items))
		}
	}()
	done := make(chan struct{})
	go func() { defer close(done); svc.Worker(ctx) }()
	defer func() { cancel(); <-done }()
	model := &app.OpenRouter{Key: cfg.OpenRouterKey, Model: cfg.Model, Base: cfg.OpenRouterURL}
	handler := (&app.Server{Service: svc, Model: model}).Handler()
	server := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("FourCore agent ready", "address", cfg.Listen, "execution_enabled", cfg.Execute)
	e = server.ListenAndServe()
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
