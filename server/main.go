package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/core-pb/authenticate/authenticate/v1/authenticateconnect"
	"github.com/core-pb/authenticate/pkg/password"
	"github.com/core-pb/tag/client"
	"github.com/core-pb/tag/tag/v1"
	"github.com/uptrace/bun"
	"go.x2ox.com/sorbifolia/bunpgd"
	"go.x2ox.com/sorbifolia/crpc"
)

func main() {
	var (
		ctx, cancel = context.WithCancel(context.Background())
		closeCh     = make(chan os.Signal, 1)
		server, err = crpc.NewServer(
			crpc.WithHealthAndMetrics(":80", ""),
			crpc.WithCertFromCheck("CERT", "cert", "build/output/cert"),
			crpc.WithCORS(nil),
		)
	)
	if err != nil {
		slog.Error("create server", slog.String("err", err.Error()))
		os.Exit(1)
	}

	initDB(ctx)
	initTagServer(ctx)

	server.Handle(authenticateconnect.NewBaseHandler(base{}))
	server.Handle(password.Enable(base{}).Handler())

	if err = server.Run(); err != nil {
		slog.Error("server run", slog.String("err", err.Error()))
		os.Exit(1)
	}

	signal.Notify(closeCh, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	server.SetReady()
	sig := <-closeCh
	server.SetNoReady("server close")

	slog.Info("server exit signal: signal notify %s", slog.String("sig", sig.String()))

	cancel()

	if err = server.Close(); err != nil {
		slog.Error("server close", slog.String("err", err.Error()))
	}
}

func initDB(ctx context.Context) {
	var (
		_ctx, cancel = context.WithCancelCause(ctx)
		err          error
	)

	if db, err = bunpgd.Open(os.Getenv("DB_DSN"),
		bunpgd.WithMaxOpenConns(256),
		bunpgd.WithMaxIdleConns(8),
		bunpgd.WithConnMaxIdleTime(time.Second*12),
		bun.WithDiscardUnknownColumns(),
		bunpgd.WithSLog(),
		bunpgd.WithCreateTable(_ctx, cancel, &Authenticate{}),
	); err != nil {
		slog.Error("connect db", slog.String("err", err.Error()))
		os.Exit(1)
	}

	if err = _ctx.Err(); err != nil {
		slog.Error("create table", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

var module *tag.Module

func initTagServer(ctx context.Context) {
	client.Set(nil, os.Getenv("TAG_ADDR"))

	res, err := client.Get().RegisterModule(ctx, "authenticate")
	if err != nil {
		slog.Error("register module", slog.String("err", err.Error()))
		os.Exit(1)
	}
	module = res

	_, err = client.Internal().RegisterTag(ctx, connect.NewRequest(&tag.RegisterTagRequest{Data: []*tag.Tag{
		{Key: "authenticate:scope:login"},
		{Key: "authenticate:scope:mfa"},
		{Key: "authenticate:scope:captcha"},
	}}))
	if err != nil {
		slog.Error("register tag", slog.String("err", err.Error()))
		os.Exit(1)
	}
}
