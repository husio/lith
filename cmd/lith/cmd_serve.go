package main

import (
	"context"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"time"

	"github.com/husio/lith/app/lith"
	"github.com/husio/lith/pkg/alert"
	"github.com/husio/lith/pkg/cache"
	"github.com/husio/lith/pkg/email"
	"github.com/husio/lith/pkg/eventbus"
	"github.com/husio/lith/pkg/secret"
	"github.com/husio/lith/pkg/taskqueue"
)

func cmdServe(ctx context.Context, conf lith.Configuration, args []string) error {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("flag parse: %w", err)
	}
	return runServer(ctx, conf)
}

func runServer(ctx context.Context, conf lith.Configuration) error {
	cache := cache.NewLocalMemCache(conf.MaxCacheSize)

	safe := secret.AESSafe(conf.Secret)
	store, err := lith.OpenSQLiteStore(conf.Database, safe)
	if err != nil {
		return fmt.Errorf("open sqlite store: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			alert.Emit(ctx,
				"msg", "Closing store.",
				"err", err.Error())
		}
	}()

	var emailserver email.Server

	switch conf.EmailBackend {
	case "smtp":
		var auth smtp.Auth
		if conf.SMTP.AllowUnencrypted {
			auth = email.UnsafePlainAuth("", conf.SMTP.Username, conf.SMTP.Password, conf.SMTP.Host)
		} else {
			auth = smtp.PlainAuth("", conf.SMTP.Username, conf.SMTP.Password, conf.SMTP.Host)
		}
		emailserver = email.NewSMTPServer(fmt.Sprintf("%s:%d", conf.SMTP.Host, conf.SMTP.Port), auth)
	case "fs":
		emailserver = email.NewFilesystemServer(conf.FilesystemEmail.Dir)
	default:
		return fmt.Errorf("email backend not supported: %s", conf.EmailBackend)
	}

	queueStore, err := taskqueue.OpenTaskQueue(conf.TaskQueueDatabase)
	if err != nil {
		return fmt.Errorf("open task queue store: %w", err)
	}
	defer queueStore.Close()
	bgJobQueue := taskqueue.NewRegistry(queueStore)
	bgJobQueue.MustRegister(lith.SendConfirmRegistration{}, lith.NewSendConfirmRegistrationHandler(emailserver))
	bgJobQueue.MustRegister(lith.SendResetPassword{}, lith.NewSendResetPasswordHandler(emailserver))

	var events eventbus.Sink
	switch conf.EventSinkBackend {
	case "dropall":
		events = eventbus.NewNoopSink()
	case "fs":
		events = eventbus.NewFsSink(conf.EventSinkFilesystem.Dir)
	case "webhook":
		events = eventbus.ThroughTaskQueue(
			eventbus.NewWebhookSink(conf.EventSinkWebhook.URL, secret.Value(conf.EventSinkWebhook.Secret), nil),
			bgJobQueue)
	}

	// Figure which application should run on which HTTP server. It is
	// allowed to an serveral apps to run on the same server.
	apps := make(map[string]*http.ServeMux)
	registerApp := func(addr, prefix string, app http.Handler) {
		mux, ok := apps[addr]
		if !ok {
			mux = http.NewServeMux()
			apps[addr] = mux
		}
		mux.Handle(prefix, app)
	}

	if addr := conf.PublicUI.ListenHTTP; addr != "" {
		sum := sha512.New512_256()
		if _, err := io.WriteString(sum, "public-ui:"+conf.Secret); err != nil {
			return fmt.Errorf("create admin secret: %w", err)
		}
		secret := sum.Sum(nil)
		registerApp(addr, conf.PublicUI.PathPrefix, lith.PublicHandler(conf.PublicUI, store, cache, safe, secret, events, bgJobQueue))
	}
	if addr := conf.API.ListenHTTP; addr != "" {
		registerApp(addr, conf.API.PathPrefix, lith.APIHandler(conf.API, store, cache, events, bgJobQueue))
	}

	if addr := conf.AdminPanel.ListenHTTP; addr != "" {
		sum := sha512.New512_256()
		if _, err := io.WriteString(sum, "admin-panel:"+conf.Secret); err != nil {
			return fmt.Errorf("create admin secret: %w", err)
		}
		secret := sum.Sum(nil)
		registerApp(addr, conf.AdminPanel.PathPrefix, lith.AdminHandler(conf.AdminPanel, store, cache, safe, secret, events))
	}

	errc := make(chan error)
	for addr, mux := range apps {
		go func(addr string, mux http.Handler) {
			ctx := alert.WithEmitter(ctx,
				alert.WithPairs(alert.UsedEmitter(ctx), "server", addr))
			if err := listenHTTP(ctx, addr, mux); err != nil {
				select {
				case errc <- fmt.Errorf("http server %q: %w", addr, err):
				default:
				}
			}
		}(addr, mux)
	}

	// Periodical storage vacuum task. Use vacuum command to cleanup right away.
	go func() {
		ctx := alert.WithEmitter(ctx,
			alert.WithPairs(alert.UsedEmitter(ctx), "service", "storage-vacuum"))
		t := time.NewTicker(conf.StoreVacuumFrequency)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				vacuumStore(ctx, store)
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		ctx := alert.WithEmitter(ctx,
			alert.WithPairs(alert.UsedEmitter(ctx), "service", "background-tasks"))
		if err := bgJobQueue.ProcessIncoming(ctx, 2); err != nil {
			select {
			case errc <- fmt.Errorf("background task processing: %w", err):
			default:
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil // SIGINT
	case err := <-errc:
		return err
	}
}

func listenHTTP(ctx context.Context, addr string, hn http.Handler) error {
	server := http.Server{
		Addr:        addr,
		Handler:     hn,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(ctx)
	}()
	if err := server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}

func vacuumStore(ctx context.Context, store lith.Store) {
	session, err := store.Session(ctx)
	if err != nil {
		alert.Emit(ctx,
			"msg", "Cannot create store session.",
			"err", err.Error())
		return
	}
	defer session.Rollback()

	if err := session.Vacuum(ctx); err != nil {
		alert.Emit(ctx,
			"msg", "Vacuum failed",
			"err", err.Error())
		return
	}

	if err := session.Commit(); err != nil {
		alert.Emit(ctx,
			"msg", "Cannot commit vacuum session",
			"err", err.Error())
		return
	}
}
