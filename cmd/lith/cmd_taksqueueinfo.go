package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"

	"github.com/husio/lith/app/lith"
	"github.com/husio/lith/pkg/taskqueue"
)

func cmdTaskQueueInfo(ctx context.Context, conf lith.Configuration, args []string) error {
	fl := flag.NewFlagSet("taskqueueinfo", flag.ContinueOnError)
	flAddr := fl.String("address", "localhost:8085", "HTTP server address.")
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("flag parse: %w", err)
	}

	queueStore, err := taskqueue.OpenTaskQueue(conf.TaskQueueDatabase)
	if err != nil {
		return fmt.Errorf("open task queue store: %w", err)
	}
	defer queueStore.Close()

	server := http.Server{
		Addr:        *flAddr,
		Handler:     queueStore,
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
