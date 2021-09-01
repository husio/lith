package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/husio/lith/app/lith"
)

func cmdVacuum(ctx context.Context, conf lith.Configuration, args []string) error {
	fl := flag.NewFlagSet("vacuum", flag.ContinueOnError)
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("flag parse: %w", err)
	}

	db, err := lith.OpenSQLiteStore(conf.Database, nil)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	session, err := db.Session(ctx)
	if err != nil {
		return fmt.Errorf("start session: %w", err)
	}
	defer session.Rollback()

	if err := session.Vacuum(ctx); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}

	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
