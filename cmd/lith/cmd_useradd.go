package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/husio/lith/app/lith"
	"github.com/husio/lith/pkg/secret"
)

func cmdUserAdd(ctx context.Context, conf lith.Configuration, args []string) error {
	fl := flag.NewFlagSet("useradd", flag.ContinueOnError)
	emailFl := fl.String("email", "", "User email.")
	passFl := fl.String("password", "", "User password.")
	groupsFl := fl.String("groups", "", "Coma separated list or permission group IDs.")
	allowInsecureFl := fl.Bool("allow-insecure", false, "Allow for an insecure password.")
	if err := fl.Parse(args); err != nil {
		return fmt.Errorf("flag parse: %w", err)
	}

	nonEmailChars := regexp.MustCompile(`[^a-z0-9@\.]`) // YOLO.
	email := nonEmailChars.ReplaceAllString(strings.ToLower(*emailFl), "")
	if len(email) == 0 {
		return errors.New("email is required")
	}

	pass := strings.TrimSpace(*passFl)
	if len(pass) < 8 && !*allowInsecureFl {
		return errors.New("password too short")
	}

	var groups []uint64
	for _, sid := range strings.Split(*groupsFl, ",") {
		if sid == "" {
			continue
		}
		id, err := strconv.ParseUint(sid, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid permission group ID: %w", err)
		}
		groups = append(groups, id)
	}

	safe := secret.AESSafe(conf.Secret)
	db, err := lith.OpenSQLiteStore(conf.Database, safe)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	session, err := db.Session(ctx)
	if err != nil {
		return fmt.Errorf("start session: %w", err)
	}
	defer session.Rollback()

	account, err := session.CreateAccount(ctx, email, pass)
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	if len(groups) > 0 {
		if err := session.UpdateAccountPermissionGroups(ctx, account.AccountID, groups); err != nil {
			return fmt.Errorf("assign permission groups: %w", err)
		}
	}
	if err := session.Commit(); err != nil {
		return fmt.Errorf("commit session: %w", err)
	}

	return nil
}
