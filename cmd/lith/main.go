package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/husio/lith/app/lith"
	"github.com/husio/lith/pkg/alert"

	"github.com/BurntSushi/toml"
)

var (
	// sourceHash is set during compilation time to git hash.
	sourceHash string = "HEAD"
)

func main() {
	// This is the default configration that can be fully or partially
	// overwritten by loading TOML file.
	conf := lith.Configuration{
		Database:             "./lith.sqlite3.db?_journal=wal&_fk=on",
		TaskQueueDatabase:    "./lith_taskqueue.sqlite3.db?_journal=wal&_fk=on",
		StoreVacuumFrequency: 31 * time.Minute,
		Secret:               "",
		EmailBackend:         "smtp",
		MaxCacheSize:         1e7,

		API: lith.APIConfiguration{
			ListenHTTP:           ":8000",
			PathPrefix:           "/api/",
			SessionMaxAge:        4 * 24 * time.Hour,
			SessionRefreshAge:    2 * 24 * time.Hour,
			RequireTwoFactorAuth: true,
			MinPasswordLength:    12,
			RegisteredAccountPermissionGroups: []uint64{
				lith.PermissionGroupActiveAccount,
			},
			AllowRegisterEmail: ".*",
		},
		PublicUI: lith.PublicUIConfiguration{
			ListenHTTP:           ":8000",
			DomainSSL:            true,
			PathPrefix:           "/",
			RequireTwoFactorAuth: true,
			SessionMaxAge:        5 * 24 * time.Hour,
			MinPasswordLength:    12,
			RegisteredAccountPermissionGroups: []uint64{
				lith.PermissionGroupActiveAccount,
			},
			AllowRegisterAccount: true,
			AllowPasswordReset:   true,
			AllowRegisterEmail:   ".*",
		},
		AdminPanel: lith.AdminPanelConfiguration{
			ListenHTTP:           ":8000",
			PathPrefix:           "/admin/",
			SessionMaxAge:        3 * 24 * time.Hour,
			RequireTwoFactorAuth: true,
		},
	}

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [<flags>] <command> [<flags>]\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Global flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nAvailable commands are:\n\t%s\n", strings.Join(availableCmds(), "\n\t"))
		fmt.Fprintf(flag.CommandLine.Output(), "\nRun '%s <command> -help' to learn more about each command.\n", os.Args[0])
	}
	confFl := flag.String("conf", "", "TOML configuration file path. If provided, overwrites default settings.")
	flag.Parse()

	if *confFl != "" {
		tomlConfig, err := ioutil.ReadFile(*confFl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Reading TOML configuration failed: %s\n", err)
			os.Exit(2)
		}
		if _, err := toml.Decode(string(tomlConfig), &conf); err != nil {
			fmt.Fprintf(os.Stderr, "Loading TOML configuration failed: %s\n", err)
			os.Exit(2)
		}
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	run, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command %q\n", args[0])
		fmt.Fprintf(os.Stderr, "\nAvailable commands are:\n\t%s\n", strings.Join(availableCmds(), "\n\t"))
		os.Exit(2)
	}

	// Validate configuration and report any critical issues.
	if issues := checkConfiguration(conf); len(issues) != 0 && args[0] != "print-config" {
		fmt.Fprintln(os.Stderr, "Configuration issues found.")
		for _, issue := range issues {
			fmt.Fprintln(os.Stderr, "\t"+issue)
		}
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	emitter := alert.NewTextEmitter(os.Stdout)
	emitter = alert.WithPairs(emitter, "sourcehash", sourceHash)
	ctx = alert.WithEmitter(ctx, emitter)

	// Skip first two arguments. Second argument is the command name that
	// we just consumed.
	if err := run(ctx, conf, args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// A list of all registered commands available by this program.
var commands = map[string]func(context.Context, lith.Configuration, []string) error{
	"print-config": cmdPrintConfig,
	"serve":        cmdServe,
	"useradd":      cmdUserAdd,
	"vacuum":       cmdVacuum,
}

// availableCmds returns a sorted list of all available commands.
func availableCmds() []string {
	available := make([]string, 0, len(commands))
	for name := range commands {
		available = append(available, name)
	}
	sort.Strings(available)
	return available
}

// checkConfiguration does a very basic validity check for the configuration to
// help avoid running obviously broken app.
func checkConfiguration(c lith.Configuration) []string {
	var issues []string

	if c.Secret == "" {
		issues = append(issues, "Secret is required.")
	}
	if c.Database == "" {
		issues = append(issues, "Database is required.")
	}
	if c.TaskQueueDatabase == "" {
		issues = append(issues, "TaskQueueDatabase is required.")
	}

	switch c.EmailBackend {
	case "smtp", "fs":
	case "":
		issues = append(issues, "EmailBackend is required.")
	default:
		issues = append(issues, "EmailBackend value is not recognized..")
	}

	apps := []struct {
		Name       string
		ListenHTTP string
		PathPrefix string
	}{
		{Name: "API", ListenHTTP: c.API.ListenHTTP, PathPrefix: c.API.PathPrefix},
		{Name: "PublicUI", ListenHTTP: c.PublicUI.ListenHTTP, PathPrefix: c.PublicUI.PathPrefix},
		{Name: "AdminPanel", ListenHTTP: c.AdminPanel.ListenHTTP, PathPrefix: c.AdminPanel.PathPrefix},
	}

	appPrefix := make(map[string][][2]string)
	for _, app := range apps {
		if app.ListenHTTP == "" {
			continue
		}
		switch {
		case len(app.PathPrefix) == 0:
			issues = append(issues, app.Name+`.PathPrefix cannot be empty. Use "/" for no prefix.`)
		case !strings.HasPrefix(app.PathPrefix, "/"):
			issues = append(issues, app.Name+`.PathPrefix must start with "/"`)
		case !strings.HasSuffix(app.PathPrefix, "/"):
			issues = append(issues, app.Name+`.PathPrefix must end with "/"`)
		}
		for _, other := range appPrefix[c.API.ListenHTTP] {
			if other[1] == app.PathPrefix {
				issues = append(issues, app.Name+`.PathPrefix and `+other[0]+`.PathPrefix must not be the same.`)
			}
		}
		appPrefix[app.ListenHTTP] = append(appPrefix[app.ListenHTTP], [2]string{app.Name, app.PathPrefix})
	}

	if _, err := regexp.Compile(c.PublicUI.AllowRegisterEmail); err != nil {
		issues = append(issues, "PublicUI.AllowRegisterEmail is not a valid regular expression.")
	}

	if c.PublicUI.ListenHTTP != "" {
		if c.PublicUI.FromEmail == "" {
			issues = append(issues, "PublicUI.FromEmail must not be empty.")
		}
		if strings.HasPrefix(c.PublicUI.Domain, "http://") || strings.HasPrefix(c.PublicUI.Domain, "https://") {
			issues = append(issues, "PublicUI.Domain must not contain protocol.")
		}
	}

	if c.API.ListenHTTP != "" {
		if _, err := regexp.Compile(c.API.AllowRegisterEmail); err != nil {
			issues = append(issues, "API.AllowRegisterEmail is not a valid regular expression.")
		}
		if c.API.FromEmail == "" {
			issues = append(issues, "API.FromEmail must not be empty.")
		}
	}

	return issues
}
