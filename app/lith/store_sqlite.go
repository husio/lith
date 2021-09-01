package lith

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "embed"

	"github.com/husio/lith/pkg/secret"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// OpenSQLiteStore returns a store implementation backed by an SQLite engine.
func OpenSQLiteStore(dbpath string, safe secret.Safe) (Store, error) {
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // Because SQLite.

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migration: %w", err)
	}
	store := &sqliteStore{
		safe: safe,
		db:   db,
	}
	return store, nil
}

//go:embed migrations/*.sql
var migrationsFs embed.FS

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS
		migrations (name TEXT UNIQUE NOT NULL)
	`); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}

	entries, err := migrationsFs.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	var migrationFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		migrationFiles = append(migrationFiles, e.Name())
	}
	if len(migrationFiles) == 0 {
		return errors.New("no migration files found")
	}

	appliedMigrations := make(map[string]struct{})
	rows, err := db.Query(`SELECT name FROM migrations`)
	if err != nil {
		return fmt.Errorf("select existing migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan migration name: %w", err)
		}
		appliedMigrations[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("existing migrations scan: %w", err)
	}

	var missingMigrations []string
	for _, name := range migrationFiles {
		if _, ok := appliedMigrations[name]; ok {
			continue
		}
		missingMigrations = append(missingMigrations, name)
	}

	for _, name := range missingMigrations {
		content, err := migrationsFs.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read %q migration file: %w", name, err)
		}
		if len(content) == 0 {
			return fmt.Errorf("empty %q migration file", name)
		}
		for i, query := range strings.Split(string(content), "\n---\n") {
			if _, err := db.Exec(query); err != nil {
				return fmt.Errorf("apply %d query from %q migration file: %w", i, name, err)
			}
		}
		if _, err := db.Exec(`INSERT INTO migrations (name) VALUES (?)`, name); err != nil {
			return fmt.Errorf("inser %q migration file into migrations table: %w", name, err)
		}
	}
	return nil
}

type sqliteStore struct {
	db   *sql.DB
	safe secret.Safe
}

// Session returns a new session that process all operations within a
// translation.
func (s *sqliteStore) Session(ctx context.Context) (StoreSession, error) {
	c, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire db connection: %w", err)
	}
	sp, err := newSavepoint(c, true)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("new savepoint: %w", err)
	}

	session := &sqliteStoreSession{
		safe: s.safe,
		sp:   sp,
		dbc:  c,
	}
	return session, nil
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

type sqliteStoreSession struct {
	safe secret.Safe
	sp   *savepoint
	dbc  interface {
		ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
		QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
		QueryRowContext(context.Context, string, ...interface{}) *sql.Row
		Close() error
	}
}

func (s *sqliteStoreSession) Session(ctx context.Context) (StoreSession, error) {
	sp, err := newSavepoint(s.dbc, false)
	if err != nil {
		return nil, fmt.Errorf("new savepoint: %w", err)
	}

	session := &sqliteStoreSession{
		sp:  sp,
		dbc: s.dbc,
	}
	return session, nil
}

func (s *sqliteStoreSession) CreateAccount(ctx context.Context, email, password string) (*Account, error) {
	passhash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	now := currentTime()
	a := &Account{
		AccountID:  generateID(),
		Email:      normalizeEmail(email),
		CreatedAt:  now.UTC(),
		ModifiedAt: now.UTC(),
	}
	_, err = s.dbc.ExecContext(ctx, `
			INSERT INTO accounts (account_id, email, password, created_at, modified_at)
			VALUES (@account_id, @email, @password, @now, @now)
		`,
		sql.Named("account_id", a.AccountID),
		sql.Named("email", a.Email),
		sql.Named("password", passhash),
		sql.Named("now", now.Unix()),
	)
	if err != nil {
		return nil, fmt.Errorf("insert: %w", castSQLiteErr(err))
	}
	return a, nil
}

const passwordHashCost = bcrypt.DefaultCost + 2

func (s *sqliteStoreSession) UpdateAccountPassword(ctx context.Context, accountID string, password string) error {
	passhash, err := bcrypt.GenerateFromPassword([]byte(password), passwordHashCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := currentTime()
	_, err = s.dbc.ExecContext(ctx, `
			UPDATE accounts
			SET password = @passhash, modified_at = @now
			WHERE account_id = @account_id
		`,
		sql.Named("passhash", passhash),
		sql.Named("now", now.Unix()),
		sql.Named("account_id", accountID),
	)
	if err != nil {
		return fmt.Errorf("update: %w", castSQLiteErr(err))
	}
	return nil
}

func (s *sqliteStoreSession) IsAccountPassword(ctx context.Context, accountID, password string) error {
	var hashed []byte
	if err := s.dbc.QueryRowContext(ctx, `SELECT password FROM accounts WHERE account_id = ? LIMIT 1`, accountID).Scan(&hashed); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("scan: %w", err)
	}
	if bcrypt.CompareHashAndPassword(hashed, []byte(password)) != nil {
		return ErrPassword
	}
	return nil
}

func (s *sqliteStoreSession) UpdateAccountTOTPSecret(ctx context.Context, accountID string, totp secret.Value) error {
	// Empty totp secret means we want to unset it.
	if len(totp) == 0 {
		res, err := s.dbc.ExecContext(ctx, `UPDATE accounts SET totp_secret = NULL WHERE account_id = ?`, accountID)
		if err != nil {
			return fmt.Errorf("update: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("rows affected: %w", err)
		} else if n == 0 {
			return ErrNotFound
		}
		return nil
	}

	ciphertext, err := s.safe.Encrypt(totp)
	if err != nil {
		return fmt.Errorf("encrypt secret: %w", err)
	}
	res, err := s.dbc.ExecContext(ctx, `UPDATE accounts SET totp_secret = ? WHERE account_id = ?`, ciphertext, accountID)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStoreSession) AccountTOTPSecret(ctx context.Context, accountID string) (secret.Value, error) {
	var ciphertext []byte
	err := s.dbc.QueryRowContext(ctx, `
			SELECT totp_secret
			FROM accounts
			WHERE totp_secret IS NOT NULL
				AND account_id = ?
			LIMIT 1
		`, accountID).Scan(&ciphertext)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(ciphertext) == 0 {
		return nil, ErrNotFound
	}
	raw, err := s.safe.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	return raw, nil
}

func (s *sqliteStoreSession) UpdateAccountPermissionGroups(ctx context.Context, accountID string, permissionGroupIDs []uint64) error {
	if _, err := s.dbc.ExecContext(ctx, `
		DELETE FROM account_permissiongroups WHERE account_id = ?
	`, accountID); err != nil {
		return fmt.Errorf("delete existing groups: %w", castSQLiteErr(err))
	}
	for _, pid := range permissionGroupIDs {
		if _, err := s.dbc.ExecContext(ctx, `
		INSERT INTO account_permissiongroups (account_id, permissiongroup_id)
		VALUES (?, ?)
	`, accountID, pid); err != nil {
			return fmt.Errorf("assign %d permission group: %w", pid, castSQLiteErr(err))
		}
	}
	return nil
}

func (s *sqliteStoreSession) AccountByID(ctx context.Context, accountID string) (*Account, error) {
	res := s.dbc.QueryRowContext(ctx, `
		SELECT
			a.email,
			a.created_at,
			a.modified_at,
			COALESCE(GROUP_CONCAT(pg.permissions_array, ','), '') AS permissions_array
		FROM accounts a
		LEFT JOIN account_permissiongroups apg ON apg.account_id = a.account_id
		LEFT JOIN permissiongroups pg ON pg.permissiongroup_id = apg.permissiongroup_id
		WHERE a.account_id = @account_id
		GROUP BY 1, 2, 3
		LIMIT 1
	`, sql.Named("account_id", accountID))
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	var (
		acc      Account
		modified int64
		created  int64
		perms    string
	)
	if err := res.Scan(&acc.Email, &created, &modified, &perms); err != nil {
		return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
	}
	acc.AccountID = accountID
	acc.CreatedAt = time.Unix(created, 0).UTC()
	acc.ModifiedAt = time.Unix(modified, 0).UTC()
	if perms != "" {
		acc.Permissions = strings.Split(perms, ",")
	}
	return &acc, nil
}

func (s *sqliteStoreSession) AccountBySession(ctx context.Context, sessionID string) (*Account, error) {
	res := s.dbc.QueryRowContext(ctx, `
		SELECT
			a.account_id,
			a.email,
			a.created_at,
			a.modified_at,
			COALESCE(GROUP_CONCAT(pg.permissions_array, ','), '') AS permissions_array
		FROM accounts a
		LEFT JOIN sessions s ON s.account_id = a.account_id
		LEFT JOIN account_permissiongroups apg ON apg.account_id = a.account_id
		LEFT JOIN permissiongroups pg ON pg.permissiongroup_id = apg.permissiongroup_id
		WHERE s.session_id = @session_id AND s.expires_at > @now
		GROUP BY 1, 2, 3, 4
		LIMIT 1
	`,
		sql.Named("session_id", sessionID),
		sql.Named("now", currentTime().Unix()),
	)
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	var (
		acc      Account
		modified int64
		created  int64
		perms    string
	)
	if err := res.Scan(&acc.AccountID, &acc.Email, &created, &modified, &perms); err != nil {
		return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
	}
	acc.CreatedAt = time.Unix(created, 0).UTC()
	acc.ModifiedAt = time.Unix(modified, 0).UTC()
	if perms != "" {
		acc.Permissions = strings.Split(perms, ",")
	}
	return &acc, nil
}

func (s *sqliteStoreSession) AccountByEmail(ctx context.Context, email string) (*Account, error) {
	email = normalizeEmail(email)
	res := s.dbc.QueryRowContext(ctx, `
		SELECT
			a.account_id,
			a.created_at,
			a.modified_at,
			COALESCE(GROUP_CONCAT(pg.permissions_array, ','), '') AS permissions_array
		FROM accounts a
		LEFT JOIN account_permissiongroups apg ON apg.account_id = a.account_id
		LEFT JOIN permissiongroups pg ON pg.permissiongroup_id = apg.permissiongroup_id
		WHERE a.email = @email
		GROUP BY 1, 2, 3
		LIMIT 1
	`, sql.Named("email", email))
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	var (
		acc      Account
		modified int64
		created  int64
		perms    string
	)
	if err := res.Scan(&acc.AccountID, &created, &modified, &perms); err != nil {
		return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
	}
	acc.Email = email
	acc.CreatedAt = time.Unix(created, 0).UTC()
	acc.ModifiedAt = time.Unix(modified, 0).UTC()
	if perms != "" {
		acc.Permissions = strings.Split(perms, ",")
	}
	return &acc, nil
}

func (s *sqliteStoreSession) ListAccounts(ctx context.Context, filter string, limit uint, offset uint) ([]*Account, error) {
	var filters []string
	for _, s := range strings.Fields(filter) {
		// All emails are stored lowercased (see normalizeEmail
		// function) and the serach is case insensitive.
		s = strings.ToLower(s)

		// Regexp is narrow enough to avoid an SQL injection.
		val := regexp.MustCompile(`[^a-z0-9\-_.@+]+`).ReplaceAllString(s, "")
		filters = append(filters, "a.email LIKE '%"+val+"%'")
	}

	var sqlWhere string
	if len(filters) > 0 {
		sqlWhere = " WHERE " + strings.Join(filters, " AND ")
	}

	rows, err := s.dbc.QueryContext(ctx, `
			SELECT
				a.account_id,
				a.email,
				a.created_at,
				a.modified_at,
				COALESCE(GROUP_CONCAT(pg.permissions_array, ','), '') AS permissions_array
			FROM accounts a
			LEFT JOIN account_permissiongroups apg ON apg.account_id = a.account_id
			LEFT JOIN permissiongroups pg ON pg.permissiongroup_id = apg.permissiongroup_id
			`+sqlWhere+`
			GROUP BY 1, 2, 3, 4
			ORDER BY a.email ASC
			LIMIT @limit
			OFFSET @offset
		`,
		sql.Named("limit", limit),
		sql.Named("offset", offset),
	)
	if err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	defer rows.Close()
	var accounts []*Account
	for rows.Next() {
		var a Account
		var created, modified int64
		var perms string
		if err := rows.Scan(&a.AccountID, &a.Email, &created, &modified, &perms); err != nil {
			return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
		}
		a.CreatedAt = time.Unix(created, 0).UTC()
		a.ModifiedAt = time.Unix(modified, 0).UTC()
		if perms != "" {
			a.Permissions = strings.Split(perms, ",")
		}
		accounts = append(accounts, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", castSQLiteErr(err))
	}
	return accounts, nil
}

func (s *sqliteStoreSession) CreateSession(ctx context.Context, accountID string, expiresIn time.Duration) (string, error) {
	now := currentTime()
	sessionID := generateID()
	_, err := s.dbc.ExecContext(ctx, `
			INSERT INTO sessions (session_id, account_id, created_at, expires_at)
			VALUES (@session_id, @account_id, @created_at, @expires_at)
		`,
		sql.Named("session_id", sessionID),
		sql.Named("account_id", accountID),
		sql.Named("created_at", now.Unix()),
		sql.Named("expires_at", now.Add(expiresIn).Unix()))
	if err != nil {
		return "", fmt.Errorf("insert session: %w", castSQLiteErr(err))
	}
	return sessionID, nil
}

func (s *sqliteStoreSession) RefreshSession(ctx context.Context, sessionID string, expiresIn time.Duration) error {
	now := currentTime()

	// To avoid writes, update session expiration time only if it is beyond
	// certain threshold. In practice, we allow for a small delay with
	// update.
	updateIfOlder := now.Add(expiresIn / 10 * 9)
	_, err := s.dbc.ExecContext(ctx, `
			UPDATE sessions
			SET expires_at = @expires_at
			WHERE session_id = @session_id AND expires_at > @older_than
		`,
		sql.Named("session_id", sessionID),
		sql.Named("expires_at", now.Add(expiresIn).Unix()),
		sql.Named("older_than", updateIfOlder.Unix()),
	)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// Because of how the query filters, we cannot return ErrNotFound
	// without making an additional db call.

	return nil
}

func (s *sqliteStoreSession) DeleteSession(ctx context.Context, sessionID string) error {
	res, err := s.dbc.ExecContext(ctx, `DELETE FROM sessions WHERE session_id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("delete: %w", castSQLiteErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", castSQLiteErr(err))
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStoreSession) CreatePermissionGroup(ctx context.Context, description string, permissions []string) (*PermissionGroup, error) {
	now := currentTime()
	res := s.dbc.QueryRowContext(ctx, `
		INSERT INTO permissiongroups (permissions_array, description, created_at, modified_at)
		VALUES (@permissions, @description, @now, @now)
		RETURNING permissiongroup_id
	`,
		sql.Named("permissions", strings.Join(permissions, ",")),
		sql.Named("description", description),
		sql.Named("now", now.Unix()),
	)
	if err := res.Err(); err != nil {
		return nil, fmt.Errorf("insert: %w", err)
	}
	var pgID uint64
	if err := res.Scan(&pgID); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	pg := &PermissionGroup{
		PermissionGroupID: pgID,
		Permissions:       permissions,
		Description:       description,
		CreatedAt:         now,
		ModifiedAt:        now,
	}
	return pg, nil
}

func (s *sqliteStoreSession) UpdatePermissionGroup(ctx context.Context, permissionGroupID uint64, description string, permissions []string) error {
	now := currentTime().Unix()
	res, err := s.dbc.ExecContext(ctx, `
			UPDATE permissiongroups SET
				description = @description,
				permissions_array = @permissions,
				modified_at = @now
			WHERE permissiongroup_id = @id
		`,
		sql.Named("id", permissionGroupID),
		sql.Named("description", description),
		sql.Named("permissions", strings.Join(permissions, ",")),
		sql.Named("now", now),
	)
	if err != nil {
		return fmt.Errorf("update: %w", castSQLiteErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", castSQLiteErr(err))
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sqliteStoreSession) PermissionGroupsByAccount(ctx context.Context, accountID string) ([]*PermissionGroup, error) {
	rows, err := s.dbc.QueryContext(ctx, `
		SELECT
			pg.permissiongroup_id,
			pg.permissions_array,
			pg.description,
			pg.created_at,
			pg.modified_at
		FROM permissiongroups pg
			INNER JOIN account_permissiongroups apg ON apg.permissiongroup_id = pg.permissiongroup_id
		WHERE apg.account_id = ?
		ORDER BY 1
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}

	var groups []*PermissionGroup
	for rows.Next() {
		var pg PermissionGroup
		var (
			permissions string
			created     int64
			modified    int64
		)
		if err := rows.Scan(&pg.PermissionGroupID, &permissions, &pg.Description, &created, &modified); err != nil {
			return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
		}
		if permissions != "" {
			pg.Permissions = strings.Split(permissions, ",")
		}
		pg.CreatedAt = time.Unix(created, 0).UTC()
		pg.ModifiedAt = time.Unix(modified, 0).UTC()
		groups = append(groups, &pg)
	}
	return groups, nil
}

func (s *sqliteStoreSession) PermissionGroupByID(ctx context.Context, permissionGroupID uint64) (*PermissionGroup, error) {
	row := s.dbc.QueryRowContext(ctx, `
		SELECT
			permissions_array,
			description,
			created_at,
			modified_at
		FROM permissiongroups
		WHERE permissiongroup_id = ?
		LIMIT 1
	`, permissionGroupID)
	if err := row.Err(); err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	pg := &PermissionGroup{
		PermissionGroupID: permissionGroupID,
	}
	var (
		permissions string
		created     int64
		modified    int64
	)
	if err := row.Scan(&permissions, &pg.Description, &created, &modified); err != nil {
		return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
	}
	pg.Permissions = strings.Split(permissions, ",")
	pg.CreatedAt = time.Unix(created, 0).UTC()
	pg.ModifiedAt = time.Unix(modified, 0).UTC()
	return pg, nil
}

func (s *sqliteStoreSession) ListPermissionGroups(ctx context.Context) ([]*PermissionGroup, error) {
	rows, err := s.dbc.QueryContext(ctx, `
		SELECT permissiongroup_id, permissions_array, description, created_at, modified_at
		FROM permissiongroups
		ORDER BY permissiongroup_id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	defer rows.Close()

	var groups []*PermissionGroup
	for rows.Next() {
		var (
			g                 PermissionGroup
			created, modified int64
			perms             string
		)
		if err := rows.Scan(&g.PermissionGroupID, &perms, &g.Description, &created, &modified); err != nil {
			return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
		}
		g.CreatedAt = time.Unix(created, 0)
		g.ModifiedAt = time.Unix(modified, 0)
		if perms != "" {
			g.Permissions = strings.Split(perms, ",")
		}
		groups = append(groups, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", castSQLiteErr(err))
	}
	return groups, nil
}

func (s *sqliteStoreSession) ListChangelogs(ctx context.Context) ([]*Changelog, error) {
	rows, err := s.dbc.QueryContext(ctx, `
		SELECT c.changelog_id, c.account_id, c.created_at, a.email, c.operation, c.entity_kind, c.entity_pk
		FROM changelogs c
		INNER JOIN accounts a ON c.account_id = a.account_id
		ORDER BY c.created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	defer rows.Close()

	var changelogs []*Changelog
	for rows.Next() {
		var (
			c       Changelog
			created int64
		)
		if err := rows.Scan(&c.ChangelogID, &c.AccountID, &created, &c.AccountEmail, &c.Operation, &c.EntityKind, &c.EntityPk); err != nil {
			return nil, fmt.Errorf("scan: %w", castSQLiteErr(err))
		}
		c.CreatedAt = time.Unix(created, 0)
		changelogs = append(changelogs, &c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", castSQLiteErr(err))
	}
	return changelogs, nil
}

func (s *sqliteStoreSession) AddChangelog(ctx context.Context, authentitcatedAs, operation, entityKind, entityPk string) error {
	_, err := s.dbc.ExecContext(ctx, `
		INSERT INTO changelogs (account_id, operation, entity_kind, entity_pk, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, authentitcatedAs, operation, entityKind, entityPk, currentTime().Unix())
	if err != nil {
		return fmt.Errorf("insert: %w", castSQLiteErr(err))
	}
	return nil
}

func (s *sqliteStoreSession) CreateEphemeralToken(ctx context.Context, action string, expireIn time.Duration, payload interface{}) (string, error) {
	serializedPayload, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("serialize payload: %w", err)
	}
	now := currentTime()
	tokenID := generateID()
	_, err = s.dbc.ExecContext(ctx, `
			INSERT INTO ephemeraltokens (token_id, action, payload, created_at, expires_at)
			VALUES (@token_id, @action, @payload, @created_at, @expires_at)
		`,
		sql.Named("token_id", tokenID),
		sql.Named("action", action),
		sql.Named("payload", serializedPayload),
		sql.Named("created_at", now.Unix()),
		sql.Named("expires_at", now.Add(expireIn).Unix()),
	)
	err = castSQLiteErr(err)
	switch {
	case err == nil:
		return tokenID, nil
	case errors.Is(err, nil):
		return "", fmt.Errorf("invalid account: %w", ErrConflict)
	default:
		return "", fmt.Errorf("insert: %w", castSQLiteErr(err))
	}
}

func (s *sqliteStoreSession) EphemeralToken(ctx context.Context, action string, tokenID string, payloadDest interface{}) error {
	now := currentTime()
	row := s.dbc.QueryRowContext(ctx, `
		SELECT payload
		FROM ephemeraltokens
		WHERE action = ?  AND token_id = ?  AND expires_at > ?
		LIMIT 1
	`, action, tokenID, now.Unix())
	if err := row.Err(); err != nil {
		return fmt.Errorf("select: %w", castSQLiteErr(err))
	}
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		return fmt.Errorf("scan: %w", castSQLiteErr(err))
	}
	if err := json.Unmarshal(payload, payloadDest); err != nil {
		return fmt.Errorf("unmarhsal payload: %w", err)
	}
	return nil
}

func (s *sqliteStoreSession) DeleteEphemeralToken(ctx context.Context, tokenID string) error {
	// Expiration time does not matter.
	res, err := s.dbc.ExecContext(ctx, `DELETE FROM ephemeraltokens WHERE token_id = ?`, tokenID)
	if err != nil {
		return fmt.Errorf("delete: %w", castSQLiteErr(err))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", castSQLiteErr(err))
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Vacuum removes stale data that is no longer requred. For example expired
// ephemeral tokens or sessions.
func (s *sqliteStoreSession) Vacuum(ctx context.Context) error {
	now := currentTime()
	if _, err := s.dbc.ExecContext(ctx, `DELETE FROM ephemeraltokens WHERE expires_at <= ?`, now.Unix()); err != nil {
		return fmt.Errorf("delete ephemeraltokens: %w", castSQLiteErr(err))
	}
	if _, err := s.dbc.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return fmt.Errorf("delete sessions: %w", castSQLiteErr(err))
	}
	// Below could be optimized by DELETE ORDER OFFSET but for some reason,
	// even though compiled in, sql syntax is not accepted by the driver.
	if _, err := s.dbc.ExecContext(ctx, `
		DELETE FROM changelogs WHERE changelog_id NOT IN (
			SELECT changelog_id FROM changelogs
			ORDER BY created_at DESC
			LIMIT 1000
		)
	`); err != nil {
		return fmt.Errorf("delete changelogs: %w", castSQLiteErr(err))
	}
	return nil
}

func (stx *sqliteStoreSession) Rollback() {
	_ = stx.sp.Rollback()
}

func (stx *sqliteStoreSession) Commit() error {
	return stx.sp.Commit()
}

// newSavepoint returns an SQLite3 savepoint implementation that can be nested.
// https://sqlite.org/lang_savepoint.html
func newSavepoint(c execCloser, outer bool) (*savepoint, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	name := "sp_" + hex.EncodeToString(b)
	if _, err := c.ExecContext(context.Background(), "SAVEPOINT "+name); err != nil {
		return nil, fmt.Errorf("create db savepoint: %w", castSQLiteErr(err))
	}
	return &savepoint{name: name, c: c, outer: outer}, nil
}

type execCloser interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	Close() error
}

type savepoint struct {
	name  string
	outer bool
	c     execCloser
}

func (sp savepoint) Rollback() error {
	_, err := sp.c.ExecContext(context.Background(), "ROLLBACK TO  "+sp.name)
	if sp.outer {
		_ = sp.c.Close()
	}
	if err != nil {
		return fmt.Errorf("rollback to savepoint: %w", castSQLiteErr(err))
	}
	return nil
}

func (sp savepoint) Commit() error {
	var err error
	if sp.outer {
		_, err = sp.c.ExecContext(context.Background(), "COMMIT")
		_ = sp.c.Close()
	} else {
		_, err = sp.c.ExecContext(context.Background(), "RELEASE "+sp.name)
	}
	if err != nil {
		return fmt.Errorf("release savepoint: %w", castSQLiteErr(err))
	}
	return nil
}

func castSQLiteErr(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}

	// http://www.sqlite.org/c3ref/c_abort.html
	if err, ok := err.(sqlite3.Error); ok {
		switch err.Code {
		case 12:
			return ErrNotFound
		case 19:
			return fmt.Errorf("%w: %s", ErrConflict, err)
		}
	}

	return err
}

func addPermissionGroups(ctx context.Context, session StoreSession, accountID string, groupIDs []uint64) error {
	groups, err := session.PermissionGroupsByAccount(ctx, accountID)
	if err != nil {
		return fmt.Errorf("account permission groups: %w", err)
	}

	all := make([]uint64, 0, len(groups)+len(groupIDs))
	missing := make(map[uint64]struct{})
	for _, id := range groupIDs {
		missing[id] = struct{}{}
	}

	for _, g := range groups {
		all = append(all, g.PermissionGroupID)
		if _, ok := missing[g.PermissionGroupID]; ok {
			delete(missing, g.PermissionGroupID)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	for id := range missing {
		all = append(all, id)
	}

	if err := session.UpdateAccountPermissionGroups(ctx, accountID, all); err != nil {
		return fmt.Errorf("update account permission groups: %w", err)
	}
	return nil
}
