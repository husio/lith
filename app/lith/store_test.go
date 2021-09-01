package lith

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"
)

func testStoreImplementation(t *testing.T, newStore func() Store) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	newSession := func(t *testing.T) StoreSession {
		t.Helper()
		s, err := newStore().Session(ctx)
		if err != nil {
			t.Fatalf("create new session: %s", err)
		}
		t.Cleanup(func() {
			// Commit, because if using persistance database for
			// debugging, we want to keep all changes.
			if err := s.Commit(); err != nil {
				t.Logf("cannot commit changes: %s", err)
			}
		})
		return s
	}

	t.Run("create and get account", func(t *testing.T) {
		db := newSession(t)

		withGenerateID(t, "user-12345")

		acc, err := db.CreateAccount(ctx, "testjoe@example.com", "qwertyuiop1234567890")
		if err != nil {
			t.Fatalf("cannot create an account: %s", err)
		}
		if want, got := "user-12345", acc.AccountID; want != got {
			t.Fatalf("account ID should be %q, got %q", want, got)
		}

		acc2, err := db.AccountByID(ctx, "user-12345")
		if err != nil {
			t.Fatalf("cannot get existing account by ID: %s", err)
		}
		if !reflect.DeepEqual(acc, acc2) {
			t.Fatalf("data corrupted\nwant %+v\n got %+v", acc, acc2)
		}
		if _, err := db.AccountByID(ctx, "unknown-user-id"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %+v", err)
		}

		acc3, err := db.AccountByEmail(ctx, "testjoe@example.com")
		if err != nil {
			t.Fatalf("cannot get existing account by login: %s", err)
		}
		if !reflect.DeepEqual(acc, acc3) {
			t.Fatalf("data corrupted\nwant %+v\n got %+v", acc, acc3)
		}
		if _, err := db.AccountByEmail(ctx, "unknown-user-login@foo.com"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %+v", err)
		}
	})

	t.Run("create and manage permission groups", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second) // UNIX
		withCurrentTime(t, now)

		db := newSession(t)
		adminPermissions := []string{
			"login", "create-users", "access-admin", "delete-session",
		}
		sort.Strings(adminPermissions)
		pg, err := db.CreatePermissionGroup(ctx, "admin", adminPermissions)
		if err != nil {
			t.Fatalf("cannot create permission group: %s", err)
		}

		want := &PermissionGroup{
			PermissionGroupID: pg.PermissionGroupID,
			Permissions:       adminPermissions,
			Description:       "admin",
			CreatedAt:         now,
			ModifiedAt:        now,
		}
		if !reflect.DeepEqual(want, pg) {
			t.Fatalf("created permission data is not as expected\nwant %+v\n got %+v", want, pg)
		}

		withCurrentTime(t, now.Add(time.Hour))
		userPermissions := []string{
			"login", "manage-blog", "invite",
		}
		sort.Strings(userPermissions)
		if err := db.UpdatePermissionGroup(ctx, pg.PermissionGroupID, "user", userPermissions); err != nil {
			t.Fatalf("cannot update permission group %d: %s", pg.PermissionGroupID, err)
		}

		got, err := db.PermissionGroupByID(ctx, pg.PermissionGroupID)
		if err != nil {
			t.Fatalf("cannot get %d permission group: %s", pg.PermissionGroupID, err)
		}
		want = &PermissionGroup{
			PermissionGroupID: pg.PermissionGroupID,
			Permissions:       userPermissions,
			Description:       "user",
			CreatedAt:         now,
			ModifiedAt:        now.Add(time.Hour),
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("created permission data is not as expected\nwant %+v\n got %+v", want, got)
		}
	})

	t.Run("update user permission groups", func(t *testing.T) {
		t.Skip("todo")
	})

	t.Run("updating non existing permission group returns ErrNotFound", func(t *testing.T) {
		db := newSession(t)
		err := db.UpdatePermissionGroup(ctx, 12412, "description", []string{"foo"})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %#v", err)
		}
	})

	t.Run("authentication session creation and use", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		withCurrentTime(t, now)
		db := newSession(t)

		acc, _ := db.CreateAccount(ctx, "testjoe@example.com", "qwertyuiop1234567890")
		sessionID, err := db.CreateSession(ctx, acc.AccountID, time.Hour)
		if err != nil {
			t.Fatalf("create session: %s", err)
		}
		acc2, err := db.AccountBySession(ctx, sessionID)
		if err != nil {
			t.Fatalf("account by session id %s: %s", sessionID, err)
		}
		if !reflect.DeepEqual(acc, acc2) {
			t.Errorf("account by session differs\nwant %+v\n got %+v", acc, acc2)
		}

		withCurrentTime(t, now.Add(100*time.Hour))
		if acc3, err := db.AccountBySession(ctx, sessionID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("session must be expired, got %+v, %v", acc3, err)
		}
	})

	t.Run("ephemeral token", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		withCurrentTime(t, now)
		db := newSession(t)

		if _, err := db.CreateEphemeralToken(ctx, "run", time.Hour, nil); err != nil {
			t.Errorf("cannot create a token with no payload: %s", err)
		}

		token, err := db.CreateEphemeralToken(ctx, "say-hello", time.Hour, "some data")
		if err != nil {
			t.Fatalf("cannot create ephemeral token: %s", err)
		}

		var payload string
		if err := db.EphemeralToken(ctx, "jump", token, &payload); !errors.Is(err, ErrNotFound) {
			t.Fatalf("when using wrong action, ErrNotFound is expected, got %+v, %v", err, payload)
		}

		withCurrentTime(t, now.Add(time.Hour+time.Second))
		if err := db.EphemeralToken(ctx, "say-hello", token, payload); !errors.Is(err, ErrNotFound) {
			t.Fatalf("when using expired token, ErrNotFound is expected, got %+v, %v", err, payload)
		}

		withCurrentTime(t, now)
		if err := db.EphemeralToken(ctx, "say-hello", token, &payload); err != nil {
			t.Fatalf("account by ephemeral token failed with: %v", err)
		}
		if payload != "some data" {
			t.Errorf("unexpected token payload: %q", payload)
		}

		if err := db.DeleteEphemeralToken(ctx, token); err != nil {
			t.Fatalf("cannot delete ephemeral token: %v", err)
		}
		if err := db.DeleteEphemeralToken(ctx, token); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleting a non existing token must return ErrNotFound, got %+v", err)
		}
	})

	t.Run("list and filter accounts", func(t *testing.T) {
		db := newSession(t)

		emails := []string{
			"alex@example.com",
			"bob+test@example.com",
			"cherry+test@example.com",
			"danny+test@void.org",
			"elisa.test@void.org",
			"freya.zero@void.org",
			"glem+test@void.org",
			"harry+zero@void.org",
			"ingmar@void.club",
		}
		for _, e := range emails {
			if _, err := db.CreateAccount(ctx, e, "xyz"); err != nil {
				t.Fatalf("cannot create %q account: %s", e, err)
			}
		}

		cases := map[string]struct {
			Filter     string
			Limit      uint
			Offset     uint
			WantEmails []string
		}{
			"no filter": {
				Filter: "",
				Limit:  3,
				Offset: 0,
				WantEmails: []string{
					"alex@example.com",
					"bob+test@example.com",
					"cherry+test@example.com",
				},
			},
			"no filter and offset": {
				Filter: "",
				Limit:  3,
				Offset: 2,
				WantEmails: []string{
					"cherry+test@example.com",
					"danny+test@void.org",
					"elisa.test@void.org",
				},
			},
			"filter by domain": {
				Filter: "@void",
				Limit:  3,
				Offset: 0,
				WantEmails: []string{
					"danny+test@void.org",
					"elisa.test@void.org",
					"freya.zero@void.org",
				},
			},
			"filter with two words": {
				Filter: "void test",
				Limit:  10,
				Offset: 0,
				WantEmails: []string{
					"danny+test@void.org",
					"elisa.test@void.org",
					"glem+test@void.org",
				},
			},
			"filter with two words and special characters": {
				Filter: "void.org +test",
				Limit:  10,
				Offset: 0,
				WantEmails: []string{
					"danny+test@void.org",
					"glem+test@void.org",
				},
			},
		}

		for testName, tc := range cases {
			t.Run(testName, func(t *testing.T) {
				accounts, err := db.ListAccounts(ctx, tc.Filter, tc.Limit, tc.Offset)
				if err != nil {
					t.Fatalf("list accounts failed: %s", err)
				}
				var emails []string
				for _, a := range accounts {
					emails = append(emails, a.Email)
				}

				if !reflect.DeepEqual(emails, tc.WantEmails) {
					t.Logf("want: %q", tc.WantEmails)
					t.Logf(" got: %q", emails)
					t.Fail()
				}
			})
		}

	})
}

// withCurrentTime overwrites the current time as observed by the store until
// the test cleanup.
func withCurrentTime(t testing.TB, now time.Time) {
	t.Helper()
	original := currentTime
	currentTime = func() time.Time { return now }
	t.Cleanup(func() { currentTime = original })
}

// withGenerateID overwrites the current ID generator to always
// return given value until the test cleanup.
func withGenerateID(t testing.TB, id string) {
	t.Helper()
	original := generateID
	generateID = func() string { return id }
	t.Cleanup(func() { generateID = original })
}

func insertAccount(t testing.TB, s StoreSession, email, password, totpSecret string, permissionGroups []uint64) string {
	t.Helper()
	ctx := context.Background()

	a, err := s.CreateAccount(ctx, email, password)
	if err != nil {
		t.Fatalf("create account: %s", err)
	}
	if err := s.UpdateAccountPermissionGroups(ctx, a.AccountID, permissionGroups); err != nil {
		t.Fatalf("cannot assign groups to jimmy: %s", err)
	}
	if err := s.UpdateAccountTOTPSecret(ctx, a.AccountID, []byte(totpSecret)); err != nil {
		t.Fatalf("cannot set TOTP secret: %s", err)
	}
	return a.AccountID
}

func atomic(t testing.TB, s Store, fn func(s StoreSession)) {
	session, err := s.Session(context.Background())
	if err != nil {
		t.Fatalf("create store session: %s", err)
	}
	defer session.Rollback()

	fn(session)

	if err := session.Commit(); err != nil {
		t.Fatalf("store session commit: %s", err)
	}
}
