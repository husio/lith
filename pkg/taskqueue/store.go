package taskqueue

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	// SQLite driver.

	_ "github.com/mattn/go-sqlite3"
)

// OpenTaskQueue returns a task queue store implementation.
func OpenTaskQueue(dbpath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbpath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	db.SetMaxOpenConns(1) // Because SQLite.
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(time.Second)
	db.SetConnMaxLifetime(time.Second * 3)

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migration: %w", err)
	}

	return &Store{db: db}, nil
}

//go:embed migrations.sql
var migrations string

func migrate(db *sql.DB) error {
	for _, query := range strings.Split(migrations, "\n---\n") {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("%w: %s", err, query)
		}
	}
	return nil
}

type Store struct {
	db *sql.DB
}

// Close the store and free all resources.
func (s *Store) Close() error {
	return s.db.Close()
}

// Push one or more tasks to the queue. This is an atomic operation.
func (s *Store) Push(ctx context.Context, tasks []Pushed) ([]string, error) {
	if len(tasks) == 0 {
		return nil, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("start transaction: %w", err)
	}
	defer tx.Rollback()

	now := currentTime()

	taskIDs := make([]string, 0, len(tasks))
	for _, t := range tasks {
		taskID := generateID()
		taskIDs = append(taskIDs, taskID)

		payload := t.Payload
		if payload == nil {
			payload = emptyPayload
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tasks (task_id, name, payload, retry, timeout, execute_at, created_at)
			VALUES (@task_id, @name, @payload, @retry, @timeout, @execute_at, @created_at)
		`,
			sql.Named("task_id", taskID),
			sql.Named("name", t.Name),
			sql.Named("payload", payload),
			sql.Named("retry", t.Retry),
			sql.Named("timeout", t.Timeout/time.Second),
			sql.Named("execute_at", now.Add(t.ExecuteIn).Unix()),
			sql.Named("created_at", now.Unix()),
		)
		if err != nil {
			return nil, fmt.Errorf("insert: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return taskIDs, nil
}

type Pushed struct {
	Name      string
	Payload   []byte
	Retry     uint
	ExecuteIn time.Duration
	Timeout   time.Duration
}

var emptyPayload = make([]byte, 0)

// Delete removes task with given ID from the queue if present and not locked
// for processing.
func (s *Store) Delete(ctx context.Context, taskID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start transaction: %w", err)
	}
	defer tx.Rollback()

	var ok bool
	switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM acquired WHERE task_id = ? LIMIT 1`, taskID).Scan(&ok); {
	case err == nil && ok:
		return fmt.Errorf("task is being processed: %w", ErrLocked)
	case errors.Is(err, sql.ErrNoRows):
		// All good.
	default:
		return fmt.Errorf("check if task is acquired: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM tasks WHERE task_id = ?`, taskID)
	if err != nil {
		return fmt.Errorf("delete task: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n != 1 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (s *Store) Pull(ctx context.Context) (*Pulled, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("start transaction: %w", err)
	}
	defer tx.Rollback()

	now := currentTime()
	row := tx.QueryRowContext(ctx, `
		SELECT task_id, name, payload, timeout
		FROM tasks
		WHERE execute_at <= ?
			AND task_id NOT IN (SELECT task_id FROM acquired)
		ORDER BY execute_at ASC
		LIMIT 1
	`, now.Unix())

	var task Pulled
	var timeout int64
	if err := row.Scan(&task.TaskID, &task.Name, &task.Payload, &timeout); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEmpty
		}
		return nil, fmt.Errorf("scan task: %w", err)
	}
	task.Timeout = time.Duration(timeout) * time.Second

	_, err = tx.ExecContext(ctx, `
			INSERT INTO acquired (task_id, created_at)
			VALUES (?, ?)
		`, task.TaskID, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("insert acquire task: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return &task, nil
}

type Pulled struct {
	TaskID  string
	Name    string
	Payload []byte
	Timeout time.Duration
}

func (s *Store) Ack(ctx context.Context, taskID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start transaction: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `
		DELETE FROM acquired WHERE task_id = ?
	`, taskID)
	if err != nil {
		return fmt.Errorf("delete acquired lock: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n != 1 {
		return fmt.Errorf("task %q is not acquired", taskID)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM tasks WHERE task_id = ?`, taskID); err != nil {
		return fmt.Errorf("delete from tasks list: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (s *Store) Nack(ctx context.Context, taskID string, reason string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start transaction: %w", err)
	}
	defer tx.Rollback()

	now := currentTime()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO failures (task_id, created_at, description)
		VALUES (?, ?, ?)
	`, taskID, now.Unix(), reason)
	if err != nil {
		return fmt.Errorf("insert failure reason: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		DELETE FROM acquired WHERE task_id = ?
	`, taskID)
	if err != nil {
		return fmt.Errorf("delete acquired lock: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("rows affected: %w", err)
	} else if n != 1 {
		return fmt.Errorf("task %q is not acquired", taskID)
	}

	var retry uint
	if err := tx.QueryRowContext(ctx, `SELECT retry FROM tasks WHERE task_id = ? LIMIT 1`, taskID).Scan(&retry); err != nil {
		return fmt.Errorf("scan task retry: %w", err)
	}
	var failures uint
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM failures WHERE task_id = ?`, taskID).Scan(&failures); err != nil {
		return fmt.Errorf("scan task failures count: %w", err)
	}

	if retry <= failures {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO deadqueue (task_id, name, payload, created_at)
			SELECT @task_id, name, payload, @created_at
			FROM tasks WHERE task_id = @task_id
		`,
			sql.Named("task_id", taskID),
			sql.Named("created_at", now.Unix()),
		)
		if err != nil {
			return fmt.Errorf("move task to deadqueue: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tasks WHERE task_id = ?`, taskID); err != nil {
			return fmt.Errorf("delete from tasks list: %w", err)
		}
	} else {
		// Delay execution of this task, so that it is not picked up
		// again instantly
		backoff := time.Duration(failures*failures) * time.Minute
		_, err := tx.ExecContext(ctx, `
			UPDATE tasks SET execute_at = ? WHERE task_id = ?
		`, now.Add(backoff).Unix(), taskID)
		if err != nil {
			return fmt.Errorf("update task execution time: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

func (s *Store) stats() (tasks, acquired, failures, deadqueue uint) {
	err := s.db.QueryRow(`
		SELECT
		(SELECT COUNT(*) FROM tasks) AS tasks,
		(SELECT COUNT(*) FROM acquired) AS acquired,
		(SELECT COUNT(*) FROM deadqueue) AS deadqueue,
		(SELECT COUNT(*) FROM failures) AS failures
	`).Scan(&tasks, &acquired, &deadqueue, &failures)
	if err != nil {
		panic(err)
	}
	return
}

func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		http.Error(w, "Cannot start transaction.", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	type failure struct {
		TaskID      string
		CreatedAt   time.Time
		Description string
	}

	type waitingtask struct {
		TaskID    string
		Name      string
		Payload   string
		Retry     int
		Timeout   time.Duration
		ExecuteAt time.Time
		CreatedAt time.Time
	}

	var info struct {
		WaitingCount   uint
		AcquiredCount  uint
		DeadqueueCount uint
		FailuresCount  uint
		Waiting        []waitingtask
		Failures       []failure
	}
	if err := tx.QueryRow(`
		SELECT
		(SELECT COUNT(*) FROM tasks) AS tasks,
		(SELECT COUNT(*) FROM acquired) AS acquired,
		(SELECT COUNT(*) FROM deadqueue) AS deadqueue,
		(SELECT COUNT(*) FROM failures) AS failures
	`).Scan(&info.WaitingCount, &info.AcquiredCount, &info.DeadqueueCount, &info.FailuresCount); err != nil {
		http.Error(w, "Cannot select counters.", http.StatusInternalServerError)
		return
	}

	failures, err := tx.QueryContext(ctx, `
		SELECT task_id, created_at, description FROM failures ORDER BY created_at DESC LIMIT 20
	`)
	if err != nil {
		http.Error(w, "Cannot query failed tasks.", http.StatusInternalServerError)
		return
	}
	defer failures.Close()

	for failures.Next() {
		var f failure
		var createdAt int64
		if err := failures.Scan(&f.TaskID, &createdAt, &f.Description); err != nil {
			http.Error(w, "Cannot scan failed task.", http.StatusInternalServerError)
			return
		}
		f.CreatedAt = time.Unix(createdAt, 0)
		info.Failures = append(info.Failures, f)
	}
	if err := failures.Err(); err != nil {
		http.Error(w, "Cannot finish failure scanning.", http.StatusInternalServerError)
		return
	}

	tasks, err := tx.QueryContext(ctx, `
		SELECT task_id, name, payload, retry, timeout, execute_at, created_at
		FROM tasks
		ORDER BY execute_at DESC
		LIMIT 10
	`)
	if err != nil {
		http.Error(w, "Query waiting tasks.", http.StatusInternalServerError)
		return
	}
	defer tasks.Close()

	for tasks.Next() {
		var t waitingtask
		var timeout, executeAt, createdAt int64
		if err := tasks.Scan(&t.TaskID, &t.Name, &t.Payload, &t.Retry, &timeout, &executeAt, &createdAt); err != nil {
			http.Error(w, "Scan waiting task.", http.StatusInternalServerError)
			return
		}
		t.Timeout = time.Duration(timeout) * time.Second
		t.ExecuteAt = time.Unix(executeAt, 0)
		t.CreatedAt = time.Unix(createdAt, 0)
		info.Waiting = append(info.Waiting, t)
	}
	if err := tasks.Err(); err != nil {
		http.Error(w, "Waiting tasks rows.", http.StatusInternalServerError)
		return
	}

	// Provide a nice, since page view on the queue state.
	var b bytes.Buffer
	if err := tmpl.Execute(&b, info); err != nil {
		http.Error(w, "Cannot render response.", http.StatusInternalServerError)
		return
	}
	w.Header().Add("content-type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = b.WriteTo(w)
}

var (
	//go:embed store_info.html
	tmplString string
	tmpl       = template.Must(template.New("").Parse(tmplString))
)

// currentTime is a variable so that it can be overwritten in tests.
var currentTime = func() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// generateID is a variable so that it can be overwritten in tests.
var generateID = func() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

var (
	ErrEmpty    = errors.New("empty")
	ErrNotFound = errors.New("task not found")
	ErrLocked   = errors.New("task is locked")
)
