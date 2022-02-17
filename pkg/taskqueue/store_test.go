package taskqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func BenchmarkStorePullHappyPath(b *testing.B) {
	// Although it gives not a real life reasult, use an in-memory database
	// because the final value heavily depends on the storage engine
	// anyway.
	// This benchmark does not give much insight anyway...
	q, err := OpenTaskQueue(":memory:")
	if err != nil {
		b.Fatalf("open queue: %s", err)
	}
	defer q.Close()

	ctx := context.Background()
	toPush := []TaskReq{{Name: "task", Retry: 10}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := q.Push(ctx, toPush); err != nil {
			b.Fatal(err)
		}
		task, err := q.Pull(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if err := q.Ack(ctx, task.TaskID); err != nil {
			b.Fatal(err)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	q, err := OpenTaskQueue(":memory:")
	if err != nil {
		t.Fatalf("open queue: %s", err)
	}
	defer q.Close()

	var wg sync.WaitGroup
	wg.Add(100)
	start := make(chan struct{})

	for i := 0; i < 100; i++ {
		go func() {
			defer wg.Done()
			<-start

			if _, err := q.Push(context.Background(), []TaskReq{{Name: "foo"}}); err != nil {
				t.Errorf("cannot push: %s", err)
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestMigrations(t *testing.T) {
	dbpath := t.TempDir() + "queue.sqlite3"

	for i := 0; i < 5; i++ {
		if q, err := OpenTaskQueue(dbpath); err != nil {
			t.Fatalf("%d: open queue: %s", i, err)
		} else {
			q.Close()
		}
	}
}

func TestTaskQueue(t *testing.T) {
	now := time.Now()
	withCurrentTime(t, now)

	q, err := OpenTaskQueue(":memory:")
	if err != nil {
		t.Fatalf("open queue: %s", err)
	}
	defer q.Close()

	ctx := context.Background()

	_, err = q.Push(ctx, []TaskReq{{Name: "first", ExecuteIn: 20 * time.Minute}})
	if err != nil {
		t.Fatalf("push first task: %s", err)
	}
	secondIDs, err := q.Push(ctx, []TaskReq{{Name: "second", Retry: 10, ExecuteIn: 5 * time.Minute}})
	if err != nil {
		t.Fatalf("push second task: %s", err)
	}
	secondID := secondIDs[0]

	thirdIDs, err := q.Push(ctx, []TaskReq{{Name: "third", Payload: []byte("3"), Retry: 10, ExecuteIn: 10 * time.Minute}})
	if err != nil {
		t.Fatalf("push third task: %s", err)
	}
	thirdID := thirdIDs[0]

	if _, err := q.Pull(ctx); err != ErrEmpty {
		t.Fatalf("expected ErrEmpty, got %+v", err)
	}

	assertStats(t, q, 3, 0, 0, 0)

	withCurrentTime(t, now.Add(10*time.Minute))

	secondTask, err := q.Pull(ctx)
	if err != nil {
		t.Fatalf("expected second task, got %v", err)
	}
	if secondTask.TaskID != secondID {
		t.Fatalf("second task ID %q is not %q", secondTask.TaskID, secondID)
	}

	thirdTask, err := q.Pull(ctx)
	if err != nil {
		t.Fatalf("expected third task, got %v", err)
	}
	if thirdTask.TaskID != thirdID {
		t.Fatalf("third task ID %q is not %q", thirdTask.TaskID, thirdID)
	}

	assertStats(t, q, 3, 2, 0, 0)

	if _, err := q.Pull(ctx); err != ErrEmpty {
		t.Fatalf("expected ErrEmpty becuse all available tasks are acquired, got %+v", err)
	}

	if err := q.Ack(ctx, secondID); err != nil {
		t.Fatalf("cannot ack second task: %s", err)
	}
	if err := q.Ack(ctx, secondID); err == nil {
		t.Error("managed to ack the same task twice")
	}

	if err := q.Nack(ctx, thirdID, "reason description"); err != nil {
		t.Fatalf("cannot nack third task: %s", err)
	}
	// When NACKed, task is available only after some time.
	if _, err := q.Pull(ctx); err != ErrEmpty {
		t.Fatalf("expected ErrEmpty, got %+v", err)
	}

	withCurrentTime(t, now.Add(11*time.Minute))

	thirdTask2, err := q.Pull(ctx)
	if err != nil {
		t.Fatalf("expected third task again, got %v", err)
	}
	if thirdTask2.TaskID != thirdID {
		t.Fatalf("third task ID %q is not %q", thirdTask.TaskID, thirdID)
	}

	assertStats(t, q, 2, 1, 1, 0)
}

func TestTaskRetryAndDeadqueue(t *testing.T) {
	now := time.Now()
	withCurrentTime(t, now)

	q, err := OpenTaskQueue(":memory:")
	if err != nil {
		t.Fatalf("open queue: %s", err)
	}
	defer q.Close()

	ctx := context.Background()

	if _, err := q.Push(ctx, []TaskReq{{Name: "first", Retry: 20}}); err != nil {
		t.Fatalf("push task: %s", err)
	}

	for i := 0; i < 20; i++ {
		task, err := q.Pull(ctx)
		if err != nil {
			t.Fatalf("%d: pull: %s", i, err)
		}
		if err := q.Nack(ctx, task.TaskID, fmt.Sprintf("failure %d", i)); err != nil {
			t.Fatalf("%d: cannot nack: %s", i, err)
		}
		// Always advance time, so that the task can be instantly pulled.
		withCurrentTime(t, currentTime().Add(999*time.Hour))
	}

	if task, err := q.Pull(ctx); err != ErrEmpty {
		t.Fatalf("after failing many times, task must be moved to deadqueue, got %v, %+v", err, task)
	}

	assertStats(t, q, 0, 0, 20, 1)
}

func TestTaskDelete(t *testing.T) {
	now := time.Now()
	withCurrentTime(t, now)

	q, err := OpenTaskQueue(":memory:")
	if err != nil {
		t.Fatalf("open queue: %s", err)
	}
	defer q.Close()

	ctx := context.Background()

	ids, err := q.Push(ctx, []TaskReq{
		{Name: "first", Retry: 20},
		{Name: "second", Retry: 20},
	})
	if err != nil {
		t.Fatalf("push tasks: %s", err)
	}

	if err := q.Delete(ctx, ids[0]); err != nil {
		t.Fatalf("cannot delete task from the queue: %s", err)
	}

	task, err := q.Pull(ctx)
	if err != nil {
		t.Fatalf("cannot pull task from the queue: %s", err)
	}
	if err := q.Delete(ctx, task.TaskID); !errors.Is(err, ErrLocked) {
		t.Fatalf("deleting a task that is acquired must return ErrLocked, got %v", err)
	}
	if err := q.Nack(ctx, task.TaskID, "testing task deletion"); err != nil {
		t.Fatalf("cannot NACK task: %s", err)
	}
	if err := q.Delete(ctx, task.TaskID); err != nil {
		t.Fatalf("it must be possible to delete a task after it was released, got %v", err)
	}
	if err := q.Delete(ctx, task.TaskID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting the same task twice must return ErrNotFound, got %v", err)
	}

	if err := q.Delete(ctx, "does-not-exist-task-id-1234"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting a task that was not scheduled must return ErrNotFound, got %v", err)
	}
}

func assertStats(t testing.TB, s *Store, wantTasks, wantAcquired, wantFailures, wantDeadqueue uint) {
	t.Helper()
	tasks, acquired, failures, deadqueue := s.stats()
	if tasks != wantTasks {
		t.Errorf("want tasks count to be %d, got %d", wantTasks, tasks)
	}
	if acquired != wantAcquired {
		t.Errorf("want acquired count to be %d, got %d", wantAcquired, acquired)
	}
	if deadqueue != wantDeadqueue {
		t.Errorf("want deadqueue count to be %d, got %d", wantDeadqueue, deadqueue)
	}
	if failures != wantFailures {
		t.Errorf("want failures count to be %d, got %d", wantFailures, failures)
	}
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
