package eventbus

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/husio/lith/pkg/taskqueue"
)

func TestThroughTaskQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	now, err := time.Parse("2006-01-02 15:04", "2020-04-20 13:45")
	if err != nil {
		t.Fatalf("parse time: %s", err)
	}

	queue, err := taskqueue.OpenTaskQueue(":memory:")
	if err != nil {
		t.Fatalf("open task queue: %s", err)
	}
	reg := taskqueue.NewRegistry(queue)

	var recSink RecordingSink

	taskSink := ThroughTaskQueue(&recSink, reg)

	type UserCreated struct {
		Name  string
		Admin bool
	}
	if err := taskSink.PublishEvent(ctx, "00001", now, UserCreated{Name: "bob", Admin: true}); err != nil {
		t.Fatalf("publish event: %s", err)
	}

	// No event should be published with recording sink before we process a
	// task.
	if len(recSink.IDs) != 0 {
		t.Fatalf("an event was published: %+v", recSink.IDs)
	}

	if err := reg.ProcessOne(ctx); err != nil {
		t.Fatalf("process one task: %s", err)
	}

	// Now that the only event was processed, an event must have been
	// published.
	want := []string{"00001"}
	if !reflect.DeepEqual(recSink.IDs, want) {
		t.Fatalf("want %q event IDs, got %q", want, recSink.IDs)
	}

	if err := reg.ProcessOne(ctx); !errors.Is(err, taskqueue.ErrEmpty) {
		t.Fatal("task queue should be empty")
	}
}
