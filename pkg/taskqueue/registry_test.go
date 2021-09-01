package taskqueue

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestHappyPath(t *testing.T) {
	store, err := OpenTaskQueue(":memory:")
	if err != nil {
		t.Fatalf("open task queue store: %s", err)
	}
	defer store.Close()

	reg := NewRegistry(store)
	reg.MustRegister(SayHiTask{}, SayHiHandler{})
	reg.MustRegister(&SayByeTask{}, SayByeHandler{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := reg.Schedule(ctx, SayByeTask{ToBye: "Andy"}, Delay(2*time.Second-1)); err != nil {
		t.Fatalf("cannot schedule Andy goodbye: %s", err)
	}
	if _, err := reg.Schedule(ctx, SayHiTask{ToGreet: "Andy"}); err != nil {
		t.Fatalf("cannot schedule Andy greeting: %s", err)
	}

	speachRegister.stack = nil
	if err := reg.ProcessIncoming(ctx, 4); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("process incomming failed: %s", err)
		}
	}

	got := speachRegister.stack
	want := []string{"say-hi:Andy", "say-bye:Andy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}

type SayHiTask struct {
	ToGreet string
}

func (SayHiTask) TaskName() string {
	return "say-hi"
}

type SayHiHandler struct {
}

func (SayHiHandler) HandleTask(ctx context.Context, s Scheduler, p Payload) error {
	t := p.(*SayHiTask)
	speachRegister.Lock()
	speachRegister.stack = append(speachRegister.stack, fmt.Sprintf("%s:%s", t.TaskName(), t.ToGreet))
	speachRegister.Unlock()
	return nil
}

type SayByeTask struct {
	ToBye string
}

func (SayByeTask) TaskName() string {
	return "say-bye"
}

type SayByeHandler struct {
}

func (SayByeHandler) HandleTask(ctx context.Context, s Scheduler, p Payload) error {
	t := p.(*SayByeTask)
	speachRegister.Lock()
	speachRegister.stack = append(speachRegister.stack, fmt.Sprintf("%s:%s", t.TaskName(), t.ToBye))
	speachRegister.Unlock()
	return nil
}

// Record data from mocks. Should be used by at most one test at a time.
var speachRegister struct {
	sync.Mutex
	stack []string
}

func BenchmarkRegisterPullHappyPath(b *testing.B) {
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

	reg := NewRegistry(q)
	reg.MustRegister(BenchTask{}, BenchHandler{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reg.Schedule(ctx, BenchTask{}); err != nil {
			b.Fatal(err)
		}
		if err := reg.ProcessOne(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

type BenchTask struct{}

func (BenchTask) TaskName() string { return "bench-task" }

type BenchHandler struct{}

func (BenchHandler) HandleTask(context.Context, Scheduler, Payload) error { return nil }
