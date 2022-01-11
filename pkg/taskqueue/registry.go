package taskqueue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/husio/lith/pkg/alert"
)

// Payload is implemented by any task that can be scheduled for execution.
type Payload interface {
	// TaskName returns a unique name of a task. This is usually
	// implemented as a static method.
	TaskName() string
}

// Handler is implemented in order to handler particular Payload type.
type Handler interface {
	// HandleTask is called in order to process given task Payload.
	//
	// Provided scheduler can be used to atomically push more tasks into
	// the queue. Tasks are scheduled only if the current task payload
	// handling was successful and no error was returned.
	//
	// Provided task payload must be an interface, but it is safe to cast
	// it into the specific for that handler payload type pointer. Each
	// handler is passed only the strcutrures that it was registered with.
	HandleTask(context.Context, Scheduler, Payload) error
}

type Scheduler interface {
	// Schedule task execution adds specified job to the queue.
	Schedule(context.Context, Payload, ...ScheduleOption) (string, error)

	// Cancel scheduled task execution. If successful, task is removed from
	// the queue and will never be executed.
	Cancel(context.Context, string) error
}

// ScheduleOption allows to configure how a task should be scheduled.
type ScheduleOption = func(*scheduleOpts)

type scheduleOpts struct {
	timeout   time.Duration
	retry     uint
	executeIn time.Duration
}

// Delay configures task execution to be postponed by given delay value.
func Delay(executeIn time.Duration) ScheduleOption {
	return func(o *scheduleOpts) {
		o.executeIn = executeIn
	}
}

// Retry configures how many failed task execution is repeated before it gets
// removed from the queue and pushed into the dead letter queue storage.
func Retry(moveToDeadqueueAfter uint) ScheduleOption {
	return func(o *scheduleOpts) {
		o.retry = moveToDeadqueueAfter
	}
}

// Timeout configures how long a task processing can be running before its
// context is cancelled.
func Timeout(cancelExecutionAfter time.Duration) ScheduleOption {
	return func(o *scheduleOpts) {
		o.timeout = cancelExecutionAfter
	}
}

// NewRegistry returns a task registry that binds together task payloads and
// handlers.
func NewRegistry(queue *Store) *Registry {
	return &Registry{
		queue:     queue,
		tasksMeta: make(map[string]taskmeta),
	}
}

// Registry binds together task payloads and handlers.
type Registry struct {
	tasksMeta map[string]taskmeta
	queue     *Store
}

// taskmeta clubs together a task handler with a data structure that should be
// used to unpack the task payload.
type taskmeta struct {
	payload reflect.Type
	handler Handler
}

// newPayload returns a new, uninitialized data structure that should be used
// to unpack task payload.
func (ti taskmeta) newPayload() Payload {
	return reflect.New(ti.payload).Interface().(Payload)
}

// Register a task handler. First argument must be a data structure that
// represents the payload.
func (r *Registry) Register(p Payload, h Handler) error {
	if _, ok := r.tasksMeta[p.TaskName()]; ok {
		return fmt.Errorf("spec for %q already registerd", p.TaskName())
	}

	tp := reflect.TypeOf(p)
	if tp.Kind() == reflect.Ptr {
		tp = tp.Elem()
	}

	r.tasksMeta[p.TaskName()] = taskmeta{
		handler: h,
		payload: tp,
	}
	return nil
}

// MustRegister is a Register call that will panic on failure.
func (r *Registry) MustRegister(p Payload, h Handler) {
	if err := r.Register(p, h); err != nil {
		panic(err)
	}
}

// Cancel is a best effort to remove a scheduled, but not yet executed task
// from the queue.
func (r *Registry) Cancel(ctx context.Context, taskID string) error {
	return r.queue.Delete(ctx, taskID)
}

// Schedule is publishing one or more tasks to be processed. Using various
// schedule options, it is possible to tune how tasks are published.
//
// This operation is atomic for all provided tasks - either or or none is
// published.
func (r *Registry) Schedule(ctx context.Context, s Payload, opts ...ScheduleOption) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}

	conf := scheduleOpts{
		retry:     10,
		timeout:   10 * time.Minute,
		executeIn: 0,
	}
	for _, fn := range opts {
		fn(&conf)
	}

	ids, err := r.queue.Push(ctx, []Pushed{
		{Name: s.TaskName(), Payload: payload, Retry: conf.retry, ExecuteIn: conf.executeIn, Timeout: conf.timeout},
	})
	if err != nil {
		return "", fmt.Errorf("push task: %w", err)
	}
	return ids[0], nil
}

// ProcessIncoming is a blocking function that is monitoring task queue and
// processing jobs. This function returns only on a worker error or when
// provided context is cancelled.
//
// When multiple worker fails, only the first error is returned.
func (r *Registry) ProcessIncoming(ctx context.Context, workers uint) error {
	if workers < 1 {
		return errors.New("at least one worker is required")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error)

	for i := uint(0); i < workers; i++ {
		go func() {
			if err := r.processIncomingWorker(ctx); err != nil {
				select {
				case errc <- err:
					cancel()
				case <-ctx.Done():
				}
			}
		}()
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Registry) processIncomingWorker(ctx context.Context) error {
	for {
		switch err := r.ProcessOne(ctx); {
		case err == nil:
			// All good.
		case errors.Is(err, ErrEmpty):
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		default:
			return err
		}
	}
}

// ProcessOne pops the first task from the task queue and process it.
func (r *Registry) ProcessOne(ctx context.Context) error {
	task, err := r.queue.Pull(ctx)
	if err != nil {
		return fmt.Errorf("pull: %w", err)
	}

	taskMeta, ok := r.tasksMeta[task.Name]
	if !ok {
		alert.Emit(ctx,
			"msg", "Cannot process message because task spec is not registered.",
			"task_id", task.TaskID,
			"task_name", task.Name)
		if err := r.queue.Nack(ctx, task.TaskID, "Task spec not registerd. No handler."); err != nil {
			return fmt.Errorf("nack: %w", err)
		}
	}

	payload := taskMeta.newPayload()
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return fmt.Errorf("unmarshal %q task: %w", task.Name, err)
	}

	taskCtx, cancel := context.WithTimeout(ctx, task.Timeout)
	var taskErr error
	func() {
		defer func() {
			if err := recover(); err != nil {
				taskErr = fmt.Errorf("panic: %v", err)
			}
		}()
		taskErr = taskMeta.handler.HandleTask(taskCtx, r, payload)
	}()
	cancel()

	if taskErr != nil {
		if err := r.queue.Nack(ctx, task.TaskID, taskErr.Error()); err != nil {
			return fmt.Errorf("nack: %w", err)
		}
	} else {
		if err := r.queue.Ack(ctx, task.TaskID); err != nil {
			return fmt.Errorf("ack: %w", err)
		}
	}
	return nil
}
