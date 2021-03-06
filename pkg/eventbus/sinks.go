package eventbus

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/husio/lith/pkg/taskqueue"
)

// Sink interface is implemented by multiple backends to allow various ways of
// subscribing to application events.
type Sink interface {
	// PublishEvent sends an event to the subscriber using mechanism
	// provided by the Sink implementation. It is up to the implementation
	// to decide how to serialize the data.
	//
	// Each event should be published with a unique identifier. Since the
	// delivery is at least once, ID allows for deduplication by the
	// client.
	PublishEvent(context.Context, Event) error
}

type Event struct {
	// Kind describes the type of the event.
	Kind string `json:"kind"`

	// ID of this event instance, used to deduplicate events.
	ID string `json:"id"`

	// CreatedAt represents the time that the event was created.
	CreatedAt time.Time `json:"created_at"`

	// Payload will loose type information when deserializing JSON. If
	// initially a structure was given, JSON will unmarshall it to
	// map[string]interface{}. This is ok as long as the event published
	// does not see a difference between those two.
	Payload interface{} `json:"payload"`
}

// NewNoopSink returns a Sink implementation that drops all events.
func NewNoopSink() Sink {
	return noopSink{}
}

type noopSink struct{}

func (noopSink) PublishEvent(context.Context, Event) error { return nil }

// NewWebhookSink returns a Sink implementation that is publishing events by
// making an HTTP POST request to given URL. Payload is JSON serialized.
func NewWebhookSink(url string, secret []byte, client *http.Client) Sink {
	if client == nil {
		client = http.DefaultClient
	}
	return &webhook{
		now:    time.Now,
		url:    url,
		secret: secret,
		cli:    client,
	}
}

type webhook struct {
	now    func() time.Time
	url    string
	secret []byte
	cli    *http.Client
}

func (w *webhook) PublishEvent(ctx context.Context, e Event) error {
	now := w.now().UTC().Truncate(time.Second)
	raw, err := json.Marshal(struct {
		Kind      string      `json:"kind"`
		ID        string      `json:"id"`
		Payload   interface{} `json:"payload"`
		CreatedAt time.Time   `json:"created_at"`
		Now       time.Time   `json:"now"`
	}{
		Kind:      e.Kind,
		ID:        e.ID,
		Payload:   e.Payload,
		CreatedAt: e.CreatedAt,
		Now:       now,
	})
	if err != nil {
		return fmt.Errorf("json serialize data: %w", err)
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	r.Header.Set("content-type", "application/json")

	mac := hmac.New(sha256.New, w.secret)
	if _, err := mac.Write(raw); err != nil {
		return fmt.Errorf("compute signature: %w", err)
	}
	r.Header.Set("signature", hex.EncodeToString(mac.Sum(nil)))

	resp, err := w.cli.Do(r)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1e5))
		return fmt.Errorf("unexpected status code: %d %s", resp.StatusCode, b)
	}
	return nil
}

// NewFsSink returns a Sink implementation that writes all events as separate
// files to given directory.
//
// This implementation must be used only for local development or tests. Be
// aware that publishing a lot of events will cause creation of a lot of files
// in a single directory.
func NewFsSink(dir string) Sink {
	_ = os.MkdirAll(dir, 0770)
	return fsSink{dir: dir}
}

type fsSink struct {
	dir string
}

func (es fsSink) PublishEvent(ctx context.Context, e Event) error {
	raw, err := json.MarshalIndent(struct {
		Kind      string      `json:"kind"`
		ID        string      `json:"id"`
		Payload   interface{} `json:"payload"`
		CreatedAt time.Time   `json:"created_at"`
	}{
		Kind:      e.Kind,
		ID:        e.ID,
		Payload:   e.Payload,
		CreatedAt: e.CreatedAt,
	}, "", "\t")
	if err != nil {
		return fmt.Errorf("json serialize data: %w", err)
	}

	filename := filepath.Join(es.dir, fmt.Sprintf("%d_%s_%s.txt", e.CreatedAt.Unix(), e.Kind, e.ID))
	if err := ioutil.WriteFile(filename, raw, 0666); err != nil {
		return fmt.Errorf("write to file: %w", err)
	}
	return nil
}

// ThroughTaskQueue wraps given sink so that all published events are first
// written to the task queue. The actual event publishing is done by each task
// consumed from the queue.
//
// This function registers a task handler within given task queue registry.
//
// Using this implementation can provide additional assurance that the event
// will be delivered despite temporary issues. Use it together with for example
// the webhook sink in order to mitigate connection issues or temporary
// recipient failure.
func ThroughTaskQueue(sink Sink, queue *taskqueue.Registry) Sink {
	queue.MustRegister(eventTask{}, &sinkHandler{sink: sink})
	return &taskqueueSink{now: time.Now, s: queue}
}

type eventTask struct {
	Event Event
}

func (eventTask) TaskName() string {
	return "publish-event"
}

type taskqueueSink struct {
	now func() time.Time
	s   taskqueue.Scheduler
}

func (sink taskqueueSink) PublishEvent(ctx context.Context, e Event) error {
	_, err := sink.s.Schedule(ctx, eventTask{Event: e}, taskqueue.Timeout(time.Minute))
	return err
}

type sinkHandler struct {
	sink Sink
}

func (h sinkHandler) HandleTask(ctx context.Context, s taskqueue.Scheduler, p taskqueue.Payload) error {
	task := p.(*eventTask)

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := h.sink.PublishEvent(ctx, task.Event); err != nil {
		return fmt.Errorf("publish event %s: %w", task.Event.ID, err)
	}
	return nil
}

// RecordingSink drops all published events, storing locally their data and ID. Use for testing.
type RecordingSink struct {
	Events []Event
}

func (s *RecordingSink) PublishEvent(ctx context.Context, e Event) error {
	s.Events = append(s.Events, e)
	return nil
}

func (s *RecordingSink) AssertPublished(t testing.TB, events ...Event) {
	t.Helper()

	if len(events) != len(s.Events) {
		t.Fatalf("want %d events published, got %d", len(events), len(s.Events))
	}

	for i := range events {
		got := s.Events[i]
		want := events[i]
		if got.Kind != want.Kind {
			t.Errorf("event %d, want kind %q, got %q", i, want.Kind, got.Kind)
		}
		if !reflect.DeepEqual(got.Payload, want.Payload) {
			t.Errorf("event %d, want data %+v, got %+v", i, want.Payload, got.Payload)
		}
	}
}
