package taskqueue

import (
	"context"
	"reflect"
	"testing"
)

// RecordingScheduler implements scheduler interface and records all scheduled
// tasks. This implementation does not execute tasks.
type RecordingScheduler struct {
	Scheduled []Payload
}

func (rs *RecordingScheduler) Schedule(ctx context.Context, p Payload, opts ...ScheduleOption) (string, error) {
	rs.Scheduled = append(rs.Scheduled, p)
	return generateID(), nil
}

// LoadRecorded assigns to dest payload recorded at specified position.
func (rs *RecordingScheduler) LoadRecorded(t testing.TB, position int, dest Payload) {
	t.Helper()

	if len(rs.Scheduled) < position {
		t.Fatalf("only %d payloads recorded", len(rs.Scheduled))
	}
	payload := rs.Scheduled[position]

	if dest == nil {
		t.Fatal("destination must not be nil")
	}

	val := reflect.ValueOf(dest)
	typ := val.Type()
	if typ.Kind() != reflect.Ptr || val.IsNil() {
		t.Fatal("dest must be a non-nil pointer")
	}
	val.Elem().Set(reflect.ValueOf(payload))
}

func (rs *RecordingScheduler) Cancel(context.Context, string) error {
	return nil
}
