package alert

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Emitter is implemented by alert sink.
type Emitter interface {
	// Emit an alert, preferably in a synchronous way.
	//
	// pairs should always be an even number.
	Emit(pairs ...string)
}

// NewTextEmitter returns an emitter that writes entries in a plain text
// format. Pairs order is preserved and written as provided to Emit method.
func NewTextEmitter(out io.Writer) Emitter {
	return &textemitter{w: out}
}

type textemitter struct {
	w io.Writer

	mu  sync.Mutex
	buf bytes.Buffer
}

func (lg *textemitter) Emit(pairs ...string) {
	lg.mu.Lock()
	defer lg.mu.Unlock()

	lg.buf.Reset()

	for i := 0; i < len(pairs); i += 2 {
		fmt.Fprintf(&lg.buf, "%s=%q\t", pairs[i], pairs[i+1])
	}
	lg.buf.WriteByte('\n')
	lg.buf.WriteTo(lg.w)
}

// NewTextEmitter returns an emitter that logs entries in a plain text
// format into given testing object.
func NewTestEmitter(t testing.TB) Emitter {
	return &testemitter{t: t}
}

type testemitter struct {
	t testing.TB
}

func (t testemitter) Emit(pairs ...string) {
	var b bytes.Buffer
	for i := 0; i < len(pairs); i += 2 {
		fmt.Fprintf(&b, "%s=%s\t", pairs[i], pairs[i+1])
	}
	t.t.Logf("alert.Emit: %s", b.String())
}

// WithEmitter adds alert emitter to the context.
func WithEmitter(ctx context.Context, emitter Emitter) context.Context {
	return context.WithValue(ctx, emitterContextKey, emitter)
}

// UsedEmitter returns alert emitter present in the context or a no-op
// implementation.
func UsedEmitter(ctx context.Context) Emitter {
	if emitter, ok := ctx.Value(emitterContextKey).(Emitter); ok {
		return emitter
	}
	return noopEmitter{}
}

type noopEmitter struct{}

func (noopEmitter) Emit(...string) {}

// Emit an alert message, using emitter attched to the context.
func Emit(ctx context.Context, pairs ...string) {
	UsedEmitter(ctx).Emit(pairs...)
}

// EmitErr emits an alert message, using emitter attched to the context.
func EmitErr(ctx context.Context, err error, message string, pairs ...string) {
	emitter := UsedEmitter(ctx)
	if _, ok := emitter.(noopEmitter); ok {
		return
	}

	newPairs := make([]string, 0, 6+len(pairs))
	newPairs = append(newPairs, "msg", message, "err", err.Error())
	newPairs = append(newPairs, pairs...)

	// Including the source information is an expensive functionality but
	// nice to have.
	if _, file, line, ok := runtime.Caller(1); ok {
		file = filepath.Base(file)
		newPairs = append(newPairs, "source_file", fmt.Sprintf("%s:%d", file, line))
	}

	emitter.Emit(newPairs...)
}

// WithPairs returns an alert emitter that will include provided pairs in each
// emitter message. pairs is expected to have an even number of strings.
func WithPairs(emitter Emitter, pairs ...string) Emitter {
	if len(pairs) == 0 {
		return emitter
	}
	if len(pairs)%2 == 1 {
		pairs = append(pairs, "")
	}

	// Microoptimization for known types to avoid extra work for a wrapper.
	switch parent := emitter.(type) {
	case withPairs:
		parent.pairs = append(parent.pairs, pairs...)
		return parent
	case noopEmitter:
		return parent
	}

	return withPairs{
		emitter: emitter,
		pairs:   pairs,
	}
}

type withPairs struct {
	emitter Emitter
	pairs   []string
}

func (lg withPairs) Emit(pairs ...string) {
	pairs = append(pairs, lg.pairs...)
	lg.emitter.Emit(pairs...)
}

type contextKey int

const (
	emitterContextKey contextKey = iota
)
