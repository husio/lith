package lith

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
	"time"

	"github.com/husio/lith/pkg/secret"
)

type EventSink interface {
	PublishEvent(ctx context.Context, id string, data interface{}) error
}

type NoopEventSink struct{}

func (NoopEventSink) PublishEvent(context.Context, string, interface{}) error { return nil }

func NewHTTPWebhook(url string, secret secret.Value, client *http.Client) *HTTPWebhook {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPWebhook{
		now:    func() time.Time { return time.Now().UTC() },
		url:    url,
		secret: secret,
		cli:    client,
	}
}

type HTTPWebhook struct {
	now    func() time.Time
	url    string
	secret secret.Value
	cli    *http.Client
}

func (w *HTTPWebhook) PublishEvent(ctx context.Context, id string, data interface{}) error {
	now := w.now()
	raw, err := json.Marshal(struct {
		ID      string      `json:"id"`
		Payload interface{} `json:"payload"`
		Now     time.Time   `json:"now"`
	}{
		ID:      id,
		Payload: data,
		Now:     now,
	})
	if err != nil {
		return fmt.Errorf("json serialize data: %w", err)
	}

	r, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	r.Header.Set("content-type", "application/json")
	r.Header.Set("created", now.Format(time.RFC3339))

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

func NewFsEventSink(dir string) EventSink {
	_ = os.MkdirAll(dir, 0770)
	return fsEventSink{dir: dir, now: time.Now}
}

type fsEventSink struct {
	dir string
	now func() time.Time
}

func (es fsEventSink) PublishEvent(ctx context.Context, id string, data interface{}) error {
	now := es.now()
	raw, err := json.Marshal(struct {
		ID      string      `json:"id"`
		Payload interface{} `json:"payload"`
		Now     time.Time   `json:"now"`
	}{
		ID:      id,
		Payload: data,
		Now:     now,
	})
	if err != nil {
		return fmt.Errorf("json serialize data: %w", err)
	}

	filename := filepath.Join(es.dir, fmt.Sprintf("%d_%s.txt", now.Unix(), id))
	if err := ioutil.WriteFile(filename, raw, 0666); err != nil {
		return fmt.Errorf("write to file: %w", err)
	}
	return nil
}
