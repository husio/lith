package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/husio/lith/app/lith"
	"github.com/husio/lith/pkg/secret"
)

var (
	//go:embed "hello.html"
	helloTmplS       string
	helloTmpl        = template.Must(template.New("").Parse(helloTmplS))
	applicationStart = time.Now()
)

func herokuLandingPage() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		helloTmpl.Execute(w, struct {
			Version           string
			ApplicationUptime time.Duration
		}{
			Version:           sourceHash,
			ApplicationUptime: time.Now().Sub(applicationStart).Truncate(time.Second),
		})
	})
}

func OpenSyncStore(fullDBpath string, syncSecret string, safe secret.Safe) (*SyncStore, error) {
	req, err := http.NewRequest("GET", storeAddr, nil)
	if err != nil {
		return nil, fmt.Errorf("new HTTP request: %w", err)
	}

	dbpath := strings.SplitN(fullDBpath, "?", 2)[0]

	now := time.Now().Unix()
	req.Header.Set("access-time", fmt.Sprint(now))
	sum := hmac.New(sha256.New, []byte(syncSecret))
	fmt.Fprint(sum, now)
	req.Header.Set("access-sum", hex.EncodeToString(sum.Sum(nil)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do HTTP request: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			Value []byte `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("decode response body: %w", err)
		}
		if err := os.WriteFile(dbpath, body.Value, 0666); err != nil {
			return nil, fmt.Errorf("create database file: %w", err)
		}
	case http.StatusNotFound:
		// No store, nothing to do.
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1e5))
		return nil, fmt.Errorf("unexpected response: %d %s", resp.StatusCode, string(b))
	}

	store, err := lith.OpenSQLiteStore(fullDBpath, safe)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}

	return &SyncStore{
		store:  store,
		dbpath: dbpath,
		secret: syncSecret,
		cli:    *http.DefaultClient,
	}, nil
}

type SyncStore struct {
	dbpath string
	secret string
	store  lith.Store
	cli    http.Client
}

const storeAddr = "https://herokubinstore.herokuapp.com/lith-demo/sync-store"

func (s *SyncStore) Session(ctx context.Context) (lith.StoreSession, error) {
	return s.store.Session(ctx)
}

func (s *SyncStore) sync() error {

	database, err := os.ReadFile(s.dbpath)
	if err != nil {
		return fmt.Errorf("read db file: %w", err)
	}

	var body bytes.Buffer
	err = json.NewEncoder(&body).Encode(struct {
		Value []byte `json:"value"`
	}{
		Value: database,
	})
	if err != nil {
		return fmt.Errorf("JSON encode: %w", err)
	}

	req, err := http.NewRequest("POST", storeAddr, &body)
	if err != nil {
		return fmt.Errorf("new HTTP request: %w", err)
	}
	req.Header.Set("content-type", "application/json")

	now := time.Now().Unix()
	req.Header.Set("access-time", fmt.Sprint(now))
	sum := hmac.New(sha256.New, []byte(s.secret))
	fmt.Fprint(sum, now)
	req.Header.Set("access-sum", hex.EncodeToString(sum.Sum(nil)))

	resp, err := s.cli.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 202 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1e5))
		return fmt.Errorf("unexpected response: %d %s", resp.StatusCode, string(b))
	}

	return nil
}

func (s *SyncStore) Close() error {
	err := s.store.Close()
	if err := s.sync(); err != nil {
		log.Printf("SyncStore: %s", err)
	}
	return err
}
