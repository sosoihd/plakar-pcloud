/*
 * Copyright (c) 2026 sosoihd
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package pcloud

// Each test in this file pins a defect found during the security and
// robustness audit of the first implementation, so that it cannot come back.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/PlakarKorp/kloset/repository"
)

// Strix vuln-0001 (CWE-598): the OAuth token was sent in the query string.
func TestRegression_TokenNeverInQueryString(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/f", []byte("x"))
	conn := newTestConnector(t, s, nil)
	ctx := t.Context()

	_ = conn.Ping(ctx)
	_, _ = conn.client.Stat(ctx, "/f")
	_, _ = conn.client.ListFolder(ctx, "/", false)
	_ = conn.client.MkdirAll(ctx, "/a/b")
	_, _ = conn.client.UploadBytes(ctx, "/a/b/c", []byte("c"), UploadOptions{})
	_ = conn.client.DeleteFile(ctx, "/a/b/c")

	for _, r := range s.recorded() {
		if strings.Contains(r.RawQuery, fakeToken) {
			t.Errorf("%s leaked the access token in its URL: %s", r.Path, r.RawQuery)
		}
	}
}

// Transport errors embed the request URL; it used to contain the token.
func TestRegression_TokenNeverInErrorMessages(t *testing.T) {
	for _, cfg := range []ClientConfig{
		{AccessToken: "SUPERSECRET"},
		{AuthToken: "SUPERSECRET"},
		{Username: "user@example.com", Password: "SUPERSECRET"},
	} {
		cfg.Scheme, cfg.Host, cfg.MaxRetries = "http", "127.0.0.1:1", -1
		c, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		err = c.Ping(t.Context())
		if err == nil {
			t.Fatal("expected a connection error")
		}
		if strings.Contains(err.Error(), "SUPERSECRET") {
			t.Errorf("credential leaked in error: %v", err)
		}
	}
}

// Strix vuln-0002 (CWE-400): UploadFile buffered the whole file in memory,
// so restoring a multi-GB file crashed with an out-of-memory error.
func TestRegression_LargeUploadsUseBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("uploads 64 MiB")
	}
	s := newFakePCloud(t)
	s.configure(func(f *fakePCloud) { f.discardUploads = true })
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})

	const size = 64 << 20
	src := io.LimitReader(zeroReader{}, size)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := c.UploadStream(t.Context(), "/huge.bin", src, size, UploadOptions{}); err != nil {
		t.Fatalf("UploadStream: %v", err)
	}
	runtime.ReadMemStats(&after)

	if got := s.stats().uploadedBytesTotal; got != size {
		t.Fatalf("server received %d bytes, want %d", got, size)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > size/2 {
		t.Errorf("uploading %d MiB allocated %d MiB: the payload is being buffered", size>>20, allocated>>20)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// A folder named like a domain (pcloud://my.photos/...) used to become the
// API host, sending the user's credentials to a third-party server.
func TestRegression_LocationCannotRedirectCredentials(t *testing.T) {
	for _, loc := range []string{
		"pcloud://attacker.example.com/Docs",
		"pcloud://my.photos/2024",
		"pcloud://127.0.0.1:8080/x",
		"pcloud://localhost/x",
	} {
		conn, err := New(t.Context(), nil, "pcloud", map[string]string{"location": loc, "access_token": "t"}, nil)
		if err != nil {
			t.Fatalf("%s: %v", loc, err)
		}
		if conn.Origin() != DefaultHostUS {
			t.Errorf("%s: credentials would be sent to %s", loc, conn.Origin())
		}
	}
}

// insecure=true used to downgrade the official API to plain HTTP.
func TestRegression_NoPlainHTTPToOfficialHosts(t *testing.T) {
	for _, loc := range []string{"pcloud:///x", "pcloud://eu/x", "pcloud://api.pcloud.com/x"} {
		_, err := New(t.Context(), nil, "pcloud", map[string]string{"location": loc, "access_token": "t", "insecure": "true"}, nil)
		if err == nil {
			t.Errorf("%s: insecure must be refused without a custom endpoint", loc)
		}
	}
}

// A rejected digest login was retried on every call, which gets the IP
// banned by pCloud (error 4000).
func TestRegression_FailedLoginIsNotRetried(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{Username: fakeUser, Password: "wrong"})
	for range 10 {
		_ = c.Ping(t.Context())
	}
	if n := s.stats().logins; n != 1 {
		t.Errorf("login attempted %d times, want 1", n)
	}
}

// A transient failure during login (network, 5xx) must still be retried.
func TestRegression_LoginRetriesTransportErrors(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{Username: fakeUser, Password: fakePass})
	s.fail("/getdigest", injectedFailure{status: http.StatusBadGateway})
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// Import blocked forever on a channel send once its context was cancelled.
func TestRegression_ImportReturnsOnCancel(t *testing.T) {
	s := newFakePCloud(t)
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		s.seedFile("/backups/"+n, []byte(n))
	}
	conn := newTestConnector(t, s, nil)
	ctx, cancel := context.WithCancel(t.Context())
	records := make(chan *connectors.Record)
	done := make(chan error, 1)
	go func() { done <- conn.Import(ctx, records, nil) }()

	<-records
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Import returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Import did not return after cancellation")
	}
}

// Export stopped reading records when cancelled, blocking the producer.
func TestRegression_ExportDrainsRecordsOnCancel(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	records := make(chan *connectors.Record)
	results := make(chan *connectors.Result, 100)
	produced := make(chan struct{})
	go func() {
		defer close(produced)
		defer close(records)
		for i := range 20 {
			records <- fileRecord("/f"+string(rune('a'+i)), []byte("x"), time.Now())
		}
	}()

	if err := conn.Export(ctx, records, results); !errors.Is(err, context.Canceled) {
		t.Errorf("Export = %v, want context.Canceled", err)
	}
	select {
	case <-produced:
	case <-time.After(5 * time.Second):
		t.Fatal("producer is still blocked: Export did not drain the records")
	}
}

// A single 502 used to fail the whole backup.
func TestRegression_TransientErrorsAreRetried(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, nil)
	s.fail("/userinfo", injectedFailure{status: http.StatusBadGateway})
	if err := conn.Ping(t.Context()); err != nil {
		t.Fatalf("Ping after one 502: %v", err)
	}
}

// The storage used to copy every packfile into ~/Library/Caches without any
// size limit, filling the local disk with a copy of the whole repository.
// It also served packfiles deleted by another machine from that cache.
func TestRegression_StorageNeverWritesToLocalDisk(t *testing.T) {
	home, cache, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("TMPDIR", tmp)

	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	ctx := t.Context()
	if err := st.Create(ctx, []byte("config")); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("p"), 3*cacheBlockSize)
	for i := range 4 {
		mac := macOf(byte(i))
		if _, err := st.Put(ctx, storage.StorageResourcePackfile, mac, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		if _, err := getAll(t, st, storage.StorageResourcePackfile, mac, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: 10, Length: 100}); err != nil {
			t.Fatal(err)
		}
	}

	for _, dir := range []string{home, cache, tmp} {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && p != dir {
				t.Errorf("connector wrote to local disk: %s", p)
			}
			return nil
		})
	}

	// A packfile removed by another client must not be served from a cache.
	mac := macOf(0)
	p, _ := st.objectPath(storage.StorageResourcePackfile, mac)
	s.remove(p)
	if _, err := getAll(t, st, storage.StorageResourcePackfile, mac, nil); !errors.Is(err, repository.ErrPackfileNotFound) {
		t.Errorf("Get of a remotely deleted packfile = %v, want ErrPackfileNotFound", err)
	}
}

// The default HTTP client had a 5-minute overall timeout, which aborted any
// download or upload of a large file.
func TestRegression_NoGlobalHTTPTimeout(t *testing.T) {
	c, err := NewClient(ClientConfig{AccessToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != 0 {
		t.Errorf("http.Client.Timeout = %s caps the duration of large transfers", c.httpClient.Timeout)
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 {
		t.Errorf("transport must still bound handshakes and response headers")
	}
}

// pCloud refuses recursive listings of the root folder (error 1101), which
// made backing up a whole account impossible.
func TestRegression_RecursiveRootListing(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/A/x", []byte("x"))
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	if _, err := c.ListFolder(t.Context(), "/", true); err != nil {
		t.Fatalf("ListFolder(/, recursive): %v", err)
	}
}

// Unparseable timestamps fell back to time.Now(), making every snapshot
// look modified.
func TestRegression_ModTimeIsDeterministic(t *testing.T) {
	m := Metadata{Modified: "garbage"}
	if a, b := m.ModTime(), m.ModTime(); !a.Equal(b) {
		t.Errorf("ModTime is not deterministic: %v vs %v", a, b)
	}
}

// Symbolic links were silently dropped during restore.
func TestRegression_SymlinksAreNotSilentlyDropped(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	link := connectors.NewRecord("/l", "/t", objects.FileInfo{Lname: "l", Lmode: fs.ModeSymlink | 0777}, nil, nil)
	results, err := runExport(t, conn, link)
	if err != nil {
		t.Fatal(err)
	}
	if results["/l"] == nil {
		t.Error("restoring a symlink must report an error")
	}
}

// Test runs used to leave packfiles in the real user cache directory.
func TestRegression_TestsDoNotTouchUserCache(t *testing.T) {
	dir, err := os.UserCacheDir()
	if err != nil {
		t.Skip("no user cache dir")
	}
	before, _ := os.ReadDir(filepath.Join(dir, "plakar-pcloud"))
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	if _, err := st.Put(t.Context(), storage.StorageResourcePackfile, macOf(1), bytes.NewReader([]byte("x"))); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadDir(filepath.Join(dir, "plakar-pcloud"))
	if len(after) != len(before) {
		t.Errorf("connector created entries in %s", filepath.Join(dir, "plakar-pcloud"))
	}
}
