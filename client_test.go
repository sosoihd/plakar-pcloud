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

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAPIErrorClassification(t *testing.T) {
	tests := []struct {
		code      int
		notExist  bool
		exist     bool
		perm      bool
		auth      bool
		temporary bool
	}{
		{code: 1000, auth: true},
		{code: 1101},
		{code: 2000, auth: true},
		{code: 2002, notExist: true},
		{code: 2003, perm: true},
		{code: 2004, exist: true},
		{code: 2005, notExist: true},
		{code: 2008},
		{code: 2009, notExist: true},
		{code: 2041, temporary: true},
		{code: 2055, notExist: true},
		{code: 2094, auth: true},
		{code: 1900, temporary: true},
		{code: 4000, temporary: true},
		{code: 5000, temporary: true},
		{code: 5002, temporary: true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			var err error = &APIError{Result: tc.code, Message: "x"}
			wrapped := fmt.Errorf("wrapped: %w", err)
			check := func(name string, got, want bool) {
				t.Helper()
				if got != want {
					t.Errorf("%s = %v, want %v", name, got, want)
				}
			}
			check("ErrNotExist", errors.Is(wrapped, fs.ErrNotExist), tc.notExist)
			check("ErrExist", errors.Is(wrapped, fs.ErrExist), tc.exist)
			check("ErrPermission", errors.Is(wrapped, fs.ErrPermission), tc.perm)
			check("ErrAuth", errors.Is(wrapped, ErrAuth), tc.auth)
			check("Temporary", err.(*APIError).Temporary(), tc.temporary)
			check("isRetryable", isRetryable(wrapped), tc.temporary)
			if !strings.Contains(err.Error(), fmt.Sprint(tc.code)) {
				t.Errorf("Error() = %q does not mention the code", err.Error())
			}
		})
	}
}

func TestAuthErrorsExplainLikelyCause(t *testing.T) {
	msg := (&APIError{Result: 2094, Message: "Invalid 'access_token' provided."}).Error()
	for _, want := range []string{"'auth' parameter", "region=eu"} {
		if !strings.Contains(msg, want) {
			t.Errorf("2094 message %q should mention %q", msg, want)
		}
	}
	if msg := (&APIError{Result: 2000, Message: "Log in failed."}).Error(); !strings.Contains(msg, "region") {
		t.Errorf("2000 message %q should mention the region", msg)
	}
	if msg := (&APIError{Result: 2009, Message: "File not found."}).Error(); strings.Contains(msg, "(") {
		t.Errorf("unrelated errors must not carry a hint: %q", msg)
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, false},
		{"deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), false},
		{"http 429", &HTTPStatusError{StatusCode: 429}, true},
		{"http 500", &HTTPStatusError{StatusCode: 500}, true},
		{"http 502", &HTTPStatusError{StatusCode: 502}, true},
		{"http 503", &HTTPStatusError{StatusCode: 503}, true},
		{"http 504", &HTTPStatusError{StatusCode: 504}, true},
		{"http 509", &HTTPStatusError{StatusCode: 509}, true},
		{"http 400", &HTTPStatusError{StatusCode: 400}, false},
		{"http 404", &HTTPStatusError{StatusCode: 404}, false},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"url error", &url.Error{Op: "Get", URL: "x", Err: errors.New("connection reset")}, true},
		{"url error canceled", &url.Error{Op: "Get", URL: "x", Err: context.Canceled}, false},
		{"net error", &net.OpError{Op: "dial", Err: errors.New("refused")}, true},
		{"idle timeout", fmt.Errorf("%w: stalled", errIdleTimeout), true},
		{"checksum", errChecksumMismatch, true},
		{"size mismatch", &url.Error{Op: "Post", URL: "x", Err: errSizeMismatch}, false},
		{"plain", errors.New("boom"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryable(tc.err); got != tc.want {
				t.Errorf("isRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestHTTPStatusErrorMessage(t *testing.T) {
	if got := (&HTTPStatusError{StatusCode: 502}).Error(); got != "pcloud http status 502" {
		t.Errorf("unexpected message %q", got)
	}
	if got := (&HTTPStatusError{StatusCode: 400, Body: "bad"}).Error(); !strings.Contains(got, "bad") {
		t.Errorf("unexpected message %q", got)
	}
}

func TestMetadataModTime(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	ref := time.Date(2024, 3, 21, 18, 31, 45, 0, time.UTC)
	tests := []struct {
		name     string
		modified string
		created  string
		want     time.Time
	}{
		{"rfc1123z", "Thu, 21 Mar 2024 18:31:45 +0000", "", ref},
		{"rfc1123", "Thu, 21 Mar 2024 18:31:45 UTC", "", ref},
		{"rfc3339", "2024-03-21T18:31:45Z", "", ref},
		{"unix timestamp", "1711045905", "", ref},
		{"fallback to created", "", "Thu, 21 Mar 2024 18:31:45 +0000", ref},
		{"garbage falls back to created", "not a date", "1711045905", ref},
		{"nothing is epoch, not now", "", "", epoch},
		{"garbage everywhere is epoch", "x", "y", epoch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := Metadata{Modified: tc.modified, Created: tc.created}
			if got := m.ModTime(); !got.Equal(tc.want) {
				t.Errorf("ModTime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseMetadata(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"absent", "", "", false},
		{"null", "null", "", false},
		{"empty array", "[]", "", false},
		{"array", `[{"name":"a"},{"name":"b"}]`, "a", false},
		{"object", ` {"name":"c"}`, "c", false},
		{"large hash", `{"name":"h","hash":10681749967730527559}`, "h", false},
		{"invalid", `{"name":`, "", true},
		{"invalid array", `[{"name":}]`, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := baseResponse{Metadata: []byte(tc.raw)}
			m, err := r.parseMetadata()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			got := ""
			if m != nil {
				got = m.Name
			}
			if got != tc.want {
				t.Errorf("name = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	got := redactURL("https://api.pcloud.com/stat?access_token=SECRET&auth=SESS&path=%2Fdocs&passworddigest=PD&username=u%40x", false)
	for _, secret := range []string{"SECRET", "SESS", "PD", "u%40x"} {
		if strings.Contains(got, secret) {
			t.Errorf("redacted URL %q still contains %q", got, secret)
		}
	}
	if !strings.Contains(got, "path=%2Fdocs") {
		t.Errorf("non-secret parameters should be kept: %q", got)
	}

	dl := redactURL("https://c123.pcloud.com/SIGNEDTOKEN/file.bin", true)
	if strings.Contains(dl, "SIGNEDTOKEN") || !strings.Contains(dl, "c123.pcloud.com") {
		t.Errorf("download URL not redacted properly: %q", dl)
	}
	if redactURL("://bad", false) != "<unparseable url>" {
		t.Errorf("unparseable URL not handled")
	}

	plain := errors.New("plain")
	if redactError(plain, false) != plain {
		t.Errorf("non-URL errors must be returned unchanged")
	}
}

func TestCleanRemotePath(t *testing.T) {
	tests := map[string]string{
		"":             "/",
		"/":            "/",
		"a":            "/a",
		"/a/b/":        "/a/b",
		"//a//b":       "/a/b",
		"/a/../../etc": "/etc",
		"../x":         "/x",
	}
	for in, want := range tests {
		if got := cleanRemotePath(in); got != want {
			t.Errorf("cleanRemotePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient(ClientConfig{Scheme: "ftp"}); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
	c, err := NewClient(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if c.host != DefaultHostUS || c.scheme != "https" || c.maxRetries != defaultMaxRetries {
		t.Errorf("unexpected defaults: host=%s scheme=%s retries=%d", c.host, c.scheme, c.maxRetries)
	}
	c, _ = NewClient(ClientConfig{MaxRetries: -1})
	if c.maxRetries != 0 {
		t.Errorf("negative MaxRetries should disable retries, got %d", c.maxRetries)
	}
}

func TestBackoffIsBounded(t *testing.T) {
	c, _ := NewClient(ClientConfig{})
	for attempt := range 40 {
		d := c.backoff(attempt)
		if d <= 0 || d > defaultRetryMaxDelay {
			t.Fatalf("backoff(%d) = %s out of bounds", attempt, d)
		}
	}
}

func TestOAuthTokenOnlyInAuthorizationHeader(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/f.txt", []byte("hello"))
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})

	if err := c.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadBytes(t.Context(), "/up.txt", []byte("x"), UploadOptions{}); err != nil {
		t.Fatal(err)
	}
	rd, err := c.OpenFile(t.Context(), "/f.txt", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rd)
	rd.Close()

	for _, r := range s.recorded() {
		if strings.Contains(r.RawQuery, fakeToken) || strings.Contains(r.RawQuery, "access_token") {
			t.Errorf("%s %s leaked the token in the query: %s", r.Method, r.Path, r.RawQuery)
		}
		if r.Path != "/dl" && r.Authorization != "Bearer "+fakeToken {
			t.Errorf("%s missing bearer header", r.Path)
		}
		if r.Path == "/dl" && r.Authorization != "" {
			t.Errorf("token must not be sent to download hosts")
		}
	}
}

func TestDigestLoginKeepsSecretsOutOfURLs(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{Username: fakeUser, Password: fakePass})

	for range 3 {
		if err := c.Ping(t.Context()); err != nil {
			t.Fatalf("Ping: %v", err)
		}
	}
	if _, err := c.UploadBytes(t.Context(), "/dir/file.bin", []byte("payload"), UploadOptions{}); err != nil {
		t.Fatalf("upload with session auth: %v", err)
	}
	st := s.stats()
	if st.logins != 1 {
		t.Errorf("logins = %d, want exactly 1", st.logins)
	}
	if st.fieldAfterFile {
		t.Errorf("multipart fields must precede the file part")
	}
	for _, r := range s.recorded() {
		for _, secret := range []string{fakeSession, "passworddigest", "username", "auth="} {
			if strings.Contains(r.RawQuery, secret) {
				t.Errorf("%s %s exposes %q in the URL: %s", r.Method, r.Path, secret, r.RawQuery)
			}
		}
	}

	if err := c.Close(t.Context()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := s.stats().logouts; n != 1 {
		t.Errorf("logouts = %d, want 1 (session created by login must be invalidated)", n)
	}
}

func TestProvidedSessionIsNotLoggedOut(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AuthToken: fakeSession})
	if err := c.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s.stats().logouts != 0 {
		t.Errorf("a user-provided auth token must not be invalidated on Close")
	}
}

func TestWrongPasswordFails(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{Username: fakeUser, Password: "wrong"})
	err := c.Ping(t.Context())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
}

func TestMissingCredentials(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{})
	if err := c.Ping(t.Context()); err == nil || !strings.Contains(err.Error(), "missing credentials") {
		t.Fatalf("err = %v, want missing credentials", err)
	}
}

func TestRetriesTransientFailures(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	s.fail("/userinfo",
		injectedFailure{status: http.StatusBadGateway},
		injectedFailure{result: 5000, msg: "Internal error"},
		injectedFailure{status: http.StatusTooManyRequests},
	)
	if err := c.Ping(t.Context()); err != nil {
		t.Fatalf("Ping should succeed after transient failures: %v", err)
	}
	if n := s.countRequests("/userinfo"); n != 4 {
		t.Errorf("requests = %d, want 4", n)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken, MaxRetries: 2})
	for range 10 {
		s.fail("/userinfo", injectedFailure{status: http.StatusServiceUnavailable})
	}
	var statusErr *HTTPStatusError
	if err := c.Ping(t.Context()); !errors.As(err, &statusErr) {
		t.Fatalf("err = %v, want HTTPStatusError", err)
	}
	if n := s.countRequests("/userinfo"); n != 3 {
		t.Errorf("requests = %d, want 3 (1 + 2 retries)", n)
	}
}

func TestPermanentErrorsAreNotRetried(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	s.fail("/userinfo", injectedFailure{result: 2003, msg: "Access denied."})
	if err := c.Ping(t.Context()); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want ErrPermission", err)
	}
	if n := s.countRequests("/userinfo"); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestRetryStopsWhenContextIsCancelled(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	c.retryBase = time.Hour
	c.retryMax = time.Hour
	s.fail("/userinfo", injectedFailure{status: http.StatusServiceUnavailable})

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("expected an error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("retry loop ignored context cancellation")
	}
}

func TestUploadVerifiesChecksumAndRetries(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	s.configure(func(f *fakePCloud) { f.corruptChecksums = 1 })

	if _, err := c.UploadBytes(t.Context(), "/a/b.bin", []byte("data"), UploadOptions{}); err != nil {
		t.Fatalf("upload should succeed after re-upload: %v", err)
	}
	if n := s.countRequests("/uploadfile"); n != 2 {
		t.Errorf("uploads = %d, want 2", n)
	}

	s.configure(func(f *fakePCloud) { f.corruptChecksums = 100 })
	_, err := c.UploadBytes(t.Context(), "/a/c.bin", []byte("data"), UploadOptions{})
	if !errors.Is(err, errChecksumMismatch) {
		t.Fatalf("err = %v, want checksum mismatch", err)
	}
}

func TestUploadRetriesTransientFailures(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	s.fail("/uploadfile", injectedFailure{status: http.StatusBadGateway}, injectedFailure{result: 2041, msg: "Connection broken."})
	if _, err := c.UploadBytes(t.Context(), "/x/y.bin", []byte("abc"), UploadOptions{}); err != nil {
		t.Fatal(err)
	}
	if e, ok := s.file("/x/y.bin"); !ok || string(e.data) != "abc" {
		t.Fatal("file not stored")
	}
}

func TestUploadRecreatesVanishedParent(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	if _, err := c.UploadBytes(t.Context(), "/a/b/one", []byte("1"), UploadOptions{}); err != nil {
		t.Fatal(err)
	}
	// Someone deletes the folder behind our back; our "ensured" cache is stale.
	s.remove("/a/b/one")
	s.remove("/a/b")
	if _, err := c.UploadBytes(t.Context(), "/a/b/two", []byte("2"), UploadOptions{}); err != nil {
		t.Fatalf("upload after parent removal: %v", err)
	}
	if _, ok := s.file("/a/b/two"); !ok {
		t.Fatal("file not stored")
	}
}

func TestUploadPreservesModTime(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	mtime := time.Date(2020, 5, 17, 10, 0, 0, 0, time.UTC)
	if _, err := c.UploadBytes(t.Context(), "/m.txt", []byte("m"), UploadOptions{ModTime: mtime}); err != nil {
		t.Fatal(err)
	}
	e, _ := s.file("/m.txt")
	if !e.modTime.Equal(mtime) {
		t.Errorf("mtime = %v, want %v", e.modTime, mtime)
	}
}

func TestUploadStreamValidatesSize(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	ctx := t.Context()

	if _, err := c.UploadStream(ctx, "/n", strings.NewReader("x"), -1, UploadOptions{}); err == nil {
		t.Error("unknown size must be rejected")
	}
	for _, size := range []int64{10, maxBufferedUpload + 10} {
		short := bytes.NewReader(make([]byte, size-1))
		if _, err := c.UploadStream(ctx, "/short", short, size, UploadOptions{}); !errors.Is(err, errSizeMismatch) {
			t.Errorf("size %d: short source err = %v, want errSizeMismatch", size, err)
		}
		long := bytes.NewReader(make([]byte, size+1))
		if _, err := c.UploadStream(ctx, "/long", long, size, UploadOptions{}); !errors.Is(err, errSizeMismatch) {
			t.Errorf("size %d: long source err = %v, want errSizeMismatch", size, err)
		}
	}
	if _, ok := s.file("/short"); ok {
		t.Error("a short upload must not leave a file behind")
	}
}

func TestUploadStreamLargeFileIsStreamedAndVerified(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	data := bytes.Repeat([]byte("0123456789abcdef"), (maxBufferedUpload+12345)/16)
	if _, err := c.UploadStream(t.Context(), "/big/file.bin", bytes.NewReader(data), int64(len(data)), UploadOptions{}); err != nil {
		t.Fatal(err)
	}
	e, ok := s.file("/big/file.bin")
	if !ok || !bytes.Equal(e.data, data) {
		t.Fatal("large file content mismatch")
	}

	s.configure(func(f *fakePCloud) { f.corruptChecksums = 1 })
	_, err := c.UploadStream(t.Context(), "/big/corrupt.bin", bytes.NewReader(data), int64(len(data)), UploadOptions{})
	if !errors.Is(err, errChecksumMismatch) {
		t.Fatalf("err = %v, want checksum mismatch on streamed upload", err)
	}
}

func TestUploadRejectsInvalidPath(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	if _, err := c.UploadBytes(t.Context(), "/", nil, UploadOptions{}); err == nil {
		t.Fatal("expected invalid path error")
	}
}

func readRemote(t *testing.T, c *Client, p string, off, n int64) ([]byte, error) {
	t.Helper()
	rd, err := c.OpenFile(t.Context(), p, off, n)
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

func TestOpenFileRanges(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/r.bin", []byte("0123456789"))
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})

	tests := []struct {
		name     string
		off, n   int64
		want     string
		noServer bool
	}{
		{"full", 0, -1, "0123456789", false},
		{"middle", 4, 3, "456", false},
		{"from offset to end", 7, -1, "789", false},
		{"crossing end", 8, 10, "89", false},
		{"past end", 20, 5, "", false},
		{"zero length", 3, 0, "", true},
	}
	for _, ignore := range []bool{false, true} {
		s.configure(func(f *fakePCloud) { f.ignoreRange = ignore })
		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/ignoreRange=%v", tc.name, ignore), func(t *testing.T) {
				if ignore && tc.name == "past end" {
					t.Skip("a server ignoring Range returns the whole file")
				}
				got, err := readRemote(t, c, "/r.bin", tc.off, tc.n)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != tc.want {
					t.Errorf("got %q, want %q", got, tc.want)
				}
			})
		}
	}
}

func TestOpenFileResumesTruncatedDownload(t *testing.T) {
	s := newFakePCloud(t)
	data := bytes.Repeat([]byte("resume-me-"), 50000)
	s.seedFile("/t.bin", data)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})

	for _, tc := range []struct {
		name   string
		off, n int64
	}{{"full", 0, -1}, {"range", 1000, 300000}} {
		t.Run(tc.name, func(t *testing.T) {
			s.configure(func(f *fakePCloud) { f.truncateDownloads = 2 })
			got, err := readRemote(t, c, "/t.bin", tc.off, tc.n)
			if err != nil {
				t.Fatalf("download should resume transparently: %v", err)
			}
			want := data[tc.off:]
			if tc.n >= 0 {
				want = want[:tc.n]
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("resumed content mismatch: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

func TestOpenFileResumesStalledDownload(t *testing.T) {
	s := newFakePCloud(t)
	data := bytes.Repeat([]byte("stall"), 100000)
	s.seedFile("/s.bin", data)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	c.idleTimeout = 100 * time.Millisecond
	s.configure(func(f *fakePCloud) { f.stallDownloads = 1 })

	got, err := readRemote(t, c, "/s.bin", 0, -1)
	if err != nil {
		t.Fatalf("stalled download should be resumed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch after stall")
	}
}

func TestOpenFileFallsBackToNextHost(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/h.txt", []byte("host fallback"))
	s.configure(func(f *fakePCloud) { f.deadHostFirst = true })
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	got, err := readRemote(t, c, "/h.txt", 0, -1)
	if err != nil || string(got) != "host fallback" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOpenFileRefreshesExpiredLink(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/e.txt", []byte("fresh"))
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	if _, err := readRemote(t, c, "/e.txt", 0, -1); err != nil {
		t.Fatal(err)
	}
	s.configure(func(f *fakePCloud) { f.linkGen++ })
	got, err := readRemote(t, c, "/e.txt", 0, -1)
	if err != nil || string(got) != "fresh" {
		t.Fatalf("got %q, %v", got, err)
	}
	if n := s.countRequests("/getfilelink"); n != 2 {
		t.Errorf("getfilelink calls = %d, want 2 (cached once, refreshed once)", n)
	}
}

func TestOpenFileNotFound(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	if _, err := c.OpenFile(t.Context(), "/missing", 0, -1); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestOpenFileReadAfterClose(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/c.txt", []byte("closed"))
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	rd, err := c.OpenFile(t.Context(), "/c.txt", 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	rd.Close()
	if _, err := rd.Read(make([]byte, 1)); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("read after close err = %v", err)
	}
}

func TestListFolderRecursiveRootWorkaround(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/top.txt", []byte("t"))
	s.seedFile("/A/a.txt", []byte("a"))
	s.seedFile("/A/sub/deep.txt", []byte("d"))
	s.seedFolder("/B")
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})

	meta, err := c.ListFolder(t.Context(), "/", true)
	if err != nil {
		t.Fatalf("recursive root listing: %v", err)
	}
	var names []string
	var walk func(prefix string, m Metadata)
	walk = func(prefix string, m Metadata) {
		for _, ch := range m.Contents {
			names = append(names, prefix+ch.Name)
			walk(prefix+ch.Name+"/", ch)
		}
	}
	walk("/", *meta)
	want := "/A,/A/a.txt,/A/sub,/A/sub/deep.txt,/B,/top.txt"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("tree = %s, want %s", got, want)
	}
}

func TestMkdirAllCachesAndCreatesParents(t *testing.T) {
	s := newFakePCloud(t)
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	if err := c.MkdirAll(t.Context(), "/x/y/z"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/x", "/x/y", "/x/y/z"} {
		s.mu.Lock()
		e, ok := s.entries[p]
		s.mu.Unlock()
		if !ok || !e.isFolder {
			t.Errorf("%s not created", p)
		}
	}
	before := len(s.recorded())
	if err := c.MkdirAll(t.Context(), "/x/y/z"); err != nil {
		t.Fatal(err)
	}
	if after := len(s.recorded()); after != before {
		t.Errorf("MkdirAll of an ensured path issued %d requests", after-before)
	}
	if err := c.MkdirAll(t.Context(), "/"); err != nil {
		t.Fatal(err)
	}
}

func TestStatCreateDelete(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/d/f.txt", []byte("12345"))
	c := newTestClient(t, s, ClientConfig{AccessToken: fakeToken})
	ctx := t.Context()

	st, err := c.Stat(ctx, "/d/f.txt")
	if err != nil || st.IsFolder || st.Size != 5 {
		t.Fatalf("stat file: %+v, %v", st, err)
	}
	st, err = c.Stat(ctx, "/d")
	if err != nil || !st.IsFolder {
		t.Fatalf("stat folder: %+v, %v", st, err)
	}
	if st, err = c.Stat(ctx, "/"); err != nil || !st.IsFolder {
		t.Fatalf("stat root: %+v, %v", st, err)
	}
	if _, err := c.Stat(ctx, "/nope"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stat missing: %v", err)
	}

	if _, err := c.CreateFolder(ctx, "/d"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("CreateFolder existing: %v", err)
	}
	if _, err := c.CreateFolder(ctx, "/new"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}

	if err := c.DeleteFile(ctx, "/d/f.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteFile(ctx, "/d/f.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("second delete: %v", err)
	}
	if err := c.DeleteFolderRecursive(ctx, "/d"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stat(ctx, "/d"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("folder still present: %v", err)
	}
}
