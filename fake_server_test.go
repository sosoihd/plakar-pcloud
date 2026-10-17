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
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
)

const (
	fakeToken   = "test-access-token"
	fakeUser    = "alice@example.com"
	fakePass    = "secret123"
	fakeDigest  = "random-digest-value"
	fakeSession = "session-token-ok"
)

type fakeEntry struct {
	isFolder bool
	data     []byte
	modTime  time.Time
}

type recordedRequest struct {
	Method        string
	Path          string
	RawQuery      string
	Authorization string
	Params        url.Values
}

// injectedFailure makes the next request to an endpoint fail.
type injectedFailure struct {
	status int    // HTTP status to return (if non-zero)
	result int    // pCloud API result code to return (if non-zero)
	msg    string // API error message
}

// fakePCloud is an in-memory emulation of the subset of the pCloud HTTP JSON
// API used by the connector, with hooks to inject faults.
type fakePCloud struct {
	t   testing.TB
	srv *httptest.Server

	mu       sync.Mutex
	entries  map[string]*fakeEntry
	sessions map[string]bool
	requests []recordedRequest
	failures map[string][]injectedFailure

	logins  int
	logouts int
	linkGen int

	// Fault injection knobs.
	deadHostFirst      bool // getfilelink advertises an unreachable host first
	ignoreRange        bool // download hosts ignore Range headers
	truncateDownloads  int  // number of downloads to cut halfway
	stallDownloads     int  // number of downloads that stop sending halfway
	corruptChecksums   int  // number of uploads answered with a wrong sha1
	discardUploads     bool // hash uploaded data without storing it
	authFieldAfterFile bool // set when an upload sent a field after the file part
	uploadedBytesCount int64
}

func newFakePCloud(t testing.TB) *fakePCloud {
	t.Helper()
	s := &fakePCloud{
		t:        t,
		entries:  map[string]*fakeEntry{"/": {isFolder: true, modTime: time.Unix(1700000000, 0)}},
		sessions: map[string]bool{fakeSession: true},
		failures: map[string][]injectedFailure{},
	}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *fakePCloud) host() string {
	u, _ := url.Parse(s.srv.URL)
	return u.Host
}

// configure mutates fault-injection knobs under the server lock.
func (s *fakePCloud) configure(f func(*fakePCloud)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

type fakeStats struct {
	logins, logouts    int
	fieldAfterFile     bool
	uploadedBytesTotal int64
}

func (s *fakePCloud) stats() fakeStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fakeStats{s.logins, s.logouts, s.authFieldAfterFile, s.uploadedBytesCount}
}

func (s *fakePCloud) fail(endpoint string, failures ...injectedFailure) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[endpoint] = append(s.failures[endpoint], failures...)
}

func (s *fakePCloud) seedFolder(remotePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mkdirAllLocked(cleanRemotePath(remotePath))
}

func (s *fakePCloud) mkdirAllLocked(p string) {
	cur := ""
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		cur += "/" + part
		if _, ok := s.entries[cur]; !ok {
			s.entries[cur] = &fakeEntry{isFolder: true, modTime: time.Unix(1700000000, 0)}
		}
	}
}

func (s *fakePCloud) seedFile(remotePath string, content []byte) {
	s.seedFileAt(remotePath, content, time.Unix(1700000000, 0))
}

func (s *fakePCloud) seedFileAt(remotePath string, content []byte, mtime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	remotePath = cleanRemotePath(remotePath)
	s.mkdirAllLocked(path.Dir(remotePath))
	s.entries[remotePath] = &fakeEntry{data: append([]byte(nil), content...), modTime: mtime}
}

func (s *fakePCloud) file(remotePath string) (*fakeEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[cleanRemotePath(remotePath)]
	if !ok || e.isFolder {
		return nil, false
	}
	return e, true
}

func (s *fakePCloud) remove(remotePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, cleanRemotePath(remotePath))
}

func (s *fakePCloud) recorded() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.requests...)
}

func (s *fakePCloud) countRequests(endpoint string) int {
	n := 0
	for _, r := range s.recorded() {
		if r.Path == endpoint {
			n++
		}
	}
	return n
}

func (s *fakePCloud) buildMetadataLocked(p string, recursive bool) (*Metadata, bool) {
	e, ok := s.entries[p]
	if !ok {
		return nil, false
	}
	name := path.Base(p)
	meta := &Metadata{
		Name:     name,
		IsFolder: e.isFolder,
		Size:     int64(len(e.data)),
		Modified: e.modTime.UTC().Format(time.RFC1123Z),
		Created:  e.modTime.UTC().Format(time.RFC1123Z),
	}
	if !recursive {
		// Like pCloud, only non-recursive answers carry the path.
		meta.Path = p
	}
	if !e.isFolder {
		return meta, true
	}

	prefix := p
	if prefix != "/" {
		prefix += "/"
	}
	var children []string
	for k := range s.entries {
		if k != p && strings.HasPrefix(k, prefix) && !strings.Contains(strings.TrimPrefix(k, prefix), "/") {
			children = append(children, k)
		}
	}
	sort.Strings(children)
	for _, cp := range children {
		ce := s.entries[cp]
		if ce.isFolder && recursive {
			cm, _ := s.buildMetadataLocked(cp, true)
			meta.Contents = append(meta.Contents, *cm)
			continue
		}
		meta.Contents = append(meta.Contents, Metadata{
			Name:     path.Base(cp),
			IsFolder: ce.isFolder,
			Size:     int64(len(ce.data)),
			Modified: ce.modTime.UTC().Format(time.RFC1123Z),
		})
	}
	return meta, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func rawJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func sha1Hex(b []byte) string {
	h := sha1.Sum(b)
	return hex.EncodeToString(h[:])
}

func (s *fakePCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/dl/") {
		s.serveDownload(w, r)
		return
	}

	var params url.Values
	var upload []byte
	var uploadSHA1 string
	var uploadLen int64
	if r.URL.Path == "/uploadfile" {
		params = r.URL.Query()
		var ok bool
		upload, uploadSHA1, uploadLen, ok = s.readUpload(w, r, params)
		if !ok {
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, baseResponse{Result: 1000, Error: err.Error()})
			return
		}
		params = r.Form
	}

	s.mu.Lock()
	s.requests = append(s.requests, recordedRequest{
		Method:        r.Method,
		Path:          r.URL.Path,
		RawQuery:      r.URL.RawQuery,
		Authorization: r.Header.Get("Authorization"),
		Params:        params,
	})
	var inj *injectedFailure
	if q := s.failures[r.URL.Path]; len(q) > 0 {
		inj = &q[0]
		s.failures[r.URL.Path] = q[1:]
	}
	s.mu.Unlock()

	if inj != nil {
		if inj.status != 0 {
			w.WriteHeader(inj.status)
			return
		}
		writeJSON(w, baseResponse{Result: inj.result, Error: inj.msg})
		return
	}

	switch r.URL.Path {
	case "/getdigest":
		writeJSON(w, baseResponse{Digest: fakeDigest})
		return
	case "/userinfo":
		if params.Get("getauth") != "" {
			s.mu.Lock()
			s.logins++
			s.mu.Unlock()
			userHash := sha1.Sum([]byte(strings.ToLower(fakeUser)))
			want := sha1Hex([]byte(fakePass + hex.EncodeToString(userHash[:]) + params.Get("digest")))
			if params.Get("username") == fakeUser && params.Get("passworddigest") == want {
				writeJSON(w, baseResponse{Auth: fakeSession})
				return
			}
			writeJSON(w, baseResponse{Result: 2000, Error: "Log in failed."})
			return
		}
	case "/logout":
		s.mu.Lock()
		s.logouts++
		delete(s.sessions, params.Get("auth"))
		s.mu.Unlock()
		writeJSON(w, baseResponse{})
		return
	}

	if !s.authorized(r, params) {
		writeJSON(w, baseResponse{Result: 2000, Error: "Log in failed."})
		return
	}

	p := cleanRemotePath(params.Get("path"))
	switch r.URL.Path {
	case "/userinfo":
		writeJSON(w, baseResponse{})

	case "/stat":
		s.mu.Lock()
		e, ok := s.entries[p]
		var meta *Metadata
		if ok && !e.isFolder {
			meta, _ = s.buildMetadataLocked(p, false)
		}
		s.mu.Unlock()
		if meta == nil {
			writeJSON(w, baseResponse{Result: 2009, Error: "File not found."})
			return
		}
		writeJSON(w, baseResponse{Metadata: rawJSON(meta)})

	case "/listfolder":
		recursive := params.Get("recursive") != ""
		if recursive && p == "/" {
			writeJSON(w, baseResponse{Result: 1101, Error: "Recursive listing of the root folder is not allowed."})
			return
		}
		s.mu.Lock()
		meta, ok := s.buildMetadataLocked(p, recursive)
		s.mu.Unlock()
		if !ok || !meta.IsFolder {
			writeJSON(w, baseResponse{Result: 2005, Error: "Directory does not exist."})
			return
		}
		writeJSON(w, baseResponse{Metadata: rawJSON(meta)})

	case "/createfolder", "/createfolderifnotexists":
		s.mu.Lock()
		parent, hasParent := s.entries[path.Dir(p)]
		existing, exists := s.entries[p]
		switch {
		case !hasParent || !parent.isFolder:
			s.mu.Unlock()
			writeJSON(w, baseResponse{Result: 2002, Error: "A component of parent directory does not exist."})
			return
		case exists && (r.URL.Path == "/createfolder" || !existing.isFolder):
			s.mu.Unlock()
			writeJSON(w, baseResponse{Result: 2004, Error: "File or folder alredy exists."})
			return
		case !exists:
			s.entries[p] = &fakeEntry{isFolder: true, modTime: time.Now()}
		}
		meta, _ := s.buildMetadataLocked(p, false)
		s.mu.Unlock()
		writeJSON(w, baseResponse{Metadata: rawJSON(meta)})

	case "/uploadfile":
		dir := cleanRemotePath(params.Get("path"))
		full := cleanRemotePath(path.Join(dir, params.Get("filename")))
		mtime := time.Now()
		if v := params.Get("mtime"); v != "" {
			secs, _ := strconv.ParseInt(v, 10, 64)
			mtime = time.Unix(secs, 0)
		}
		s.mu.Lock()
		if d, ok := s.entries[dir]; !ok || !d.isFolder {
			s.mu.Unlock()
			writeJSON(w, baseResponse{Result: 2005, Error: "Directory does not exist."})
			return
		}
		if !s.discardUploads {
			s.entries[full] = &fakeEntry{data: upload, modTime: mtime}
		}
		s.uploadedBytesCount += uploadLen
		corrupt := s.corruptChecksums > 0
		if corrupt {
			s.corruptChecksums--
		}
		meta := &Metadata{Name: path.Base(full), Size: uploadLen, Modified: mtime.UTC().Format(time.RFC1123Z)}
		s.mu.Unlock()
		sum := uploadSHA1
		if corrupt {
			sum = strings.Repeat("0", 40)
		}
		writeJSON(w, baseResponse{
			Metadata:  rawJSON([]*Metadata{meta}),
			FileIDs:   []uint64{1},
			Checksums: []checksums{{SHA1: sum}},
		})

	case "/getfilelink":
		s.mu.Lock()
		e, ok := s.entries[p]
		gen := s.linkGen
		dead := s.deadHostFirst
		s.mu.Unlock()
		if !ok || e.isFolder {
			writeJSON(w, baseResponse{Result: 2009, Error: "File not found."})
			return
		}
		hosts := []string{r.Host}
		if dead {
			hosts = []string{"127.0.0.1:1", r.Host}
		}
		writeJSON(w, baseResponse{
			Hosts:   hosts,
			Path:    fmt.Sprintf("/dl/%d%s", gen, p),
			Expires: time.Now().Add(6 * time.Hour).UTC().Format(time.RFC1123Z),
		})

	case "/deletefile":
		s.mu.Lock()
		e, ok := s.entries[p]
		if !ok || e.isFolder {
			s.mu.Unlock()
			writeJSON(w, baseResponse{Result: 2009, Error: "File not found."})
			return
		}
		delete(s.entries, p)
		s.mu.Unlock()
		writeJSON(w, baseResponse{})

	case "/deletefolderrecursive":
		s.mu.Lock()
		for k := range s.entries {
			if k == p || strings.HasPrefix(k, p+"/") {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
		writeJSON(w, baseResponse{})

	default:
		http.NotFound(w, r)
	}
}

func (s *fakePCloud) authorized(r *http.Request, params url.Values) bool {
	if r.Header.Get("Authorization") == "Bearer "+fakeToken {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return params.Get("access_token") == fakeToken || s.sessions[params.Get("auth")]
}

// readUpload parses the multipart body in order, as pCloud does: fields must
// precede the file part.
func (s *fakePCloud) readUpload(w http.ResponseWriter, r *http.Request, params url.Values) ([]byte, string, int64, bool) {
	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, baseResponse{Result: 1000, Error: err.Error()})
		return nil, "", 0, false
	}
	var data []byte
	var sum string
	var n int64
	sawFile := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, baseResponse{Result: 5001, Error: err.Error()})
			return nil, "", 0, false
		}
		if part.FormName() == "file" {
			sawFile = true
			h := sha1.New()
			if s.discardUploads {
				n, err = io.Copy(h, part)
			} else {
				data, err = io.ReadAll(io.TeeReader(part, h))
				n = int64(len(data))
			}
			if err != nil {
				// Mirrors pCloud's nopartial: nothing is stored.
				writeJSON(w, baseResponse{Result: 2041, Error: "Connection broken."})
				return nil, "", 0, false
			}
			sum = hex.EncodeToString(h.Sum(nil))
			continue
		}
		v, _ := io.ReadAll(part)
		if sawFile {
			s.mu.Lock()
			s.authFieldAfterFile = true
			s.mu.Unlock()
		}
		params.Set(part.FormName(), string(v))
	}
	if !sawFile {
		writeJSON(w, baseResponse{Result: 1000, Error: "No file uploaded."})
		return nil, "", 0, false
	}
	return data, sum, n, true
}

func (s *fakePCloud) serveDownload(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/dl/")
	genStr, filePath, _ := strings.Cut(rest, "/")
	gen, _ := strconv.Atoi(genStr)

	s.mu.Lock()
	s.requests = append(s.requests, recordedRequest{Method: r.Method, Path: "/dl", RawQuery: r.URL.RawQuery, Authorization: r.Header.Get("Authorization")})
	e, ok := s.entries[cleanRemotePath(filePath)]
	stale := gen != s.linkGen
	ignoreRange := s.ignoreRange
	truncate := s.truncateDownloads > 0
	if truncate {
		s.truncateDownloads--
	}
	stall := s.stallDownloads > 0
	if stall {
		s.stallDownloads--
	}
	var data []byte
	if ok {
		data = e.data
	}
	s.mu.Unlock()

	if stale {
		http.Error(w, "link expired", http.StatusGone)
		return
	}
	if !ok || e.isFolder {
		http.NotFound(w, r)
		return
	}

	status := http.StatusOK
	if rg := r.Header.Get("Range"); rg != "" && !ignoreRange {
		start, end, valid := parseRange(rg, len(data))
		if !valid {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(data)))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		data = data[start : end+1]
		status = http.StatusPartialContent
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	if truncate || stall {
		half := len(data) / 2
		_, _ = w.Write(data[:half])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if stall {
			<-r.Context().Done()
		}
		panic(http.ErrAbortHandler)
	}
	_, _ = w.Write(data)
}

func parseRange(h string, size int) (int, int, bool) {
	spec, ok := strings.CutPrefix(h, "bytes=")
	if !ok {
		return 0, 0, false
	}
	a, b, _ := strings.Cut(spec, "-")
	start, err := strconv.Atoi(a)
	if err != nil || start >= size {
		return 0, 0, false
	}
	end := size - 1
	if b != "" {
		if e, err := strconv.Atoi(b); err == nil && e < end {
			end = e
		}
	}
	return start, end, true
}

// newTestConnector builds a connector pointed at the fake server with fast
// retries.
func newTestConnector(t testing.TB, s *fakePCloud, extra map[string]string) *Connector {
	t.Helper()
	cfg := map[string]string{
		"location":     "pcloud:///backups",
		"endpoint":     s.host(),
		"insecure":     "true",
		"access_token": fakeToken,
	}
	for k, v := range extra {
		if v == "" {
			delete(cfg, k)
		} else {
			cfg[k] = v
		}
	}
	opts := &connectors.Options{
		Hostname:        "localhost",
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		CWD:             "/",
		MaxConcurrency:  4,
	}
	conn, err := New(t.Context(), opts, "pcloud", cfg, s.srv.Client())
	if err != nil {
		t.Fatalf("New connector failed: %v", err)
	}
	speedUp(conn.client)
	t.Cleanup(func() { _ = conn.Close(t.Context()) })
	return conn
}

func speedUp(c *Client) {
	c.retryBase = time.Millisecond
	c.retryMax = 5 * time.Millisecond
}

func newTestClient(t testing.TB, s *fakePCloud, cfg ClientConfig) *Client {
	t.Helper()
	cfg.Scheme = "http"
	cfg.Host = s.host()
	cfg.HTTPClient = s.srv.Client()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	speedUp(c)
	return c
}
