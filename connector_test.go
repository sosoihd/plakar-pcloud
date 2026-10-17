package pcloud

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/location"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/PlakarKorp/kloset/repository"
)

type fakeEntry struct {
	isFolder bool
	data     []byte
	modTime  time.Time
}

type fakePCloudServer struct {
	mu      sync.Mutex
	entries map[string]*fakeEntry
	token   string
	user    string
	pass    string
	digest  string
}

func newFakePCloudServer() *fakePCloudServer {
	s := &fakePCloudServer{
		entries: make(map[string]*fakeEntry),
		token:   "test-access-token",
		user:    "alice@example.com",
		pass:    "secret123",
		digest:  "random-digest-value",
	}
	s.entries["/"] = &fakeEntry{isFolder: true, modTime: time.Now()}
	return s
}

func (s *fakePCloudServer) seedFolder(remotePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	remotePath = cleanRemotePath(remotePath)
	parts := strings.Split(strings.TrimPrefix(remotePath, "/"), "/")
	cur := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur = cur + "/" + part
		if _, ok := s.entries[cur]; !ok {
			s.entries[cur] = &fakeEntry{isFolder: true, modTime: time.Now()}
		}
	}
}

func (s *fakePCloudServer) seedFile(remotePath string, content []byte) {
	remotePath = cleanRemotePath(remotePath)
	s.seedFolder(path.Dir(remotePath))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[remotePath] = &fakeEntry{
		isFolder: false,
		data:     append([]byte(nil), content...),
		modTime:  time.Now(),
	}
}

func (s *fakePCloudServer) checkAuth(r *http.Request) bool {
	if authHeader := r.Header.Get("Authorization"); authHeader == "Bearer "+s.token {
		return true
	}
	q := r.URL.Query()
	if q.Get("access_token") == s.token || q.Get("auth") == "session-token-ok" {
		return true
	}
	return false
}

func (s *fakePCloudServer) buildMetadataLocked(p string, recursive bool) (*Metadata, bool) {
	p = cleanRemotePath(p)
	e, ok := s.entries[p]
	if !ok {
		return nil, false
	}
	name := path.Base(p)
	if p == "/" {
		name = "/"
	}
	meta := &Metadata{
		Name:     name,
		Path:     p,
		IsFolder: e.isFolder,
		Size:     int64(len(e.data)),
		Modified: e.modTime.UTC().Format(time.RFC1123Z),
	}
	if !e.isFolder {
		return meta, true
	}

	var childPaths []string
	prefix := p
	if prefix != "/" {
		prefix += "/"
	}
	for k := range s.entries {
		if k == p || !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		if !strings.Contains(rest, "/") {
			childPaths = append(childPaths, k)
		}
	}
	sort.Strings(childPaths)

	for _, cp := range childPaths {
		ce := s.entries[cp]
		if ce.isFolder && recursive {
			if cm, ok := s.buildMetadataLocked(cp, true); ok {
				meta.Contents = append(meta.Contents, *cm)
			}
		} else {
			meta.Contents = append(meta.Contents, Metadata{
				Name:     path.Base(cp),
				Path:     cp,
				IsFolder: ce.isFolder,
				Size:     int64(len(ce.data)),
				Modified: ce.modTime.UTC().Format(time.RFC1123Z),
			})
		}
	}
	return meta, true
}

func (s *fakePCloudServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	switch r.URL.Path {
	case "/getdigest":
		writeJSON(baseResponse{Result: 0, Digest: s.digest})
		return

	case "/userinfo":
		if q.Get("getauth") == "1" {
			userHash := sha1.Sum([]byte(strings.ToLower(s.user)))
			expectedHash := sha1.Sum([]byte(s.pass + hex.EncodeToString(userHash[:]) + s.digest))
			expectedDigest := hex.EncodeToString(expectedHash[:])
			if q.Get("username") == s.user && q.Get("passworddigest") == expectedDigest {
				writeJSON(baseResponse{Result: 0, Auth: "session-token-ok"})
				return
			}
			writeJSON(baseResponse{Result: 2000, Error: "Log in failed."})
			return
		}
		if !s.checkAuth(r) {
			writeJSON(baseResponse{Result: 2000, Error: "Log in required."})
			return
		}
		writeJSON(baseResponse{Result: 0})
		return
	}

	if strings.HasPrefix(r.URL.Path, "/dl/") {
		p := cleanRemotePath(strings.TrimPrefix(r.URL.Path, "/dl"))
		s.mu.Lock()
		e, ok := s.entries[p]
		s.mu.Unlock()
		if !ok || e.isFolder {
			http.NotFound(w, r)
			return
		}
		data := e.data
		if rg := r.Header.Get("Range"); strings.HasPrefix(rg, "bytes=") {
			spec := strings.TrimPrefix(rg, "bytes=")
			parts := strings.SplitN(spec, "-", 2)
			if len(parts) == 2 {
				start, _ := strconv.Atoi(parts[0])
				end, _ := strconv.Atoi(parts[1])
				if start < len(data) {
					if end >= len(data) {
						end = len(data) - 1
					}
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write(data[start : end+1])
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	if !s.checkAuth(r) {
		writeJSON(baseResponse{Result: 2000, Error: "Log in required."})
		return
	}

	switch r.URL.Path {
	case "/stat":
		p := cleanRemotePath(q.Get("path"))
		s.mu.Lock()
		meta, ok := s.buildMetadataLocked(p, false)
		s.mu.Unlock()
		if !ok {
			writeJSON(baseResponse{Result: 2009, Error: "File not found."})
			return
		}
		writeJSON(baseResponse{Result: 0, Metadata: meta})

	case "/listfolder":
		p := cleanRemotePath(q.Get("path"))
		rec := q.Get("recursive") == "1"
		s.mu.Lock()
		meta, ok := s.buildMetadataLocked(p, rec)
		s.mu.Unlock()
		if !ok || !meta.IsFolder {
			writeJSON(baseResponse{Result: 2005, Error: "Directory does not exist."})
			return
		}
		writeJSON(baseResponse{Result: 0, Metadata: meta})

	case "/createfolderifnotexists", "/createfolder":
		p := cleanRemotePath(q.Get("path"))
		s.mu.Lock()
		parent := path.Dir(p)
		if _, ok := s.entries[parent]; !ok {
			s.mu.Unlock()
			writeJSON(baseResponse{Result: 2002, Error: "A component of parent directory does not exist."})
			return
		}
		if _, exists := s.entries[p]; !exists {
			s.entries[p] = &fakeEntry{isFolder: true, modTime: time.Now()}
		}
		meta, _ := s.buildMetadataLocked(p, false)
		s.mu.Unlock()
		writeJSON(baseResponse{Result: 0, Metadata: meta})

	case "/uploadfile":
		dir := cleanRemotePath(q.Get("path"))
		filename := q.Get("filename")
		if err := r.ParseMultipartForm(16 << 20); err != nil {
			writeJSON(baseResponse{Result: 4000, Error: err.Error()})
			return
		}
		f, hdr, err := r.FormFile("file")
		if err != nil {
			writeJSON(baseResponse{Result: 4000, Error: err.Error()})
			return
		}
		defer f.Close()
		if filename == "" {
			filename = hdr.Filename
		}
		content, err := io.ReadAll(f)
		if err != nil {
			writeJSON(baseResponse{Result: 4000, Error: err.Error()})
			return
		}
		fullPath := cleanRemotePath(path.Join(dir, filename))
		s.mu.Lock()
		if _, ok := s.entries[dir]; !ok {
			s.mu.Unlock()
			writeJSON(baseResponse{Result: 2002, Error: "Parent directory does not exist."})
			return
		}
		s.entries[fullPath] = &fakeEntry{
			isFolder: false,
			data:     content,
			modTime:  time.Now(),
		}
		s.mu.Unlock()
		writeJSON(baseResponse{Result: 0})

	case "/getfilelink":
		p := cleanRemotePath(q.Get("path"))
		s.mu.Lock()
		e, ok := s.entries[p]
		s.mu.Unlock()
		if !ok || e.isFolder {
			writeJSON(baseResponse{Result: 2009, Error: "File not found."})
			return
		}
		writeJSON(baseResponse{
			Result: 0,
			Hosts:  []string{r.Host},
			Path:   "/dl" + p,
		})

	case "/deletefile":
		p := cleanRemotePath(q.Get("path"))
		s.mu.Lock()
		e, ok := s.entries[p]
		if !ok || e.isFolder {
			s.mu.Unlock()
			writeJSON(baseResponse{Result: 2009, Error: "File not found."})
			return
		}
		delete(s.entries, p)
		s.mu.Unlock()
		writeJSON(baseResponse{Result: 0})

	default:
		http.NotFound(w, r)
	}
}

func newTestConnector(t *testing.T, srv *httptest.Server, extra map[string]string) *Connector {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	cfg := map[string]string{
		"location":     "pcloud://" + u.Host + "/backups",
		"access_token": "test-access-token",
		"insecure":     "true",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	opts := &connectors.Options{
		Hostname:        "localhost",
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		CWD:             "/",
		MaxConcurrency:  2,
	}
	conn, err := New(t.Context(), opts, "pcloud", cfg, srv.Client())
	if err != nil {
		t.Fatalf("New connector failed: %v", err)
	}
	return conn
}

func TestMetadataAndRegions(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]string
		wantOrigin string
		wantRoot   string
		wantErr    bool
	}{
		{
			name: "default US region with folder path",
			config: map[string]string{
				"location":     "pcloud:///Documents/Notes",
				"access_token": "tok",
			},
			wantOrigin: DefaultHostUS,
			wantRoot:   "/Documents/Notes",
		},
		{
			name: "EU region via host shorthand",
			config: map[string]string{
				"location":     "pcloud://eu/MyBackups",
				"access_token": "tok",
			},
			wantOrigin: DefaultHostEU,
			wantRoot:   "/MyBackups",
		},
		{
			name: "EU region via parameter",
			config: map[string]string{
				"location":     "pcloud:///Photos",
				"region":       "eu",
				"access_token": "tok",
			},
			wantOrigin: DefaultHostEU,
			wantRoot:   "/Photos",
		},
		{
			name: "missing credentials fails",
			config: map[string]string{
				"location": "pcloud:///Photos",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := New(t.Context(), nil, "pcloud", tc.config, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conn.Type() != "pcloud" {
				t.Errorf("Type() = %q, want pcloud", conn.Type())
			}
			if conn.Origin() != tc.wantOrigin {
				t.Errorf("Origin() = %q, want %q", conn.Origin(), tc.wantOrigin)
			}
			if conn.Root() != tc.wantRoot {
				t.Errorf("Root() = %q, want %q", conn.Root(), tc.wantRoot)
			}
			if conn.Flags() != location.Flags(0) {
				t.Errorf("Flags() = %v, want 0", conn.Flags())
			}
		})
	}
}

func TestDigestAuthAndPing(t *testing.T) {
	fake := newFakePCloudServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	conn, err := New(t.Context(), nil, "pcloud", map[string]string{
		"location": "pcloud://" + u.Host + "/",
		"username": fake.user,
		"password": fake.pass,
		"insecure": "true",
	}, srv.Client())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := conn.Ping(t.Context()); err != nil {
		t.Fatalf("Ping with digest auth failed: %v", err)
	}
}

// Test1_BackupFileFromPCloudToLocalMac teste la sauvegarde d'un fichier (et d'une arborescence)
// présent sur pCloud vers un dossier local sur le Mac via le connecteur Importer.
func Test1_BackupFileFromPCloudToLocalMac(t *testing.T) {
	fake := newFakePCloudServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	// 1. On place des fichiers sur le serveur pCloud distant
	pcloudFiles := map[string]string{
		"/Documents/notes.md":            "# Mes notes sur pCloud\nSauvegardées sur mon Mac via Plakar.\n",
		"/Documents/projets/readme.txt":  "Contenu du fichier readme depuis pCloud\n",
		"/Documents/projets/config.json": `{"env":"prod","region":"eu"}`,
	}
	for remotePath, content := range pcloudFiles {
		fake.seedFile(remotePath, []byte(content))
	}

	// 2. Dossier local sur le Mac qui recevra la sauvegarde issue de pCloud
	macBackupDir := t.TempDir()

	// 3. On initialise l'Importer pCloud pointant sur /Documents
	conn := newTestConnector(t, srv, map[string]string{
		"root": "/Documents",
	})

	records := make(chan *connectors.Record)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for rec := range records {
			if rec.Err != nil {
				t.Errorf("erreur d'import sur %s: %v", rec.Pathname, rec.Err)
				continue
			}

			localTarget := filepath.Join(macBackupDir, filepath.FromSlash(rec.Pathname))
			if rec.FileInfo.IsDir() {
				if err := os.MkdirAll(localTarget, 0755); err != nil {
					t.Errorf("mkdir local %s: %v", localTarget, err)
				}
				_ = rec.Close()
				continue
			}

			if err := os.MkdirAll(filepath.Dir(localTarget), 0755); err != nil {
				t.Errorf("mkdir parent local %s: %v", localTarget, err)
				_ = rec.Close()
				continue
			}

			data, err := io.ReadAll(rec.Reader)
			_ = rec.Close()
			if err != nil {
				t.Errorf("lecture depuis pCloud %s: %v", rec.Pathname, err)
				continue
			}

			if err := os.WriteFile(localTarget, data, 0644); err != nil {
				t.Errorf("écriture sur le Mac %s: %v", localTarget, err)
			}
		}
	}()

	if err := conn.Import(t.Context(), records, nil); err != nil {
		t.Fatalf("Import depuis pCloud échoué: %v", err)
	}
	<-done

	// 4. On vérifie que chaque fichier de pCloud est bien présent sur le disque du Mac
	for remotePath, wantContent := range pcloudFiles {
		localPath := filepath.Join(macBackupDir, filepath.FromSlash(remotePath))
		gotBytes, err := os.ReadFile(localPath)
		if err != nil {
			t.Fatalf("fichier %s non trouvé sur le Mac (%s): %v", remotePath, localPath, err)
		}
		if string(gotBytes) != wantContent {
			t.Errorf("contenu sur le Mac pour %s = %q, attendu %q", remotePath, string(gotBytes), wantContent)
		}
	}
}

// Test2_BackupLocalMacFolderToPCloud teste la sauvegarde d'un dossier local du Mac
// vers pCloud (via Exporter et via Storage).
func Test2_BackupLocalMacFolderToPCloud(t *testing.T) {
	fake := newFakePCloudServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	// 1. On crée un vrai dossier sur le Mac avec plusieurs fichiers et sous-dossiers
	macSourceDir := t.TempDir()
	localFiles := map[string]string{
		"rapport.txt":             "Rapport annuel depuis mon Mac\n",
		"scripts/deploy.sh":       "#!/bin/sh\necho 'Deploying to production'\n",
		"photos/2026/legende.txt": "Souvenirs de voyage\n",
	}

	for relPath, content := range localFiles {
		fullLocalPath := filepath.Join(macSourceDir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(fullLocalPath), 0755); err != nil {
			t.Fatalf("création dossier local sur le Mac: %v", err)
		}
		if err := os.WriteFile(fullLocalPath, []byte(content), 0644); err != nil {
			t.Fatalf("création fichier local sur le Mac: %v", err)
		}
	}

	// 2. On configure le connecteur pCloud cible dans /MacBackup
	conn := newTestConnector(t, srv, map[string]string{
		"root": "/MacBackup",
	})

	exportRecords := make(chan *connectors.Record)
	exportResults := make(chan *connectors.Result)

	// On parcourt le dossier local du Mac et on envoie chaque entrée vers pCloud
	go func() {
		defer close(exportRecords)
		_ = filepath.WalkDir(macSourceDir, func(currentPath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(macSourceDir, currentPath)
			if err != nil {
				return err
			}
			slashRel := "/"
			if rel != "." {
				slashRel = "/" + filepath.ToSlash(rel)
			}

			var rd io.ReadCloser
			if !d.IsDir() {
				f, err := os.Open(currentPath)
				if err != nil {
					return err
				}
				rd = f
			}

			exportRecords <- &connectors.Record{
				Reader:   rd,
				Pathname: slashRel,
				FileInfo: objects.FileInfo{
					Lname:    info.Name(),
					Lsize:    info.Size(),
					Lmode:    info.Mode(),
					LmodTime: info.ModTime(),
				},
			}
			return nil
		})
	}()

	var exportErrs []error
	doneResults := make(chan struct{})
	go func() {
		defer close(doneResults)
		for res := range exportResults {
			if res.Err != nil {
				exportErrs = append(exportErrs, res.Err)
			}
		}
	}()

	if err := conn.Export(t.Context(), exportRecords, exportResults); err != nil {
		t.Fatalf("Export du dossier Mac vers pCloud échoué: %v", err)
	}
	<-doneResults
	if len(exportErrs) > 0 {
		t.Fatalf("erreurs lors de l'envoi vers pCloud: %v", exportErrs)
	}

	// 3. On vérifie sur le serveur pCloud que tous les fichiers du Mac y sont bien stockés
	for relPath, wantContent := range localFiles {
		remotePCloudPath := path.Join("/MacBackup", relPath)
		rd, err := conn.client.OpenFile(t.Context(), remotePCloudPath, nil)
		if err != nil {
			t.Fatalf("fichier %s introuvable sur pCloud après backup: %v", remotePCloudPath, err)
		}
		gotBytes, err := io.ReadAll(rd)
		_ = rd.Close()
		if err != nil {
			t.Fatalf("lecture du fichier %s sur pCloud: %v", remotePCloudPath, err)
		}
		if string(gotBytes) != wantContent {
			t.Errorf("contenu sur pCloud pour %s = %q, attendu %q", remotePCloudPath, string(gotBytes), wantContent)
		}
	}
}

func TestStorageLifecycle(t *testing.T) {
	fake := newFakePCloudServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	store := newTestConnector(t, srv, map[string]string{
		"root": "/kloset-repo",
	})

	ctx := t.Context()
	cfgBytes := []byte("kloset-repository-config-v1")

	if err := store.Create(ctx, cfgBytes); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Second Create must fail because CONFIG already exists
	if err := store.Create(ctx, cfgBytes); err == nil {
		t.Fatalf("expected second Create to fail")
	}

	opened, err := store.Open(ctx)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(opened, cfgBytes) {
		t.Fatalf("Open returned %q, want %q", string(opened), string(cfgBytes))
	}

	var mac objects.MAC
	for i := range mac {
		mac[i] = byte(i + 1)
	}
	payload := []byte("0123456789abcdef-packfile-payload")

	n, err := store.Put(ctx, storage.StorageResourcePackfile, mac, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put packfile failed: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("Put size = %d, want %d", n, len(payload))
	}

	macs, err := store.List(ctx, storage.StorageResourcePackfile)
	if err != nil {
		t.Fatalf("List packfiles failed: %v", err)
	}
	if len(macs) != 1 || macs[0] != mac {
		t.Fatalf("List packfiles = %v, want [%x]", macs, mac)
	}

	// Full Get
	rd, err := store.Get(ctx, storage.StorageResourcePackfile, mac, nil)
	if err != nil {
		t.Fatalf("Get packfile failed: %v", err)
	}
	gotData, err := io.ReadAll(rd)
	_ = rd.Close()
	if err != nil || !bytes.Equal(gotData, payload) {
		t.Fatalf("Get packfile = %q (err=%v), want %q", string(gotData), err, string(payload))
	}

	// Range Get
	rg := &storage.Range{Offset: 4, Length: 6}
	rdRange, err := store.Get(ctx, storage.StorageResourcePackfile, mac, rg)
	if err != nil {
		t.Fatalf("Get range failed: %v", err)
	}
	gotRange, err := io.ReadAll(rdRange)
	_ = rdRange.Close()
	if err != nil || string(gotRange) != "456789" {
		t.Fatalf("Get range = %q (err=%v), want %q", string(gotRange), err, "456789")
	}

	// Delete and verify ErrPackfileNotFound
	if err := store.Delete(ctx, storage.StorageResourcePackfile, mac); err != nil {
		t.Fatalf("Delete packfile failed: %v", err)
	}
	_, err = store.Get(ctx, storage.StorageResourcePackfile, mac, nil)
	if !errors.Is(err, repository.ErrPackfileNotFound) {
		t.Fatalf("Get deleted packfile error = %v, want ErrPackfileNotFound", err)
	}
}
