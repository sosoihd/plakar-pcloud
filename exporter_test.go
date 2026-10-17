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
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/objects"
)

func fileRecord(pathname string, content []byte, mtime time.Time) *connectors.Record {
	return connectors.NewRecord(pathname, "", objects.FileInfo{
		Lname:    path.Base(pathname),
		Lsize:    int64(len(content)),
		Lmode:    0644,
		LmodTime: mtime,
	}, nil, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	})
}

func dirRecord(pathname string) *connectors.Record {
	return connectors.NewRecord(pathname, "", objects.FileInfo{
		Lname: path.Base(pathname),
		Lmode: fs.ModeDir | 0755,
	}, nil, nil)
}

// runExport feeds records to Export and returns the per-record results.
func runExport(t *testing.T, conn *Connector, recs ...*connectors.Record) (map[string]error, error) {
	t.Helper()
	records := make(chan *connectors.Record)
	results := make(chan *connectors.Result)
	go func() {
		defer close(records)
		for _, r := range recs {
			records <- r
		}
	}()
	got := map[string]error{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for res := range results {
			got[res.Record.Pathname] = res.Err
		}
	}()
	err := conn.Export(t.Context(), records, results)
	<-done
	return got, err
}

func TestExportLocalTree(t *testing.T) {
	s := newFakePCloud(t)
	src := t.TempDir()
	mtime := time.Date(2021, 6, 7, 8, 9, 10, 0, time.UTC)
	files := map[string]string{
		"report.txt":             "annual report\n",
		"scripts/deploy.sh":      "#!/bin/sh\necho deploy\n",
		"photos/2026/legend.txt": "holidays\n",
		"empty.txt":              "",
	}
	for rel, content := range files {
		full := filepath.Join(src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(full, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}

	var recs []*connectors.Record
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		pathname := "/" + filepath.ToSlash(rel)
		if rel == "." {
			pathname = "/"
		}
		fi := objects.FileInfo{Lname: info.Name(), Lsize: info.Size(), Lmode: info.Mode(), LmodTime: info.ModTime()}
		local := p
		recs = append(recs, connectors.NewRecord(pathname, "", fi, nil, func() (io.ReadCloser, error) {
			return os.Open(local)
		}))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := newTestConnector(t, s, map[string]string{"root": "/MacBackup"})
	results, err := runExport(t, conn, recs...)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	for p, rerr := range results {
		if rerr != nil {
			t.Errorf("%s: %v", p, rerr)
		}
	}
	if len(results) != len(recs) {
		t.Errorf("got %d results for %d records", len(results), len(recs))
	}
	for rel, want := range files {
		e, ok := s.file(path.Join("/MacBackup", rel))
		if !ok {
			t.Fatalf("%s missing on pCloud", rel)
		}
		if string(e.data) != want {
			t.Errorf("%s = %q, want %q", rel, e.data, want)
		}
		if !e.modTime.Equal(mtime) {
			t.Errorf("%s mtime = %v, want %v", rel, e.modTime, mtime)
		}
	}
}

func TestExportLargeFileIsStreamed(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	data := bytes.Repeat([]byte("L"), maxBufferedUpload+1)
	results, err := runExport(t, conn, dirRecord("/"), fileRecord("/big.bin", data, time.Now()))
	if err != nil || results["/big.bin"] != nil {
		t.Fatalf("export = %v / %v", err, results["/big.bin"])
	}
	if e, ok := s.file("/R/big.bin"); !ok || !bytes.Equal(e.data, data) {
		t.Fatal("large file not restored correctly")
	}
}

func TestExportRejectsPathTraversal(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/Restore"})
	results, err := runExport(t, conn, fileRecord("/../../etc/passwd", []byte("x"), time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	// path.Join cleans "/Restore/../../etc/passwd" to "/etc/passwd".
	if results["/../../etc/passwd"] == nil {
		t.Fatal("traversal must be rejected")
	}
	if _, ok := s.file("/etc/passwd"); ok {
		t.Fatal("file written outside the restore root")
	}
}

func TestExportReportsUnsupportedTypes(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	link := connectors.NewRecord("/link", "/target", objects.FileInfo{Lname: "link", Lmode: fs.ModeSymlink | 0777}, nil, nil)
	pipe := connectors.NewRecord("/pipe", "", objects.FileInfo{Lname: "pipe", Lmode: fs.ModeNamedPipe | 0644}, nil, nil)
	sock := connectors.NewRecord("/sock", "", objects.FileInfo{Lname: "sock", Lmode: fs.ModeSocket | 0644}, nil, nil)
	dev := connectors.NewRecord("/dev", "", objects.FileInfo{Lname: "dev", Lmode: fs.ModeDevice | 0644}, nil, nil)
	results, err := runExport(t, conn, link, pipe, sock, dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/link", "/pipe", "/sock", "/dev"} {
		if !errors.Is(results[p], errors.ErrUnsupported) {
			t.Errorf("%s: err = %v, want ErrUnsupported", p, results[p])
		}
	}
}

func TestExportAcknowledgesErrorAndXattrRecords(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	errRec := connectors.NewError("/broken", errors.New("source error"))
	xattr := connectors.NewXattr("/f", "user.k", objects.AttributeExtended, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(nil)), nil
	})
	results, err := runExport(t, conn, errRec, xattr)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %v", results)
	}
	for p, rerr := range results {
		if rerr != nil {
			t.Errorf("%s should be acknowledged, got %v", p, rerr)
		}
	}
}

func TestExportReportsUploadFailures(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	s.fail("/uploadfile", injectedFailure{result: 2008, msg: "User is over quota."})
	results, err := runExport(t, conn, fileRecord("/a.txt", []byte("a"), time.Now()), fileRecord("/b.txt", []byte("b"), time.Now()))
	if err != nil {
		t.Fatalf("a per-file failure must not abort the export: %v", err)
	}
	failed := 0
	for _, rerr := range results {
		if rerr != nil {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1 (results %v)", failed, results)
	}
}

func TestExportSizeMismatchIsReported(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/R"})
	rec := connectors.NewRecord("/lie.txt", "", objects.FileInfo{Lname: "lie.txt", Lsize: 100, Lmode: 0644}, nil, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte("short"))), nil
	})
	results, err := runExport(t, conn, rec)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(results["/lie.txt"], errSizeMismatch) {
		t.Fatalf("err = %v, want errSizeMismatch", results["/lie.txt"])
	}
}
