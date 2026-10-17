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
	"errors"
	"io"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/objects"
)

type importedEntry struct {
	fi      objects.FileInfo
	content string
}

func runImport(t *testing.T, conn *Connector) (map[string]importedEntry, error) {
	t.Helper()
	records := make(chan *connectors.Record)
	got := map[string]importedEntry{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for rec := range records {
			if rec.Err != nil {
				t.Errorf("record error on %s: %v", rec.Pathname, rec.Err)
				continue
			}
			e := importedEntry{fi: rec.FileInfo}
			if !rec.FileInfo.IsDir() {
				data, err := io.ReadAll(rec.Reader)
				if err != nil {
					t.Errorf("read %s: %v", rec.Pathname, err)
				}
				e.content = string(data)
			}
			_ = rec.Close()
			got[rec.Pathname] = e
		}
	}()
	err := conn.Import(t.Context(), records, nil)
	<-done
	return got, err
}

func sortedKeys(m map[string]importedEntry) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

func TestImportTree(t *testing.T) {
	s := newFakePCloud(t)
	mtime := time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC)
	s.seedFileAt("/Documents/notes.md", []byte("# notes\n"), mtime)
	s.seedFile("/Documents/projects/readme.txt", []byte("readme"))
	s.seedFile("/Documents/projects/config.json", []byte(`{"env":"prod"}`))
	s.seedFolder("/Documents/empty")
	s.seedFile("/Elsewhere/ignored.txt", []byte("not imported"))

	conn := newTestConnector(t, s, map[string]string{"root": "/Documents"})
	got, err := runImport(t, conn)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	want := "/Documents,/Documents/empty,/Documents/notes.md,/Documents/projects,/Documents/projects/config.json,/Documents/projects/readme.txt"
	if keys := sortedKeys(got); keys != want {
		t.Fatalf("paths = %s\nwant    %s", keys, want)
	}

	notes := got["/Documents/notes.md"]
	if notes.content != "# notes\n" || notes.fi.Size() != 8 || notes.fi.Name() != "notes.md" {
		t.Errorf("notes.md = %+v", notes)
	}
	if !notes.fi.ModTime().Equal(mtime) {
		t.Errorf("mtime = %v, want %v", notes.fi.ModTime(), mtime)
	}
	if !notes.fi.Mode().IsRegular() {
		t.Errorf("notes.md mode = %v", notes.fi.Mode())
	}
	dir := got["/Documents/projects"]
	if !dir.fi.IsDir() || dir.fi.Size() != 0 || dir.fi.Name() != "projects" {
		t.Errorf("projects dir = %+v", dir.fi)
	}
	if got["/Documents/projects/config.json"].content != `{"env":"prod"}` {
		t.Errorf("config.json content mismatch")
	}
}

func TestImportWholeAccount(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/top.txt", []byte("t"))
	s.seedFile("/A/deep/f.txt", []byte("f"))

	conn := newTestConnector(t, s, map[string]string{"location": "pcloud:///"})
	got, err := runImport(t, conn)
	if err != nil {
		t.Fatalf("importing the account root must work despite pCloud error 1101: %v", err)
	}
	want := "/,/A,/A/deep,/A/deep/f.txt,/top.txt"
	if keys := sortedKeys(got); keys != want {
		t.Fatalf("paths = %s, want %s", keys, want)
	}
}

func TestImportSingleFile(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/Docs/only.txt", []byte("single"))
	conn := newTestConnector(t, s, map[string]string{"root": "/Docs/only.txt"})
	got, err := runImport(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["/Docs/only.txt"].content != "single" {
		t.Fatalf("got %+v", got)
	}
}

func TestImportMissingRoot(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, map[string]string{"root": "/missing"})
	if _, err := runImport(t, conn); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want ErrNotExist", err)
	}
}

func TestImportHonoursExcludes(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFile("/D/keep.txt", []byte("k"))
	s.seedFile("/D/skip.tmp", []byte("s"))
	s.seedFile("/D/cache/big.bin", []byte("b"))
	conn := newTestConnector(t, s, map[string]string{"root": "/D"})
	if err := conn.excludes.AddRulesFromArray([]string{"*.tmp", "/D/cache/"}); err != nil {
		t.Fatal(err)
	}
	got, err := runImport(t, conn)
	if err != nil {
		t.Fatal(err)
	}
	if keys := sortedKeys(got); keys != "/D,/D/keep.txt" {
		t.Fatalf("paths = %s", keys)
	}
}

func TestImportReadersAreLazy(t *testing.T) {
	s := newFakePCloud(t)
	for _, name := range []string{"a", "b", "c"} {
		s.seedFile("/L/"+name, []byte(name))
	}
	conn := newTestConnector(t, s, map[string]string{"root": "/L"})
	records := make(chan *connectors.Record, 10)
	if err := conn.Import(t.Context(), records, nil); err != nil {
		t.Fatal(err)
	}
	for rec := range records {
		_ = rec.Close()
	}
	if n := s.countRequests("/getfilelink"); n != 0 {
		t.Errorf("unread files triggered %d link requests", n)
	}
}

func TestImportListingFailure(t *testing.T) {
	s := newFakePCloud(t)
	s.seedFolder("/X")
	conn := newTestConnector(t, s, map[string]string{"root": "/X"})
	s.fail("/listfolder", injectedFailure{result: 2003, msg: "Access denied."})
	s.fail("/stat", injectedFailure{result: 2003, msg: "Access denied."})
	if _, err := runImport(t, conn); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want ErrPermission", err)
	}
}
