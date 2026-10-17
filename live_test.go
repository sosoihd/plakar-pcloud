//go:build live

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

// Live tests against the real pCloud API. They run in a throw-away folder
// that is deleted afterwards (deleted files go to the pCloud trash).
//
//	PCLOUD_ACCESS_TOKEN=... PCLOUD_REGION=eu go test -tags live -run Live -v
//	PCLOUD_USERNAME=... PCLOUD_PASSWORD=... PCLOUD_REGION=eu go test -tags live -run Live -v

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/connectors/storage"
)

func liveConfigs(t *testing.T) map[string]map[string]string {
	t.Helper()
	region := os.Getenv("PCLOUD_REGION")
	folder := fmt.Sprintf("/plakar-pcloud-live-%d", time.Now().UnixNano())
	configs := map[string]map[string]string{}
	if tok := os.Getenv("PCLOUD_ACCESS_TOKEN"); tok != "" {
		configs["oauth"] = map[string]string{"location": "pcloud://" + folder + "-oauth", "access_token": tok, "region": region}
	}
	if u, p := os.Getenv("PCLOUD_USERNAME"), os.Getenv("PCLOUD_PASSWORD"); u != "" && p != "" {
		configs["digest"] = map[string]string{"location": "pcloud://" + folder + "-digest", "username": u, "password": p, "region": region}
	}
	if len(configs) == 0 {
		t.Skip("set PCLOUD_ACCESS_TOKEN and/or PCLOUD_USERNAME+PCLOUD_PASSWORD")
	}
	return configs
}

func TestLive(t *testing.T) {
	for name, cfg := range liveConfigs(t) {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			conn, err := New(ctx, &connectors.Options{MaxConcurrency: 4}, "pcloud", cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			root := conn.Root()
			t.Cleanup(func() {
				if err := conn.client.DeleteFolderRecursive(context.Background(), root); err != nil {
					t.Logf("cleanup of %s failed: %v", root, err)
				}
				_ = conn.Close(context.Background())
			})

			if err := conn.Ping(ctx); err != nil {
				t.Fatalf("Ping: %v", err)
			}
			t.Run("storage", func(t *testing.T) { liveStorage(t, ctx, conn) })
			t.Run("transfers", func(t *testing.T) { liveTransfers(t, ctx, conn) })
			t.Run("import", func(t *testing.T) { liveImport(t, ctx, conn) })
		})
	}
}

func liveStorage(t *testing.T, ctx context.Context, base *Connector) {
	st := *base
	st.rootDir = base.storePath("repo")
	if err := st.Create(ctx, []byte("live-config")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if cfg, err := st.Open(ctx); err != nil || string(cfg) != "live-config" {
		t.Fatalf("Open = %q, %v", cfg, err)
	}
	data := make([]byte, 3*cacheBlockSize+100)
	for i := range data {
		data[i] = byte(rand.Uint32())
	}
	for _, res := range allResources {
		mac := macOf(byte(res) * 17)
		if _, err := st.Put(ctx, res, mac, bytes.NewReader(data)); err != nil {
			t.Fatalf("%s Put: %v", res, err)
		}
		macs, err := st.List(ctx, res)
		if err != nil || len(macs) != 1 || macs[0] != mac {
			t.Fatalf("%s List = %v, %v", res, macs, err)
		}
		rd, err := st.Get(ctx, res, mac, &storage.Range{Offset: cacheBlockSize - 5, Length: 10})
		if err != nil {
			t.Fatalf("%s Get range: %v", res, err)
		}
		got, _ := io.ReadAll(rd)
		rd.Close()
		if !bytes.Equal(got, data[cacheBlockSize-5:cacheBlockSize+5]) {
			t.Fatalf("%s range mismatch", res)
		}
		if err := st.Delete(ctx, res, mac); err != nil {
			t.Fatalf("%s Delete: %v", res, err)
		}
	}
}

func liveTransfers(t *testing.T, ctx context.Context, conn *Connector) {
	c := conn.client
	big := make([]byte, maxBufferedUpload+3<<20)
	for i := range big {
		big[i] = byte(i % 251)
	}
	p := conn.rootDir + "/transfers/big.bin"
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := c.UploadStream(ctx, p, bytes.NewReader(big), int64(len(big)), UploadOptions{ModTime: mtime}); err != nil {
		t.Fatalf("streamed upload: %v", err)
	}
	st, err := c.Stat(ctx, p)
	if err != nil || st.Size != int64(len(big)) {
		t.Fatalf("Stat = %+v, %v", st, err)
	}
	if !st.ModTime().Equal(mtime) {
		t.Errorf("mtime = %v, want %v", st.ModTime(), mtime)
	}
	rd, err := c.OpenFile(ctx, p, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rd)
	rd.Close()
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("download mismatch (%d bytes, %v)", len(got), err)
	}
}

func liveImport(t *testing.T, ctx context.Context, conn *Connector) {
	src := conn.rootDir + "/import"
	files := map[string]string{"/a.txt": "a", "/sub/b.txt": "bb", "/sub/deeper/c.txt": "ccc"}
	for rel, content := range files {
		if _, err := conn.client.UploadBytes(ctx, src+rel, []byte(content), UploadOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	imp := *conn
	imp.rootDir = src
	records := make(chan *connectors.Record)
	got := map[string]string{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for rec := range records {
			if !rec.FileInfo.IsDir() {
				b, _ := io.ReadAll(rec.Reader)
				got[rec.Pathname[len(src):]] = string(b)
			}
			rec.Close()
		}
	}()
	if err := imp.Import(ctx, records, nil); err != nil {
		t.Fatal(err)
	}
	<-done
	for rel, want := range files {
		if got[rel] != want {
			t.Errorf("%s = %q, want %q", rel, got[rel], want)
		}
	}
}
