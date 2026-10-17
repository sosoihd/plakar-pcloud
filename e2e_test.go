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
	"io"
	"math/rand/v2"
	"path"
	"testing"

	"github.com/PlakarKorp/kloset/caching"
	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/encryption"
	"github.com/PlakarKorp/kloset/hashing"
	"github.com/PlakarKorp/kloset/kcontext"
	"github.com/PlakarKorp/kloset/logging"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/PlakarKorp/kloset/repository"
	"github.com/PlakarKorp/kloset/resources"
	"github.com/PlakarKorp/kloset/snapshot"
	"github.com/PlakarKorp/kloset/versioning"
)

func newKContext(t *testing.T) *kcontext.KContext {
	t.Helper()
	ctx := kcontext.NewKContext()
	ctx.Client = "plakar-pcloud-test/1.0.0"
	ctx.MaxConcurrency = 2
	ctx.SetCache(caching.NewManager(memCacheConstructor()))
	ctx.CacheDir = t.TempDir()
	ctx.SetLogger(logging.NewLogger(io.Discard, io.Discard))
	t.Cleanup(ctx.Close)
	return ctx
}

// createRepository initializes an encrypted Kloset repository on store and
// returns the derived key.
func createRepository(t *testing.T, kctx *kcontext.KContext, store storage.Store, passphrase []byte) []byte {
	t.Helper()
	config := storage.NewConfiguration()
	key, err := encryption.DeriveKey(config.Encryption.KDFParams, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	canary, err := encryption.DeriveCanary(config.Encryption, key)
	if err != nil {
		t.Fatal(err)
	}
	config.Encryption.Canary = canary
	// Small packfiles force several of them, exercising List and ranged Get.
	config.Packfile.MaxSize = 256 << 10

	serialized, err := config.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	hasher := hashing.GetMACHasher(storage.DEFAULT_HASHING_ALGORITHM, key)
	wrapped, err := storage.Serialize(hasher, resources.RT_CONFIG, versioning.GetCurrentVersion(resources.RT_CONFIG), bytes.NewReader(serialized))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(kctx, data); err != nil {
		t.Fatalf("store Create: %v", err)
	}
	return key
}

func openRepository(t *testing.T, kctx *kcontext.KContext, store storage.Store, key []byte) *repository.Repository {
	t.Helper()
	serialized, err := store.Open(kctx)
	if err != nil {
		t.Fatalf("store Open: %v", err)
	}
	repo, err := repository.NewRepository(kctx, key, store, serialized, &repository.RepositoryOpts{DoRebuild: true, RWStateCache: true})
	if err != nil {
		t.Fatalf("repository.NewRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

// TestEndToEnd backs up a pCloud folder (importer) into a Kloset repository
// hosted on pCloud (storage), reopens it from scratch and restores the
// snapshot to another pCloud folder (exporter).
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	s := newFakePCloud(t)

	rng := rand.New(rand.NewPCG(7, 7))
	source := map[string][]byte{
		"/Source/readme.md":         []byte("# hello pCloud\n"),
		"/Source/empty":             {},
		"/Source/docs/report.txt":   bytes.Repeat([]byte("report line\n"), 5000),
		"/Source/docs/deep/a/b.txt": []byte("deep"),
	}
	random := make([]byte, 3<<20)
	for i := range random {
		random[i] = byte(rng.Uint32())
	}
	source["/Source/media/random.bin"] = random
	for p, data := range source {
		s.seedFile(p, data)
	}
	s.seedFolder("/Source/emptydir")

	passphrase := []byte("correct horse battery staple")

	// 1. Back up /Source into a repository stored in /Repo.
	kctx := newKContext(t)
	store := newTestConnector(t, s, map[string]string{"root": "/Repo", "cache_size": "4MiB"})
	key := createRepository(t, kctx, store, passphrase)
	repo := openRepository(t, kctx, store, key)

	imp := newTestConnector(t, s, map[string]string{"root": "/Source"})
	builder, err := snapshot.Create(repo, repository.DefaultType, t.TempDir(), objects.NilMac, &snapshot.BuilderOptions{Name: "e2e"})
	if err != nil {
		t.Fatalf("snapshot.Create: %v", err)
	}
	src, err := snapshot.NewSource(repo.AppContext(), imp)
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Backup(src); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if err := builder.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	snapID := builder.Header.Identifier
	if err := builder.Close(); err != nil {
		t.Fatal(err)
	}

	if macs, err := store.List(kctx, storage.StorageResourcePackfile); err != nil || len(macs) < 2 {
		t.Fatalf("expected several packfiles on pCloud, got %d (%v)", len(macs), err)
	}

	// 2. Reopen the repository with a fresh connector and context, as a
	//    later `plakar` invocation would.
	kctx2 := newKContext(t)
	store2 := newTestConnector(t, s, map[string]string{"root": "/Repo", "cache_size": "4MiB"})
	repo2 := openRepository(t, kctx2, store2, key)

	found := false
	for mac, err := range repo2.ListSnapshots() {
		if err != nil {
			t.Fatal(err)
		}
		found = found || mac == snapID
	}
	if !found {
		t.Fatal("snapshot not listed after reopening the repository")
	}

	snap, err := snapshot.Load(repo2, snapID)
	if err != nil {
		t.Fatalf("snapshot.Load: %v", err)
	}
	defer snap.Close()

	// 3. Restore into /Restored.
	exp := newTestConnector(t, s, map[string]string{"root": "/Restored"})
	if err := snap.Export(exp, "/Source", &snapshot.ExportOptions{}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	for p, want := range source {
		restored := path.Join("/Restored", p[len("/Source"):])
		e, ok := s.file(restored)
		if !ok {
			t.Errorf("%s missing after restore", restored)
			continue
		}
		if !bytes.Equal(e.data, want) {
			t.Errorf("%s: restored %d bytes differ from the %d source bytes", restored, len(e.data), len(want))
		}
	}
	if st, err := exp.client.Stat(t.Context(), "/Restored/emptydir"); err != nil || !st.IsFolder {
		t.Errorf("empty directory not restored: %v", err)
	}
}
