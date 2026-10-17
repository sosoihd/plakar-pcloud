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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/PlakarKorp/kloset/repository"
)

var allResources = []storage.StorageResource{
	storage.StorageResourcePackfile,
	storage.StorageResourceState,
	storage.StorageResourceLock,
	storage.StorageResourceECCPackfile,
	storage.StorageResourceECCState,
}

func macOf(seed byte) objects.MAC {
	var m objects.MAC
	for i := range m {
		m[i] = seed + byte(i)
	}
	return m
}

func getAll(t *testing.T, st *Connector, res storage.StorageResource, mac objects.MAC, rg *storage.Range) ([]byte, error) {
	t.Helper()
	rd, err := st.Get(t.Context(), res, mac, rg)
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

func TestStorageLifecycle(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/kloset-repo"})
	ctx := t.Context()
	cfg := []byte("kloset-repository-config-v1")

	if err := st.Create(ctx, cfg); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Create(ctx, cfg); err == nil {
		t.Fatal("second Create must fail")
	}
	opened, err := st.Open(ctx)
	if err != nil || !bytes.Equal(opened, cfg) {
		t.Fatalf("Open = %q, %v", opened, err)
	}

	mac := macOf(1)
	payload := []byte("0123456789abcdef-packfile-payload")
	n, err := st.Put(ctx, storage.StorageResourcePackfile, mac, bytes.NewReader(payload))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("Put = %d, %v", n, err)
	}

	macs, err := st.List(ctx, storage.StorageResourcePackfile)
	if err != nil || len(macs) != 1 || macs[0] != mac {
		t.Fatalf("List = %v, %v", macs, err)
	}

	if got, err := getAll(t, st, storage.StorageResourcePackfile, mac, nil); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if got, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: 4, Length: 6}); err != nil || string(got) != "456789" {
		t.Fatalf("Get range = %q, %v", got, err)
	}
	if got, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: 4, Length: 0}); err != nil || len(got) != 0 {
		t.Fatalf("Get zero-length range = %q, %v", got, err)
	}

	if err := st.Delete(ctx, storage.StorageResourcePackfile, mac); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := getAll(t, st, storage.StorageResourcePackfile, mac, nil); !errors.Is(err, repository.ErrPackfileNotFound) {
		t.Fatalf("Get deleted = %v, want ErrPackfileNotFound", err)
	}
	if _, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: 0, Length: 4}); !errors.Is(err, repository.ErrPackfileNotFound) {
		t.Fatalf("ranged Get deleted = %v, want ErrPackfileNotFound", err)
	}
	if err := st.Delete(ctx, storage.StorageResourcePackfile, mac); err != nil {
		t.Fatalf("Delete must be idempotent: %v", err)
	}
}

func TestStorageAllResources(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	ctx := t.Context()

	for i, res := range allResources {
		t.Run(res.String(), func(t *testing.T) {
			mac := macOf(byte(10 * (i + 1)))
			data := []byte("data for " + res.String())
			if _, err := st.Put(ctx, res, mac, bytes.NewReader(data)); err != nil {
				t.Fatalf("Put: %v", err)
			}
			macs, err := st.List(ctx, res)
			if err != nil || len(macs) != 1 || macs[0] != mac {
				t.Fatalf("List = %v, %v", macs, err)
			}
			got, err := getAll(t, st, res, mac, nil)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("Get = %q, %v", got, err)
			}
			got, err = getAll(t, st, res, mac, &storage.Range{Offset: 5, Length: 3})
			if err != nil || !bytes.Equal(got, data[5:8]) {
				t.Fatalf("Get range = %q, %v", got, err)
			}
			if err := st.Delete(ctx, res, mac); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if macs, _ := st.List(ctx, res); len(macs) != 0 {
				t.Fatalf("List after delete = %v", macs)
			}
		})
	}
}

func TestStorageUnsupportedResource(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, nil)
	ctx := t.Context()
	bad := storage.StorageResource(99)

	if _, err := st.List(ctx, bad); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("List: %v", err)
	}
	if _, err := st.Put(ctx, bad, macOf(1), bytes.NewReader(nil)); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Put: %v", err)
	}
	if _, err := st.Get(ctx, bad, macOf(1), nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Get: %v", err)
	}
	if err := st.Delete(ctx, bad, macOf(1)); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Delete: %v", err)
	}
}

func TestStorageLayoutIsStable(t *testing.T) {
	// Repositories created by earlier versions must stay readable.
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	mac := macOf(0xab)
	macHex := hex.EncodeToString(mac[:])

	want := map[storage.StorageResource]string{
		storage.StorageResourcePackfile:    "/repo/packfiles/ab/" + macHex,
		storage.StorageResourceState:       "/repo/states/ab/" + macHex,
		storage.StorageResourceLock:        "/repo/locks/" + macHex,
		storage.StorageResourceECCPackfile: "/repo/eccpackfiles/ab/" + macHex,
		storage.StorageResourceECCState:    "/repo/eccstates/ab/" + macHex,
	}
	for res, p := range want {
		if _, err := st.Put(t.Context(), res, mac, bytes.NewReader([]byte("x"))); err != nil {
			t.Fatal(err)
		}
		if _, ok := s.file(p); !ok {
			t.Errorf("%s not stored at %s", res, p)
		}
	}
}

func TestStorageListSkipsForeignFiles(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	good := macOf(3)
	goodHex := hex.EncodeToString(good[:])

	s.seedFile("/repo/packfiles/03/"+goodHex, []byte("ok"))
	s.seedFile("/repo/packfiles/03/"+goodHex+".partial", []byte("partial"))
	s.seedFile("/repo/packfiles/03/not-hex", []byte("junk"))
	s.seedFile("/repo/packfiles/03/abcd", []byte("short"))
	s.seedFile("/repo/packfiles/stray-at-top-level", []byte("junk"))
	s.seedFolder("/repo/packfiles/03/nested-folder")
	s.seedFile("/repo/locks/"+goodHex, []byte("lock"))
	folderMAC := macOf(4)
	s.seedFolder("/repo/locks/" + hex.EncodeToString(folderMAC[:]))

	macs, err := st.List(t.Context(), storage.StorageResourcePackfile)
	if err != nil || len(macs) != 1 || macs[0] != good {
		t.Fatalf("packfiles = %v, %v", macs, err)
	}
	macs, err = st.List(t.Context(), storage.StorageResourceLock)
	if err != nil || len(macs) != 1 || macs[0] != good {
		t.Fatalf("locks = %v, %v", macs, err)
	}
}

func TestStorageListMissingDirectory(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/nowhere"})
	for _, res := range allResources {
		macs, err := st.List(t.Context(), res)
		if err != nil || macs == nil || len(macs) != 0 {
			t.Errorf("%s: List = %v, %v; want empty non-nil slice", res, macs, err)
		}
	}
}

func TestStorageListPropagatesErrors(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, nil)
	s.fail("/listfolder", injectedFailure{result: 2003, msg: "Access denied."})
	if _, err := st.List(t.Context(), storage.StorageResourceLock); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("List err = %v", err)
	}
}

func TestStorageModeAndSize(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, nil)
	mode, err := st.Mode(t.Context())
	if err != nil || mode != storage.ModeRead|storage.ModeWrite {
		t.Errorf("Mode = %v, %v", mode, err)
	}
	size, err := st.Size(t.Context())
	if err != nil || size != -1 {
		t.Errorf("Size = %d, %v", size, err)
	}
}

func TestStorageOpenErrors(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	if _, err := st.Open(t.Context()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open without CONFIG = %v", err)
	}
	s.seedFile("/repo/CONFIG", make([]byte, maxConfigSize+1))
	if _, err := st.Open(t.Context()); err == nil {
		t.Fatal("oversized CONFIG must be rejected")
	}
}

func TestStorageCreatePropagatesStatErrors(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	s.fail("/stat", injectedFailure{result: 2003, msg: "Access denied."})
	if err := st.Create(t.Context(), []byte("c")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Create = %v", err)
	}
}

func TestStorageGetMissingState(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, nil)
	_, err := getAll(t, st, storage.StorageResourceState, macOf(1), nil)
	if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, repository.ErrPackfileNotFound) {
		t.Fatalf("missing state err = %v", err)
	}
}

func TestStorageRangedReadsUseBlockCache(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	ctx := t.Context()

	data := make([]byte, 3*cacheBlockSize+12345)
	for i := range data {
		data[i] = byte(i * 7)
	}
	mac := macOf(9)
	if _, err := st.Put(ctx, storage.StorageResourcePackfile, mac, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	read := func(off uint64, n uint32) []byte {
		t.Helper()
		got, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: off, Length: n})
		if err != nil {
			t.Fatalf("Get(%d,%d): %v", off, n, err)
		}
		return got
	}

	before := s.countRequests("/dl")
	if got := read(100, 50); !bytes.Equal(got, data[100:150]) {
		t.Fatal("first read mismatch")
	}
	if got := read(4000, 1000); !bytes.Equal(got, data[4000:5000]) {
		t.Fatal("second read mismatch")
	}
	if n := s.countRequests("/dl") - before; n != 1 {
		t.Errorf("two reads in the same block issued %d downloads, want 1", n)
	}

	// A read crossing into the next block only fetches the missing block.
	off := uint64(cacheBlockSize - 10)
	if got := read(off, 20); !bytes.Equal(got, data[off:off+20]) {
		t.Fatal("cross-block read mismatch")
	}
	if n := s.countRequests("/dl") - before; n != 2 {
		t.Errorf("downloads = %d, want 2", n)
	}

	// Tail of the object (short last block).
	tail := uint64(len(data) - 100)
	if got := read(tail, 500); !bytes.Equal(got, data[tail:]) {
		t.Fatal("tail read mismatch")
	}

	// Delete evicts the cached blocks.
	if err := st.Delete(ctx, storage.StorageResourcePackfile, mac); err != nil {
		t.Fatal(err)
	}
	if st.cache.size() != 0 {
		t.Errorf("cache still holds %d bytes after Delete", st.cache.size())
	}
	if _, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: 100, Length: 50}); !errors.Is(err, repository.ErrPackfileNotFound) {
		t.Fatalf("read after delete = %v", err)
	}
}

func TestStorageRangedReadsMatchContent(t *testing.T) {
	for _, cacheSize := range []string{"0", "3MiB", "256MiB"} {
		t.Run("cache_size="+cacheSize, func(t *testing.T) {
			s := newFakePCloud(t)
			st := newTestConnector(t, s, map[string]string{"root": "/repo", "cache_size": cacheSize})
			data := make([]byte, 5*cacheBlockSize+777)
			rng := rand.New(rand.NewPCG(1, 2))
			for i := range data {
				data[i] = byte(rng.Uint32())
			}
			mac := macOf(42)
			if _, err := st.Put(t.Context(), storage.StorageResourcePackfile, mac, bytes.NewReader(data)); err != nil {
				t.Fatal(err)
			}
			for range 60 {
				off := rng.IntN(len(data))
				n := rng.IntN(3*cacheBlockSize) + 1
				got, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: uint64(off), Length: uint32(n)})
				if err != nil {
					t.Fatal(err)
				}
				want := data[off:min(off+n, len(data))]
				if !bytes.Equal(got, want) {
					t.Fatalf("range (%d,%d): got %d bytes, want %d", off, n, len(got), len(want))
				}
			}
			if st.cache != nil && st.cache.size() > st.cache.budget {
				t.Errorf("cache uses %d bytes, over its %d budget", st.cache.size(), st.cache.budget)
			}
		})
	}
}

func TestStorageLargeRangeBypassesCache(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	data := bytes.Repeat([]byte{7}, maxCachedRead+cacheBlockSize)
	mac := macOf(5)
	if _, err := st.Put(t.Context(), storage.StorageResourcePackfile, mac, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	got, err := getAll(t, st, storage.StorageResourcePackfile, mac, &storage.Range{Offset: 1, Length: uint32(maxCachedRead + 1)})
	if err != nil || len(got) != maxCachedRead+1 {
		t.Fatalf("large range = %d bytes, %v", len(got), err)
	}
	if st.cache.size() != 0 {
		t.Errorf("large reads must not populate the cache")
	}
}

func TestStorageConcurrentAccess(t *testing.T) {
	s := newFakePCloud(t)
	st := newTestConnector(t, s, map[string]string{"root": "/repo"})
	ctx := t.Context()

	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mac := macOf(byte(i * 3))
			data := bytes.Repeat([]byte{byte(i)}, 2*cacheBlockSize+i)
			if _, err := st.Put(ctx, storage.StorageResourcePackfile, mac, bytes.NewReader(data)); err != nil {
				errs <- err
				return
			}
			for j := range 5 {
				off := uint64(j * 300000)
				rd, err := st.Get(ctx, storage.StorageResourcePackfile, mac, &storage.Range{Offset: off, Length: 1000})
				if err != nil {
					errs <- err
					return
				}
				got, _ := io.ReadAll(rd)
				rd.Close()
				if !bytes.Equal(got, data[off:off+1000]) {
					errs <- fmt.Errorf("worker %d: mismatch at %d", i, off)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	macs, err := st.List(ctx, storage.StorageResourcePackfile)
	if err != nil || len(macs) != workers {
		t.Fatalf("List = %d macs, %v", len(macs), err)
	}
}
