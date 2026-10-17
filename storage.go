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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/PlakarKorp/kloset/repository"
)

// maxConfigSize bounds the CONFIG file read by Open.
const maxConfigSize = 1 << 20

func (c *Connector) storePath(parts ...string) string {
	all := append([]string{c.rootDir}, parts...)
	return cleanRemotePath(path.Join(all...))
}

func resToPrefix(res storage.StorageResource) (string, bool, error) {
	switch res {
	case storage.StorageResourcePackfile:
		return "packfiles", true, nil
	case storage.StorageResourceState:
		return "states", true, nil
	case storage.StorageResourceLock:
		return "locks", false, nil
	case storage.StorageResourceECCPackfile:
		return "eccpackfiles", true, nil
	case storage.StorageResourceECCState:
		return "eccstates", true, nil
	default:
		return "", false, errors.ErrUnsupported
	}
}

func (c *Connector) objectPath(res storage.StorageResource, mac objects.MAC) (string, error) {
	prefix, bucketed, err := resToPrefix(res)
	if err != nil {
		return "", err
	}
	macHex := hex.EncodeToString(mac[:])
	if bucketed {
		return c.storePath(prefix, macHex[:2], macHex), nil
	}
	return c.storePath(prefix, macHex), nil
}

// isCacheable reports whether ranged reads of res may be served from the
// in-memory block cache. Only immutable, randomly accessed objects qualify.
func isCacheable(res storage.StorageResource) bool {
	return res == storage.StorageResourcePackfile || res == storage.StorageResourceECCPackfile
}

func (c *Connector) Mode(ctx context.Context) (storage.Mode, error) {
	return storage.ModeRead | storage.ModeWrite, nil
}

func (c *Connector) Size(ctx context.Context) (int64, error) {
	return -1, nil
}

func (c *Connector) Create(ctx context.Context, config []byte) error {
	cfgPath := c.storePath("CONFIG")
	if st, err := c.client.Stat(ctx, cfgPath); err == nil && st != nil && !st.IsFolder {
		return fmt.Errorf("pcloud repository at %s already initialized", c.rootDir)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("pcloud stat CONFIG: %w", err)
	}

	for _, dir := range []string{"packfiles", "states", "locks"} {
		if err := c.client.MkdirAll(ctx, c.storePath(dir)); err != nil {
			return fmt.Errorf("pcloud create %s directory: %w", dir, err)
		}
	}

	if _, err := c.client.UploadBytes(ctx, cfgPath, config, UploadOptions{}); err != nil {
		return fmt.Errorf("pcloud write CONFIG: %w", err)
	}
	return nil
}

func (c *Connector) Open(ctx context.Context) ([]byte, error) {
	rd, err := c.client.OpenFile(ctx, c.storePath("CONFIG"), 0, -1)
	if err != nil {
		return nil, fmt.Errorf("pcloud open CONFIG: %w", err)
	}
	defer rd.Close()

	data, err := io.ReadAll(io.LimitReader(rd, maxConfigSize+1))
	if err != nil {
		return nil, fmt.Errorf("pcloud read CONFIG: %w", err)
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("pcloud CONFIG exceeds %d bytes", maxConfigSize)
	}
	return data, nil
}

func (c *Connector) List(ctx context.Context, res storage.StorageResource) ([]objects.MAC, error) {
	prefix, bucketed, err := resToPrefix(res)
	if err != nil {
		return nil, err
	}

	meta, err := c.client.ListFolder(ctx, c.storePath(prefix), bucketed)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []objects.MAC{}, nil
		}
		return nil, err
	}

	macs := []objects.MAC{}
	collect := func(items []Metadata) {
		for _, item := range items {
			if item.IsFolder {
				continue
			}
			// Skip anything that is not a MAC (partial uploads, stray files).
			if m, ok := parseMAC(item.Name); ok {
				macs = append(macs, m)
			}
		}
	}
	if bucketed {
		for _, sub := range meta.Contents {
			if sub.IsFolder {
				collect(sub.Contents)
			}
		}
	} else {
		collect(meta.Contents)
	}
	return macs, nil
}

func parseMAC(name string) (objects.MAC, bool) {
	if len(name) != 64 {
		return objects.MAC{}, false
	}
	raw, err := hex.DecodeString(name)
	if err != nil || len(raw) != 32 {
		return objects.MAC{}, false
	}
	var m objects.MAC
	copy(m[:], raw)
	return m, true
}

// Put stores an object. Objects are bounded by the repository packfile size,
// so they are held in memory to allow verified, retried uploads. Nothing is
// ever written to the local disk.
func (c *Connector) Put(ctx context.Context, res storage.StorageResource, mac objects.MAC, rd io.Reader) (int64, error) {
	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return -1, err
	}

	data, err := io.ReadAll(rd)
	if err != nil {
		return -1, err
	}

	if _, err := c.client.UploadBytes(ctx, objPath, data, UploadOptions{}); err != nil {
		return 0, err
	}
	return int64(len(data)), nil
}

func (c *Connector) Get(ctx context.Context, res storage.StorageResource, mac objects.MAC, rg *storage.Range) (io.ReadCloser, error) {
	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return nil, err
	}

	notFound := func(err error) error {
		if errors.Is(err, fs.ErrNotExist) && res == storage.StorageResourcePackfile {
			return repository.ErrPackfileNotFound
		}
		return err
	}

	if rg == nil {
		rd, err := c.client.OpenFile(ctx, objPath, 0, -1)
		if err != nil {
			return nil, notFound(err)
		}
		return rd, nil
	}
	if rg.Length == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	offset, length := int64(rg.Offset), int64(rg.Length)
	if c.cache != nil && isCacheable(res) && length <= maxCachedRead {
		data, err := c.cache.readRange(ctx, objPath, offset, length, func(ctx context.Context, off, n int64) ([]byte, error) {
			return readAllFrom(c.client.OpenFile(ctx, objPath, off, n))
		})
		if err != nil {
			return nil, notFound(err)
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	rd, err := c.client.OpenFile(ctx, objPath, offset, length)
	if err != nil {
		return nil, notFound(err)
	}
	return rd, nil
}

func (c *Connector) Delete(ctx context.Context, res storage.StorageResource, mac objects.MAC) error {
	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return err
	}
	c.cache.evictObject(objPath)

	err = c.client.DeleteFile(ctx, objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
