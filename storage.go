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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/objects"
	"github.com/PlakarKorp/kloset/repository"
)

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
	macHex := fmt.Sprintf("%064x", mac)
	if bucketed {
		return c.storePath(prefix, fmt.Sprintf("%02x", mac[0]), macHex), nil
	}
	return c.storePath(prefix, macHex), nil
}

func (c *Connector) localCachePath(res storage.StorageResource, mac objects.MAC) (string, bool) {
	switch res {
	case storage.StorageResourcePackfile, storage.StorageResourceState,
		storage.StorageResourceECCPackfile, storage.StorageResourceECCState:
	default:
		return "", false
	}

	prefix, _, err := resToPrefix(res)
	if err != nil {
		return "", false
	}

	baseDir, err := os.UserCacheDir()
	if err != nil || baseDir == "" {
		baseDir = os.TempDir()
	}
	storeHash := sha256.Sum256([]byte(c.host + ":" + c.rootDir))
	storeID := hex.EncodeToString(storeHash[:8])
	macHex := fmt.Sprintf("%064x", mac)

	return filepath.Join(baseDir, "plakar-pcloud", storeID, prefix, fmt.Sprintf("%02x", mac[0]), macHex), true
}

func writeCacheFileAtomic(cachePath string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(cachePath), ".tmp-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, cachePath)
}

func openCachedFileRange(cachePath string, rg *storage.Range) (io.ReadCloser, error) {
	f, err := os.Open(cachePath)
	if err != nil {
		return nil, err
	}
	if rg == nil {
		return f, nil
	}
	if rg.Length == 0 {
		_ = f.Close()
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	if _, err := f.Seek(int64(rg.Offset), io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &limitedReadCloser{
		Reader: io.LimitReader(f, int64(rg.Length)),
		Closer: f,
	}, nil
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

	if _, err := c.client.UploadFile(ctx, cfgPath, bytes.NewReader(config)); err != nil {
		return fmt.Errorf("pcloud write CONFIG: %w", err)
	}
	return nil
}

func (c *Connector) Open(ctx context.Context) ([]byte, error) {
	rd, err := c.client.OpenFile(ctx, c.storePath("CONFIG"), nil)
	if err != nil {
		return nil, fmt.Errorf("pcloud open CONFIG: %w", err)
	}
	defer rd.Close()

	data, err := io.ReadAll(rd)
	if err != nil {
		return nil, fmt.Errorf("pcloud read CONFIG: %w", err)
	}
	return data, nil
}

func (c *Connector) List(ctx context.Context, res storage.StorageResource) ([]objects.MAC, error) {
	prefix, bucketed, err := resToPrefix(res)
	if err != nil {
		return nil, err
	}

	dirPath := c.storePath(prefix)
	meta, err := c.client.ListFolder(ctx, dirPath, bucketed)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []objects.MAC{}, nil
		}
		return nil, err
	}

	var macs []objects.MAC
	if bucketed {
		for _, sub := range meta.Contents {
			if !sub.IsFolder {
				continue
			}
			for _, item := range sub.Contents {
				if item.IsFolder {
					continue
				}
				if m, ok := parseMAC(item.Name); ok {
					macs = append(macs, m)
				}
			}
		}
	} else {
		for _, item := range meta.Contents {
			if item.IsFolder {
				continue
			}
			if m, ok := parseMAC(item.Name); ok {
				macs = append(macs, m)
			}
		}
	}

	return macs, nil
}

func parseMAC(name string) (objects.MAC, bool) {
	raw, err := hex.DecodeString(name)
	if err != nil || len(raw) != 32 {
		return objects.MAC{}, false
	}
	var m objects.MAC
	copy(m[:], raw)
	return m, true
}

func (c *Connector) Put(ctx context.Context, res storage.StorageResource, mac objects.MAC, rd io.Reader) (int64, error) {
	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return -1, err
	}

	data, err := io.ReadAll(rd)
	if err != nil {
		return -1, err
	}

	n, err := c.client.UploadFile(ctx, objPath, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}

	if cachePath, ok := c.localCachePath(res, mac); ok {
		writeCacheFileAtomic(cachePath, data)
	}

	return n, nil
}

func (c *Connector) Get(ctx context.Context, res storage.StorageResource, mac objects.MAC, rg *storage.Range) (io.ReadCloser, error) {
	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return nil, err
	}

	if cachePath, ok := c.localCachePath(res, mac); ok {
		if rd, err := openCachedFileRange(cachePath, rg); err == nil {
			return rd, nil
		}

		// Download immutable packfile/state once and cache on disk so all subsequent
		// B-tree range reads (e.g. during `plakar ui` or `plakar ls`) are instantaneous.
		_, err, _ := c.sf.Do(cachePath, func() (any, error) {
			if _, statErr := os.Stat(cachePath); statErr == nil {
				return nil, nil
			}
			remoteRd, dlErr := c.client.OpenFile(ctx, objPath, nil)
			if dlErr != nil {
				return nil, dlErr
			}
			defer remoteRd.Close()
			data, readErr := io.ReadAll(remoteRd)
			if readErr != nil {
				return nil, readErr
			}
			writeCacheFileAtomic(cachePath, data)
			return nil, nil
		})
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && res == storage.StorageResourcePackfile {
				return nil, repository.ErrPackfileNotFound
			}
			return nil, err
		}

		if rd, err := openCachedFileRange(cachePath, rg); err == nil {
			return rd, nil
		}
	}

	rd, err := c.client.OpenFile(ctx, objPath, rg)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && res == storage.StorageResourcePackfile {
			return nil, repository.ErrPackfileNotFound
		}
		return nil, err
	}
	return rd, nil
}

func (c *Connector) Delete(ctx context.Context, res storage.StorageResource, mac objects.MAC) error {
	if cachePath, ok := c.localCachePath(res, mac); ok {
		_ = os.Remove(cachePath)
	}

	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return err
	}
	err = c.client.DeleteFile(ctx, objPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
