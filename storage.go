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
	return c.client.UploadFile(ctx, objPath, rd)
}

func (c *Connector) Get(ctx context.Context, res storage.StorageResource, mac objects.MAC, rg *storage.Range) (io.ReadCloser, error) {
	objPath, err := c.objectPath(res, mac)
	if err != nil {
		return nil, err
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
