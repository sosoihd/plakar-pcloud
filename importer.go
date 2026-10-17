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
	"context"
	"io"
	"io/fs"
	"path"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/objects"
)

func (c *Connector) Import(ctx context.Context, records chan<- *connectors.Record, results <-chan *connectors.Result) error {
	defer close(records)

	rootMeta, err := c.client.ListFolder(ctx, c.rootDir, true)
	if err != nil {
		// Check if rootDir points to a single file rather than a folder.
		st, statErr := c.client.Stat(ctx, c.rootDir)
		if statErr != nil || st == nil {
			return err
		}
		if !st.IsFolder {
			c.emitMetadata(ctx, c.rootDir, *st, records)
			return nil
		}
		return err
	}

	c.walkTree(ctx, c.rootDir, *rootMeta, records)
	return ctx.Err()
}

func (c *Connector) walkTree(ctx context.Context, currentPath string, meta Metadata, records chan<- *connectors.Record) {
	if ctx.Err() != nil {
		return
	}

	currentPath = cleanRemotePath(currentPath)
	if currentPath != "/" && c.excludes != nil && c.excludes.IsExcluded(currentPath, meta.IsFolder) {
		return
	}

	c.emitMetadata(ctx, currentPath, meta, records)

	if !meta.IsFolder {
		return
	}

	for _, child := range meta.Contents {
		if ctx.Err() != nil {
			return
		}
		childPath := path.Join(currentPath, child.Name)
		c.walkTree(ctx, childPath, child, records)
	}
}

func (c *Connector) emitMetadata(ctx context.Context, entryPath string, meta Metadata, records chan<- *connectors.Record) {
	name := meta.Name
	if entryPath == "/" || name == "" {
		name = path.Base(entryPath)
	}

	mode := fs.FileMode(0644)
	if meta.IsFolder {
		mode = fs.ModeDir | 0755
	}

	fi := objects.FileInfo{
		Lname:    name,
		Lsize:    meta.Size,
		Lmode:    mode,
		LmodTime: meta.ModTime(),
	}

	if meta.IsFolder {
		records <- connectors.NewRecord(entryPath, "", fi, nil, nil)
		return
	}

	filePath := entryPath
	records <- connectors.NewRecord(filePath, "", fi, nil, func() (io.ReadCloser, error) {
		return c.client.OpenFile(ctx, filePath, nil)
	})
}
