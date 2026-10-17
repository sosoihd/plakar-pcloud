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
		// rootDir may point to a single file rather than a folder.
		st, statErr := c.client.Stat(ctx, c.rootDir)
		if statErr != nil || st == nil || st.IsFolder {
			return err
		}
		c.emit(ctx, c.rootDir, *st, records)
		return ctx.Err()
	}

	c.walkTree(ctx, c.rootDir, *rootMeta, records)
	return ctx.Err()
}

func (c *Connector) walkTree(ctx context.Context, currentPath string, meta Metadata, records chan<- *connectors.Record) bool {
	currentPath = cleanRemotePath(currentPath)
	if currentPath != "/" && c.excludes != nil && c.excludes.IsExcluded(currentPath, meta.IsFolder) {
		return true
	}

	if !c.emit(ctx, currentPath, meta, records) {
		return false
	}
	if !meta.IsFolder {
		return true
	}

	for _, child := range meta.Contents {
		if !c.walkTree(ctx, path.Join(currentPath, child.Name), child, records) {
			return false
		}
	}
	return true
}

// emit sends one record, giving up when ctx is cancelled so that Import never
// blocks on a consumer that has stopped reading.
func (c *Connector) emit(ctx context.Context, entryPath string, meta Metadata, records chan<- *connectors.Record) bool {
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
		Lnlink:   1,
	}
	if meta.IsFolder {
		fi.Lsize = 0
	}

	var rec *connectors.Record
	if meta.IsFolder {
		rec = connectors.NewRecord(entryPath, "", fi, nil, nil)
	} else {
		filePath := entryPath
		rec = connectors.NewRecord(filePath, "", fi, nil, func() (io.ReadCloser, error) {
			return c.client.OpenFile(ctx, filePath, 0, -1)
		})
	}

	select {
	case records <- rec:
		return true
	case <-ctx.Done():
		return false
	}
}
