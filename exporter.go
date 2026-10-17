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
	"errors"
	"fmt"
	"io/fs"
	"path"

	"github.com/PlakarKorp/kloset/connectors"
	"golang.org/x/sync/errgroup"
)

func (c *Connector) Export(ctx context.Context, records <-chan *connectors.Record, results chan<- *connectors.Result) (ret error) {
	defer close(results)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(c.maxConcurrency)

loop:
	for {
		select {
		case <-gctx.Done():
			ret = gctx.Err()
			break loop

		case record, ok := <-records:
			if !ok {
				break loop
			}
			c.exportRecord(gctx, g, record, results)
		}
	}

	if err := g.Wait(); err != nil && ret == nil {
		ret = err
	}
	if ret != nil {
		// Keep consuming so the producer never blocks on a dead exporter.
		for record := range records {
			results <- record.Error(ret)
		}
	}
	return ret
}

func (c *Connector) exportRecord(ctx context.Context, g *errgroup.Group, record *connectors.Record, results chan<- *connectors.Result) {
	if record.Err != nil || record.IsXattr {
		results <- record.Ok()
		return
	}

	dest := path.Join(c.rootDir, record.Pathname)
	if !isContained(c.rootDir, dest) {
		results <- record.Error(fmt.Errorf("path %q escapes restore root", record.Pathname))
		return
	}

	mode := record.FileInfo.Mode()
	switch {
	case mode.IsDir():
		results <- record.Error(c.client.MkdirAll(ctx, dest))

	case mode.IsRegular():
		size := record.FileInfo.Size()
		opts := UploadOptions{ModTime: record.FileInfo.ModTime()}
		g.Go(func() error {
			_, err := c.client.UploadStream(ctx, dest, record.Reader, size, opts)
			results <- record.Error(err)
			return nil
		})

	default:
		results <- record.Error(fmt.Errorf("%w: pCloud cannot store %s", errors.ErrUnsupported, describeMode(mode)))
	}
}

func describeMode(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSymlink != 0:
		return "symbolic links"
	case mode&fs.ModeNamedPipe != 0:
		return "named pipes"
	case mode&fs.ModeSocket != 0:
		return "sockets"
	case mode&fs.ModeDevice != 0:
		return "device files"
	default:
		return "special files"
	}
}
