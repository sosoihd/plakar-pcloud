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
	"fmt"
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

			if record.Err != nil || record.IsXattr {
				results <- record.Ok()
				continue
			}

			dest := path.Join(c.rootDir, record.Pathname)
			if !isContained(c.rootDir, dest) {
				results <- record.Error(fmt.Errorf("path %q escapes restore root", record.Pathname))
				continue
			}

			if record.FileInfo.IsDir() {
				err := c.client.MkdirAll(gctx, dest)
				results <- record.Error(err)
				continue
			}

			if !record.FileInfo.Mode().IsRegular() {
				results <- record.Ok()
				continue
			}

			rec := record
			targetPath := dest
			g.Go(func() error {
				_, err := c.client.UploadFile(gctx, targetPath, rec.Reader)
				results <- rec.Error(err)
				return nil
			})
		}
	}

	if err := g.Wait(); err != nil && ret == nil {
		ret = err
	}
	return ret
}
