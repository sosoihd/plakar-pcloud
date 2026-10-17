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
	"iter"
	"slices"
	"sync"

	"github.com/PlakarKorp/kloset/caching"
)

// memCache is a minimal in-memory caching.Cache for the end-to-end test. It
// avoids depending on the pebble backend, whose cockroachdb/swiss dependency
// does not build with every Go release.
type memCache struct {
	mu   sync.Mutex
	data map[string][]byte
}

func memCacheConstructor() caching.Constructor {
	return func(version, name, repoid string, opts caching.Option) (caching.Cache, error) {
		return &memCache{data: map[string][]byte{}}, nil
	}
}

func (c *memCache) Put(k, v []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[string(k)] = bytes.Clone(v)
	return nil
}

func (c *memCache) Has(k []byte) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.data[string(k)]
	return ok, nil
}

func (c *memCache) Get(k []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[string(k)]
	if !ok {
		return nil, nil
	}
	return bytes.Clone(v), nil
}

func (c *memCache) Delete(k []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, string(k))
	return nil
}

func (c *memCache) Scan(prefix []byte, reverse bool) iter.Seq2[[]byte, []byte] {
	return func(yield func([]byte, []byte) bool) {
		c.mu.Lock()
		var keys []string
		for k := range c.data {
			if bytes.HasPrefix([]byte(k), prefix) {
				keys = append(keys, k)
			}
		}
		c.mu.Unlock()
		slices.Sort(keys)
		if reverse {
			slices.Reverse(keys)
		}
		for _, k := range keys {
			v, err := c.Get([]byte(k))
			if err != nil || v == nil {
				continue
			}
			if !yield([]byte(k), v) {
				return
			}
		}
	}
}

func (c *memCache) NewBatch() caching.Batch { return &memBatch{c: c} }

func (c *memCache) Close() error { return nil }

type memBatch struct {
	c    *memCache
	kv   [][2][]byte
	size uint32
}

func (b *memBatch) Put(k, v []byte) error {
	b.kv = append(b.kv, [2][]byte{bytes.Clone(k), bytes.Clone(v)})
	b.size++
	return nil
}

func (b *memBatch) Count() uint32 { return b.size }

func (b *memBatch) Commit() error {
	for _, kv := range b.kv {
		_ = b.c.Put(kv[0], kv[1])
	}
	b.kv, b.size = nil, 0
	return nil
}
