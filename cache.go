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
	"container/list"
	"context"
	"fmt"
	"io"
	"sync"

	"golang.org/x/sync/singleflight"
)

const (
	// cacheBlockSize is the granularity of ranged packfile reads. A small
	// read fetches the surrounding aligned block so that neighbouring reads
	// (index and B-tree nodes are packed together) are served from memory.
	cacheBlockSize = 1 << 20

	// Reads larger than this bypass the cache and are streamed directly.
	maxCachedRead = 8 << 20
)

type blockKey struct {
	object string
	index  int64
}

type cacheEntry struct {
	key  blockKey
	data []byte
}

// blockCache is a bounded, in-memory LRU of immutable object blocks. It never
// touches the disk: the whole point of this connector is to keep the
// repository off the local machine.
type blockCache struct {
	mu      sync.Mutex
	budget  int64
	used    int64
	lru     *list.List
	items   map[blockKey]*list.Element
	objects map[string]map[int64]struct{}
	flight  singleflight.Group
}

// newBlockCache returns nil (a disabled cache) when budget cannot hold a
// single block.
func newBlockCache(budget int64) *blockCache {
	if budget < cacheBlockSize {
		return nil
	}
	return &blockCache{
		budget:  budget,
		lru:     list.New(),
		items:   make(map[blockKey]*list.Element),
		objects: make(map[string]map[int64]struct{}),
	}
}

func (b *blockCache) get(k blockKey) ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	el, ok := b.items[k]
	if !ok {
		return nil, false
	}
	b.lru.MoveToFront(el)
	return el.Value.(*cacheEntry).data, true
}

func (b *blockCache) put(k blockKey, data []byte) {
	if int64(len(data)) > b.budget {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if el, ok := b.items[k]; ok {
		b.used -= int64(len(el.Value.(*cacheEntry).data))
		el.Value.(*cacheEntry).data = data
		b.used += int64(len(data))
		b.lru.MoveToFront(el)
	} else {
		b.items[k] = b.lru.PushFront(&cacheEntry{key: k, data: data})
		b.used += int64(len(data))
		if b.objects[k.object] == nil {
			b.objects[k.object] = make(map[int64]struct{})
		}
		b.objects[k.object][k.index] = struct{}{}
	}
	for b.used > b.budget {
		b.removeLocked(b.lru.Back())
	}
}

func (b *blockCache) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	e := el.Value.(*cacheEntry)
	b.lru.Remove(el)
	delete(b.items, e.key)
	b.used -= int64(len(e.data))
	if idx := b.objects[e.key.object]; idx != nil {
		delete(idx, e.key.index)
		if len(idx) == 0 {
			delete(b.objects, e.key.object)
		}
	}
}

func (b *blockCache) evictObject(object string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for idx := range b.objects[object] {
		b.removeLocked(b.items[blockKey{object, idx}])
	}
}

func (b *blockCache) purge() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lru.Init()
	b.items = make(map[blockKey]*list.Element)
	b.objects = make(map[string]map[int64]struct{})
	b.used = 0
}

func (b *blockCache) size() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// fetchFunc reads length bytes of object starting at offset. It may return
// fewer bytes when the object ends earlier.
type fetchFunc func(ctx context.Context, offset, length int64) ([]byte, error)

// readRange returns up to length bytes at offset, fetching missing aligned
// blocks with a single request.
func (b *blockCache) readRange(ctx context.Context, object string, offset, length int64, fetch fetchFunc) ([]byte, error) {
	first := offset / cacheBlockSize
	last := (offset + length - 1) / cacheBlockSize
	blocks := make([][]byte, last-first+1)

	missFirst, missLast := int64(-1), int64(-1)
	for i := first; i <= last; i++ {
		if data, ok := b.get(blockKey{object, i}); ok {
			blocks[i-first] = data
			continue
		}
		if missFirst < 0 {
			missFirst = i
		}
		missLast = i
	}

	if missFirst >= 0 {
		flightKey := fmt.Sprintf("%s\x00%d\x00%d", object, missFirst, missLast)
		v, err, _ := b.flight.Do(flightKey, func() (any, error) {
			return fetch(ctx, missFirst*cacheBlockSize, (missLast-missFirst+1)*cacheBlockSize)
		})
		if err != nil {
			return nil, err
		}
		data := v.([]byte)
		for i := missFirst; i <= missLast; i++ {
			start := (i - missFirst) * cacheBlockSize
			if start >= int64(len(data)) {
				break
			}
			end := min(start+cacheBlockSize, int64(len(data)))
			blk := bytes.Clone(data[start:end])
			b.put(blockKey{object, i}, blk)
			blocks[i-first] = blk
		}
	}

	out := make([]byte, 0, length)
	for i, blk := range blocks {
		idx := first + int64(i)
		if blk == nil {
			break
		}
		start := int64(0)
		if idx == first {
			start = offset - first*cacheBlockSize
		}
		if start >= int64(len(blk)) {
			break
		}
		end := int64(len(blk))
		if idx == last {
			end = min(end, offset+length-idx*cacheBlockSize)
		}
		out = append(out, blk[start:end]...)
		if int64(len(blk)) < cacheBlockSize {
			break
		}
	}
	return out, nil
}

func readAllFrom(rc io.ReadCloser, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}
