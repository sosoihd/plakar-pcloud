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
	"net/url"
	"path"
	"strings"
	"testing"
)

func FuzzCleanRemotePath(f *testing.F) {
	for _, seed := range []string{"", "/", "a/b", "../../etc", "/a/./b/../c", "//x//", "\x00", "é/ü"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got := cleanRemotePath(p)
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("%q -> %q is not absolute", p, got)
		}
		if cleanRemotePath(got) != got {
			t.Fatalf("not idempotent: %q -> %q", p, got)
		}
		for _, seg := range strings.Split(got, "/") {
			if seg == ".." {
				t.Fatalf("%q -> %q still contains ..", p, got)
			}
		}
	})
}

func FuzzExportContainment(f *testing.F) {
	for _, seed := range [][2]string{{"/Restore", "/a"}, {"/Restore", "/../x"}, {"/", "/etc"}, {"/r", "/r/../../x"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, root, rel string) {
		root = cleanRemotePath(root)
		dest := path.Join(root, rel)
		if !isContained(root, dest) {
			return
		}
		cleanDest := path.Clean(dest)
		if root != "/" && cleanDest != root && !strings.HasPrefix(cleanDest, root+"/") {
			t.Fatalf("isContained(%q, %q) accepted an escape to %q", root, dest, cleanDest)
		}
	})
}

func FuzzParseMAC(f *testing.F) {
	f.Add(strings.Repeat("ab", 32))
	f.Add("not-a-mac")
	f.Add(strings.Repeat("ab", 32) + ".partial")
	f.Fuzz(func(t *testing.T, name string) {
		mac, ok := parseMAC(name)
		if !ok {
			return
		}
		if got := hex.EncodeToString(mac[:]); !strings.EqualFold(got, name) {
			t.Fatalf("parseMAC(%q) round-trips to %q", name, got)
		}
	})
}

func FuzzParseMetadata(f *testing.F) {
	for _, seed := range []string{`{"name":"a"}`, `[{"name":"b"}]`, `null`, `[]`, `{"contents":[{"contents":[]}]}`, `{"hash":18446744073709551615}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := baseResponse{Metadata: raw}
		m, err := r.parseMetadata()
		if err == nil && m != nil {
			_ = m.ModTime()
		}
	})
}

// FuzzLocationHost checks that no location can make the connector talk to a
// host other than the official pCloud APIs.
func FuzzLocationHost(f *testing.F) {
	for _, seed := range []string{"pcloud:///x", "pcloud://eu/x", "pcloud://evil.com/x", "pcloud://evil.com:443/x", "pcloud://[::1]/x", "pcloud://a@b/x", "pcloud://%65u/x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, loc string) {
		u, err := url.Parse(loc)
		if err != nil {
			return
		}
		host, root, err := resolveHostAndRoot(u, "", "", "")
		if err != nil {
			return
		}
		if host != DefaultHostUS && host != DefaultHostEU {
			t.Fatalf("location %q selected host %q", loc, host)
		}
		if !strings.HasPrefix(root, "/") {
			t.Fatalf("location %q produced relative root %q", loc, root)
		}
	})
}

func FuzzBlockCacheReadRange(f *testing.F) {
	f.Add(uint32(0), uint32(10), uint32(1000))
	f.Add(uint32(cacheBlockSize-1), uint32(2), uint32(2*cacheBlockSize))
	f.Add(uint32(5), uint32(cacheBlockSize*2), uint32(cacheBlockSize+7))
	f.Fuzz(func(t *testing.T, off, n, size uint32) {
		size %= 4 * cacheBlockSize
		n = n%(3*cacheBlockSize) + 1
		off %= size + 10
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*31 + i>>8)
		}
		fetch := func(_ context.Context, o, l int64) ([]byte, error) {
			if o >= int64(len(data)) {
				return nil, nil
			}
			return data[o:min(o+l, int64(len(data)))], nil
		}
		c := newBlockCache(2 * cacheBlockSize)
		for range 2 {
			got, err := c.readRange(context.Background(), "obj", int64(off), int64(n), fetch)
			if err != nil {
				t.Fatal(err)
			}
			var want []byte
			if int(off) < len(data) {
				want = data[off:min(int(off)+int(n), len(data))]
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("readRange(%d,%d) on %d bytes: got %d bytes, want %d", off, n, size, len(got), len(want))
			}
			if c.size() > c.budget {
				t.Fatalf("cache over budget: %d > %d", c.size(), c.budget)
			}
		}
	})
}
