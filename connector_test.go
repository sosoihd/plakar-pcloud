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
	"strings"
	"testing"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/connectors/exporter"
	"github.com/PlakarKorp/kloset/connectors/importer"
	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/location"
)

// Compile-time interface checks.
var (
	_ importer.Importer = (*Connector)(nil)
	_ exporter.Exporter = (*Connector)(nil)
	_ storage.Store     = (*Connector)(nil)
)

func TestConfigParsing(t *testing.T) {
	tok := map[string]string{"access_token": "tok"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range tok {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	tests := []struct {
		name       string
		config     map[string]string
		wantOrigin string
		wantRoot   string
		wantErr    string
	}{
		{name: "default US with path", config: with("location", "pcloud:///Documents/Notes"), wantOrigin: DefaultHostUS, wantRoot: "/Documents/Notes"},
		{name: "empty path is root", config: with("location", "pcloud://"), wantOrigin: DefaultHostUS, wantRoot: "/"},
		{name: "eu shorthand", config: with("location", "pcloud://eu/MyBackups"), wantOrigin: DefaultHostEU, wantRoot: "/MyBackups"},
		{name: "us shorthand", config: with("location", "pcloud://us/x"), wantOrigin: DefaultHostUS, wantRoot: "/x"},
		{name: "EU uppercase", config: with("location", "pcloud://EU/x"), wantOrigin: DefaultHostEU, wantRoot: "/x"},
		{name: "official EU host", config: with("location", "pcloud://eapi.pcloud.com/Photos"), wantOrigin: DefaultHostEU, wantRoot: "/Photos"},
		{name: "official US host", config: with("location", "pcloud://api.pcloud.com/Photos"), wantOrigin: DefaultHostUS, wantRoot: "/Photos"},
		{name: "region parameter", config: with("location", "pcloud:///Photos", "region", "eu"), wantOrigin: DefaultHostEU, wantRoot: "/Photos"},
		{name: "region parameter is case-insensitive", config: with("location", "pcloud:///P", "region", " EU "), wantOrigin: DefaultHostEU, wantRoot: "/P"},
		{name: "first segment as folder", config: with("location", "pcloud://Documents/Sub"), wantOrigin: DefaultHostUS, wantRoot: "/Documents/Sub"},
		{name: "dotted folder is not a host", config: with("location", "pcloud://my.photos/2024"), wantOrigin: DefaultHostUS, wantRoot: "/my.photos/2024"},
		{name: "host:port is not a host", config: with("location", "pcloud://evil.example.com:443/x"), wantOrigin: DefaultHostUS, wantRoot: "/evil.example.com:443/x"},
		{name: "localhost is a folder", config: with("location", "pcloud://localhost/x"), wantOrigin: DefaultHostUS, wantRoot: "/localhost/x"},
		{name: "explicit root overrides path", config: with("location", "pcloud:///ignored", "root", "/Real"), wantOrigin: DefaultHostUS, wantRoot: "/Real"},
		{name: "relative root is cleaned", config: with("location", "pcloud://", "root", "a/../b"), wantOrigin: DefaultHostUS, wantRoot: "/b"},
		{name: "traversal in path is cleaned", config: with("location", "pcloud:///a/../../etc"), wantOrigin: DefaultHostUS, wantRoot: "/etc"},
		{name: "custom endpoint", config: with("location", "pcloud:///x", "endpoint", "127.0.0.1:8080"), wantOrigin: "127.0.0.1:8080", wantRoot: "/x"},
		{name: "custom endpoint with scheme", config: with("location", "pcloud:///x", "endpoint", "https://mock.example/"), wantOrigin: "mock.example", wantRoot: "/x"},
		{name: "custom endpoint localhost:port", config: with("location", "pcloud:///x", "endpoint", "localhost:9000"), wantOrigin: "localhost:9000", wantRoot: "/x"},
		{name: "insecure with endpoint", config: with("location", "pcloud:///x", "endpoint", "127.0.0.1:1", "insecure", "true"), wantOrigin: "127.0.0.1:1", wantRoot: "/x"},
		{name: "session token", config: map[string]string{"location": "pcloud:///", "auth": "sess"}, wantOrigin: DefaultHostUS, wantRoot: "/"},
		{name: "username and password", config: map[string]string{"location": "pcloud:///", "username": "u", "password": "p"}, wantOrigin: DefaultHostUS, wantRoot: "/"},
		{name: "cache size", config: with("location", "pcloud:///", "cache_size", "64MiB"), wantOrigin: DefaultHostUS, wantRoot: "/"},
		{name: "cache disabled", config: with("location", "pcloud:///", "cache_size", "0"), wantOrigin: DefaultHostUS, wantRoot: "/"},

		{name: "missing location", config: tok, wantErr: "missing location"},
		{name: "blank location", config: with("location", "  "), wantErr: "missing location"},
		{name: "wrong scheme", config: with("location", "s3://bucket/x"), wantErr: "scheme"},
		{name: "missing credentials", config: map[string]string{"location": "pcloud:///"}, wantErr: "missing credentials"},
		{name: "username without password", config: map[string]string{"location": "pcloud:///", "username": "u"}, wantErr: "missing credentials"},
		{name: "credentials in location", config: with("location", "pcloud://user:pass@eu/x"), wantErr: "must not be embedded"},
		{name: "username in location", config: with("location", "pcloud://user@eu/x"), wantErr: "must not be embedded"},
		{name: "invalid region", config: with("location", "pcloud:///", "region", "asia"), wantErr: "invalid region"},
		{name: "invalid insecure", config: with("location", "pcloud:///", "insecure", "maybe"), wantErr: "invalid insecure"},
		{name: "invalid debug", config: with("location", "pcloud:///", "debug", "maybe"), wantErr: "invalid debug"},
		{name: "insecure without endpoint", config: with("location", "pcloud:///", "insecure", "true"), wantErr: "only allowed together with a custom endpoint"},
		{name: "endpoint with path", config: with("location", "pcloud:///", "endpoint", "https://h.example/api"), wantErr: "invalid endpoint"},
		{name: "endpoint with userinfo", config: with("location", "pcloud:///", "endpoint", "https://u:p@h.example"), wantErr: "invalid endpoint"},
		{name: "invalid cache size", config: with("location", "pcloud:///", "cache_size", "lots"), wantErr: "invalid cache_size"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := New(t.Context(), nil, "pcloud", tc.config, nil)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (origin=%s root=%s)", tc.wantErr, conn.Origin(), conn.Root())
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if conn.Type() != "pcloud" {
				t.Errorf("Type() = %q", conn.Type())
			}
			if conn.Origin() != tc.wantOrigin {
				t.Errorf("Origin() = %q, want %q", conn.Origin(), tc.wantOrigin)
			}
			if conn.Root() != tc.wantRoot {
				t.Errorf("Root() = %q, want %q", conn.Root(), tc.wantRoot)
			}
			if conn.Flags() != location.Flags(0) {
				t.Errorf("Flags() = %v, want 0", conn.Flags())
			}
		})
	}
}

func TestSchemeFollowsInsecureFlag(t *testing.T) {
	conn, err := New(t.Context(), nil, "pcloud", map[string]string{"location": "pcloud://eu/", "access_token": "t"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn.client.scheme != "https" {
		t.Errorf("official hosts must use https, got %s", conn.client.scheme)
	}
	conn, err = New(t.Context(), nil, "pcloud", map[string]string{"location": "pcloud:///", "access_token": "t", "endpoint": "127.0.0.1:1", "insecure": "1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn.client.scheme != "http" {
		t.Errorf("insecure endpoint should use http, got %s", conn.client.scheme)
	}
}

func TestCacheSizeConfiguration(t *testing.T) {
	cfg := func(size string) map[string]string {
		m := map[string]string{"location": "pcloud:///", "access_token": "t"}
		if size != "" {
			m["cache_size"] = size
		}
		return m
	}
	conn, _ := New(t.Context(), nil, "pcloud", cfg(""), nil)
	if conn.cache == nil || conn.cache.budget != defaultCacheSize {
		t.Errorf("default cache budget not applied")
	}
	conn, _ = New(t.Context(), nil, "pcloud", cfg("0"), nil)
	if conn.cache != nil {
		t.Errorf("cache_size=0 must disable the cache")
	}
	conn, _ = New(t.Context(), nil, "pcloud", cfg("16MB"), nil)
	if conn.cache == nil || conn.cache.budget != 16_000_000 {
		t.Errorf("cache_size=16MB not honoured")
	}
}

func TestOptionsAreApplied(t *testing.T) {
	opts := &connectors.Options{MaxConcurrency: 9, Excludes: []string{"*.tmp"}}
	conn, err := New(t.Context(), opts, "pcloud", map[string]string{"location": "pcloud:///", "access_token": "t"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn.maxConcurrency != 9 {
		t.Errorf("maxConcurrency = %d", conn.maxConcurrency)
	}
	if !conn.excludes.IsExcluded("/a/b.tmp", false) {
		t.Errorf("exclude rules not applied")
	}
}

func TestUnsupportedProtocol(t *testing.T) {
	if _, err := New(t.Context(), nil, "s3", map[string]string{"location": "pcloud:///", "access_token": "t"}, nil); err == nil {
		t.Fatal("expected unsupported protocol error")
	}
}

func TestPublicConstructors(t *testing.T) {
	cfg := map[string]string{"location": "pcloud://eu/x", "access_token": "t"}
	if imp, err := NewImporter(t.Context(), &connectors.Options{}, "pcloud", cfg); err != nil || imp.Root() != "/x" {
		t.Errorf("NewImporter: %v", err)
	}
	if exp, err := NewExporter(t.Context(), &connectors.Options{}, "pcloud", cfg); err != nil || exp.Origin() != DefaultHostEU {
		t.Errorf("NewExporter: %v", err)
	}
	if st, err := NewStore(t.Context(), "pcloud", cfg); err != nil || st.Type() != "pcloud" {
		t.Errorf("NewStore: %v", err)
	}
}

func TestIsContained(t *testing.T) {
	tests := []struct {
		root, joined string
		want         bool
	}{
		{"/r", "/r", true},
		{"/r", "/r/a", true},
		{"/r", "/r/../etc", false},
		{"/r", "/rx", false},
		{"/", "/anything", true},
		{"/r/", "/r/a", true},
	}
	for _, tc := range tests {
		if got := isContained(tc.root, tc.joined); got != tc.want {
			t.Errorf("isContained(%q, %q) = %v, want %v", tc.root, tc.joined, got, tc.want)
		}
	}
}

func TestPingAndClose(t *testing.T) {
	s := newFakePCloud(t)
	conn := newTestConnector(t, s, nil)
	if err := conn.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	bad := newTestConnector(t, s, map[string]string{"access_token": "wrong"})
	if err := bad.Ping(t.Context()); err == nil {
		t.Fatal("Ping with a bad token should fail")
	}
}
