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
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type jsonSchema struct {
	Schema               string                    `json:"$schema"`
	Type                 string                    `json:"type"`
	AdditionalProperties *bool                     `json:"additionalProperties"`
	Required             []string                  `json:"required"`
	Properties           map[string]map[string]any `json:"properties"`
	AnyOf                []map[string][]string     `json:"anyOf"`
}

// configKeys lists every configuration key read by New, per connector.
var configKeys = map[string][]string{
	"importer": {"location", "access_token", "auth", "username", "password", "region", "root", "endpoint", "insecure", "debug"},
	"exporter": {"location", "access_token", "auth", "username", "password", "region", "root", "endpoint", "insecure", "debug"},
	"storage":  {"location", "access_token", "auth", "username", "password", "region", "root", "endpoint", "insecure", "debug", "cache_size"},
}

func loadSchema(t *testing.T, kind string) jsonSchema {
	t.Helper()
	raw, err := os.ReadFile("cmd/" + kind + "/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s jsonSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%s schema is not valid JSON: %v", kind, err)
	}
	return s
}

func TestSchemasMatchConfiguration(t *testing.T) {
	for kind, keys := range configKeys {
		t.Run(kind, func(t *testing.T) {
			s := loadSchema(t, kind)
			if s.Schema != "https://json-schema.org/draft/2020-12/schema" || s.Type != "object" {
				t.Errorf("schema must be a draft 2020-12 object schema")
			}
			if s.AdditionalProperties == nil || *s.AdditionalProperties {
				t.Errorf("additionalProperties must be false so typos are reported")
			}
			if !slices.Equal(s.Required, []string{"location"}) {
				t.Errorf("required = %v", s.Required)
			}
			got := slices.Sorted(maps.Keys(s.Properties))
			want := slices.Sorted(slices.Values(keys))
			if !slices.Equal(got, want) {
				t.Errorf("schema properties = %v\nconfig keys       = %v", got, want)
			}
			// Plakar's validator requires a flat schema with typed properties.
			for name, prop := range s.Properties {
				typ, _ := prop["type"].(string)
				if typ == "" || typ == "object" || typ == "array" {
					t.Errorf("property %s must have a scalar type, got %q", name, typ)
				}
				if enum, ok := prop["enum"].([]any); ok {
					for _, v := range enum {
						if _, ok := v.(string); !ok {
							t.Errorf("property %s: enum values must be strings", name)
						}
					}
				}
			}
			if len(s.AnyOf) != 3 {
				t.Errorf("schema must require one of the three authentication methods")
			}
		})
	}
}

func TestSchemaPatternsAgreeWithCode(t *testing.T) {
	s := loadSchema(t, "storage")
	locPattern := regexp.MustCompile(s.Properties["location"]["pattern"].(string))
	for _, loc := range []string{"pcloud:///x", "pcloud://eu/x", "pcloud://"} {
		if !locPattern.MatchString(loc) {
			t.Errorf("schema rejects valid location %q", loc)
		}
	}
	if locPattern.MatchString("s3://bucket") {
		t.Errorf("schema accepts a foreign scheme")
	}

	sizePattern := regexp.MustCompile(s.Properties["cache_size"]["pattern"].(string))
	base := map[string]string{"location": "pcloud:///", "access_token": "t"}
	for _, v := range []string{"0", "256MiB", "1GB", "64 MiB", "512k", "1.5GiB", "100", "2T"} {
		if !sizePattern.MatchString(v) {
			t.Errorf("schema rejects cache_size %q", v)
			continue
		}
		cfg := maps.Clone(base)
		cfg["cache_size"] = v
		if _, err := New(t.Context(), nil, "pcloud", cfg, nil); err != nil {
			t.Errorf("schema accepts cache_size %q but the connector rejects it: %v", v, err)
		}
	}
	if sizePattern.MatchString("lots") {
		t.Errorf("schema accepts an invalid cache_size")
	}

	regions := s.Properties["region"]["enum"].([]any)
	for _, r := range regions {
		cfg := maps.Clone(base)
		cfg["region"] = r.(string)
		if _, err := New(t.Context(), nil, "pcloud", cfg, nil); err != nil {
			t.Errorf("region %v accepted by schema but rejected by code: %v", r, err)
		}
	}
}

func TestManifestReferencesBuiltArtifacts(t *testing.T) {
	manifest, err := os.ReadFile("manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	makefile, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := string(manifest)
	for _, kind := range []string{"importer", "exporter", "storage"} {
		exe := "pcloud-" + kind
		if !strings.Contains(m, "executable: ./"+exe) {
			t.Errorf("manifest does not declare %s", exe)
		}
		if !strings.Contains(string(makefile), "-o "+exe) {
			t.Errorf("Makefile does not build %s", exe)
		}
		if !strings.Contains(m, "validator: ./cmd/"+kind+"/schema.json") {
			t.Errorf("manifest does not reference the %s schema", kind)
		}
	}
	if !strings.Contains(m, "api_version: v1.1.0") {
		t.Errorf("api_version must be the canonical semver v1.1.0")
	}
}
