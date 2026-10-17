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
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/PlakarKorp/kloset/connectors"
	"github.com/PlakarKorp/kloset/connectors/exporter"
	"github.com/PlakarKorp/kloset/connectors/importer"
	"github.com/PlakarKorp/kloset/connectors/storage"
	"github.com/PlakarKorp/kloset/exclude"
	"github.com/PlakarKorp/kloset/location"
	"github.com/dustin/go-humanize"
)

const defaultCacheSize = 256 << 20

func init() {
	importer.Register("pcloud", 0, NewImporter)
	exporter.Register("pcloud", 0, NewExporter)
	storage.Register("pcloud", 0, NewStore)
}

// Connector implements Plakar's Importer, Exporter, and Store interfaces for pCloud.
type Connector struct {
	client         *Client
	host           string
	rootDir        string
	maxConcurrency int
	excludes       *exclude.RuleSet
	cache          *blockCache
}

func New(ctx context.Context, opts *connectors.Options, proto string, config map[string]string, httpClient *http.Client) (*Connector, error) {
	if proto != "pcloud" {
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}

	rawLoc, ok := config["location"]
	if !ok || strings.TrimSpace(rawLoc) == "" {
		return nil, fmt.Errorf("missing location")
	}
	u, err := url.Parse(rawLoc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse location: %w", err)
	}
	if u.Scheme != "pcloud" {
		return nil, fmt.Errorf("invalid location scheme %q: expected pcloud://", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("credentials must not be embedded in the location: use the username/password or access_token parameters")
	}

	insecure, err := parseBool(config, "insecure")
	if err != nil {
		return nil, err
	}
	debug, err := parseBool(config, "debug")
	if err != nil {
		return nil, err
	}

	region := strings.ToLower(strings.TrimSpace(config["region"]))
	endpoint := strings.TrimSpace(config["endpoint"])

	host, rootDir, err := resolveHostAndRoot(u, region, endpoint, config["root"])
	if err != nil {
		return nil, err
	}

	scheme := "https"
	if insecure {
		if endpoint == "" {
			return nil, fmt.Errorf("insecure=true is only allowed together with a custom endpoint: credentials are never sent to pCloud in clear text")
		}
		scheme = "http"
	}

	accessToken := strings.TrimSpace(config["access_token"])
	authToken := strings.TrimSpace(config["auth"])
	username := strings.TrimSpace(config["username"])
	password := config["password"]
	if accessToken == "" && authToken == "" && (username == "" || password == "") {
		return nil, fmt.Errorf("missing credentials: provide access_token, auth, or username and password")
	}

	cacheSize := uint64(defaultCacheSize)
	if v, ok := config["cache_size"]; ok && strings.TrimSpace(v) != "" {
		cacheSize, err = humanize.ParseBytes(v)
		if err != nil {
			return nil, fmt.Errorf("invalid cache_size %q: %w", v, err)
		}
	}

	client, err := NewClient(ClientConfig{
		Scheme:      scheme,
		Host:        host,
		AccessToken: accessToken,
		AuthToken:   authToken,
		Username:    username,
		Password:    password,
		Debug:       debug,
		HTTPClient:  httpClient,
	})
	if err != nil {
		return nil, err
	}

	maxConcurrency := 4
	excludes := exclude.NewRuleSet()
	if opts != nil {
		if opts.MaxConcurrency > 0 {
			maxConcurrency = opts.MaxConcurrency
		}
		if len(opts.Excludes) > 0 {
			if err := excludes.AddRulesFromArray(opts.Excludes); err != nil {
				return nil, fmt.Errorf("failed to setup exclude rules: %w", err)
			}
		}
	}

	return &Connector{
		client:         client,
		host:           host,
		rootDir:        rootDir,
		maxConcurrency: maxConcurrency,
		excludes:       excludes,
		cache:          newBlockCache(int64(min(cacheSize, 1<<40))),
	}, nil
}

func parseBool(config map[string]string, key string) (bool, error) {
	v, ok := config[key]
	if !ok || v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q: %w", key, v, err)
	}
	return b, nil
}

// resolveHostAndRoot derives the API host and the root folder. Only the
// official pCloud hosts (or their us/eu aliases) are recognized in the
// location; any other "host" is the first folder of the path. A custom API
// host can only be set explicitly through the endpoint parameter, so a
// folder name can never redirect credentials to a third-party server.
func resolveHostAndRoot(u *url.URL, region, endpoint, explicitRoot string) (string, string, error) {
	var host string
	switch region {
	case "", "us":
		host = DefaultHostUS
	case "eu":
		host = DefaultHostEU
	default:
		return "", "", fmt.Errorf("invalid region %q: must be 'us' or 'eu'", region)
	}

	urlPath := u.Path
	if u.Host != "" {
		switch strings.ToLower(u.Host) {
		case "us", DefaultHostUS:
			host = DefaultHostUS
		case "eu", DefaultHostEU:
			host = DefaultHostEU
		default:
			urlPath = path.Join("/", u.Host, u.Path)
		}
	}

	if endpoint != "" {
		eu, err := url.Parse(endpoint)
		if err != nil || eu.Host == "" {
			eu, err = url.Parse("//" + endpoint)
		}
		if err != nil || eu.Host == "" || (eu.Path != "" && eu.Path != "/") || eu.User != nil {
			return "", "", fmt.Errorf("invalid endpoint %q: expected host[:port]", endpoint)
		}
		host = eu.Host
	}

	rootDir := urlPath
	if explicitRoot != "" {
		rootDir = explicitRoot
	}
	return host, cleanRemotePath(rootDir), nil
}

func NewImporter(ctx context.Context, opts *connectors.Options, proto string, config map[string]string) (importer.Importer, error) {
	return New(ctx, opts, proto, config, nil)
}

func NewExporter(ctx context.Context, opts *connectors.Options, proto string, config map[string]string) (exporter.Exporter, error) {
	return New(ctx, opts, proto, config, nil)
}

func NewStore(ctx context.Context, proto string, config map[string]string) (storage.Store, error) {
	return New(ctx, nil, proto, config, nil)
}

func (c *Connector) Origin() string        { return c.host }
func (c *Connector) Type() string          { return "pcloud" }
func (c *Connector) Root() string          { return c.rootDir }
func (c *Connector) Flags() location.Flags { return 0 }

func (c *Connector) Ping(ctx context.Context) error {
	return c.client.Ping(ctx)
}

func (c *Connector) Close(ctx context.Context) error {
	c.cache.purge()
	return c.client.Close(ctx)
}

// isContained reports whether joined is rooted within root, guarding against
// path traversal ("../") escaping the restore root.
func isContained(root, joined string) bool {
	cleanRoot := path.Clean(root)
	cleanJoined := path.Clean(joined)

	if cleanJoined == cleanRoot {
		return true
	}

	prefix := cleanRoot
	if prefix != "/" {
		prefix += "/"
	}
	return strings.HasPrefix(cleanJoined, prefix)
}
