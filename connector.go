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
	"golang.org/x/sync/singleflight"
)

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
	sf             singleflight.Group
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
		return nil, fmt.Errorf("failed to parse location %q: %w", rawLoc, err)
	}

	scheme := "https"
	if v, ok := config["insecure"]; ok && v != "" {
		insecure, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid insecure value %q: %w", v, err)
		}
		if insecure {
			scheme = "http"
		}
	}

	region := strings.ToLower(strings.TrimSpace(config["region"]))
	endpoint := strings.TrimSpace(config["endpoint"])

	host, rootDir, err := resolveHostAndRoot(u, region, endpoint, config["root"])
	if err != nil {
		return nil, err
	}

	accessToken := strings.TrimSpace(config["access_token"])
	authToken := strings.TrimSpace(config["auth"])
	username := strings.TrimSpace(config["username"])
	password := config["password"]

	if u.User != nil {
		if username != "" {
			return nil, fmt.Errorf("cannot specify both user@host in location and username parameter")
		}
		username = u.User.Username()
		if pw, hasPw := u.User.Password(); hasPw && password == "" {
			password = pw
		}
	}

	if accessToken == "" && authToken == "" && (username == "" || password == "") {
		return nil, fmt.Errorf("missing credentials: provide access_token, auth, or username and password")
	}

	debug := false
	if v, ok := config["debug"]; ok && v != "" {
		d, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("invalid debug value %q: %w", v, err)
		}
		debug = d
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
	}, nil
}

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
			if strings.Contains(u.Host, ".") || strings.Contains(u.Host, ":") || u.Host == "localhost" {
				host = u.Host
			} else {
				// Treat pcloud://Folder/Subfolder as path /Folder/Subfolder
				urlPath = path.Join("/", u.Host, u.Path)
			}
		}
	}

	if endpoint != "" {
		host = strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
		host = strings.TrimSuffix(host, "/")
	}

	rootDir := urlPath
	if explicitRoot != "" {
		rootDir = explicitRoot
	}
	rootDir = cleanRemotePath(rootDir)
	return host, rootDir, nil
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
	return nil
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
