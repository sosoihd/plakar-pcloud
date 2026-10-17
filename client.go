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
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/PlakarKorp/kloset/connectors/storage"
)

const (
	DefaultHostUS = "api.pcloud.com"
	DefaultHostEU = "eapi.pcloud.com"
	UserAgent     = "plakar-pcloud/1.0.0"
)

var (
	ErrNotFound      = fs.ErrNotExist
	ErrAlreadyExists = fs.ErrExist
)

// APIError represents an error returned by the pCloud JSON API.
type APIError struct {
	Result  int    `json:"result"`
	Message string `json:"error"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("pcloud api error %d: %s", e.Result, e.Message)
}

func (e *APIError) Is(target error) bool {
	switch target {
	case fs.ErrNotExist:
		// 2002: A component of parent directory does not exist
		// 2009: File not found
		// 2010: Invalid path
		// 2055: Directory does not exist
		return e.Result == 2002 || e.Result == 2009 || e.Result == 2055
	case fs.ErrExist:
		// 2004: File or folder already exists
		return e.Result == 2004
	}
	return false
}

// Metadata represents a pCloud file or folder metadata entry.
type Metadata struct {
	Name           string     `json:"name"`
	Path           string     `json:"path"`
	Created        string     `json:"created"`
	Modified       string     `json:"modified"`
	IsFolder       bool       `json:"isfolder"`
	FolderID       uint64     `json:"folderid"`
	FileID         uint64     `json:"fileid"`
	ParentFolderID uint64     `json:"parentfolderid"`
	Size           int64      `json:"size"`
	ContentType    string     `json:"contenttype"`
	Hash           uint64     `json:"hash"`
	Contents       []Metadata `json:"contents"`
}

// ModTime parses the pCloud RFC1123Z timestamp ("Mon, 02 Jan 2006 15:04:05 -0700").
func (m *Metadata) ModTime() time.Time {
	if m.Modified == "" {
		return time.Now()
	}
	if t, err := time.Parse(time.RFC1123Z, m.Modified); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC1123, m.Modified); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, m.Modified); err == nil {
		return t
	}
	return time.Now()
}

type baseResponse struct {
	Result   int        `json:"result"`
	Error    string     `json:"error"`
	Digest   string     `json:"digest"`
	Auth     string     `json:"auth"`
	Metadata *Metadata  `json:"metadata"`
	Hosts    []string   `json:"hosts"`
	Path     string     `json:"path"`
	FileIDs  []uint64   `json:"fileids"`
	MetadataList []Metadata `json:"metadata_list,omitempty"`
}

// Client is an HTTP client for the pCloud API.
type Client struct {
	baseURL     string
	scheme      string
	host        string
	accessToken string
	authToken   string
	username    string
	password    string
	httpClient  *http.Client

	mu       sync.Mutex
	ensured  map[string]struct{}
}

// ClientConfig holds settings to initialize a pCloud Client.
type ClientConfig struct {
	Scheme      string
	Host        string
	AccessToken string
	AuthToken   string
	Username    string
	Password    string
	HTTPClient  *http.Client
}

func NewClient(cfg ClientConfig) (*Client, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := cfg.Host
	if host == "" {
		host = DefaultHostUS
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConnsPerHost = 64
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   0, // streaming transfers use context cancellation
		}
	}

	return &Client{
		baseURL:     fmt.Sprintf("%s://%s", scheme, host),
		scheme:      scheme,
		host:        host,
		accessToken: cfg.AccessToken,
		authToken:   cfg.AuthToken,
		username:    cfg.Username,
		password:    cfg.Password,
		httpClient:  httpClient,
		ensured:     make(map[string]struct{}),
	}, nil
}

func (c *Client) ensureAuth(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.accessToken != "" || c.authToken != "" {
		return nil
	}
	if c.username == "" || c.password == "" {
		return fmt.Errorf("pcloud: missing credentials (provide access_token, auth, or username and password)")
	}

	// Step 1: getdigest
	var digestResp baseResponse
	if err := c.doJSONUnlocked(ctx, http.MethodGet, "/getdigest", nil, nil, &digestResp, false); err != nil {
		return fmt.Errorf("pcloud getdigest: %w", err)
	}
	if digestResp.Digest == "" {
		return fmt.Errorf("pcloud getdigest returned empty digest")
	}

	// Step 2: compute passworddigest = sha1(password + sha1(lowercase(username)) + digest)
	userHash := sha1.Sum([]byte(strings.ToLower(c.username)))
	userHex := hex.EncodeToString(userHash[:])
	pwHash := sha1.Sum([]byte(c.password + userHex + digestResp.Digest))
	pwDigest := hex.EncodeToString(pwHash[:])

	q := url.Values{}
	q.Set("getauth", "1")
	q.Set("logout", "1")
	q.Set("username", c.username)
	q.Set("digest", digestResp.Digest)
	q.Set("passworddigest", pwDigest)

	var authResp baseResponse
	if err := c.doJSONUnlocked(ctx, http.MethodGet, "/userinfo", q, nil, &authResp, false); err != nil {
		return fmt.Errorf("pcloud login failed: %w", err)
	}
	if authResp.Auth == "" {
		return fmt.Errorf("pcloud login returned empty auth token")
	}
	c.authToken = authResp.Auth
	return nil
}

func (c *Client) applyAuth(req *http.Request, q url.Values) {
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	} else if c.authToken != "" {
		q.Set("auth", c.authToken)
	}
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, q url.Values, body io.Reader, contentType string, out *baseResponse) error {
	if err := c.ensureAuth(ctx); err != nil {
		return err
	}
	return c.doJSONWithContentType(ctx, method, endpoint, q, body, contentType, out, true)
}

func (c *Client) doJSONUnlocked(ctx context.Context, method, endpoint string, q url.Values, body io.Reader, out *baseResponse, withAuth bool) error {
	return c.doJSONWithContentType(ctx, method, endpoint, q, body, "", out, withAuth)
}

func (c *Client) doJSONWithContentType(ctx context.Context, method, endpoint string, q url.Values, body io.Reader, contentType string, out *baseResponse, withAuth bool) error {
	if q == nil {
		q = url.Values{}
	}
	u, err := url.Parse(c.baseURL + endpoint)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if withAuth {
		c.applyAuth(req, q)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("pcloud http status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("pcloud decode response: %w", err)
	}
	if out.Result != 0 {
		return &APIError{
			Result:  out.Result,
			Message: out.Error,
		}
	}
	return nil
}

// Ping verifies connectivity and credentials against pCloud.
func (c *Client) Ping(ctx context.Context) error {
	var resp baseResponse
	return c.doJSON(ctx, http.MethodGet, "/userinfo", nil, nil, "", &resp)
}

// Stat returns metadata for a file or folder at remotePath.
func (c *Client) Stat(ctx context.Context, remotePath string) (*Metadata, error) {
	remotePath = cleanRemotePath(remotePath)
	if remotePath == "/" {
		return c.ListFolder(ctx, "/", false)
	}
	q := url.Values{}
	q.Set("path", remotePath)

	var resp baseResponse
	if err := c.doJSON(ctx, http.MethodGet, "/stat", q, nil, "", &resp); err == nil && resp.Metadata != nil {
		return resp.Metadata, nil
	} else if err != nil {
		// Fallback to listfolder in case remotePath is a folder and /stat only checks files on some endpoints
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.Result == 2009 || apiErr.Result == 2002 || apiErr.Result == 2055) {
			if folderMeta, ferr := c.ListFolder(ctx, remotePath, false); ferr == nil {
				return folderMeta, nil
			}
		}
		return nil, err
	}
	return nil, ErrNotFound
}

// ListFolder returns folder metadata (and its contents) at remotePath.
func (c *Client) ListFolder(ctx context.Context, remotePath string, recursive bool) (*Metadata, error) {
	remotePath = cleanRemotePath(remotePath)
	q := url.Values{}
	q.Set("path", remotePath)
	if recursive {
		q.Set("recursive", "1")
	}

	var resp baseResponse
	if err := c.doJSON(ctx, http.MethodGet, "/listfolder", q, nil, "", &resp); err != nil {
		return nil, err
	}
	if resp.Metadata == nil {
		return nil, ErrNotFound
	}
	return resp.Metadata, nil
}

// CreateFolder creates a single directory at remotePath, failing if it already exists.
func (c *Client) CreateFolder(ctx context.Context, remotePath string) (*Metadata, error) {
	remotePath = cleanRemotePath(remotePath)
	q := url.Values{}
	q.Set("path", remotePath)

	var resp baseResponse
	if err := c.doJSON(ctx, http.MethodPost, "/createfolder", q, nil, "", &resp); err != nil {
		return nil, err
	}
	return resp.Metadata, nil
}

// CreateFolderIfNotExists creates a single directory at remotePath if it does not exist.
func (c *Client) CreateFolderIfNotExists(ctx context.Context, remotePath string) (*Metadata, error) {
	remotePath = cleanRemotePath(remotePath)
	if remotePath == "/" {
		return &Metadata{Name: "/", Path: "/", IsFolder: true}, nil
	}

	c.mu.Lock()
	if _, ok := c.ensured[remotePath]; ok {
		c.mu.Unlock()
		return &Metadata{Name: path.Base(remotePath), Path: remotePath, IsFolder: true}, nil
	}
	c.mu.Unlock()

	q := url.Values{}
	q.Set("path", remotePath)

	var resp baseResponse
	if err := c.doJSON(ctx, http.MethodPost, "/createfolderifnotexists", q, nil, "", &resp); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.ensured[remotePath] = struct{}{}
	c.mu.Unlock()

	return resp.Metadata, nil
}

// MkdirAll ensures all directory components of remotePath exist.
func (c *Client) MkdirAll(ctx context.Context, remotePath string) error {
	remotePath = cleanRemotePath(remotePath)
	if remotePath == "/" {
		return nil
	}

	parts := strings.Split(strings.TrimPrefix(remotePath, "/"), "/")
	cur := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		cur = cur + "/" + part
		if _, err := c.CreateFolderIfNotExists(ctx, cur); err != nil {
			return err
		}
	}
	return nil
}

// UploadFile uploads a file to remotePath, creating parent directories if needed.
func (c *Client) UploadFile(ctx context.Context, remotePath string, rd io.Reader) (int64, error) {
	remotePath = cleanRemotePath(remotePath)
	dir := path.Dir(remotePath)
	filename := path.Base(remotePath)
	if filename == "/" || filename == "." || filename == "" {
		return 0, fmt.Errorf("pcloud: invalid file path %q", remotePath)
	}

	if err := c.MkdirAll(ctx, dir); err != nil {
		return 0, fmt.Errorf("pcloud mkdir parent %s: %w", dir, err)
	}

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)

	var written int64
	go func() {
		part, err := mw.CreateFormFile("file", filename)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		n, err := io.Copy(part, rd)
		written = n
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := mw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	q := url.Values{}
	q.Set("path", dir)
	q.Set("filename", filename)
	q.Set("nopartial", "1")

	var resp baseResponse
	if err := c.doJSON(ctx, http.MethodPost, "/uploadfile", q, pr, mw.FormDataContentType(), &resp); err != nil {
		_ = pr.Close()
		return 0, err
	}
	return written, nil
}

// OpenFile opens a file at remotePath for reading, optionally restricted to a byte range.
func (c *Client) OpenFile(ctx context.Context, remotePath string, rg *storage.Range) (io.ReadCloser, error) {
	remotePath = cleanRemotePath(remotePath)
	if rg != nil && rg.Length == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	q := url.Values{}
	q.Set("path", remotePath)

	var linkResp baseResponse
	if err := c.doJSON(ctx, http.MethodGet, "/getfilelink", q, nil, "", &linkResp); err != nil {
		return nil, err
	}
	if len(linkResp.Hosts) == 0 || linkResp.Path == "" {
		return nil, fmt.Errorf("pcloud getfilelink returned empty download link for %s", remotePath)
	}

	dlURL := fmt.Sprintf("%s://%s%s", c.scheme, linkResp.Hosts[0], linkResp.Path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	if rg != nil {
		end := rg.Offset + uint64(rg.Length) - 1
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", rg.Offset, end))
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("pcloud download status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// If server ignored the Range header and returned 200 OK instead of 206 Partial Content,
	// slice the stream locally so callers always receive the requested byte range.
	if rg != nil && resp.StatusCode == http.StatusOK {
		if _, err := io.CopyN(io.Discard, resp.Body, int64(rg.Offset)); err != nil {
			resp.Body.Close()
			if errors.Is(err, io.EOF) {
				return io.NopCloser(bytes.NewReader(nil)), nil
			}
			return nil, err
		}
		return &limitedReadCloser{
			Reader: io.LimitReader(resp.Body, int64(rg.Length)),
			Closer: resp.Body,
		}, nil
	}

	return resp.Body, nil
}

type limitedReadCloser struct {
	io.Reader
	io.Closer
}

// DeleteFile deletes a single file at remotePath.
func (c *Client) DeleteFile(ctx context.Context, remotePath string) error {
	remotePath = cleanRemotePath(remotePath)
	q := url.Values{}
	q.Set("path", remotePath)

	var resp baseResponse
	return c.doJSON(ctx, http.MethodPost, "/deletefile", q, nil, "", &resp)
}

// DeleteFolderRecursive deletes a folder and its contents at remotePath.
func (c *Client) DeleteFolderRecursive(ctx context.Context, remotePath string) error {
	remotePath = cleanRemotePath(remotePath)
	q := url.Values{}
	q.Set("path", remotePath)

	c.mu.Lock()
	delete(c.ensured, remotePath)
	c.mu.Unlock()

	var resp baseResponse
	return c.doJSON(ctx, http.MethodPost, "/deletefolderrecursive", q, nil, "", &resp)
}

func cleanRemotePath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(p, "/"))
	return cleaned
}
