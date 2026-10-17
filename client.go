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
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math/rand/v2"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultHostUS = "api.pcloud.com"
	DefaultHostEU = "eapi.pcloud.com"
	UserAgent     = "plakar-pcloud/1.1.0"

	defaultMaxRetries     = 5
	defaultRetryBaseDelay = 250 * time.Millisecond
	defaultRetryMaxDelay  = 15 * time.Second
	defaultIdleTimeout    = 2 * time.Minute

	// Download links returned by getfilelink are cached at most this long,
	// and never past their advertised expiry minus linkExpiryMargin.
	maxLinkTTL       = 30 * time.Minute
	linkExpiryMargin = 30 * time.Second

	// Uploads up to this size are held in memory so they can be retried;
	// larger ones are streamed straight from their source.
	maxBufferedUpload = 8 << 20

	maxErrorBody = 4096
)

var (
	ErrNotFound      = fs.ErrNotExist
	ErrAlreadyExists = fs.ErrExist

	// ErrAuth is matched (via errors.Is) by API errors caused by missing,
	// invalid or expired credentials.
	ErrAuth = errors.New("pcloud: authentication failed")

	errChecksumMismatch = errors.New("pcloud: uploaded file checksum mismatch")
	errIdleTimeout      = errors.New("pcloud: transfer stalled")
	errSizeMismatch     = errors.New("pcloud: source size does not match declared size")
)

// APIError represents an error returned by the pCloud JSON API.
type APIError struct {
	Result  int    `json:"result"`
	Message string `json:"error"`
}

// apiErrorHints explains the most common configuration mistakes behind
// authentication errors, which pCloud reports tersely.
var apiErrorHints = map[int]string{
	2000: "check the credentials, and that the region matches the account (region=eu or pcloud://eu/... for EU accounts)",
	2094: "the value is not a valid OAuth access token for this region: a session token belongs in the 'auth' parameter, and EU accounts need region=eu or pcloud://eu/...",
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("pcloud api error %d: %s", e.Result, e.Message)
	if hint, ok := apiErrorHints[e.Result]; ok {
		msg += " (" + hint + ")"
	}
	return msg
}

func (e *APIError) Is(target error) bool {
	switch target {
	case fs.ErrNotExist:
		// 2002: a component of parent directory does not exist
		// 2005: directory does not exist
		// 2009: file not found
		// 2055: directory does not exist
		return e.Result == 2002 || e.Result == 2005 || e.Result == 2009 || e.Result == 2055
	case fs.ErrExist:
		return e.Result == 2004
	case fs.ErrPermission:
		return e.Result == 2003
	case ErrAuth:
		// 1000: log in required, 2000: log in failed, 2094: invalid access_token
		return e.Result == 1000 || e.Result == 2000 || e.Result == 2094
	}
	return false
}

// Temporary reports whether the request may succeed if retried later.
// See https://docs.pcloud.com/errors/: 19xx, 4xxx and 5xxx are transient,
// 2041 is a broken connection.
func (e *APIError) Temporary() bool {
	switch {
	case e.Result == 2041:
		return true
	case e.Result/100 == 19:
		return true
	case e.Result/1000 == 4, e.Result/1000 == 5:
		return true
	}
	return false
}

// HTTPStatusError is returned when pCloud answers with a non-2xx HTTP status.
type HTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("pcloud http status %d", e.StatusCode)
	}
	return fmt.Sprintf("pcloud http status %d: %s", e.StatusCode, e.Body)
}

func (e *HTTPStatusError) Temporary() bool {
	switch e.StatusCode {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout, 509:
		return true
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

// ModTime returns the modification time, falling back to the creation time
// and finally to the Unix epoch so that snapshots stay deterministic.
func (m *Metadata) ModTime() time.Time {
	if t, ok := parsePCloudTime(m.Modified); ok {
		return t
	}
	if t, ok := parsePCloudTime(m.Created); ok {
		return t
	}
	return time.Unix(0, 0).UTC()
}

func parsePCloudTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(secs, 0).UTC(), true
	}
	return time.Time{}, false
}

type checksums struct {
	SHA1   string `json:"sha1"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

type baseResponse struct {
	Result    int             `json:"result"`
	Error     string          `json:"error"`
	Digest    string          `json:"digest"`
	Auth      string          `json:"auth"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	Hosts     []string        `json:"hosts"`
	Path      string          `json:"path"`
	Expires   string          `json:"expires"`
	FileIDs   []uint64        `json:"fileids"`
	Checksums []checksums     `json:"checksums"`
}

func (r *baseResponse) parseMetadata() (*Metadata, error) {
	trimmed := bytes.TrimSpace(r.Metadata)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var list []Metadata
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		if len(list) == 0 {
			return nil, nil
		}
		return &list[0], nil
	}
	var m Metadata
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

type downloadLink struct {
	urls      []string
	expiresAt time.Time
}

// Client is an HTTP client for the pCloud API.
type Client struct {
	scheme      string
	host        string
	accessToken string
	username    string
	password    string
	debug       bool
	httpClient  *http.Client

	maxRetries  int
	retryBase   time.Duration
	retryMax    time.Duration
	idleTimeout time.Duration
	sleep       func(context.Context, time.Duration) error

	authMu     sync.Mutex
	authToken  string
	ownSession bool
	authErr    error

	mu      sync.Mutex
	ensured map[string]struct{}
	links   map[string]downloadLink
}

// ClientConfig holds settings to initialize a pCloud Client.
type ClientConfig struct {
	Scheme      string
	Host        string
	AccessToken string
	AuthToken   string
	Username    string
	Password    string
	Debug       bool
	HTTPClient  *http.Client

	// MaxRetries is the number of retries after a transient failure.
	// Zero selects the default; a negative value disables retries.
	MaxRetries int
	// RetryBaseDelay is the initial backoff delay (doubled on each retry).
	RetryBaseDelay time.Duration
	// IdleTimeout aborts a transfer that makes no progress for this long.
	IdleTimeout time.Duration
}

func NewClient(cfg ClientConfig) (*Client, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("pcloud: unsupported scheme %q", scheme)
	}
	host := cfg.Host
	if host == "" {
		host = DefaultHostUS
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConns = 128
		transport.MaxIdleConnsPerHost = 64
		transport.DialContext = (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
		transport.TLSHandshakeTimeout = 15 * time.Second
		// pCloud may take a while to acknowledge a large upload, but a server
		// that never answers must not hang the backup forever.
		transport.ResponseHeaderTimeout = 5 * time.Minute
		// Session resumption avoids full TLS handshakes when the EU API
		// closes connections after each request.
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ClientSessionCache: tls.NewLRUClientSessionCache(256),
		}
		// No overall http.Client timeout: it would also cap the time spent
		// streaming a large body. Stalls are detected by the idle watchdog.
		httpClient = &http.Client{Transport: transport}
	}

	maxRetries := cfg.MaxRetries
	switch {
	case maxRetries == 0:
		maxRetries = defaultMaxRetries
	case maxRetries < 0:
		maxRetries = 0
	}
	retryBase := cfg.RetryBaseDelay
	if retryBase <= 0 {
		retryBase = defaultRetryBaseDelay
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}

	return &Client{
		scheme:      scheme,
		host:        host,
		accessToken: cfg.AccessToken,
		authToken:   cfg.AuthToken,
		username:    cfg.Username,
		password:    cfg.Password,
		debug:       cfg.Debug || os.Getenv("PLAKAR_PCLOUD_DEBUG") != "",
		httpClient:  httpClient,
		maxRetries:  maxRetries,
		retryBase:   retryBase,
		retryMax:    defaultRetryMaxDelay,
		idleTimeout: idle,
		sleep:       sleepCtx,
		ensured:     make(map[string]struct{}),
		links:       make(map[string]downloadLink),
	}, nil
}

func (c *Client) logf(format string, args ...any) {
	if !c.debug {
		return
	}
	fmt.Fprintf(os.Stderr, "[pcloud] "+format+"\n", args...)
}

func (c *Client) apiURL(endpoint string) string {
	return c.scheme + "://" + c.host + endpoint
}

// Retry machinery.

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	d := c.retryBase << min(attempt, 16)
	if d <= 0 || d > c.retryMax {
		d = c.retryMax
	}
	// Full jitter in [d/2, d).
	half := d / 2
	if half <= 0 {
		return d
	}
	return half + rand.N(half)
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errSizeMismatch) {
		return false
	}
	if errors.Is(err, errIdleTimeout) || errors.Is(err, errChecksumMismatch) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Temporary()
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Temporary()
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

func (c *Client) retry(ctx context.Context, op string, fn func() error) error {
	return c.retryIf(ctx, op, isRetryable, fn)
}

func (c *Client) retryIf(ctx context.Context, op string, retryable func(error) bool, fn func() error) error {
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if attempt >= c.maxRetries || ctx.Err() != nil || !retryable(err) {
			return err
		}
		d := c.backoff(attempt)
		c.logf("%s failed (attempt %d/%d), retrying in %s: %v", op, attempt+1, c.maxRetries+1, d, err)
		if serr := c.sleep(ctx, d); serr != nil {
			return err
		}
	}
}

// Secret redaction.

var sensitiveParams = []string{"access_token", "auth", "password", "passworddigest", "digest", "username"}

// redactURL strips credentials from a URL. Download URLs carry a signed path
// that grants access to the file, so their path is dropped altogether.
func redactURL(raw string, dropPath bool) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable url>"
	}
	u.User = nil
	if dropPath {
		u.Path, u.RawPath, u.RawQuery = "/<redacted>", "", ""
		return u.String()
	}
	q := u.Query()
	for _, k := range sensitiveParams {
		if q.Has(k) {
			q.Set(k, "REDACTED")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func redactError(err error, dropPath bool) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return &url.Error{Op: urlErr.Op, URL: redactURL(urlErr.URL, dropPath), Err: urlErr.Err}
	}
	return err
}

// Idle watchdog: cancels a transfer when no bytes move for idleTimeout.

type watchdog struct {
	timer  *time.Timer
	d      time.Duration
	fired  atomic.Bool
	cancel context.CancelFunc
}

func (c *Client) newWatchdog(cancel context.CancelFunc) *watchdog {
	w := &watchdog{d: c.idleTimeout, cancel: cancel}
	w.timer = time.AfterFunc(w.d, func() {
		w.fired.Store(true)
		cancel()
	})
	return w
}

func (w *watchdog) kick()      { w.timer.Reset(w.d) }
func (w *watchdog) stop() bool { return w.timer.Stop() }

func (w *watchdog) wrap(err error) error {
	if err != nil && w.fired.Load() {
		return fmt.Errorf("%w: no progress for %s", errIdleTimeout, w.d)
	}
	return err
}

type watchedBody struct {
	rc io.ReadCloser
	w  *watchdog
}

func (b *watchedBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.w.kick()
	}
	return n, b.w.wrap(err)
}

func (b *watchedBody) Close() error {
	b.w.stop()
	b.w.cancel()
	return b.rc.Close()
}

// watchedUpload kicks the watchdog as the transport consumes the request body
// and disarms it once the body is fully sent.
type watchedUpload struct {
	r io.Reader
	w *watchdog
}

func (u *watchedUpload) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	if n > 0 {
		u.w.kick()
	}
	if err == io.EOF {
		u.w.stop()
	}
	return n, err
}

// Authentication.

func (c *Client) currentAuth() (accessToken, authToken string) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.accessToken, c.authToken
}

func (c *Client) ensureAuth(ctx context.Context) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	if c.accessToken != "" || c.authToken != "" {
		return nil
	}
	if c.authErr != nil {
		// A rejected login is never retried: pCloud bans the IP after too
		// many failed attempts (error 4000).
		return c.authErr
	}
	if c.username == "" || c.password == "" {
		return fmt.Errorf("pcloud: missing credentials (provide access_token, auth, or username and password)")
	}

	c.logf("authenticating on %s via digest", c.host)
	onlyTransport := func(err error) bool {
		var apiErr *APIError
		return !errors.As(err, &apiErr) && isRetryable(err)
	}

	var token string
	err := c.retryIf(ctx, "login", onlyTransport, func() error {
		var digestResp baseResponse
		if err := c.doAPI(ctx, "/getdigest", nil, &digestResp, false); err != nil {
			return fmt.Errorf("pcloud getdigest: %w", err)
		}
		if digestResp.Digest == "" {
			return fmt.Errorf("pcloud getdigest returned an empty digest")
		}

		// passworddigest = sha1(password + sha1(lowercase(username)) + digest)
		userHash := sha1.Sum([]byte(strings.ToLower(c.username)))
		pwHash := sha1.Sum([]byte(c.password + hex.EncodeToString(userHash[:]) + digestResp.Digest))

		params := url.Values{}
		params.Set("getauth", "1")
		params.Set("logout", "1")
		params.Set("username", c.username)
		params.Set("digest", digestResp.Digest)
		params.Set("passworddigest", hex.EncodeToString(pwHash[:]))

		var authResp baseResponse
		if err := c.doAPI(ctx, "/userinfo", params, &authResp, false); err != nil {
			return fmt.Errorf("pcloud login failed: %w", err)
		}
		if authResp.Auth == "" {
			return fmt.Errorf("pcloud login returned an empty auth token")
		}
		token = authResp.Auth
		return nil
	})
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			c.authErr = err
		}
		return err
	}
	c.authToken = token
	c.ownSession = true
	c.logf("digest authentication succeeded")
	return nil
}

// Logout invalidates the session token if this client created it by logging
// in, then releases idle connections.
func (c *Client) Close(ctx context.Context) error {
	c.authMu.Lock()
	token, own := c.authToken, c.ownSession
	if own {
		c.authToken = ""
		c.ownSession = false
	}
	c.authMu.Unlock()

	var err error
	if own && token != "" {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		params := url.Values{}
		params.Set("auth", token)
		var resp baseResponse
		err = c.doAPI(lctx, "/logout", params, &resp, false)
		cancel()
	}
	c.httpClient.CloseIdleConnections()
	return err
}

// Request plumbing.

// call performs an authenticated API call with retries.
func (c *Client) call(ctx context.Context, endpoint string, params url.Values, out *baseResponse) error {
	if err := c.ensureAuth(ctx); err != nil {
		return err
	}
	return c.retry(ctx, endpoint, func() error {
		*out = baseResponse{}
		return c.doAPI(ctx, endpoint, params, out, true)
	})
}

// doAPI performs a single API request. Secrets never go into the URL: the
// OAuth token travels in the Authorization header, and any other credential
// (session token, password digest) is sent in a form-encoded POST body.
func (c *Client) doAPI(ctx context.Context, endpoint string, params url.Values, out *baseResponse, withAuth bool) error {
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}

	var bearer string
	if withAuth {
		accessToken, authToken := c.currentAuth()
		if accessToken != "" {
			bearer = accessToken
		} else if authToken != "" {
			form.Set("auth", authToken)
		}
	}

	hasSecret := false
	for _, k := range sensitiveParams {
		if form.Has(k) {
			hasSecret = true
			break
		}
	}

	var req *http.Request
	var err error
	if hasSecret {
		body := form.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL(endpoint), strings.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL(endpoint), nil)
		if err != nil {
			return err
		}
		req.URL.RawQuery = form.Encode()
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("User-Agent", UserAgent)

	return c.doJSON(req, endpoint, form.Get("path"), out)
}

func (c *Client) doJSON(req *http.Request, endpoint, logPath string, out *baseResponse) error {
	start := time.Now()
	c.logf("-> %s %s (path=%q)", req.Method, endpoint, logPath)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		err = redactError(err, false)
		c.logf("<- %s error after %s: %v", endpoint, time.Since(start).Round(time.Millisecond), err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return &HTTPStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("pcloud decode %s response: %w", endpoint, err)
	}
	if out.Result != 0 {
		c.logf("<- %s api error %d (%s) in %s", endpoint, out.Result, out.Error, time.Since(start).Round(time.Millisecond))
		return &APIError{Result: out.Result, Message: out.Error}
	}
	c.logf("<- %s OK in %s", endpoint, time.Since(start).Round(time.Millisecond))
	return nil
}

// Metadata operations.

// Ping verifies connectivity and credentials against pCloud.
func (c *Client) Ping(ctx context.Context) error {
	var resp baseResponse
	return c.call(ctx, "/userinfo", nil, &resp)
}

// Stat returns metadata for a file or folder at remotePath.
func (c *Client) Stat(ctx context.Context, remotePath string) (*Metadata, error) {
	remotePath = cleanRemotePath(remotePath)
	if remotePath == "/" {
		return c.listFolder(ctx, "/", false)
	}

	params := url.Values{}
	params.Set("path", remotePath)
	var resp baseResponse
	err := c.call(ctx, "/stat", params, &resp)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// stat only addresses files on some API versions; retry as a folder.
			if meta, ferr := c.listFolder(ctx, remotePath, false); ferr == nil {
				meta.Contents = nil
				return meta, nil
			}
		}
		return nil, err
	}
	meta, err := resp.parseMetadata()
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, ErrNotFound
	}
	return meta, nil
}

// ListFolder returns folder metadata (and its contents) at remotePath.
func (c *Client) ListFolder(ctx context.Context, remotePath string, recursive bool) (*Metadata, error) {
	remotePath = cleanRemotePath(remotePath)
	if !recursive || remotePath != "/" {
		return c.listFolder(ctx, remotePath, recursive)
	}

	// pCloud rejects recursive listings of the root folder (error 1101), so
	// list the root shallowly and each top-level folder recursively.
	root, err := c.listFolder(ctx, "/", false)
	if err != nil {
		return nil, err
	}
	for i := range root.Contents {
		child := &root.Contents[i]
		if !child.IsFolder {
			continue
		}
		sub, err := c.listFolder(ctx, path.Join("/", child.Name), true)
		if err != nil {
			return nil, err
		}
		child.Contents = sub.Contents
	}
	return root, nil
}

func (c *Client) listFolder(ctx context.Context, remotePath string, recursive bool) (*Metadata, error) {
	params := url.Values{}
	params.Set("path", remotePath)
	if recursive {
		params.Set("recursive", "1")
	}

	var resp baseResponse
	if err := c.call(ctx, "/listfolder", params, &resp); err != nil {
		return nil, err
	}
	meta, err := resp.parseMetadata()
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, ErrNotFound
	}
	return meta, nil
}

// CreateFolder creates a single directory at remotePath, failing if it already exists.
func (c *Client) CreateFolder(ctx context.Context, remotePath string) (*Metadata, error) {
	params := url.Values{}
	params.Set("path", cleanRemotePath(remotePath))
	var resp baseResponse
	if err := c.call(ctx, "/createfolder", params, &resp); err != nil {
		return nil, err
	}
	return resp.parseMetadata()
}

func (c *Client) isEnsured(p string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.ensured[p]
	return ok
}

func (c *Client) forgetEnsured(p string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.ensured {
		if k == p || strings.HasPrefix(k, p+"/") || strings.HasPrefix(p, k+"/") {
			delete(c.ensured, k)
		}
	}
}

func (c *Client) createFolderIfNotExists(ctx context.Context, p string) error {
	params := url.Values{}
	params.Set("path", p)
	var resp baseResponse
	if err := c.call(ctx, "/createfolderifnotexists", params, &resp); err != nil {
		return err
	}
	c.mu.Lock()
	c.ensured[p] = struct{}{}
	c.mu.Unlock()
	return nil
}

// MkdirAll ensures all directory components of remotePath exist. It first
// tries the full path and only walks up when a parent is missing.
func (c *Client) MkdirAll(ctx context.Context, remotePath string) error {
	remotePath = cleanRemotePath(remotePath)
	if remotePath == "/" || c.isEnsured(remotePath) {
		return nil
	}
	err := c.createFolderIfNotExists(ctx, remotePath)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := c.MkdirAll(ctx, path.Dir(remotePath)); err != nil {
		return err
	}
	return c.createFolderIfNotExists(ctx, remotePath)
}

// DeleteFile deletes a single file at remotePath.
func (c *Client) DeleteFile(ctx context.Context, remotePath string) error {
	remotePath = cleanRemotePath(remotePath)
	c.dropLink(remotePath)
	params := url.Values{}
	params.Set("path", remotePath)
	var resp baseResponse
	return c.call(ctx, "/deletefile", params, &resp)
}

// DeleteFolderRecursive deletes a folder and its contents at remotePath.
func (c *Client) DeleteFolderRecursive(ctx context.Context, remotePath string) error {
	remotePath = cleanRemotePath(remotePath)
	c.forgetEnsured(remotePath)
	params := url.Values{}
	params.Set("path", remotePath)
	var resp baseResponse
	return c.call(ctx, "/deletefolderrecursive", params, &resp)
}

// Uploads.

// UploadOptions tunes an upload.
type UploadOptions struct {
	// ModTime, when non-zero, is recorded as the file modification time.
	ModTime time.Time
}

// UploadBytes uploads data to remotePath, creating parent folders as needed.
// The upload is retried on transient failures and verified against the
// size and SHA-1 checksum reported by pCloud.
func (c *Client) UploadBytes(ctx context.Context, remotePath string, data []byte, opts UploadOptions) (*Metadata, error) {
	dir, filename, err := splitUploadPath(remotePath)
	if err != nil {
		return nil, err
	}
	if err := c.MkdirAll(ctx, dir); err != nil {
		return nil, fmt.Errorf("pcloud mkdir %s: %w", dir, err)
	}
	sum := sha1.Sum(data)
	wantSHA1 := hex.EncodeToString(sum[:])

	var meta *Metadata
	err = c.retry(ctx, "/uploadfile", func() error {
		var uerr error
		meta, uerr = c.uploadOnce(ctx, dir, filename, bytes.NewReader(data), int64(len(data)), opts, func() string { return wantSHA1 })
		if uerr != nil && errors.Is(uerr, fs.ErrNotExist) {
			// The parent folder vanished since we created it: recreate it.
			c.forgetEnsured(dir)
			if merr := c.MkdirAll(ctx, dir); merr != nil {
				return merr
			}
			meta, uerr = c.uploadOnce(ctx, dir, filename, bytes.NewReader(data), int64(len(data)), opts, func() string { return wantSHA1 })
		}
		return uerr
	})
	if err != nil {
		return nil, err
	}
	return meta, nil
}

// UploadStream uploads exactly size bytes read from rd to remotePath. Small
// payloads are buffered and retried; larger ones are streamed without being
// held in memory and therefore cannot be retried.
func (c *Client) UploadStream(ctx context.Context, remotePath string, rd io.Reader, size int64, opts UploadOptions) (*Metadata, error) {
	if size < 0 {
		return nil, fmt.Errorf("pcloud: upload of %s requires a known size", remotePath)
	}
	if size <= maxBufferedUpload {
		data, err := io.ReadAll(io.LimitReader(rd, size+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != size {
			return nil, fmt.Errorf("%w: got %d bytes, expected %d", errSizeMismatch, len(data), size)
		}
		return c.UploadBytes(ctx, remotePath, data, opts)
	}

	dir, filename, err := splitUploadPath(remotePath)
	if err != nil {
		return nil, err
	}
	if err := c.MkdirAll(ctx, dir); err != nil {
		return nil, fmt.Errorf("pcloud mkdir %s: %w", dir, err)
	}
	er := &exactReader{r: rd, remaining: size, h: sha1.New()}
	return c.uploadOnce(ctx, dir, filename, er, size, opts, er.sum)
}

func splitUploadPath(remotePath string) (string, string, error) {
	remotePath = cleanRemotePath(remotePath)
	filename := path.Base(remotePath)
	if remotePath == "/" || filename == "." || filename == "" {
		return "", "", fmt.Errorf("pcloud: invalid file path %q", remotePath)
	}
	return path.Dir(remotePath), filename, nil
}

// exactReader yields exactly `remaining` bytes, failing if the source is
// shorter or longer, and hashes what it yields.
type exactReader struct {
	r         io.Reader
	remaining int64
	h         hash.Hash
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.remaining <= 0 {
		var probe [1]byte
		n, err := e.r.Read(probe[:])
		if n > 0 {
			return 0, errSizeMismatch
		}
		if err == nil {
			return 0, nil
		}
		if err == io.EOF {
			return 0, io.EOF
		}
		return 0, err
	}
	if int64(len(p)) > e.remaining {
		p = p[:e.remaining]
	}
	n, err := e.r.Read(p)
	e.h.Write(p[:n])
	e.remaining -= int64(n)
	if err == io.EOF {
		if e.remaining > 0 {
			return n, fmt.Errorf("%w: source ended %d bytes early", errSizeMismatch, e.remaining)
		}
		err = nil
	}
	return n, err
}

func (e *exactReader) sum() string { return hex.EncodeToString(e.h.Sum(nil)) }

// uploadOnce streams one multipart upload. wantSHA1 is evaluated after the
// body has been sent so that streaming sources can hash on the fly.
func (c *Client) uploadOnce(ctx context.Context, dir, filename string, body io.Reader, size int64, opts UploadOptions, wantSHA1 func() string) (*Metadata, error) {
	if err := c.ensureAuth(ctx); err != nil {
		return nil, err
	}
	accessToken, authToken := c.currentAuth()

	fields := url.Values{}
	if accessToken == "" && authToken != "" {
		// Multipart fields must precede the file part.
		fields.Set("auth", authToken)
	}
	prefix, suffix, contentType, err := multipartEnvelope(fields, filename)
	if err != nil {
		return nil, err
	}

	q := url.Values{}
	q.Set("path", dir)
	q.Set("filename", filename)
	q.Set("nopartial", "1")
	if !opts.ModTime.IsZero() && opts.ModTime.Unix() > 0 {
		q.Set("mtime", strconv.FormatInt(opts.ModTime.Unix(), 10))
	}

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	wd := c.newWatchdog(cancel)
	defer wd.stop()

	payload := &watchedUpload{r: io.MultiReader(bytes.NewReader(prefix), body, bytes.NewReader(suffix)), w: wd}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.apiURL("/uploadfile"), payload)
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = q.Encode()
	req.ContentLength = int64(len(prefix)) + size + int64(len(suffix))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", UserAgent)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	var resp baseResponse
	if err := c.doJSON(req, "/uploadfile", path.Join(dir, filename), &resp); err != nil {
		return nil, wd.wrap(err)
	}
	c.dropLink(path.Join(dir, filename))

	meta, err := resp.parseMetadata()
	if err != nil {
		return nil, fmt.Errorf("pcloud upload response: %w", err)
	}
	if meta != nil && !meta.IsFolder && meta.Size != size {
		return nil, fmt.Errorf("%w: pCloud stored %d bytes, expected %d", errChecksumMismatch, meta.Size, size)
	}
	if len(resp.Checksums) > 0 && resp.Checksums[0].SHA1 != "" {
		if want := wantSHA1(); !strings.EqualFold(resp.Checksums[0].SHA1, want) {
			return nil, fmt.Errorf("%w: sha1 %s, expected %s", errChecksumMismatch, resp.Checksums[0].SHA1, want)
		}
	}
	return meta, nil
}

func multipartEnvelope(fields url.Values, filename string) (prefix, suffix []byte, contentType string, err error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := mw.WriteField(k, fields.Get(k)); err != nil {
			return nil, nil, "", err
		}
	}
	if _, err := mw.CreateFormFile("file", filename); err != nil {
		return nil, nil, "", err
	}
	prefix = bytes.Clone(buf.Bytes())
	buf.Reset()
	if err := mw.Close(); err != nil {
		return nil, nil, "", err
	}
	suffix = bytes.Clone(buf.Bytes())
	return prefix, suffix, mw.FormDataContentType(), nil
}

// Downloads.

func (c *Client) dropLink(remotePath string) {
	c.mu.Lock()
	delete(c.links, remotePath)
	c.mu.Unlock()
}

func (c *Client) resolveDownloadURLs(ctx context.Context, remotePath string, forceRefresh bool) ([]string, error) {
	if !forceRefresh {
		c.mu.Lock()
		entry, ok := c.links[remotePath]
		c.mu.Unlock()
		if ok && time.Now().Before(entry.expiresAt) {
			return entry.urls, nil
		}
	}

	params := url.Values{}
	params.Set("path", remotePath)
	var resp baseResponse
	if err := c.call(ctx, "/getfilelink", params, &resp); err != nil {
		return nil, err
	}
	if len(resp.Hosts) == 0 || resp.Path == "" {
		return nil, fmt.Errorf("pcloud getfilelink returned an empty download link for %s", remotePath)
	}

	urls := make([]string, 0, len(resp.Hosts))
	for _, h := range resp.Hosts {
		if h != "" {
			urls = append(urls, c.scheme+"://"+h+resp.Path)
		}
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("pcloud getfilelink returned no usable host for %s", remotePath)
	}

	expiresAt := time.Now().Add(maxLinkTTL)
	if t, ok := parsePCloudTime(resp.Expires); ok {
		if e := t.Add(-linkExpiryMargin); e.Before(expiresAt) {
			expiresAt = e
		}
	}
	c.mu.Lock()
	c.links[remotePath] = downloadLink{urls: urls, expiresAt: expiresAt}
	c.mu.Unlock()
	return urls, nil
}

// OpenFile opens remotePath for reading. With a non-nil range, at most
// length bytes starting at offset are returned. Interrupted transfers are
// transparently resumed from the last byte received.
func (c *Client) OpenFile(ctx context.Context, remotePath string, offset int64, length int64) (io.ReadCloser, error) {
	remotePath = cleanRemotePath(remotePath)
	if length == 0 {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	end := int64(-1)
	if length > 0 {
		end = offset + length
	}
	r := &resumableReader{ctx: ctx, c: c, path: remotePath, offset: offset, end: end}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

type resumableReader struct {
	ctx     context.Context
	c       *Client
	path    string
	offset  int64 // absolute offset of the next byte to return
	end     int64 // absolute end (exclusive), -1 when unknown
	body    io.ReadCloser
	resumes int
	closed  bool
}

func (r *resumableReader) open() error {
	var body io.ReadCloser
	var total int64
	err := r.c.retry(r.ctx, "download", func() error {
		var err error
		body, total, err = r.c.openRange(r.ctx, r.path, r.offset, r.end)
		return err
	})
	if err != nil {
		return err
	}
	// Trust the length announced by the server: a truncated body is reported
	// by net/http as io.ErrUnexpectedEOF, and a short range means the file
	// ends there.
	if total >= 0 && (r.end < 0 || r.offset+total < r.end) {
		r.end = r.offset + total
	}
	r.body = body
	return nil
}

func (r *resumableReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, fs.ErrClosed
	}
	for {
		if r.end >= 0 && r.offset >= r.end {
			return 0, io.EOF
		}
		if r.body == nil {
			if err := r.open(); err != nil {
				return 0, err
			}
		}
		buf := p
		if r.end >= 0 && int64(len(buf)) > r.end-r.offset {
			buf = buf[:r.end-r.offset]
		}
		n, err := r.body.Read(buf)
		r.offset += int64(n)
		if err == nil {
			if n > 0 {
				r.resumes = 0
			}
			return n, nil
		}
		if err == io.EOF {
			if r.end < 0 || r.offset >= r.end {
				return n, io.EOF
			}
			err = io.ErrUnexpectedEOF
		}

		r.body.Close()
		r.body = nil
		if !isRetryable(err) || r.resumes >= r.c.maxRetries || r.ctx.Err() != nil {
			return n, err
		}
		r.resumes++
		r.c.logf("download of %s interrupted at byte %d, resuming: %v", r.path, r.offset, err)
		if n > 0 {
			return n, nil
		}
		if serr := r.c.sleep(r.ctx, r.c.backoff(r.resumes-1)); serr != nil {
			return 0, err
		}
	}
}

func (r *resumableReader) Close() error {
	r.closed = true
	if r.body != nil {
		err := r.body.Close()
		r.body = nil
		return err
	}
	return nil
}

// openRange issues one ranged GET, trying every download host in turn and
// refreshing the link once if it was rejected. It returns the body and the
// number of bytes it will yield (-1 if unknown).
func (c *Client) openRange(ctx context.Context, remotePath string, offset, end int64) (io.ReadCloser, int64, error) {
	urls, err := c.resolveDownloadURLs(ctx, remotePath, false)
	if err != nil {
		return nil, 0, err
	}

	refreshed := false
	var lastErr error
	for i := 0; i < len(urls); i++ {
		body, total, status, err := c.doDownload(ctx, urls[i], offset, end)
		if err == nil {
			return body, total, nil
		}
		lastErr = err
		switch {
		case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusGone:
			if refreshed {
				return nil, 0, err
			}
			refreshed = true
			c.dropLink(remotePath)
			if urls, err = c.resolveDownloadURLs(ctx, remotePath, true); err != nil {
				return nil, 0, err
			}
			i = -1
		case status == http.StatusNotFound:
			return nil, 0, ErrNotFound
		case status == http.StatusRequestedRangeNotSatisfiable:
			return io.NopCloser(bytes.NewReader(nil)), 0, nil
		case !isRetryable(err):
			return nil, 0, err
		}
	}
	return nil, 0, lastErr
}

func (c *Client) doDownload(ctx context.Context, dlURL string, offset, end int64) (io.ReadCloser, int64, int, error) {
	reqCtx, cancel := context.WithCancel(ctx)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, dlURL, nil)
	if err != nil {
		cancel()
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", UserAgent)
	ranged := offset > 0 || end >= 0
	if ranged {
		if end >= 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end-1))
		} else {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		cancel()
		return nil, 0, 0, redactError(err, true)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		resp.Body.Close()
		cancel()
		return nil, 0, resp.StatusCode, &HTTPStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(msg))}
	}

	wd := c.newWatchdog(cancel)
	body := io.ReadCloser(&watchedBody{rc: resp.Body, w: wd})
	total := resp.ContentLength

	if ranged && resp.StatusCode == http.StatusOK && offset > 0 {
		// The server ignored the Range header: skip to the requested offset.
		if _, err := io.CopyN(io.Discard, body, offset); err != nil {
			body.Close()
			if errors.Is(err, io.EOF) {
				return io.NopCloser(bytes.NewReader(nil)), 0, resp.StatusCode, nil
			}
			return nil, 0, resp.StatusCode, err
		}
		if total >= 0 {
			total -= offset
		}
	}
	if end >= 0 {
		want := end - offset
		if total < 0 || total > want {
			total = want
		}
	}
	return body, total, resp.StatusCode, nil
}

func cleanRemotePath(p string) string {
	if p == "" {
		return "/"
	}
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}
