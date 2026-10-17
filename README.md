# pCloud Integration for Plakar

This package provides a [Plakar](https://plakar.io) integration for
[pCloud](https://www.pcloud.com), implementing the three Plakar connector types:

- **Importer** (`pcloud-importer`): back up files and folders stored on pCloud.
- **Exporter** (`pcloud-exporter`): restore snapshots directly to pCloud.
- **Storage** (`pcloud-storage`): host a Kloset repository on pCloud.

Both pCloud data regions are supported: **US** (`api.pcloud.com`) and **EU**
(`eapi.pcloud.com`).

The storage connector talks to the pCloud API directly. Unlike a repository
placed in a folder synchronized by the pCloud Drive desktop app, it never keeps
a local copy of the repository: backups do not consume local disk space.

---

## Requirements

- Go 1.26 or later (to build)
- `plakar` v1.1 or later

## Build, package and install

```bash
make install        # build, package and install the unsigned local build
```

Or step by step:

```bash
make build                                         # compile the 3 executables
make package                                       # create pcloud_v1.1.0_<os>_<arch>.ptar
plakar pkg add -allow-unsigned ./pcloud_v1.1.0_*.ptar
plakar pkg show
```

Use `make reinstall` to replace an existing installation.

---

## Configuration

| Parameter      | Required | Default  | Description |
|----------------|----------|----------|-------------|
| `location`     | yes      | —        | `pcloud://[us\|eu\|api.pcloud.com\|eapi.pcloud.com]/path`. Any other host part is the first folder of the path: `pcloud://Documents/Notes` is `/Documents/Notes`. |
| `access_token` | one of   | —        | OAuth2 access token (recommended). |
| `auth`         | one of   | —        | pCloud session token. |
| `username`     | one of   | —        | Account email, used with `password` (digest login). |
| `password`     | one of   | —        | Account password, used with `username`. |
| `region`       | no       | `us`     | `us` or `eu`. Overridden by an explicit region in `location`. |
| `root`         | no       | `/`      | Absolute pCloud path, overriding the path of `location`. |
| `cache_size`   | no       | `256MiB` | *Storage only.* Memory budget for caching ranged packfile reads (`64MiB`, `1GB`, `0` to disable). |
| `debug`        | no       | `false`  | Verbose logging to stderr (also enabled by `PLAKAR_PCLOUD_DEBUG=1`). Credentials are never logged. |
| `endpoint`     | no       | —        | *Testing only.* API `host[:port]` of a pCloud emulator. |
| `insecure`     | no       | `false`  | *Testing only.* Plain HTTP; refused unless `endpoint` is set. |

### Authentication

Provide exactly one of `access_token`, `auth`, or `username` + `password`.

- **OAuth2 access token (recommended).** It is the only method that works with
  two-factor authentication. pCloud OAuth tokens do not expire. To obtain one,
  run `rclone authorize "pcloud"`, log in in the browser window that opens, and
  copy the `access_token` value from the JSON printed in the terminal. You can
  also register your own application at <https://docs.pcloud.com/my_apps/>.
  A token only works on its account's region: EU accounts need `pcloud://eu/...`
  or `region=eu`, otherwise pCloud answers `2094 Invalid 'access_token'`.
- **Session token (`auth`).** A session token (40 characters, obtained from a
  `userinfo?getauth=1` login) is not an OAuth token: pass it as `auth=...`, not
  `access_token=...`. It expires after 31 days without use by default.
- **Username and password.** The connector performs a digest login. The session
  it creates is invalidated when the connector closes. A rejected login is never
  retried, because pCloud bans the IP address after too many failed attempts.
  Two-factor authentication is not supported by this method.

### Security

- The OAuth token travels only in the `Authorization` header. Session tokens and
  password digests travel only in POST bodies. No credential ever appears in a
  URL, a log line or an error message.
- Credentials can only reach the official pCloud API hosts. A custom host must be
  set explicitly with `endpoint`, and plain HTTP is refused for official hosts.
- Credentials embedded in the location (`pcloud://user:pass@...`) are rejected.
  Prefer `plakar store add ... access_token=...` so the secret is not stored in
  the location string.

---

## Usage

### Back up a pCloud folder (importer)

```bash
plakar source add mypcloud pcloud://eu/Documents access_token=YOUR_TOKEN
plakar at /var/backups backup @mypcloud
```

### Restore a snapshot to pCloud (exporter)

```bash
plakar destination add mypclouddst pcloud://eu/Restored access_token=YOUR_TOKEN
plakar at /var/backups restore -to @mypclouddst <snapshot_id>
```

### Host a Kloset repository on pCloud (storage)

```bash
plakar store add mypcloudstore pcloud://eu/PlakarRepo access_token=YOUR_TOKEN
plakar at @mypcloudstore create
plakar at @mypcloudstore backup ~/Documents
```

---

## Behaviour and limitations

- **No local disk usage.** The storage connector never writes repository data
  to disk. Ranged reads of packfiles (used by `plakar ls`, `plakar ui`, restores)
  are served from a bounded in-memory cache of 1 MiB blocks, sized by
  `cache_size`. Uploads are held in memory only up to one packfile.
- **Robust transfers.** Transient failures (network errors, HTTP 429/5xx, pCloud
  4xxx/5xxx errors) are retried with exponential backoff. Interrupted or stalled
  downloads resume from the last received byte. Every upload is verified against
  the size and SHA-1 checksum reported by pCloud.
- **Large files** are streamed without being buffered. Files up to 8 MiB are
  retried as a whole on failure. Larger files cannot be replayed and are
  reported as failed if the transfer breaks.
- **Restores** preserve file modification times. pCloud has no symbolic links or
  special files: those entries are reported as unsupported instead of being
  silently skipped.
- **pCloud trash and revisions.** Files deleted by Plakar maintenance go to the
  pCloud trash and stay restorable during its retention period. Overwritten files
  keep a revision. Trash and revisions do not count against your storage quota
  but have their own limits, beyond which pCloud purges the oldest entries.
- **Names.** pCloud names are case-sensitive and cannot contain `/`, `\` or NUL.

---

## Development

```bash
make test         # unit, regression and end-to-end tests with the race detector
make test-short   # skip the slower tests
make cover        # coverage summary
make fuzz         # run every fuzz target (FUZZTIME=30s each)
make lint         # gofmt, go vet, staticcheck
make vuln         # govulncheck
make validate     # Plakar manifest and schema validator
make check        # lint + test + validate
```

Tests run against an in-memory pCloud emulator (`fake_server_test.go`) that can
inject faults: HTTP errors, API errors, broken or stalled transfers, expired
download links, unreachable download hosts and corrupted checksums. Tests are
organized as follows:

- `client_test.go`, `storage_test.go`, `importer_test.go`, `exporter_test.go`
  and `connector_test.go` test each component.
- `regression_test.go` pins every defect fixed after the security audit.
- `e2e_test.go` backs up a pCloud folder into an encrypted Kloset repository
  hosted on pCloud, reopens it and restores it with the three connectors.
- `fuzz_test.go` checks path cleaning, restore containment, location parsing
  and the block cache.

Live tests against the real pCloud API run in a temporary folder that is deleted
afterwards:

```bash
PCLOUD_ACCESS_TOKEN=... PCLOUD_REGION=eu make test-live
PCLOUD_USERNAME=... PCLOUD_PASSWORD=... PCLOUD_REGION=eu make test-live
```

## License

ISC
