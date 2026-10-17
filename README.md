# pCloud Integration for Plakar

This package provides a [Plakar](https://plakar.io) integration for **pCloud**, implementing all three Plakar connector types:

- **Importer** (`pcloud-importer`): Back up files and directories from pCloud into a Kloset repository.
- **Exporter** (`pcloud-exporter`): Restore snapshots from a Kloset repository directly to pCloud.
- **Storage** (`pcloud-storage`): Host a Kloset repository directly on pCloud.

Both **US** (`api.pcloud.com`) and **EU** (`eapi.pcloud.com`) pCloud data regions are supported, as well as OAuth2 access tokens (`access_token`), session tokens (`auth`), and digest authentication (`username` + `password`).

---

## Requirements

- Go 1.25 or later
- `plakar` CLI installed and available in `$PATH`

---

## Project Layout

```text
.
├── client.go                  # pCloud HTTP API client (US/EU, OAuth2 & Digest auth)
├── connector.go               # Shared connector configuration & registration
├── importer.go                # Importer implementation (backup from pCloud)
├── exporter.go                # Exporter implementation (restore to pCloud)
├── storage.go                 # Storage backend implementation (Kloset store on pCloud)
├── connector_test.go          # Unit & integration tests against a mock pCloud server
├── cmd/
│   ├── importer/
│   │   ├── main.go            # Importer entrypoint
│   │   └── schema.json        # Importer config JSON Schema validator
│   ├── exporter/
│   │   ├── main.go            # Exporter entrypoint
│   │   └── schema.json        # Exporter config JSON Schema validator
│   └── storage/
│       ├── main.go            # Storage entrypoint
│       └── schema.json        # Storage config JSON Schema validator
├── manifest.yaml              # Plakar plugin manifest
├── Makefile                   # Build, package, install, and test targets
├── go.mod
└── go.sum
```

---

## Build, Package & Install

Build the connector binaries, create the `.ptar` package, and install it into Plakar in one step:

```bash
make install
```

Or step by step:

```bash
# 1. Compile the 3 executables
make build

# 2. Package into pcloud_v1.0.0_<os>_<arch>.ptar
make package

# 3. Install unsigned local build
plakar pkg add -allow-unsigned ./pcloud_v1.0.0_*.ptar

# 4. Verify installation
plakar pkg show
```

To update an existing installation:

```bash
make reinstall
```

---

## Configuration Options

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `location` | Yes | — | pCloud URI, e.g. `pcloud:///Documents`, `pcloud://eu/Backups`, or `pcloud://api.pcloud.com/Photos` |
| `access_token` | Cond. | — | pCloud OAuth2 access token (recommended) |
| `auth` | Cond. | — | pCloud session authentication token |
| `username` | Cond. | — | pCloud account email (used with `password` for SHA-1 digest login) |
| `password` | Cond. | — | pCloud account password (used with `username`) |
| `region` | No | `us` | pCloud region: `us` (`api.pcloud.com`) or `eu` (`eapi.pcloud.com`) |
| `root` | No | `/` | Override root path inside pCloud |
| `endpoint` | No | — | Custom API endpoint host (for testing/emulators) |
| `insecure` | No | `false` | Use plain HTTP instead of HTTPS (for local testing only) |

> **Authentication:** Provide at least one of `access_token`, `auth`, or the pair `username` + `password`.

---

## Usage Examples

### 1. Back up a pCloud folder (Importer)

```bash
# Configure a pCloud source (EU region with OAuth2 token)
plakar source add mypcloud pcloud://eu/Documents access_token=YOUR_ACCESS_TOKEN

# Run a backup into a local Kloset repository
plakar at /var/backups backup @mypcloud
```

Or using username/password digest authentication:

```bash
plakar source add mypcloud pcloud:///Documents region=eu username=user@example.com password=YOUR_PASSWORD
plakar at /var/backups backup @mypcloud
```

### 2. Restore a snapshot to pCloud (Exporter)

```bash
# Configure a pCloud destination
plakar destination add mypclouddst pcloud://eu/Restored access_token=YOUR_ACCESS_TOKEN

# Restore a snapshot to pCloud
plakar at /var/backups restore -to @mypclouddst <snapshot_id>
```

### 3. Host a Kloset repository on pCloud (Storage)

```bash
# Configure a pCloud store
plakar store add mypcloudstore pcloud://eu/PlakarRepo access_token=YOUR_ACCESS_TOKEN

# Initialize the Kloset repository on pCloud
plakar at @mypcloudstore create

# Back up a local directory directly to pCloud storage
plakar at @mypcloudstore backup ~/Documents
```

---

## Running Tests

```bash
make test
```

## License

ISC
