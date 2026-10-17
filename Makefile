GO	= go
EXT	=

PLAKAR	= plakar
VERSION	= v1.0.0

FUZZTIME = 30s

all: build

build:
	${GO} build -v -o pcloud-importer${EXT} ./cmd/importer
	${GO} build -v -o pcloud-exporter${EXT} ./cmd/exporter
	${GO} build -v -o pcloud-storage${EXT} ./cmd/storage

package: build
	rm -f pcloud_${VERSION}_*.ptar
	${PLAKAR} pkg create ./manifest.yaml ${VERSION}

uninstall:
	-${PLAKAR} pkg rm pcloud

install: package
	${PLAKAR} pkg add -allow-unsigned ./pcloud_${VERSION}_*.ptar

reinstall: uninstall install

test:
	${GO} test -race -shuffle=on -count=1 ./...

test-short:
	${GO} test -short -count=1 ./...

# Requires PCLOUD_ACCESS_TOKEN and/or PCLOUD_USERNAME + PCLOUD_PASSWORD,
# and optionally PCLOUD_REGION=eu.
test-live:
	${GO} test -tags live -count=1 -run TestLive -v .

cover:
	${GO} test -count=1 -coverprofile=coverage.out .
	${GO} tool cover -func=coverage.out | tail -1

fuzz:
	for f in $$(${GO} test -list '^Fuzz' . | grep ^Fuzz); do \
		${GO} test -run '^$$' -fuzz "^$$f$$" -fuzztime ${FUZZTIME} . || exit 1; \
	done

lint:
	test -z "$$(gofmt -l .)" || (gofmt -l . && false)
	${GO} vet ./...
	${GO} vet -tags live ./...
	${GO} run honnef.co/go/tools/cmd/staticcheck@latest ./...

vuln:
	${GO} run golang.org/x/vuln/cmd/govulncheck@latest ./...

validate:
	${GO} run github.com/PlakarKorp/pkg/cmd/validator@latest repo .

check: lint test validate

clean:
	rm -f pcloud-importer${EXT} pcloud-exporter${EXT} pcloud-storage${EXT} pcloud_*.ptar coverage.out

.PHONY: all build package uninstall install reinstall test test-short test-live cover fuzz lint vuln validate check clean
