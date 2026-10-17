GO	= go
EXT	=

PLAKAR	= plakar
VERSION	= v1.0.0

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
	${GO} test -v ./...

check: test

clean:
	rm -f pcloud-importer${EXT} pcloud-exporter${EXT} pcloud-storage${EXT} pcloud_*.ptar

.PHONY: all build package uninstall install reinstall test check clean
