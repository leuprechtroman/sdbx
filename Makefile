VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo 0.1.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unbekannt)
LDFLAGS := -s -w -X sdbx/internal/version.Version=$(VERSION) -X sdbx/internal/version.Commit=$(COMMIT)
export CGO_ENABLED=0

.PHONY: build test escape race cover golden cross clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/sdbx ./cmd/sdbx

test:
	go vet ./...
	go test ./...

# Ausbruchstests: echtes Binary gegen echte Sandbox, als normaler Nutzer (nicht root)
escape:
	go test -tags escape -count=1 -v ./test/escape/

# Race-Detector braucht cgo; Builds bleiben statisch (CGO_ENABLED=0 oben).
race:
	CGO_ENABLED=1 go test -race ./...

# Coverage aus Unit-Tests plus Ausbruchstests (instrumentiertes Binary); Prozesse in der Sandbox schreiben keine Daten
cover:
	rm -rf cover && mkdir -p cover/unit cover/escape
	go test -cover -coverpkg=sdbx/... ./... -args -test.gocoverdir=$(CURDIR)/cover/unit
	GOCOVERDIR=$(CURDIR)/cover/escape go test -tags escape -count=1 -v ./test/escape/
	go tool covdata textfmt -i=cover/unit,cover/escape -o cover/cover.out
	go tool cover -func=cover/cover.out | tail -1

# Seatbelt-Golden-Datei nach beabsichtigten Profiländerungen aktualisieren
golden:
	go test ./internal/backend/darwin/ -update

cross:
	GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/sdbx-linux-amd64  ./cmd/sdbx
	GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/sdbx-linux-arm64  ./cmd/sdbx
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/sdbx-darwin-arm64 ./cmd/sdbx
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/sdbx-darwin-amd64 ./cmd/sdbx
	cd dist && (command -v sha256sum >/dev/null && sha256sum sdbx-* || shasum -a 256 sdbx-*) > SHA256SUMS

clean:
	rm -rf bin dist cover
