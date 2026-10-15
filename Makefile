.PHONY: run build test check package

run:
	go run ./cmd/govweave -config examples/deployment.json

build:
	CGO_ENABLED=0 go build -trimpath -o bin/govweave ./cmd/govweave

test:
	go test -race ./...

check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
	node --check internal/server/web/app.js
	node --check internal/server/web/gateway.js
	node --check internal/server/web/policies.js
	node --check internal/server/web/i18n.js
	node tests/i18n-check.cjs

package:
	sh scripts/package-offline.sh
