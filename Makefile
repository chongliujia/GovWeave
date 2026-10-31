.PHONY: run build test check package demo demo-tools demo-agent demo-sensitive demo-output-governance demo-output-assessment demo-tool-assessment demo-application-assessment evaluate-agent validate-sensitive validate-canary benchmark-canary validate-routing

run:
	go run ./cmd/govweave -config examples/deployment.json

build:
	CGO_ENABLED=0 go build -trimpath -o bin/govweave ./cmd/govweave

demo: build
	python3 scripts/demo-assessment.py

demo-tools: build
	python3 scripts/demo-tools.py

demo-agent: build
	python3 scripts/demo-agent.py

demo-sensitive: build
	python3 scripts/demo-sensitive.py
	python3 scripts/demo-sensitive.py --detector sensitive-text-v2

demo-output-governance: build
	python3 scripts/demo-output-governance.py

demo-output-assessment: build
	python3 scripts/demo-output-assessment.py

demo-tool-assessment: build
	python3 scripts/demo-tool-assessment.py

demo-application-assessment: build
	python3 scripts/demo-application-assessment.py

evaluate-agent: build
	python3 scripts/eval-knowledge-agent.py

.PHONY: accept-agent
accept-agent: build
	python3 scripts/accept-knowledge-agent.py

.PHONY: validate-task-grading
validate-task-grading:
	python3 scripts/eval-task-grading.py

.PHONY: demo-support-agent
demo-support-agent: build
	python3 scripts/trial-support-agent.py

.PHONY: demo-multi-agent-trace
demo-multi-agent-trace: build
	python3 scripts/demo-multi-agent-trace.py

FRAMEWORK_PYTHON ?= python3
.PHONY: trial-framework-trace
trial-framework-trace: build
	$(FRAMEWORK_PYTHON) scripts/trial-framework-trace.py

.PHONY: evaluate-agent-controls
evaluate-agent-controls: build
	python3 scripts/eval-knowledge-agent.py --corpus v2 --controls baseline
	python3 scripts/eval-knowledge-agent.py --corpus v2 --controls instructions-v1

.PHONY: evaluate-agent-reviews
evaluate-agent-reviews: build
	python3 scripts/eval-knowledge-agent.py --corpus v3 --controls instructions-v1
	python3 scripts/eval-knowledge-agent.py --corpus v3 --controls instructions-v2
	python3 scripts/eval-knowledge-agent.py --corpus v3 --controls instructions-v2-reviewed

validate-sensitive:
	go run ./cmd/sensitive-eval
	go run ./cmd/sensitive-eval -detector sensitive-text-v2
	go run ./cmd/sensitive-eval -corpus tests/testdata/sensitive-validation-v2.json
	go run ./cmd/sensitive-eval -detector sensitive-text-v2 -corpus tests/testdata/sensitive-validation-v2.json

.PHONY: validate-sensitive-v3
validate-sensitive-v3:
	go run ./cmd/sensitive-eval -detector sensitive-text-v2 -corpus tests/testdata/sensitive-validation-v3.json
	go run ./cmd/sensitive-eval -detector sensitive-text-v3 -corpus tests/testdata/sensitive-validation-v3.json
	go run ./cmd/sensitive-eval -detector sensitive-text-v3 -corpus tests/testdata/sensitive-validation-v1.json
	go run ./cmd/sensitive-eval -detector sensitive-text-v3 -corpus tests/testdata/sensitive-validation-v2.json

validate-canary:
	go run ./cmd/canary-eval
	go run ./cmd/canary-eval -corpus tests/testdata/canary-validation-v2.json

benchmark-canary:
	go run ./cmd/canary-bench
	go run ./cmd/canary-bench -corpus tests/testdata/canary-validation-v2.json

validate-routing:
	go run ./cmd/canary-bench -routing -corpus tests/testdata/canary-validation-v3.json

test:
	go test -race ./...

check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
	node --check internal/server/web/app.js
	node --check internal/server/web/gateway.js
	node --check internal/server/web/integration.js
	node --check internal/server/web/evidence.js
	node --check internal/server/web/policies.js
	node --check internal/server/web/i18n.js
	node tests/i18n-check.cjs

package:
	sh scripts/package-offline.sh
