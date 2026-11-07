SHELL := /bin/bash
DIGEST ?=
VENV := .venv/bin

.PHONY: tools venv test scan opa-test mocks tunnel verify kind-up demo-good demo-unsigned demo-sde release

tools:            ## pinned, checksum-verified scanners/verifiers into ~/.local/bin
	scripts/install-tools.sh

venv:
	python3 -m venv .venv
	$(VENV)/pip install -q --require-hashes -r requirements.txt
	$(VENV)/pip install -q -r requirements-dev.txt -r mocks/requirements.txt

test: venv opa-test      ## app + mock unit tests + policy tests
	$(VENV)/pytest -q app mocks

opa-test:
	opa test policy/ -v

scan:             ## same scans + OPA build gate as CI, against a local build
	docker build -q -t lab-app:local .
	scripts/scan.sh lab-app:local

mocks:            ## mock ServiceNow + SD Elements on :8000 (tokens from mocks/.env.local)
	set -a; . mocks/.env.local; set +a; $(VENV)/uvicorn mocks.main:app --host 127.0.0.1 --port 8000

tunnel:           ## public URL for Actions -> set it as the `release` env var MOCK_URL
	cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8000

verify:           ## make verify DIGEST=sha256:...  (what release.yml does, locally)
	scripts/verify.sh $(DIGEST)
	python3 scripts/bundle.py evidence $(DIGEST) > evidence/evidence.json
	opa eval --format pretty -d policy/release.rego -d policy/thresholds.json -i evidence/evidence.json data.release.decision

release:          ## make release DIGEST=sha256:...
	gh workflow run release.yml -f digest=$(DIGEST)

kind-up:
	deploy/up.sh

demo-good:        ## make demo-good DIGEST=sha256:...
	deploy/demo.sh good $(DIGEST)

demo-unsigned:
	deploy/demo.sh unsigned

demo-sde:         ## developer tries to mark T-SAST Complete
	scripts/sde-breakit.sh $(DIGEST)
