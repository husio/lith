VERSION = $(shell git rev-parse --short HEAD)

# Switch to docker if it is the preferred tool. It would be nice to detect this
# during the runtime instead of hardcoded value.
CONTAINER_ENGINE=podman

all: help

help:
	@echo
	@echo "Commands"
	@echo "========"
	@echo
	@sed -n '/^[a-zA-Z0-9_-]*:/s/:.*//p' < Makefile | grep -v -E 'default|help.*' | sort


build: build-lith

build-%:
	mkdir -p bin
	CGO_ENABLED=1 go build -ldflags="-X 'main.sourceHash=${VERSION}'" -o bin/${*} github.com/husio/lith/cmd/${*}

vendor:
	go mod tidy && go mod vendor && go mod verify

container-image:
	$(CONTAINER_ENGINE) build -t "lith:${VERSION}" -t "lith:latest" .

run-lith:
	@# In order to run with live reload, install cespare/reflex
	@# https://github.com/cespare/reflex
	reflex -s -- sh -c 'go run github.com/husio/lith/cmd/lith -conf examples/lith.conf serve'

run-monitor-queue:
	@echo
	@echo "Running Task Queue Info server on http://localhost:8085"
	@go run github.com/husio/lith/cmd/lith -conf examples/lith.conf taskqueueinfo

run-test-mailserver:
	@echo
	@echo
	@echo "Running UI on http://localhost:8025"
	@echo "Running SMTP server on localhost:11025"
	@echo
	@echo
	$(CONTAINER_ENGINE) run -p 11025:1025 -p 8025:8025 mailhog/mailhog

run-demo: build-lith
	@bin/lith -conf examples/lith.conf useradd -email admin@example.com -password "admin" -groups=1,2 -allow-insecure 2> /dev/null || true
	@echo ""
	@echo ""
	@echo "Running public UI on http://localhost:8000/login/"
	@echo "Running admin panel on http://localhost:8001"
	@echo "Emails are written to /tmp/lith_outgoing_emails/"
	@echo ""
	@echo "Admin credentials are"
	@echo "      email:  admin@example.com"
	@echo "   password:  admin"
	@echo ""
	@echo ""
	@echo "Press Ctrl+c to stop the application."
	@bin/lith -conf examples/lith.conf serve

test:
	go test -race -test.timeout 4m github.com/husio/lith/...

translations-collect: build-translations-collect
	bin/translations-collect -dir app/lith -o app/lith/po/en.pot
	find app/lith/po/ -name '*.po' -exec msgmerge --no-wrap --add-location --sort-output --update {} app/lith/po/en.pot \;

translations-edit:
	poedit .


.PHONY: help tasks vendor container-image run-server test
