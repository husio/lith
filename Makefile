VERSION = $(shell git rev-parse --short HEAD)

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

docker-image:
	docker build -t "lith:${VERSION}" -t "lith:latest" .

run-lith:
	@# https://github.com/cespare/reflex
	reflex -s -R examples/ -- sh -c 'go run github.com/husio/lith/cmd/lith -conf examples/lith.conf serve'

run-monitor-queue:
	watch 'echo "select * from failures order by created_at desc limit 2" | sqlite3 /tmp/lith_taskqueue.sqlite3.db'

run-test-mailserver:
	@# 1025 is SMTP port, 8025 is for HTTP interface
	docker run -p 11025:1025 -p 8025:8025 mailhog/mailhog

test:
	go test -race -test.timeout 4m github.com/husio/lith/...

translations-collect: build-translations-collect
	bin/translations-collect -dir app/lith -o app/lith/po/en.pot
	find app/lith/po/ -name '*.po' -exec msgmerge --no-wrap --add-location --sort-output --update {} app/lith/po/en.pot \;

translations-edit:
	poedit .


.PHONY: help tasks vendor docker-image run-server test
