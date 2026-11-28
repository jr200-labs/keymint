OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')

.DEFAULT_GOAL := all

.PHONY: all fmt test test-all lint build clean hooks-install hooks-run

all: fmt lint build

fmt:
	cargo fmt --all

test:
	cargo test --locked

test-all: test

lint:
	cargo fmt --all --check
	cargo clippy --locked --all-targets -- -D warnings

build:
	cargo build --release --locked
	mkdir -p build
	cp target/release/keymint build/keymint-$(OS)-$(ARCH)

clean:
	rm -rf build
	cargo clean

hooks-install:
	pre-commit install
	pre-commit install --hook-type commit-msg

hooks-run:
	pre-commit run --all-files
