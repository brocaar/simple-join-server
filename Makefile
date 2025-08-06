.PHONY: dist
PKG_VERSION := $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')

# Compile the binaries for all targets.
build: \
	build-x86_64-unknown-linux-musl

build-x86_64-unknown-linux-musl:
	cross build --target x86_64-unknown-linux-musl --release
