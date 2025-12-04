.PHONY: dist
PKG_VERSION := $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')

# Compile the binaries for all targets.
build: \
	build-x86_64-unknown-linux-musl

build-x86_64-unknown-linux-musl:
	cross build --target x86_64-unknown-linux-musl --release

# Dependencies
dev-dependencies:
	cargo install cross --git https://github.com/cross-rs/cross --rev c7dee4d008475ce1c140773cbcd6078f4b86c2aa --locked
