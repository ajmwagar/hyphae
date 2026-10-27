# hyphae — generated assets are reproducible from source

.PHONY: logo
logo:
	python3 tools/gen_logo.py docs/img/hyphae-logo.svg

.PHONY: check test
check:
	cargo check --workspace

test:
	cargo test --workspace
