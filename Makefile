BUILD_MODE ?= dev

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: wasm
wasm: ## Build the wasm bits
wasm:
	cargo clean
	cd wasm && wasm-pack build --target web --$(BUILD_MODE) --no-typescript --no-pack && rm pkg/.gitignore

.PHONY: web
web: ## Build the web things
web: wasm
	rm -rf target/web && mkdir -p target/web
	rsync -av static/* target/web/
	rsync -av wasm/pkg/* target/web/

.PHONY: serve
serve: ## Run the webserver
serve:
	python -m http.server --directory target/web