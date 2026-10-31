# Dummy Exchange Data Source Plugin

This folder is a **template** for a Plusev `datasrc` plugin.

- It registers a plugin in `init()`
- Implements the required lifecycle methods
- Exposes standard datasource commands:
  - `getMarkets`
  - `getTimeframes`
  - `getOHLCV`

Everything returns dummy data so you can replace the internals with a real exchange client.

## Files

- `main.go`: complete minimal plugin + dummy exchange implementation

## Build

Your other plugins in this workspace build via `build.sh` at repo root.

For a new plugin repo, you typically:

1) create `go.mod`
2) run `go mod tidy`
3) compile to WASM (often TinyGo)

If you tell me which toolchain you use (TinyGo vs Go wasm) and the expected output filename (e.g. `plugin.wasm`), I’ll add an exact `build.sh` here.
