# Module Not Instantiated Fix

## Problem

After fixing the namespace issue, a new error appeared:
```
[ERRO] failed to get plugin metadata: failed to create plugin instance: 
      module[env] not instantiated
```

## Root Cause

When a plugin is loaded, the terminal first calls the `meta` export to get plugin information. During this **metadata call**, it only provides **dummy host functions** for basic operations:

```go
if isMetaCall {
    return []extism.HostFunction{
        p.NewDummyHostFunction("log_record"),
        p.NewDummyHostFunction("http_request"),
    }, nil
}
```

However, the **generic plugin declares WebSocket host function imports at the module level**:

```go
//go:wasmimport env ws_connect
func hostWSConnect(uint64) uint64

//go:wasmimport env ws_send
func hostWSSend(uint64) uint64

//go:wasmimport env ws_receive
func hostWSReceive(uint64) uint64

//go:wasmimport env ws_close
func hostWSClose(uint64) uint64

//go:wasmimport env publish_stream_data
func hostPublishStreamData(uint64) uint64
```

These imports are **required at module instantiation** (before any function is called), even if they're never used during the metadata call. Since they weren't provided, the `env` module couldn't be instantiated.

## Solution

Add **dummy WebSocket host functions** for metadata calls in `/home/pk/golang/plusev/terminal/datasrc/plugin/manager.go`:

```go
if isMetaCall {
    return []extism.HostFunction{
        p.NewDummyHostFunction("log_record"),
        p.NewDummyHostFunction("http_request"),
        p.NewDummyHostFunction("ws_connect"),         // ✅ Added
        p.NewDummyHostFunction("ws_send"),            // ✅ Added
        p.NewDummyHostFunction("ws_receive"),         // ✅ Added
        p.NewDummyHostFunction("ws_close"),           // ✅ Added
        p.NewDummyHostFunction("publish_stream_data"), // ✅ Added
    }, nil
}
```

### What Are Dummy Host Functions?

Dummy host functions are placeholder implementations that satisfy WASM module instantiation but aren't actually called. They're used during metadata extraction where the plugin shouldn't need to make network calls or use advanced features.

A dummy function typically:
```go
func NewDummyHostFunction(name string) extism.HostFunction {
    return extism.NewHostFunctionWithStack(
        name,
        func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
            // Do nothing - just return success
            stack[0] = 0
        },
        []extism.ValueType{extism.ValueTypeI64},
        []extism.ValueType{extism.ValueTypeI64},
    )
}
```

## Why This Happens

### WASM Module Instantiation
When a WASM module is loaded:
1. All `//go:wasmimport` declarations are checked
2. The runtime verifies all imported functions exist
3. **Only then** can the module be instantiated
4. **Only then** can you call exports like `meta`

### Plugin Lifecycle
```
1. Load WASM file
2. Check imports (ws_connect, ws_send, etc. must exist)  ← Error happened here
3. Instantiate module
4. Call "meta" export
5. Read metadata
```

### Why Not Remove Imports from Plugin?

We **can't conditionally import** host functions in Go WASM. The `//go:wasmimport` directives are compile-time declarations, not runtime imports. All declared imports must be satisfied when the module loads.

## Alternative Approaches (Not Used)

### 1. Separate Metadata Module
Create a separate `meta.wasm` that only has `plugin_info` export and no host function imports. This is cleaner but requires maintaining two WASM files.

### 2. Lazy Loading Pattern
Use function pointers and late binding, but Go's WASM doesn't support this well.

### 3. Plugin-Specific Metadata Check
Check if plugin needs WebSocket before adding dummies, but this defeats the purpose of generic loading.

## Best Practice

**Always provide dummy host functions for ALL imports during metadata calls**, even if they won't be used. This ensures any plugin (old interface or new generic interface) can be loaded for metadata extraction.

## Files Changed

1. `/home/pk/golang/plusev/terminal/datasrc/plugin/manager.go`
   - Added 5 dummy WebSocket host functions to `isMetaCall` branch
   - Now provides: `log_record`, `http_request`, `ws_connect`, `ws_send`, `ws_receive`, `ws_close`, `publish_stream_data`

## Testing

After this fix, the plugin should load successfully:
```bash
plusev plugin install woox-plugin-generic.wasm
```

The metadata should be extracted without errors, and the actual WebSocket host functions (with real implementations) will be provided when the plugin is used for streaming.
