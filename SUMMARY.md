# Generic Plugin Integration - Complete Fix Summary

## Overview

Successfully integrated the generic plugin system with the WooX datasource plugin. Fixed multiple issues related to WASM host function imports and plugin lifecycle.

## Issues Fixed

### 1. ❌ Invalid WASM Import (String Return Types)
**Error**: `go:wasmimport: unsupported result type string`

**Problem**: Used string return types in wasmimport declarations
```go
//go:wasmimport env ws_connect
func hostWSConnect(request string) string  // ❌ WASM doesn't support this
```

**Fix**: Use memory-based communication with uint64 offsets
```go
//go:wasmimport env ws_connect
func hostWSConnect(uint64) uint64  // ✅ Pass/return memory offsets

func wsConnect(url string, headers map[string]string) (string, error) {
    mem, _ := pdk.AllocateJSON(req)        // Allocate in memory
    ptr := hostWSConnect(mem.Offset())      // Call host (pass offset)
    rmem := pdk.FindMemory(ptr)             // Read response
    // Parse and return...
}
```

**See**: `WASMIMPORT_FIX.md`

---

### 2. ❌ Wrong Host Function Namespace
**Error**: `"ws_connect" is not exported in module "extism:host/user"`

**Problem**: Plugin used wrong namespace
```go
//go:wasmimport extism:host/user ws_connect  // ❌ Terminal doesn't use this
```

**Fix**: Use default `env` namespace (matches terminal)
```go
//go:wasmimport env ws_connect  // ✅ Terminal registers in 'env'
```

**See**: `NAMESPACE_FIX.md`

---

### 3. ❌ Missing `publish_stream_data` Host Function
**Error**: Plugin calls undefined host function

**Problem**: Plugin needs `publish_stream_data` to send data to actor system, but terminal didn't provide it.

**Fix**: Added host function to `websocket_host.go`:
```go
extism.NewHostFunctionWithStack(
    "publish_stream_data",
    func(ctx context.Context, plugin *extism.CurrentPlugin, stack []uint64) {
        inputOffset := stack[0]
        responseOffset := handlePublishStreamData(plugin, pluginID, inputOffset)
        stack[0] = responseOffset
    },
    []extism.ValueType{extism.ValueTypeI64},
    []extism.ValueType{extism.ValueTypeI64},
)
```

**See**: `NAMESPACE_FIX.md`

---

### 4. ❌ Module Not Instantiated During Metadata Call
**Error**: `module[env] not instantiated`

**Problem**: Metadata extraction only provided dummy functions for `log_record` and `http_request`, but generic plugin imports WebSocket functions at module level.

**Fix**: Added dummy WebSocket host functions for metadata calls in `manager.go`:
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

**See**: `MODULE_INSTANTIATION_FIX.md`

---

## Files Modified

### Plugin Side
1. **`/home/pk/golang/plusev_datasource_woox_plugin/main_generic.go`**
   - ✅ Fixed wasmimport to use memory offsets (uint64)
   - ✅ Changed namespace from `extism:host/user` to `env`
   - ✅ Added `func main() {}`
   - ✅ Successfully compiles to `woox-plugin-generic.wasm` (3.5MB)

2. **`/home/pk/golang/plusev/datasource-plugin-minimal-template/main.go`**
   - ✅ Same fixes as woox plugin
   - ✅ Updated `go.mod` to use `go-pdk v1.1.3`
   - ✅ Successfully compiles to `plugin.wasm` (3.4MB)

### Terminal Side
3. **`/home/pk/golang/plusev/terminal/datasrc/websocket_host.go`**
   - ✅ Added `publish_stream_data` host function
   - ✅ Added `handlePublishStreamData()` implementation

4. **`/home/pk/golang/plusev/terminal/datasrc/plugin/manager.go`**
   - ✅ Added 5 dummy WebSocket host functions for metadata calls

### Documentation
5. **`WASMIMPORT_FIX.md`** - WASM string return type issue
6. **`NAMESPACE_FIX.md`** - Host function namespace issue
7. **`MODULE_INSTANTIATION_FIX.md`** - Module loading issue
8. **`SUMMARY.md`** - This file (complete overview)

---

## Known Remaining Issues

### Terminal Still Uses Old Plugin Interface
The terminal's `websocket.go` still calls `handle_stream_message`, which doesn't exist in the generic interface:

```go
// OLD interface (used by terminal)
plugin.Call("handle_stream_message", requestData)

// NEW interface (generic plugins)
// No handle_stream_message - uses start_stream/stop_stream instead
```

**Impact**: The terminal's streaming system won't work with generic plugins yet.

**Fix Needed**: Update terminal to:
1. Detect plugin interface type (old vs generic)
2. Use `start_stream`/`stop_stream` for generic plugins
3. Keep `handle_stream_message` for old plugins (backward compatibility)

This requires changes to `/home/pk/golang/plusev/terminal/datasrc/stream/websocket.go` and the stream manager.

---

## How It Works Now

### Generic Plugin Exports
```go
//go:wasmexport plugin_info
func plugin_info() int32 { ... }

//go:wasmexport plugin_configure  
func plugin_configure() int32 { ... }

//go:wasmexport start_stream
func start_stream() int32 { ... }

//go:wasmexport stop_stream
func stop_stream() int32 { ... }
```

### Host Functions Available to Plugin
All in `env` namespace:
- `env.http_request` - HTTP requests
- `env.log_record` - Logging
- `env.ws_connect` - WebSocket connect
- `env.ws_send` - WebSocket send
- `env.ws_receive` - WebSocket receive
- `env.ws_close` - WebSocket close
- `env.publish_stream_data` - Publish to actor system

### Plugin Flow
```
1. Terminal loads plugin
2. Calls plugin_info (with dummy host functions)
3. Gets metadata (name, version, features, etc.)
4. For actual use:
   - Calls plugin_configure with config
   - Calls start_stream with StreamKey
   - Plugin uses WebSocket host functions
   - Plugin calls publish_stream_data to send data
   - Terminal calls stop_stream when done
```

---

## Building Plugins

### WooX Plugin
```bash
cd /home/pk/golang/plusev_datasource_woox_plugin
GOOS=wasip1 GOARCH=wasm go build -o woox-plugin-generic.wasm main_generic.go
```

### Minimal Template
```bash
cd /home/pk/golang/plusev/datasource-plugin-minimal-template
GOOS=wasip1 GOARCH=wasm go build -o plugin.wasm main.go
```

---

## Testing Checklist

- [x] Plugin compiles without errors
- [x] Plugin loads for metadata extraction
- [x] Host functions resolve correctly (namespace)
- [x] All imports satisfied (dummy functions)
- [ ] Plugin can be configured (needs terminal update)
- [ ] Stream can be started (needs terminal update)
- [ ] WebSocket delegation works (needs terminal update)
- [ ] Data publishing works (needs terminal update)

---

## Next Steps

1. **Update Terminal Stream Manager** to support generic plugin interface
2. **Test WebSocket delegation** end-to-end
3. **Verify data publishing** to actor system
4. **Update documentation** with complete generic plugin development guide
5. **Create migration guide** for converting old plugins to generic interface

---

## Key Learnings

1. **WASM Import Limitations**: Can only pass numeric types (i32, i64, f32, f64) across boundaries. Strings must use memory.

2. **Extism Host Function Namespaces**: Default namespace is `env`. Plugin imports must match exactly.

3. **Module Instantiation**: ALL imports must be satisfied before WASM module loads, even for metadata calls.

4. **Dummy Host Functions**: Required for metadata extraction to prevent "module not instantiated" errors.

5. **Memory-Based Communication**: Use `pdk.AllocateJSON()` and `pdk.FindMemory()` for plugin↔host data exchange.

6. **Generic Plugin Pattern**: Self-contained with WebSocket delegation, no external dependencies besides Extism PDK.
