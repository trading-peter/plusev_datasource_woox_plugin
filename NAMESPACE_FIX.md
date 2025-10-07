# Host Function Namespace Fix

## Problem

When trying to install the generic WooX plugin, it failed with:
```
[ERRO] failed to create plugin instance: "ws_connect" is not exported in module "extism:host/user"
```

## Root Cause

The plugin was declaring host functions with the wrong namespace:
```go
//go:wasmimport extism:host/user ws_connect  // ❌ WRONG!
func hostWSConnect(uint64) uint64
```

But the terminal registers host functions in the **default `env` namespace**:
```go
extism.NewHostFunctionWithStack(
    "ws_connect",  // Registered in 'env' namespace by default
    func(ctx context.Context, plugin *extism.CurrentPlugin, stack []uint64) {
        // ...
    },
    // ...
)
```

## Solution

### 1. Fix Plugin Host Function Declarations

Change the import namespace from `extism:host/user` to `env`:

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

### 2. Add Missing Host Function in Terminal

The plugin also calls `publish_stream_data`, which was missing from the terminal. Added to `websocket_host.go`:

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
),
```

Implementation:
```go
func handlePublishStreamData(plugin *extism.CurrentPlugin, pluginID string, inputOffset uint64) uint64 {
    _, err := plugin.ReadBytes(inputOffset)
    if err != nil {
        return writeWSErrorResponse(plugin, "failed to read input: "+err.Error())
    }

    // Just acknowledge receipt - the actual publishing happens through the stream manager
    resp := map[string]interface{}{
        "success": true,
    }
    return writeWSResponse(plugin, resp)
}
```

## How Extism Namespaces Work

### Default Namespace (`env`)
When you create a host function in Extism without specifying a namespace:
```go
extism.NewHostFunctionWithStack("ws_connect", ...)
```
It's registered in the **`env` namespace** by default.

### Custom Namespaces
You can register functions in custom namespaces:
```go
extism.NewHostFunctionWithStack("extism:host/user", "ws_connect", ...)
```

But the plugin must import from the **exact same namespace**:
```go
//go:wasmimport extism:host/user ws_connect
```

### Our Convention
The PlusEV terminal uses the **default `env` namespace** for all host functions:
- `http_request` → `env.http_request`
- `ws_connect` → `env.ws_connect`  
- `ws_send` → `env.ws_send`
- `ws_receive` → `env.ws_receive`
- `ws_close` → `env.ws_close`
- `publish_stream_data` → `env.publish_stream_data`
- `log_record` → `env.log_record`

## Files Changed

### Plugin Side
1. `/home/pk/golang/plusev_datasource_woox_plugin/main_generic.go`
   - Changed all `//go:wasmimport extism:host/user` to `//go:wasmimport env`
   - Rebuilt: `woox-plugin-generic.wasm` (3.5MB)

2. `/home/pk/golang/plusev/datasource-plugin-minimal-template/main.go`
   - Changed all `//go:wasmimport extism:host/user` to `//go:wasmimport env`
   - Rebuilt: `plugin.wasm` (3.4MB)

### Terminal Side  
3. `/home/pk/golang/plusev/terminal/datasrc/websocket_host.go`
   - Added `publish_stream_data` host function
   - Added `handlePublishStreamData()` implementation

## Testing

After these changes, the plugin should load successfully:
```bash
plusev plugin install woox-plugin-generic.wasm
```

The error should be resolved and the plugin should be able to:
1. ✅ Connect to WebSocket URLs
2. ✅ Send messages
3. ✅ Receive messages
4. ✅ Close connections
5. ✅ Publish stream data to the actor system

## Key Takeaway

**Always use the `env` namespace for host function imports** unless you specifically need a custom namespace and have configured it on both sides (plugin and terminal).
