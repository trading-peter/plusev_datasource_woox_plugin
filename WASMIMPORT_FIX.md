# WASM Host Function Import Fix

## Problem

The initial generic plugin implementation used `go:wasmimport` directives with string return types:

```go
//go:wasmimport env ws_connect
func hostWSConnect(request string) string
```

This caused compilation errors:
```
go:wasmimport: unsupported result type string
```

**Root Cause**: The WASM specification doesn't support string types directly in imported functions. Strings must be passed through memory using offsets.

## Solution

Use **Extism PDK's memory-based communication pattern** instead:

### Correct Pattern

```go
//go:wasmimport env ws_connect
func hostWSConnect(uint64) uint64

func wsConnect(url string, headers map[string]string) (string, error) {
    req := map[string]interface{}{
        "url":     url,
        "headers": headers,
    }
    
    // 1. Allocate JSON in WASM memory
    mem, err := pdk.AllocateJSON(req)
    if err != nil {
        return "", fmt.Errorf("failed to allocate memory: %w", err)
    }
    
    // 2. Call host function (passes memory offset)
    ptr := hostWSConnect(mem.Offset())
    
    // 3. Read response from memory
    rmem := pdk.FindMemory(ptr)
    respData := rmem.ReadBytes()
    
    // 4. Parse response
    var resp struct {
        Success      bool   `json:"success"`
        ConnectionID string `json:"connectionId"`
        Error        string `json:"error"`
    }
    if err := json.Unmarshal(respData, &resp); err != nil {
        return "", fmt.Errorf("failed to parse response: %w", err)
    }
    
    if !resp.Success {
        return "", fmt.Errorf("%s", resp.Error)
    }
    
    return resp.ConnectionID, nil
}
```

### Key Changes

1. **Import Namespace**: Use `env` (default namespace)
   - This is where Extism registers host functions by default

2. **Function Signatures**: Changed to `func(uint64) uint64`
   - Takes memory offset as input
   - Returns memory offset as output
   - No direct string handling

3. **Memory Operations**:
   - `pdk.AllocateJSON()` - Allocate memory for request
   - `pdk.FindMemory()` - Read memory at offset
   - `mem.Offset()` - Get memory offset
   - `mem.ReadBytes()` - Read bytes from memory

## Files Fixed

### 1. WooX Plugin Generic
- **File**: `/home/pk/golang/plusev_datasource_woox_plugin/main_generic.go`
- **Fixed Functions**:
  - `hostWSConnect`
  - `hostWSSend`
  - `hostWSReceive`
  - `hostWSClose`
  - `hostPublishStreamData`
- **Result**: ✅ Compiles successfully (`woox-plugin-generic.wasm` - 3.5MB)

### 2. Minimal Template
- **File**: `/home/pk/golang/plusev/datasource-plugin-minimal-template/main.go`
- **Same Functions Fixed**
- **Also Updated**: `go.mod` to use `go-pdk v1.1.3` (required for `AllocateJSON`)
- **Result**: ✅ Compiles successfully (`plugin.wasm` - 3.4MB)

## How Host Functions Work

### In the Plugin (WASM)

```go
// Declare host function (in 'env' namespace - default)
//go:wasmimport env ws_connect
func hostWSConnect(uint64) uint64

// Wrapper function
func wsConnect(url string, headers map[string]string) (string, error) {
    // Prepare request
    req := map[string]interface{}{
        "url": url,
        "headers": headers,
    }
    
    // Allocate in WASM memory
    mem, _ := pdk.AllocateJSON(req)
    
    // Call host (pass offset, get offset)
    responseOffset := hostWSConnect(mem.Offset())
    
    // Read response from memory
    rmem := pdk.FindMemory(responseOffset)
    data := rmem.ReadBytes()
    
    // Parse and return
    var resp Response
    json.Unmarshal(data, &resp)
    return resp.ConnectionID, nil
}
```

### In the Terminal (Host)

```go
// Register host function
plugin.WithHostFunction(
    extism.NewHostFunctionWithStack(
        "ws_connect",
        func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
            // Read request from plugin memory
            requestOffset := stack[0]
            requestData := p.Memory().ReadBytes(requestOffset)
            
            var req WSConnectRequest
            json.Unmarshal(requestData, &req)
            
            // Execute actual WebSocket connection
            connID, err := wsManager.Connect(req.URL, req.Headers)
            
            // Prepare response
            resp := WSConnectResponse{
                Success: err == nil,
                ConnectionID: connID,
                Error: err.Error(),
            }
            
            // Write response to plugin memory
            respData, _ := json.Marshal(resp)
            responseOffset := p.Memory().WriteBytes(respData)
            
            // Return offset
            stack[0] = responseOffset
        },
        []api.ValueType{api.ValueTypeI64}, // input: memory offset
        []api.ValueType{api.ValueTypeI64}, // output: memory offset
    ),
)
```

## Why This Pattern?

1. **WASM Limitation**: WASM only supports numeric types (i32, i64, f32, f64) at function boundaries
2. **String Handling**: Strings must be passed through linear memory
3. **Extism Solution**: Provides memory allocation/access functions
4. **Type Safety**: JSON serialization ensures type safety across the boundary

## Building

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

## References

- [Extism Go PDK Documentation](https://extism.org/docs/write-a-plugin/go-pdk)
- [WASM Import/Export Spec](https://webassembly.github.io/spec/core/syntax/modules.html#imports)
- [Go WASM Import Directive](https://pkg.go.dev/cmd/compile#hdr-Compiler_Directives)
