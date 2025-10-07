# Plugin Credential Persistence Architecture

## The Challenge

**WASM/Extism plugins don't persist state between function calls.** Each time you get a plugin instance, it starts with a fresh memory state. This means:

- ❌ Setting credentials in one call doesn't persist to the next call
- ❌ Plugin global variables reset between instances
- ❌ You can't rely on plugin-side state management

## The Solution: Configure on Every Instance

### Terminal Side (Host)

The terminal uses a **two-level caching strategy**:

#### 1. **Compiled Plugin Cache** (Extism Level)
- The WASM binary is compiled once and cached
- Reused across multiple instances
- Cache key: `pluginID:conn-{connectionID}`
- This saves compilation time but NOT runtime state

#### 2. **Configuration on Every Instance** (Our Level)
```go
func (p *PluginCexAPI) newInstance() (*extism.Plugin, error) {
    // Get instance (may be from compiled cache)
    instance, err := GetPluginManager().GetPluginInstance(ctx, pluginID, cacheKey)
    
    // MUST configure credentials on EVERY instance
    // Because instance memory state is fresh each time
    err = p.configurePlugin(instance)
    
    return instance, nil
}
```

### Plugin Side (Guest)

The plugin uses **global variables that get set on each configuration**:

```go
var (
    wooxClient    *woox.Client
    activeStreams = make(map[string]*StreamContext)
)

//go:wasmexport plugin_configure
func plugin_configure() int32 {
    // This gets called on EVERY instance creation
    config := parseInput()
    
    // Set credentials on the global client
    wooxClient.SetCredentials(config)
    
    return 0
}
```

## Why `plugin_configure` Instead of `set_credentials`?

### Old Design (`set_credentials`)
- ❌ Only handles API keys
- ❌ Limited to authentication
- ❌ Doesn't support other configuration

### New Design (`plugin_configure`)
- ✅ Flexible configuration object
- ✅ Can handle credentials + settings
- ✅ Supports different plugin types (data sources, indicators, strategies)
- ✅ Future-proof for additional config options

Example configuration:
```json
{
  "api_key": "...",
  "api_secret": "...",
  "base_url": "https://api.woox.io",
  "timeout_ms": "5000",
  "rate_limit": "10"
}
```

## How It Works in Practice

### 1. User Creates Connection
```
User → Web UI → Terminal → Database
```
- Credentials stored in DB (encrypted)
- Connection has unique ID

### 2. Making API Calls
```
Terminal → GetPluginInstance(pluginID, "pluginID:conn-123")
         ↓
         Fresh WASM instance created
         ↓
         plugin_configure(credentials) called
         ↓
         Plugin's wooxClient.SetCredentials(...)
         ↓
         Plugin ready for API calls
         ↓
         list_markets() → Uses configured client
```

### 3. Instance Lifecycle
```
1. newInstance()           # Fresh memory state
2. plugin_configure()      # Set credentials
3. list_markets()          # Use configured client
4. instance.Close()        # Memory released

5. newInstance()           # Fresh memory state AGAIN
6. plugin_configure()      # MUST reconfigure
7. get_ohlcv()            # Use configured client
8. instance.Close()
```

## Performance Considerations

### ✅ What's Optimized
- **WASM compilation** is cached (expensive operation)
- **Network requests** use host functions (no WASM overhead)
- **Same connection reuses compiled plugin** via cacheKey

### ⚠️ What's Not Optimized
- Configuration call on every instance (cheap JSON marshal/unmarshal)
- Plugin state recreation (in-memory, very fast)

### 💡 Why This Is Actually Good
- **Stateless design** = no memory leaks
- **Clean instances** = no state corruption
- **Configuration overhead** is negligible (~1ms)
- **Compilation caching** saves 100-500ms per instance

## Best Practices

### For Plugin Authors

1. **Accept configuration in `plugin_configure`**
   ```go
   //go:wasmexport plugin_configure
   func plugin_configure() int32 {
       config := parseConfig()
       globalClient.SetCredentials(config)
       return 0
   }
   ```

2. **Store state in global variables**
   ```go
   var (
       client *APIClient
       activeStreams map[string]*Stream
   )
   ```

3. **Don't expect state to persist between calls**
   - Each export function gets a configured environment
   - But don't rely on state from previous exports

### For Terminal Developers

1. **Always configure after getting instance**
   ```go
   instance := GetPluginInstance(...)
   configurePlugin(instance)  // REQUIRED
   ```

2. **Use connection-specific cache keys**
   ```go
   cacheKey := fmt.Sprintf("%s:conn-%d", pluginID, connectionID)
   ```

3. **Close instances when done**
   ```go
   defer instance.Close(ctx)
   ```

## Migration from Old Plugins

### Old Plugin (set_credentials)
```go
//export set_credentials
func set_credentials() int32 {
    // Only handles auth
}
```

### New Plugin (plugin_configure)
```go
//go:wasmexport plugin_configure
func plugin_configure() int32 {
    // Handles full configuration
}
```

**NO BACKWARDS COMPATIBILITY** - all plugins must use `plugin_configure`.

## Summary

**The key insight**: Since WASM instances don't persist state, we embrace stateless design:
1. Configure on every instance creation
2. Use global variables for runtime state
3. Cache compiled plugins, not instances
4. Keep configuration lightweight

This gives us **clean, predictable behavior** without the complexity of persistent state management.
