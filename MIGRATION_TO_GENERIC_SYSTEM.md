# Migration Guide: WooX Plugin to Generic Actor System

## Problem

The current WooX plugin uses the old finance-specific plugin interface (`go-plugin-common/datasrc`) which is incompatible with the new generic actor-based datasource system.

## Required Changes

### 1. Update Plugin Interface (High Priority)

The plugin needs to implement the new generic interface instead of the finance-specific one.

**Old Interface (Current):**
```go
type DataSource interface {
    GetName() string
    GetCredentialFields() ([]dt.CredentialField, error)
    SetCredentials(creds map[string]string) error
    GetMarkets() ([]dt.MarketMeta, error)
    GetTimeframes() []dt.Timeframe
    GetOHLCV(params dt.OHLCVParams) ([]dt.OHLCVRecord, error)
    PrepareStream(request dt.StreamSetupRequest) (dt.StreamSetupResponse, error)
    HandleStreamMessage(request dt.StreamMessageRequest) (dt.StreamMessageResponse, error)
    HandleConnectionEvent(event dt.StreamConnectionEvent) (dt.StreamConnectionResponse, error)
    SupportsStreaming() bool
}
```

**New Interface (Required):**
```go
// Generic plugin interface
type DataSourcePlugin interface {
    // Metadata
    GetInfo() PluginInfo
    
    // Lifecycle
    Initialize(config map[string]string) error
    Shutdown() error
    
    // Streaming
    StartStream(key StreamKey) (string, error)  // Returns stream ID
    StopStream(streamID string) error
    SendData(data StreamData) error  // Plugin sends data to host
    
    // Requests (optional)
    HandleRequest(requestType string, params map[string]any) (any, error)
}

type StreamKey struct {
    Type       string            // "ohlcv", "orderbook", "ticker", "trades"
    Source     string            // "woox"
    Identifier string            // "BTC-PERP", "SPOT_BTC_USDT"
    Parameters map[string]string // {"timeframe": "1m"}
    ConnectionID *uint64         // Account/connection ID
}

type StreamData interface {
    GetSource() string       // "woox"
    GetDataType() string     // "ohlcv", "orderbook", etc.
    GetIdentifier() string   // "BTC-PERP"
    GetTimestamp() time.Time
    GetConnectionID() *uint64
}
```

### 2. Implementation Strategy

#### Option A: Wrapper Adapter (Quick Fix)

Create an adapter that wraps the existing woox client to work with both systems:

```go
// adapter.go
package main

import (
    "encoding/json"
    "fmt"
    
    "github.com/trading-peter/plusev_datasource_woox_plugin/woox"
)

// WooXAdapter adapts the old woox client to the new generic interface
type WooXAdapter struct {
    client        *woox.Client
    activeStreams map[string]*streamState
}

type streamState struct {
    key    StreamKey
    cancel context.CancelFunc
}

func NewWooXAdapter(client *woox.Client) *WooXAdapter {
    return &WooXAdapter{
        client:        client,
        activeStreams: make(map[string]*streamState),
    }
}

func (a *WooXAdapter) StartStream(keyJSON string) (string, error) {
    var key StreamKey
    if err := json.Unmarshal([]byte(keyJSON), &key); err != nil {
        return "", err
    }
    
    // Map generic key to WooX-specific stream setup
    streamID := fmt.Sprintf("woox:%s:%s", key.Type, key.Identifier)
    
    // Convert generic StreamKey to old PrepareStream format
    oldRequest := convertToOldFormat(key)
    
    // Use existing client logic
    response, err := a.client.PrepareStream(oldRequest)
    if err != nil {
        return "", err
    }
    
    // Start stream goroutine
    ctx, cancel := context.WithCancel(context.Background())
    a.activeStreams[streamID] = &streamState{
        key:    key,
        cancel: cancel,
    }
    
    go a.streamLoop(ctx, streamID, key, response)
    
    return streamID, nil
}

func (a *WooXAdapter) streamLoop(ctx context.Context, streamID string, key StreamKey, setup StreamSetupResponse) {
    // Use WebSocket connection from old implementation
    // Convert incoming messages to generic StreamData
    // Send via SendData()
    
    for {
        select {
        case <-ctx.Done():
            return
        case msg := <-setup.MessageChannel:
            // Convert old message format to new StreamData
            data := convertToStreamData(msg, key)
            
            // Send to host
            dataJSON, _ := json.Marshal(data)
            sendToHost(string(dataJSON))
        }
    }
}

func convertToOldFormat(key StreamKey) dt.StreamSetupRequest {
    // Map generic params to old format
    return dt.StreamSetupRequest{
        StreamType: key.Type,
        Symbol:     key.Identifier,
        Timeframe:  key.Parameters["timeframe"],
        // ... other fields
    }
}

func convertToStreamData(oldMsg any, key StreamKey) StreamData {
    // Convert old message types to new generic StreamData
    switch key.Type {
    case "ohlcv":
        // Convert to OHLCVData that implements StreamData
        return &OHLCVData{
            Source:     "woox",
            Identifier: key.Identifier,
            // ... populate from oldMsg
        }
    // ... other types
    }
}
```

#### Option B: Full Rewrite (Recommended)

Rewrite the plugin using the new architecture from scratch:

1. **Keep the WooX client** (`woox/client.go`) - it's still good
2. **Create new main.go** using generic interface
3. **Create StreamData implementations** for each data type
4. **Use direct WebSocket** instead of old PrepareStream pattern

Example structure:
```
woox-plugin-v2/
├── main.go           # New generic plugin interface
├── types.go          # StreamData implementations
├── woox/
│   ├── client.go     # Existing client (reuse)
│   └── stream.go     # New streaming with generic data
└── build.sh
```

### 3. Host-Side Changes

The terminal also needs updates to support generic plugins:

**Update `datasrc/plugin/` package:**

```go
// datasrc/plugin/generic.go
package plugin

import (
    "encoding/json"
    dsactor "plus-ev.io/terminal/datasrc/actor"
)

// GenericPluginBridge bridges generic plugins to the actor system
type GenericPluginBridge struct {
    pluginInfo *pluginmgr.PluginInfo
    plugin     *extism.Plugin
}

func (b *GenericPluginBridge) StartStream(key dsactor.StreamKey) error {
    // Convert StreamKey to JSON
    keyJSON, _ := json.Marshal(key)
    
    // Call plugin's start_stream export
    _, err := b.plugin.Call("start_stream", keyJSON)
    if err != nil {
        return err
    }
    
    // Plugin will send data via sendToHost callback
    // which we bridge to dsactor.Publish()
    
    return nil
}

// Host function that plugin calls to send data
func (b *GenericPluginBridge) ReceiveData(dataJSON string) {
    var data map[string]any
    json.Unmarshal([]byte(dataJSON), &data)
    
    // Reconstruct appropriate StreamData type
    streamData := reconstructStreamData(data)
    
    // Publish to actor system
    dsactor.Publish(streamData)
}
```

**Update registry to detect plugin type:**

```go
// datasrc/registry.go
func (r *DataSourceRegistry) registerPlugin(pluginInfo pluginmgr.PluginInfo) error {
    // Check plugin version/capabilities
    if pluginInfo.SupportsGenericInterface() {
        // New generic plugin
        bridge := plugin.NewGenericPluginBridge(&pluginInfo)
        r.managers[pluginInfo.Name] = bridge
    } else {
        // Old finance-specific plugin (legacy support)
        pluginApi, err := plugin.NewPluginCexDataSrc(&pluginInfo)
        if err != nil {
            return err
        }
        r.managers[pluginInfo.Name] = cex.NewCexManager(pluginApi)
    }
    
    return nil
}
```

### 4. Migration Steps

#### Phase 1: Compatibility Layer (Temporary)
1. Keep old plugin interface working
2. Add generic wrapper in terminal
3. Both systems work during transition

#### Phase 2: Update Plugin
1. Update `go-plugin-common` library with generic interface
2. Migrate woox plugin to use generic interface
3. Test with both old and new terminal versions

#### Phase 3: Full Migration
1. Remove finance-specific plugin interface
2. All plugins use generic interface
3. Clean up legacy code

### 5. Testing Plan

```go
// Test generic plugin with actor system
func TestWooXGenericPlugin(t *testing.T) {
    // Load plugin
    pluginInfo := loadWooXPlugin()
    
    // Start stream
    key := dsactor.StreamKey{
        Type:       "ohlcv",
        Source:     "woox",
        Identifier: "BTC-PERP",
        Parameters: map[string]string{"timeframe": "1m"},
    }
    
    // Subscribe via actor system
    received := make(chan *dsactor.OHLCVData, 10)
    bot := &TestBot{received: received}
    pid := engine.Spawn(func() actor.Receiver { return bot }, "test")
    
    _, err := dsactor.Subscribe(pid, key)
    require.NoError(t, err)
    
    // Verify data arrives
    select {
    case data := <-received:
        assert.Equal(t, "woox", data.GetSource())
        assert.Equal(t, "BTC-PERP", data.GetIdentifier())
    case <-time.After(30 * time.Second):
        t.Fatal("timeout")
    }
}
```

## Timeline

- **Week 1**: Design generic plugin interface
- **Week 2**: Implement compatibility layer in terminal
- **Week 3**: Update go-plugin-common library
- **Week 4**: Migrate woox plugin
- **Week 5**: Testing and rollout
- **Week 6**: Remove legacy code

## Breaking Changes

- Plugin developers must update to new interface
- Old plugins won't work with new terminal (without compatibility layer)
- New plugins won't work with old terminal

## Recommendation

**Start with Option A (Adapter)** for quick compatibility, then migrate to **Option B (Full Rewrite)** for cleaner long-term architecture.

The adapter lets you ship now while planning the proper migration.
