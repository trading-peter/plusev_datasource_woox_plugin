package main

import (
	"fmt"

	"github.com/extism/go-pdk"
	"github.com/plusev-terminal/go-plugin-common/datasrc"
	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	m "github.com/plusev-terminal/go-plugin-common/meta"
	"github.com/plusev-terminal/go-plugin-common/requester"

	"github.com/trading-peter/plusev_datasource_woox_plugin/woox"
)

// ============================================================================
// Plugin Implementation
// ============================================================================

// WooXPlugin implements the DataSourcePlugin interface
type WooXPlugin struct {
	config *datasrc.ConfigStore
	client *woox.Client
}

// GetMeta returns the plugin metadata
func (p *WooXPlugin) GetMeta() m.Meta {
	return m.Meta{
		PluginID:    "woox-datasource",
		Name:        "WooX Exchange",
		AppID:       "datasrc",
		Category:    "cex",
		Description: "WooX Exchange data source - spot and futures markets",
		Author:      "PlusEV Team",
		Version:     "3.0.0",
		Repository:  "https://github.com/trading-peter/plusev_datasource_woox_plugin",
		Tags:        []string{"woox", "crypto", "exchange", "spot", "futures"},
		Contacts: []m.AuthorContact{
			{
				Kind:  "x.com",
				Value: "https://x.com/trading_peter",
			},
		},
		Resources: m.ResourceAccess{
			AllowedNetworkTargets: []m.NetworkTargetRule{
				{Pattern: "https://api.woox.io/*"},
				{Pattern: "https://api.staging.woox.io/*"},
				{Pattern: "wss://wss.woox.io/*"},
				{Pattern: "wss://wss.staging.woox.io/*"},
			},
			StdoutAccess: false,
			StderrAccess: false,
		},
		// Features will be auto-populated with registered commands
		Features: []string{},
	}
}

// GetConfigFields returns the configuration fields needed by this plugin
func (p *WooXPlugin) GetConfigFields() []dt.ConfigField {
	// Initialize client if needed to get config fields
	if p.client == nil {
		p.client = woox.NewClient(requester.NewRequester(), "https://api.woox.io")
	}
	return p.client.GetConfigFields()
}

// OnInit is called when the plugin is initialized with user configuration
func (p *WooXPlugin) OnInit(config *datasrc.ConfigStore) error {
	p.config = config

	// Create WooX client
	p.client = woox.NewClient(requester.NewRequester(), "https://api.woox.io")

	// Set credentials on the client
	credentials := make(map[string]string)
	if appID := config.Get("applicationID"); appID != "" {
		credentials["applicationID"] = appID
	}
	if apiKey := config.Get("key"); apiKey != "" {
		credentials["key"] = apiKey
	}
	if apiSecret := config.Get("secret"); apiSecret != "" {
		credentials["secret"] = apiSecret
	}

	p.client.SetCredentials(credentials)

	// Store reference for stream handling exports
	registeredPluginInstance = p

	return nil
}

// OnShutdown is called when the plugin is being shut down
func (p *WooXPlugin) OnShutdown() error {
	// Cleanup resources if needed
	return nil
}

// RegisterCommands registers all command handlers
func (p *WooXPlugin) RegisterCommands(router *datasrc.CommandRouter) {
	router.Register("getMarkets", p.handleGetMarkets)
	router.Register("getTimeframes", p.handleGetTimeframes)
	router.Register("ohlcvStream", p.handleOHLCVStream)
	router.Register("getOHLCV", p.handleGetOHLCV) // Historical OHLCV
}

// ============================================================================
// Command Handlers
// ============================================================================

// handleGetMarkets returns available trading pairs
func (p *WooXPlugin) handleGetMarkets(params map[string]any) dt.Response {
	markets, err := p.client.GetMarkets()
	if err != nil {
		return datasrc.ErrorResponse(err)
	}

	return datasrc.SuccessResponse(markets)
}

// handleGetTimeframes returns supported timeframes
func (p *WooXPlugin) handleGetTimeframes(params map[string]any) dt.Response {
	timeframes := p.client.GetTimeframes()
	return datasrc.SuccessResponse(timeframes)
}

// handleGetOHLCV returns historical OHLCV data
func (p *WooXPlugin) handleGetOHLCV(params map[string]any) dt.Response {
	// Extract parameters
	symbol, _ := params["symbol"].(string)
	timeframe, _ := params["timeframe"].(string)

	// Optional parameters
	var startTime, endTime int64
	var limit int

	if st, ok := params["startTime"].(float64); ok {
		startTime = int64(st)
	}
	if et, ok := params["endTime"].(float64); ok {
		endTime = int64(et)
	}
	if l, ok := params["limit"].(float64); ok {
		limit = int(l)
	}

	if symbol == "" {
		return datasrc.ErrorResponseMsg("symbol parameter is required")
	}
	if timeframe == "" {
		timeframe = "1m" // Default
	}

	// Fetch OHLCV data
	ohlcvParams := dt.OHLCVParams{
		Symbol:    symbol,
		Timeframe: timeframe,
		StartTime: startTime,
		EndTime:   endTime,
		Limit:     limit,
	}

	records, err := p.client.GetOHLCV(ohlcvParams)
	if err != nil {
		return datasrc.ErrorResponse(err)
	}

	return datasrc.SuccessResponse(records)
}

// handleOHLCVStream sets up a WebSocket stream for OHLCV data
func (p *WooXPlugin) handleOHLCVStream(params map[string]any) dt.Response {
	// Extract parameters
	symbol, ok := params["symbol"].(string)
	if !ok || symbol == "" {
		return datasrc.ErrorResponseMsg("symbol parameter is required")
	}

	interval, ok := params["interval"].(string)
	if !ok || interval == "" {
		interval = "1m" // Default
	}

	// Prepare stream setup request
	streamReq := dt.StreamSetupRequest{
		StreamID:   fmt.Sprintf("woox_ohlcv_%s_%s", symbol, interval),
		StreamType: "ohlcv",
		Parameters: map[string]any{
			"symbol":   symbol,
			"interval": interval,
			"private":  false, // Public stream for OHLCV
		},
	}

	// Get stream setup from client
	setupResp, err := p.client.PrepareStream(streamReq)
	if err != nil {
		return datasrc.ErrorResponse(err)
	}

	if !setupResp.Success {
		return datasrc.ErrorResponseMsg(setupResp.Error)
	}

	// Return stream marker for the datasrc system to handle
	return datasrc.SuccessResponse(map[string]any{
		"_stream":         true,
		"streamID":        streamReq.StreamID,
		"websocketUrl":    setupResp.WebSocketURL,
		"headers":         setupResp.Headers,
		"subprotocol":     setupResp.Subprotocol,
		"initialMessages": setupResp.InitialMessages,
	})
}

// ============================================================================
// Main - Register the plugin
// ============================================================================

func init() {
	// Register the plugin - this generates all WASM exports automatically
	// IMPORTANT: Must be in init(), not main(), so it runs before WASM exports are called
	datasrc.RegisterPlugin(&WooXPlugin{})
}

func main() {
	// Required for WASM, but can be empty
}

// ============================================================================
// Additional WASM Exports for Stream Handling
// ============================================================================

//go:wasmexport handle_stream_message
func handle_stream_message() int32 {
	// Get the plugin instance
	plugin := registeredPluginInstance
	if plugin == nil {
		pdk.OutputJSON(dt.StreamMessageResponse{Success: false})
		return 1
	}

	// Read the request
	var req dt.StreamMessageRequest
	if err := pdk.InputJSON(&req); err != nil {
		pdk.OutputJSON(dt.StreamMessageResponse{Success: false})
		return 1
	}

	// Call client's message handler
	resp, err := plugin.client.HandleStreamMessage(req)
	if err != nil {
		pdk.OutputJSON(dt.StreamMessageResponse{Success: false})
		return 1
	}

	// Write response
	pdk.OutputJSON(resp)
	return 0
}

//go:wasmexport handle_connection_event
func handle_connection_event() int32 {
	// Get the plugin instance
	plugin := registeredPluginInstance
	if plugin == nil {
		pdk.OutputJSON(dt.StreamConnectionResponse{Success: false})
		return 1
	}

	// Read the event
	var event dt.StreamConnectionEvent
	if err := pdk.InputJSON(&event); err != nil {
		pdk.OutputJSON(dt.StreamConnectionResponse{Success: false})
		return 1
	}

	// Call client's event handler
	resp, err := plugin.client.HandleConnectionEvent(event)
	if err != nil {
		pdk.OutputJSON(dt.StreamConnectionResponse{Success: false})
		return 1
	}

	// Write response
	pdk.OutputJSON(resp)
	return 0
}

// Store plugin instance for stream handling exports
var registeredPluginInstance *WooXPlugin
