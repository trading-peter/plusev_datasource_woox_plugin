package main

import (
	"fmt"
	"strings"
	"time"

	ex "github.com/plusev-terminal/go-plugin-common/datasrc/exchange"
	"github.com/plusev-terminal/go-plugin-common/logging"
	m "github.com/plusev-terminal/go-plugin-common/meta"
	"github.com/plusev-terminal/go-plugin-common/plugin"
	"github.com/plusev-terminal/go-plugin-common/requester"
	commonstream "github.com/plusev-terminal/go-plugin-common/stream"

	"github.com/trading-peter/plusev_datasource_woox_plugin/woox"
)

// ============================================================================
// Main - Register the plugin
// ============================================================================

func init() {
	// Create plugin instance
	p := &WooXPlugin{}

	// Register the plugin - this generates all standard WASM exports automatically
	// IMPORTANT: Must be in init(), not main(), so it runs before WASM exports are called
	plugin.RegisterPlugin(p)

	// Register stream handler - this generates handle_stream_message and handle_connection_event exports
	// The client implements the StreamHandler interface (HandleStreamMessage, HandleConnectionEvent)
	// NOTE: client will be initialized in OnInit, but we register it here so the exports are available
	// The actual client instance will be set when OnInit is called
	plugin.RegisterStreamHandler(&streamHandlerWrapper{p: p})
}

func main() {
	// Required for WASM, but can be empty
}

// ============================================================================
// Plugin Implementation
// ============================================================================

// WooXPlugin implements the DataSourcePlugin interface
type WooXPlugin struct {
	config *plugin.ConfigStore
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
		Version:     "3.1.1",
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
				{Pattern: "https://api-pub.woox.io/*"},
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

func (p *WooXPlugin) GetRateLimits() []plugin.RateLimit {
	// Define rate limits based on WooX API documentation
	// Public endpoints: rate limit is based on IP address
	// Private endpoints: rate limit is based on account (application ID)

	return []plugin.RateLimit{
		// Public endpoints - IP-based rate limits (10 requests per 1 second per IP)
		{
			Command: ex.CMD_GET_MARKETS, // GET /v1/public/info
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeIP},
			RPS:     10.0,
			Burst:   10,
		},
		{
			Command: ex.CMD_GET_TIMEFRAMES, // No API call, returns static data
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeIP},
			RPS:     10.0,
			Burst:   10,
		},
		{
			Command: ex.CMD_GET_OHLCV, // GET /v1/public/kline or /v1/hist/kline
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeIP},
			RPS:     1.0,
			Burst:   1.0,
		},

		// WebSocket streams - Connection limits per IP (1000 concurrent)
		// Per account: 80 concurrent connections max
		{
			Command: ex.CMD_OHLCV_STREAM,
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeAPIKey}, // Per account limit
			RPS:     1.0,                                                  // Allow setup, actual limit is concurrent connections
			Burst:   80,                                                   // Max 80 concurrent connections per account
		},
	}
}

// GetConfigFields returns the configuration fields needed by this plugin
func (p *WooXPlugin) GetConfigFields() []plugin.ConfigField {
	// Initialize client if needed to get config fields
	if p.client == nil {
		p.client = woox.NewClient(requester.NewRequester(), "https://api.woox.io")
	}
	return p.client.GetConfigFields()
}

// OnInit is called when the plugin is initialized with user configuration
func (p *WooXPlugin) OnInit(config *plugin.ConfigStore) error {
	p.config = config

	// Create WooX client
	p.client = woox.NewClient(requester.NewRequester(), "https://api.woox.io")

	// Set credentials on the client
	credentials := make(map[string]string)
	if appID := config.GetString("applicationID"); appID != "" {
		credentials["applicationID"] = appID
	}
	if apiKey := config.GetString("key"); apiKey != "" {
		credentials["key"] = apiKey
	}
	if apiSecret := config.GetString("secret"); apiSecret != "" {
		credentials["secret"] = apiSecret
	}

	p.client.SetCredentials(credentials)

	return nil
}

// OnShutdown is called when the plugin is being shut down
func (p *WooXPlugin) OnShutdown() error {
	// Cleanup resources if needed
	return nil
}

// RegisterCommands registers all command handlers
func (p *WooXPlugin) RegisterCommands(router *plugin.CommandRouter) {
	router.Register(ex.CMD_GET_MARKETS, p.handleGetMarkets)
	router.Register(ex.CMD_GET_TIMEFRAMES, p.handleGetTimeframes)
	router.Register(ex.CMD_OHLCV_STREAM, p.handleOHLCVStream)
	router.Register(ex.CMD_GET_OHLCV, p.handleGetOHLCV)
}

// ============================================================================
// Command Handlers
// ============================================================================

// handleGetMarkets returns available trading pairs
func (p *WooXPlugin) handleGetMarkets(params map[string]any) plugin.Response {
	markets, err := p.client.GetMarkets()
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	return plugin.SuccessResponse(markets, time.Hour*12)
}

// handleGetTimeframes returns supported timeframes
func (p *WooXPlugin) handleGetTimeframes(params map[string]any) plugin.Response {
	timeframes := p.client.GetTimeframes()
	return plugin.SuccessResponse(timeframes, time.Hour*12)
}

// handleGetOHLCV returns historical OHLCV data
func (p *WooXPlugin) handleGetOHLCV(params map[string]any) plugin.Response {
	// Extract validated parameters - validation already done by terminal
	ohlcvParams := ex.GetOHLCVParamsFromMap(params)

	// Fetch OHLCV data
	records, err := p.client.GetOHLCV(ohlcvParams)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	return plugin.SuccessResponse(records)
}

// handleOHLCVStream sets up a WebSocket stream for OHLCV data
func (p *WooXPlugin) handleOHLCVStream(params map[string]any) plugin.Response {
	logging.NewLogger("woox-datasource").InfoWithData("handleOHLCVStream", params)

	// Extract validated parameters - validation already done by terminal
	streamParams := ex.OHLCVStreamParamsFromMap(params)
	if strings.TrimSpace(streamParams.Market.Symbol) == "" {
		return plugin.ErrorResponseMsg("market.symbol is required")
	}

	assetType := strings.TrimSpace(streamParams.Market.AssetType)

	// Prepare stream setup request
	streamReq := plugin.StreamSetupRequest{
		StreamID:   fmt.Sprintf("woox_ohlcv_%s_%s", streamParams.Market.Symbol, streamParams.Timeframe),
		StreamType: "ohlcv",
		Parameters: map[string]any{
			"market":    streamParams.Market,
			"timeframe": streamParams.Timeframe,
			"private":   false, // Public stream for OHLCV
			"streamContext": map[string]any{
				"symbol":    streamParams.Market.Symbol,
				"timeframe": streamParams.Timeframe,
				"assetType": assetType,
			},
		},
	}

	// Get stream setup from client
	setupResp, err := p.client.PrepareStream(streamReq)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	if !setupResp.Success {
		return plugin.ErrorResponseMsg(setupResp.Error)
	}

	marker := commonstream.StreamMarker{
		Stream:          true,
		StreamID:        streamReq.StreamID,
		WebSocketURL:    setupResp.WebSocketURL,
		Headers:         setupResp.Headers,
		Subprotocol:     setupResp.Subprotocol,
		InitialMessages: setupResp.InitialMessages,
		StreamContext:   setupResp.StreamContext,
		Heartbeat: &commonstream.StreamHeartbeatSpec{
			App: &commonstream.AppHeartbeatSpec{
				MatchJSONField:       "event",
				PingValue:            "ping",
				PongValue:            "pong",
				ClientPingIntervalMs: 0,
			},
		},
	}
	if err := marker.Validate(); err != nil {
		return plugin.ErrorResponseMsg(err.Error())
	}

	if marker.Heartbeat != nil && marker.Heartbeat.App != nil {
		if err := marker.Heartbeat.App.Validate(); err != nil {
			return plugin.ErrorResponseMsg(err.Error())
		}
	}

	return plugin.SuccessTypedResponse("StreamMarker", marker)
}

// ============================================================================
// Stream Handler Wrapper
// ============================================================================

// streamHandlerWrapper wraps the plugin to provide StreamHandler interface
// This allows us to register the stream handler before the client is initialized
type streamHandlerWrapper struct {
	p *WooXPlugin
}

func (w *streamHandlerWrapper) HandleStreamMessage(req plugin.StreamMessageRequest) (plugin.StreamMessageResponse, error) {
	if w.p.client == nil {
		return plugin.StreamMessageResponse{Success: false, Action: "ignore"}, fmt.Errorf("client not initialized")
	}
	return w.p.client.HandleStreamMessage(req)
}

func (w *streamHandlerWrapper) HandleConnectionEvent(event plugin.StreamConnectionEvent) (plugin.StreamConnectionResponse, error) {
	if w.p.client == nil {
		return plugin.StreamConnectionResponse{Success: false, Action: "ignore"}, fmt.Errorf("client not initialized")
	}
	return w.p.client.HandleConnectionEvent(event)
}
