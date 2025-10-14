package main

import (
	"fmt"
	"time"

	"github.com/plusev-terminal/go-plugin-common/datasrc"
	cex "github.com/plusev-terminal/go-plugin-common/datasrc/cex"
	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	"github.com/plusev-terminal/go-plugin-common/logging"
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

func (p *WooXPlugin) GetRateLimits() []dt.RateLimit {
	// Define rate limits based on WooX API documentation
	// Public endpoints: rate limit is based on IP address
	// Private endpoints: rate limit is based on account (application ID)

	return []dt.RateLimit{
		// Public endpoints - IP-based rate limits (10 requests per 1 second per IP)
		{
			Command: "getMarkets", // GET /v1/public/info
			Scope:   dt.RateLimitScopeIP,
			RPS:     10.0,
			Burst:   10,
		},
		{
			Command: "getTimeframes", // No API call, returns static data
			Scope:   dt.RateLimitScopeIP,
			RPS:     10.0,
			Burst:   10,
		},
		{
			Command: "getOHLCV", // GET /v1/public/kline or /v1/hist/kline
			Scope:   dt.RateLimitScopeIP,
			RPS:     10.0,
			Burst:   10,
		},

		// WebSocket streams - Connection limits per IP (1000 concurrent)
		// Per account: 80 concurrent connections max
		{
			Command: "ohlcvStream",
			Scope:   dt.RateLimitScopeAPIKey, // Per account limit
			RPS:     1.0,                     // Allow setup, actual limit is concurrent connections
			Burst:   80,                      // Max 80 concurrent connections per account
		},
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

	return nil
}

// OnShutdown is called when the plugin is being shut down
func (p *WooXPlugin) OnShutdown() error {
	// Cleanup resources if needed
	return nil
}

// RegisterCommands registers all command handlers
func (p *WooXPlugin) RegisterCommands(router *datasrc.CommandRouter) {
	router.Register(cex.CEX_CMD_GET_MARKETS, p.handleGetMarkets)
	router.Register(cex.CEX_CMD_GET_TIMEFRAMES, p.handleGetTimeframes)
	router.Register(cex.CEX_CMD_OHLCV_STREAM, p.handleOHLCVStream)
	router.Register(cex.CEX_CMD_GET_OHLCV, p.handleGetOHLCV)
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

	return datasrc.SuccessResponse(markets, time.Hour*12)
}

// handleGetTimeframes returns supported timeframes
func (p *WooXPlugin) handleGetTimeframes(params map[string]any) dt.Response {
	timeframes := p.client.GetTimeframes()
	return datasrc.SuccessResponse(timeframes, time.Hour*12)
}

// handleGetOHLCV returns historical OHLCV data
func (p *WooXPlugin) handleGetOHLCV(params map[string]any) dt.Response {
	// Extract validated parameters - validation already done by terminal
	ohlcvParams := cex.GetOHLCVParamsFromMap(params)

	// Convert to client's OHLCVParams format
	clientParams := dt.OHLCVParams{
		Symbol:    ohlcvParams.Symbol,
		Timeframe: ohlcvParams.Timeframe,
		Limit:     ohlcvParams.Limit,
	}

	// Convert time.Time to unix milliseconds if provided
	if ohlcvParams.StartTime != nil {
		clientParams.StartTime = ohlcvParams.StartTime.UnixMilli()
	}
	if ohlcvParams.EndTime != nil {
		clientParams.EndTime = ohlcvParams.EndTime.UnixMilli()
	}

	// Fetch OHLCV data
	records, err := p.client.GetOHLCV(clientParams)
	if err != nil {
		return datasrc.ErrorResponse(err)
	}

	return datasrc.SuccessResponse(records)
}

// handleOHLCVStream sets up a WebSocket stream for OHLCV data
func (p *WooXPlugin) handleOHLCVStream(params map[string]any) dt.Response {
	logging.NewLogger("woox-datasource").InfoWithData("handleOHLCVStream", params)

	// Extract validated parameters - validation already done by terminal
	streamParams := cex.OHLCVStreamParamsFromMap(params)

	// Prepare stream setup request
	streamReq := dt.StreamSetupRequest{
		StreamID:   fmt.Sprintf("woox_ohlcv_%s_%s", streamParams.Symbol, streamParams.Timeframe),
		StreamType: "ohlcv",
		Parameters: map[string]any{
			"symbol":    streamParams.Symbol,
			"timeframe": streamParams.Timeframe,
			"private":   false, // Public stream for OHLCV
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
	// Create plugin instance
	plugin := &WooXPlugin{}

	// Register the plugin - this generates all standard WASM exports automatically
	// IMPORTANT: Must be in init(), not main(), so it runs before WASM exports are called
	datasrc.RegisterPlugin(plugin)

	// Register stream handler - this generates handle_stream_message and handle_connection_event exports
	// The client implements the StreamHandler interface (HandleStreamMessage, HandleConnectionEvent)
	// NOTE: client will be initialized in OnInit, but we register it here so the exports are available
	// The actual client instance will be set when OnInit is called
	datasrc.RegisterStreamHandler(&streamHandlerWrapper{plugin: plugin})
}

func main() {
	// Required for WASM, but can be empty
}

// ============================================================================
// Stream Handler Wrapper
// ============================================================================

// streamHandlerWrapper wraps the plugin to provide StreamHandler interface
// This allows us to register the stream handler before the client is initialized
type streamHandlerWrapper struct {
	plugin *WooXPlugin
}

func (w *streamHandlerWrapper) HandleStreamMessage(req dt.StreamMessageRequest) (dt.StreamMessageResponse, error) {
	if w.plugin.client == nil {
		return dt.StreamMessageResponse{Success: false, Action: "ignore"}, fmt.Errorf("client not initialized")
	}
	return w.plugin.client.HandleStreamMessage(req)
}

func (w *streamHandlerWrapper) HandleConnectionEvent(event dt.StreamConnectionEvent) (dt.StreamConnectionResponse, error) {
	if w.plugin.client == nil {
		return dt.StreamConnectionResponse{Success: false, Action: "ignore"}, fmt.Errorf("client not initialized")
	}
	return w.plugin.client.HandleConnectionEvent(event)
}
