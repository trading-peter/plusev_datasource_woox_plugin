package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/extism/go-pdk"
	feat "github.com/plusev-terminal/go-plugin-common/datasrc/features"
	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	"github.com/plusev-terminal/go-plugin-common/logging"
	m "github.com/plusev-terminal/go-plugin-common/meta"
	"github.com/plusev-terminal/go-plugin-common/requester"

	"github.com/trading-peter/plusev_datasource_woox_plugin/woox"
)

func main() {}

// ============================================================================
// GENERIC PLUGIN INTERFACE
// ============================================================================

// StreamKey uniquely identifies a data stream
type StreamKey struct {
	Type         string            `json:"type"`         // "ohlcv", "orderbook", "trades"
	Source       string            `json:"source"`       // "woox"
	Identifier   string            `json:"identifier"`   // "BTC-PERP"
	Parameters   map[string]string `json:"parameters"`   // {"interval": "1h"}
	ConnectionID *uint64           `json:"connectionId"` // Optional
}

// StreamData is published to the actor system
type StreamData struct {
	Key       StreamKey       `json:"key"`
	Data      json.RawMessage `json:"data"` // The actual data (OHLCV, orderbook, etc.)
	Timestamp time.Time       `json:"timestamp"`
}

// OHLCVData represents OHLCV candlestick data
type OHLCVData struct {
	Symbol    string    `json:"symbol"`
	Interval  string    `json:"interval"`
	Timestamp time.Time `json:"timestamp"`
	Open      float64   `json:"open"`
	High      float64   `json:"high"`
	Low       float64   `json:"low"`
	Close     float64   `json:"close"`
	Volume    float64   `json:"volume"`
}

// ============================================================================
// PLUGIN STATE
// ============================================================================

var (
	wooxClient    *woox.Client
	pluginMutex   sync.RWMutex
	activeStreams = make(map[string]*StreamContext)
	streamMutex   sync.RWMutex
)

type StreamContext struct {
	Key          StreamKey
	ConnectionID string
	Cancel       context.CancelFunc
	Running      bool
}

func init() {
	// Create woox client with requester that uses host's http_request function
	wooxClient = woox.NewClient(requester.NewRequester(), "https://api.woox.io")
}

// ============================================================================
// PLUGIN METADATA
// ============================================================================

//go:wasmexport meta
func meta() int32 {
	pdk.OutputJSON(m.Meta{
		PluginID:    "woox-datasource-generic",
		Name:        "WooX Exchange (Generic)",
		AppID:       "datasrc",
		Category:    "CexDataSource",
		Description: "WooX Exchange data source using generic streaming interface",
		Author:      "PlusEV Team",
		Version:     "2.0.1",
		Repository:  "https://github.com/trading-peter/plusev_datasource_woox_plugin",
		Tags:        []string{"woox", "crypto", "exchange", "spot", "futures", "generic"},
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
		},
		Features: []string{
			feat.HISTORIC_OHLCV,
			feat.OHLCV_STREAM,
		},
	})

	return 0
}

//go:wasmexport plugin_info
func plugin_info() int32 {
	info := map[string]interface{}{
		"name":        "woox-generic",
		"version":     "2.0.0",
		"author":      "PlusEV Team",
		"type":        "datasource",
		"description": "WooX Exchange data source - generic interface",
		"streamTypes": []string{"ohlcv", "orderbook", "trades"},
		"networkTargets": []string{
			"https://api.woox.io/*",
			"wss://wss.woox.io/*",
		},
	}
	pdk.OutputJSON(info)
	return 0
}

// ============================================================================
// CONFIGURATION
// ============================================================================

//go:wasmexport plugin_configure
func plugin_configure() int32 {
	input := pdk.Input()
	var config map[string]string
	if err := json.Unmarshal(input, &config); err != nil {
		pdk.SetError(fmt.Errorf("invalid config: %w", err))
		return 1
	}

	pluginMutex.Lock()
	defer pluginMutex.Unlock()

	// Set credentials on the woox client
	wooxClient.SetCredentials(config)

	pdk.OutputString("configured")
	return 0
}

// ============================================================================
// STREAM MANAGEMENT
// ============================================================================

//go:wasmexport start_stream
func start_stream() int32 {
	input := pdk.Input()

	var key StreamKey
	if err := json.Unmarshal(input, &key); err != nil {
		return errorResponse(fmt.Sprintf("invalid stream key: %v", err))
	}

	logging.NewLogger("woox-datasource").Info(fmt.Sprintf("Starting stream: %s:%s:%s at timeframe %s", key.Source, key.Type, key.Identifier, key.Parameters["timeframe"]))

	// Route to appropriate stream handler
	switch key.Type {
	case "ohlcv":
		return startOHLCVStream(key)
	case "orderbook":
		return errorResponse("orderbook streams not yet implemented")
	case "trades":
		return errorResponse("trade streams not yet implemented")
	default:
		return errorResponse(fmt.Sprintf("unknown stream type: %s", key.Type))
	}
}

//go:wasmexport stop_stream
func stop_stream() int32 {
	input := pdk.Input()

	var key StreamKey
	if err := json.Unmarshal(input, &key); err != nil {
		return errorResponse(fmt.Sprintf("invalid stream key: %v", err))
	}

	streamID := keyToStreamID(key)

	streamMutex.Lock()
	ctx, exists := activeStreams[streamID]
	if exists {
		if ctx.Cancel != nil {
			ctx.Cancel()
		}
		delete(activeStreams, streamID)
	}
	streamMutex.Unlock()

	if !exists {
		return errorResponse("stream not found")
	}

	// Close WebSocket connection
	if ctx.ConnectionID != "" {
		wsClose(ctx.ConnectionID)
	}

	return successResponse(map[string]string{"status": "stopped"})
}

// ============================================================================
// OHLCV STREAM IMPLEMENTATION
// ============================================================================

func startOHLCVStream(key StreamKey) int32 {
	// Get parameters
	symbol := key.Identifier
	interval := key.Parameters["timeframe"] // Changed from "interval" to "timeframe"

	if symbol == "" {
		return errorResponse("symbol is required")
	}
	if interval == "" {
		interval = "1h" // Default
	}

	// Convert interval to WooX format
	wooxInterval := convertInterval(interval)
	if wooxInterval == "" {
		return errorResponse(fmt.Sprintf("unsupported interval: %s", interval))
	}

	// Connect to WebSocket with applicationID from credentials
	// Get applicationID from plugin vars (set via plugin_configure)
	appIDBytes := pdk.GetVar("applicationID")
	applicationID := "public" // Default fallback
	if len(appIDBytes) > 0 {
		applicationID = string(appIDBytes)
	}

	wsURL := fmt.Sprintf("wss://wss.woox.io/ws/stream/%s", applicationID)
	connID, err := wsConnect(wsURL, nil)
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to connect: %v", err))
	}

	// Subscribe to kline stream
	channel := fmt.Sprintf("%s@kline_%s", symbol, wooxInterval)
	subscribeMsg := map[string]interface{}{
		"id":    "kline_" + symbol + "_" + wooxInterval,
		"topic": channel,
		"event": "subscribe",
	}

	if err := wsSend(connID, subscribeMsg); err != nil {
		wsClose(connID)
		return errorResponse(fmt.Sprintf("failed to subscribe: %v", err))
	}

	// Create stream context
	ctx, cancel := context.WithCancel(context.Background())
	streamID := keyToStreamID(key)

	streamMutex.Lock()
	activeStreams[streamID] = &StreamContext{
		Key:          key,
		ConnectionID: connID,
		Cancel:       cancel,
		Running:      true,
	}
	streamMutex.Unlock()

	// Start message receiver
	logging.NewLogger("woox-datasource").Info("About to start receiveOHLCVMessages goroutine")
	go receiveOHLCVMessages(ctx, connID, key, symbol, interval)
	logging.NewLogger("woox-datasource").Info("receiveOHLCVMessages goroutine started")

	// Give the goroutine a chance to start (WASM compatibility)
	time.Sleep(10 * time.Millisecond)
	logging.NewLogger("woox-datasource").Info("After sleep, returning from startOHLCVStream")

	return successResponse(map[string]string{
		"status":       "started",
		"connectionId": connID,
		"channel":      channel,
	})
}

func receiveOHLCVMessages(ctx context.Context, connID string, key StreamKey, symbol, interval string) {
	log := logging.NewLogger("woox-datasource")

	log.Info(fmt.Sprintf("Started OHLCV stream for %s at interval %s", symbol, interval))

	defer func() {
		streamID := keyToStreamID(key)
		streamMutex.Lock()
		delete(activeStreams, streamID)
		streamMutex.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Receive message with 5 second timeout
			msg, timeout, err := wsReceive(connID, 5000)

			if err != nil {
				log.Warn(fmt.Sprintf("WebSocket receive error for %s: %v", symbol, err))
				continue
			}

			if timeout {
				continue // No message, try again
			}

			// Log all non-empty messages to see what we're getting
			if msg != "" {
				log.Info(fmt.Sprintf("Received message: %s", msg))
			}

			// Parse WooX message
			var wsMsg struct {
				Topic string          `json:"topic"`
				Data  json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal([]byte(msg), &wsMsg); err != nil {
				log.Debug(fmt.Sprintf("Failed to parse WebSocket message: %v", err))
				continue
			}

			// Log the topic to see what we're getting
			if wsMsg.Topic != "" {
				log.Info(fmt.Sprintf("Message topic: %s", wsMsg.Topic))
			}

			// Check if it's a kline message (format: {symbol}@kline_{interval})
			if !strings.Contains(wsMsg.Topic, "@kline_") {
				log.Info(fmt.Sprintf("Skipping non-kline message: %s", wsMsg.Topic))
				continue // Not a kline message
			}

			log.Info(fmt.Sprintf("Processing kline message: %s", wsMsg.Topic))

			// Parse kline data - WooX uses "startTime" not "startTimestamp" per docs
			var kline struct {
				Symbol    string  `json:"symbol"`
				Type      string  `json:"type"`
				Open      float64 `json:"open"`
				Close     float64 `json:"close"`
				High      float64 `json:"high"`
				Low       float64 `json:"low"`
				Volume    float64 `json:"volume"`
				Amount    float64 `json:"amount"`
				StartTime int64   `json:"startTime"`
				EndTime   int64   `json:"endTime"`
			}
			if err := json.Unmarshal(wsMsg.Data, &kline); err != nil {
				log.Debug(fmt.Sprintf("Failed to parse kline data: %v", err))
				continue
			}

			// Convert to OHLCVData
			ohlcv := OHLCVData{
				Symbol:    symbol,
				Interval:  interval,
				Timestamp: time.UnixMilli(kline.StartTime),
				Open:      kline.Open,
				High:      kline.High,
				Low:       kline.Low,
				Close:     kline.Close,
				Volume:    kline.Volume,
			}

			// Publish to actor system
			if err := publishStreamData(key, ohlcv); err != nil {
				log.Error(fmt.Sprintf("Failed to publish stream data: %v", err))
			}
		}
	}
}

// ============================================================================
// HOST FUNCTIONS (WebSocket Delegation)
// ============================================================================

// Host function declarations (provided by terminal)
//
//go:wasmimport extism:host/user ws_connect
func hostWSConnect(uint64) uint64

//go:wasmimport extism:host/user ws_send
func hostWSSend(uint64) uint64

//go:wasmimport extism:host/user ws_receive
func hostWSReceive(uint64) uint64

//go:wasmimport extism:host/user ws_close
func hostWSClose(uint64) uint64

//go:wasmimport extism:host/user publish_stream_data
func hostPublishStreamData(uint64) uint64

func wsConnect(url string, headers map[string]string) (string, error) {
	req := map[string]interface{}{
		"url":     url,
		"headers": headers,
	}

	mem, err := pdk.AllocateJSON(req)
	if err != nil {
		return "", fmt.Errorf("failed to allocate memory: %w", err)
	}

	ptr := hostWSConnect(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	respData := rmem.ReadBytes()

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

func wsSend(connID string, message interface{}) error {
	msgJSON, err := json.Marshal(message)
	if err != nil {
		return err
	}

	req := map[string]interface{}{
		"connectionId": connID,
		"message":      string(msgJSON),
	}

	mem, err := pdk.AllocateJSON(req)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %w", err)
	}

	ptr := hostWSSend(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	respData := rmem.ReadBytes()

	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("%s", resp.Error)
	}

	return nil
}

func wsReceive(connID string, timeoutMs int) (string, bool, error) {
	req := map[string]interface{}{
		"connectionId": connID,
		"timeoutMs":    timeoutMs,
	}

	mem, err := pdk.AllocateJSON(req)
	if err != nil {
		return "", false, fmt.Errorf("failed to allocate memory: %w", err)
	}

	ptr := hostWSReceive(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	respData := rmem.ReadBytes()

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Timeout bool   `json:"timeout"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", false, fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Success {
		return "", false, fmt.Errorf("%s", resp.Error)
	}

	return resp.Message, resp.Timeout, nil
}

func wsClose(connID string) error {
	req := map[string]interface{}{
		"connectionId": connID,
	}

	mem, err := pdk.AllocateJSON(req)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %w", err)
	}

	ptr := hostWSClose(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	respData := rmem.ReadBytes()

	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("%s", resp.Error)
	}

	return nil
}

// ============================================================================
// UTILITIES
// ============================================================================

func publishStreamData(key StreamKey, data interface{}) error {
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	streamData := StreamData{
		Key:       key,
		Data:      dataJSON,
		Timestamp: time.Now(),
	}

	mem, err := pdk.AllocateJSON(streamData)
	if err != nil {
		return fmt.Errorf("failed to allocate memory: %w", err)
	}

	ptr := hostPublishStreamData(mem.Offset())
	rmem := pdk.FindMemory(ptr)
	respData := rmem.ReadBytes()

	var resp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("%s", resp.Error)
	}

	return nil
}

// ============================================================================
// DATA DISCOVERY FUNCTIONS (Required by CexDataSource category)
// ============================================================================

//go:wasmexport get_credential_fields
func get_credential_fields() int32 {
	fields, err := wooxClient.GetCredentialFields()
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to get credential fields: %v", err))
	}
	pdk.OutputJSON(fields)
	return 0
}

//go:wasmexport get_name
func get_name() int32 {
	pdk.OutputString(wooxClient.GetName())
	return 0
}

//go:wasmexport list_markets
func list_markets() int32 {
	markets, err := wooxClient.GetMarkets()
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to get markets: %v", err))
	}
	pdk.OutputJSON(markets)
	return 0
}

//go:wasmexport get_timeframes
func get_timeframes() int32 {
	timeframes := wooxClient.GetTimeframes()
	pdk.OutputJSON(timeframes)
	return 0
}

//go:wasmexport get_ohlcv
func get_ohlcv() int32 {
	input := pdk.Input()

	var params dt.OHLCVParams
	if err := json.Unmarshal(input, &params); err != nil {
		return errorResponse(fmt.Sprintf("invalid params: %v", err))
	}

	records, err := wooxClient.GetOHLCV(params)
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to get OHLCV: %v", err))
	}

	pdk.OutputJSON(records)
	return 0
}

//go:wasmexport prepare_stream
func prepare_stream() int32 {
	input := pdk.Input()

	var request dt.StreamSetupRequest
	if err := json.Unmarshal(input, &request); err != nil {
		return errorResponse(fmt.Sprintf("invalid request: %v", err))
	}

	response, err := wooxClient.PrepareStream(request)
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to prepare stream: %v", err))
	}

	pdk.OutputJSON(response)
	if response.Success {
		return 0
	}
	return 1
}

//go:wasmexport handle_stream_message
func handle_stream_message() int32 {
	input := pdk.Input()

	var request dt.StreamMessageRequest
	if err := json.Unmarshal(input, &request); err != nil {
		return errorResponse(fmt.Sprintf("invalid request: %v", err))
	}

	response, err := wooxClient.HandleStreamMessage(request)
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to handle message: %v", err))
	}

	// If action is "data", publish it via the stream system
	if response.Action == "data" {
		// Extract stream parameters from request to build stream key
		// The terminal should have sent these with the message
		streamKey := StreamKey{
			Type:       response.DataType,
			Source:     "woox-datasource-generic",
			Identifier: request.StreamID, // Temporary - should come from params
			Parameters: make(map[string]string),
		}

		// Publish the data
		if err := publishStreamData(streamKey, response.Data); err != nil {
			logging.NewLogger("woox-datasource").Warn(fmt.Sprintf("Failed to publish stream data: %v", err))
		}
	}

	pdk.OutputJSON(response)
	if response.Success {
		return 0
	}
	return 1
}

//go:wasmexport stream_connection_event
func stream_connection_event() int32 {
	input := pdk.Input()

	var event dt.StreamConnectionEvent
	if err := json.Unmarshal(input, &event); err != nil {
		return errorResponse(fmt.Sprintf("invalid event: %v", err))
	}

	response, err := wooxClient.HandleConnectionEvent(event)
	if err != nil {
		return errorResponse(fmt.Sprintf("failed to handle event: %v", err))
	}

	pdk.OutputJSON(response)
	if response.Success {
		return 0
	}
	return 1
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func convertInterval(interval string) string {
	// Map generic intervals to WooX format
	mapping := map[string]string{
		"1m":  "1m",
		"5m":  "5m",
		"15m": "15m",
		"30m": "30m",
		"1h":  "1h",
		"4h":  "4h",
		"12h": "12h",
		"1d":  "1d",
		"1w":  "1w",
		"1M":  "1mon",
	}
	return mapping[interval]
}

func keyToStreamID(key StreamKey) string {
	return fmt.Sprintf("%s:%s:%s:%s", key.Type, key.Source, key.Identifier, key.Parameters["timeframe"])
}

func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

func successResponse(data interface{}) int32 {
	resp := map[string]interface{}{
		"success": true,
		"data":    data,
	}
	pdk.OutputJSON(resp)
	return 0
}

func errorResponse(message string) int32 {
	resp := map[string]interface{}{
		"success": false,
		"error":   message,
	}
	pdk.OutputJSON(resp)
	return 1
}
