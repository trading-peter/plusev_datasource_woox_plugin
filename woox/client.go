package woox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/plusev-terminal/go-plugin-common/datasrc/exchange"
	"github.com/plusev-terminal/go-plugin-common/logging"

	"github.com/plusev-terminal/go-plugin-common/plugin"
	rt "github.com/plusev-terminal/go-plugin-common/requester/types"
	tt "github.com/plusev-terminal/go-plugin-common/trading"
)

// Client represents a client for the WooX v3 API
type Client struct {
	name          string
	baseURL       string
	requester     rt.RequestDoer
	log           *logging.Logger
	applicationID string // WooX Application ID (decrypted)
	apiKey        string // API Key (decrypted)
	apiSecret     string // API Secret (decrypted)
}

// NewClient creates a new WooX API client
func NewClient(req rt.RequestDoer, baseURL string) *Client {
	return &Client{
		name:      "WooX",
		baseURL:   baseURL,
		requester: req,
		log:       logging.NewLogger("woox-datasource"),
	}
}

// WooX v3 API response structures
type Instrument struct {
	Symbol               string `json:"symbol"`
	Status               string `json:"status"`
	BaseAsset            string `json:"baseAsset"`
	BaseAssetMultiplier  int    `json:"baseAssetMultiplier"`
	QuoteAsset           string `json:"quoteAsset"`
	QuoteMin             string `json:"quoteMin"`
	QuoteMax             string `json:"quoteMax"`
	QuoteTick            string `json:"quoteTick"`
	BaseMin              string `json:"baseMin"`
	BaseMax              string `json:"baseMax"`
	BaseTick             string `json:"baseTick"`
	MinNotional          string `json:"minNotional"`
	BidCapRatio          string `json:"bidCapRatio"`
	BidFloorRatio        string `json:"bidFloorRatio"`
	AskCapRatio          string `json:"askCapRatio"`
	AskFloorRatio        string `json:"askFloorRatio"`
	FundingIntervalHours int    `json:"fundingIntervalHours"`
	FundingCap           string `json:"fundingCap"`
	FundingFloor         string `json:"fundingFloor"`
	OrderMode            string `json:"orderMode"`
	BaseIMR              string `json:"baseIMR"`
	BaseMMR              string `json:"baseMMR"`
	IsAllowedRpi         bool   `json:"isAllowedRpi"`
}

type InstrumentsResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		Rows []Instrument `json:"rows"`
	} `json:"data"`
}

type KlineData struct {
	Symbol         string  `json:"symbol"`
	Open           float64 `json:"open"`
	Close          float64 `json:"close"`
	High           float64 `json:"high"`
	Low            float64 `json:"low"`
	Volume         float64 `json:"volume"`
	Amount         float64 `json:"amount"`
	Type           string  `json:"type"`
	StartTimestamp int64   `json:"start_timestamp"` // Note: snake_case as per API docs
	EndTimestamp   int64   `json:"end_timestamp"`   // Note: snake_case as per API docs
}

type KlineResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		Rows []KlineData `json:"rows"`
	} `json:"data"`
}

// WooX WebSocket message structures
// WebSocket API V2 subscription message structure
type WSSubscribeMessage struct {
	ID    string `json:"id"`
	Event string `json:"event"` // "subscribe" or "unsubscribe"
	Topic string `json:"topic"` // Format: {symbol}@kline_{time}
}

type WSResponse struct {
	ID      string `json:"id"`
	Event   string `json:"event"`
	Success bool   `json:"success"`
	Ts      int64  `json:"ts"`
	Data    any    `json:"data,omitempty"`
}

type WSKlineUpdate struct {
	Topic string      `json:"topic"`
	Ts    int64       `json:"ts"`
	Data  WSKlineData `json:"data"`
}

type WSKlineData struct {
	Symbol    string  `json:"symbol"`    // symbol name
	Type      string  `json:"type"`      // kline type (1m, 5m, etc.)
	Open      float64 `json:"open"`      // open price
	Close     float64 `json:"close"`     // close price
	High      float64 `json:"high"`      // high price
	Low       float64 `json:"low"`       // low price
	Volume    float64 `json:"volume"`    // volume in base token
	Amount    float64 `json:"amount"`    // amount in quote currency
	StartTime int64   `json:"startTime"` // kline start timestamp (milliseconds)
	EndTime   int64   `json:"endTime"`   // kline end timestamp (milliseconds)
}

// Listen Key API structures for private WebSocket authentication
type ListenKeyResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		ListenKey string `json:"listenKey"`
	} `json:"data"`
}

// Account info structures for private endpoints
type AccountInfo struct {
	ApplicationID       string `json:"applicationId"`
	Account             string `json:"account"`
	Alias               string `json:"alias"`
	AccountMode         string `json:"accountMode"`
	LeverageMode        string `json:"leverageMode"`
	TakerFeeRate        string `json:"takerFeeRate"`
	MakerFeeRate        string `json:"makerFeeRate"`
	InterestRate        string `json:"interestRate"`
	FuturesTakerFeeRate string `json:"futuresTakerFeeRate"`
	FuturesMakerFeeRate string `json:"futuresMakerFeeRate"`
	OtcCredit           string `json:"otcCredit"`
	DepositEnabled      bool   `json:"depositEnabled"`
	WithdrawEnabled     bool   `json:"withdrawEnabled"`
	TradeEnabled        bool   `json:"tradeEnabled"`
}

type AccountInfoResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		Rows []AccountInfo `json:"rows"`
	} `json:"data"`
}

// Balance and position structures
type Balance struct {
	Token    string `json:"token"`
	Holding  string `json:"holding"`
	Frozen   string `json:"frozen"`
	Interest string `json:"interest"`
	Pending  string `json:"pending"`
	Staked   string `json:"staked"`
}

type BalanceResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		Holding []Balance `json:"holding"`
	} `json:"data"`
}

// Order structures
type OrderRequest struct {
	Symbol        string `json:"symbol"`
	ClientID      string `json:"clientOrderId,omitempty"`
	OrderTag      string `json:"orderTag,omitempty"`
	OrderType     string `json:"orderType"` // LIMIT, MARKET, IOC, FOK, POST_ONLY, ASK, BID
	Side          string `json:"side"`      // BUY, SELL
	Amount        string `json:"amount,omitempty"`
	Price         string `json:"price,omitempty"`
	TriggerPrice  string `json:"triggerPrice,omitempty"`
	Quantity      string `json:"quantity,omitempty"`
	QuoteQuantity string `json:"quoteQuantity,omitempty"`
	ReduceOnly    bool   `json:"reduceOnly,omitempty"`
}

type Order struct {
	OrderID               int64  `json:"orderId"`
	ClientID              string `json:"clientOrderId"`
	OrderTag              string `json:"orderTag"`
	Symbol                string `json:"symbol"`
	Side                  string `json:"side"`
	OrderType             string `json:"orderType"`
	Quantity              string `json:"quantity"`
	Amount                string `json:"amount"`
	Price                 string `json:"price"`
	TriggerPrice          string `json:"triggerPrice"`
	OrderStatus           string `json:"status"`
	CreatedTime           int64  `json:"createdTime"`
	UpdatedTime           int64  `json:"updatedTime"`
	TotalExecutedQuantity string `json:"totalExecutedQuantity"`
	TotalFee              string `json:"totalFee"`
	FeeAsset              string `json:"feeAsset"`
	TotalRebate           string `json:"totalRebate"`
	RebateAsset           string `json:"rebateAsset"`
	ReduceOnly            bool   `json:"reduceOnly"`
}

type OrderResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		Rows []Order `json:"rows"`
	} `json:"data"`
}

func (c *Client) SetCredentials(creds map[string]string) {
	// Store decrypted credentials in the client struct (NOT in pdk.SetVar!)
	if appID, ok := creds["applicationID"]; ok {
		c.applicationID = appID
	}

	if key, ok := creds["key"]; ok {
		c.apiKey = key
	}

	if secret, ok := creds["secret"]; ok {
		c.apiSecret = secret
	}
}

// GetName returns the name of the data source
func (c *Client) GetName() string {
	return c.name
}

func (c *Client) GetConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Label:    "Application ID",
			Name:     "applicationID",
			Required: true,
			Encrypt:  true,
			Mask:     false,
		},
		{
			Label:       "API Key",
			Name:        "key",
			Description: "Generate here: https://woox.io/en/account/sub-account",
			Required:    true,
			Encrypt:     true,
			Mask:        true,
		},
		{
			Label:    "API Secret",
			Name:     "secret",
			Required: true,
			Encrypt:  true,
			Mask:     true,
		},
	}
}

// GetMarkets returns all available trading markets from WooX
func (c *Client) GetMarkets() ([]tt.Market, error) {
	req := &rt.Request{
		Method: "GET",
		URL:    c.baseURL + "/v3/public/instruments",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	// Add authentication if available for enhanced market data
	c.addAuthHeaders(req, "")

	var response InstrumentsResponse
	_, err := c.requester.Send(req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch instruments from WooX: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("WooX API returned success=false")
	}

	var markets []tt.Market
	for _, instrument := range response.Data.Rows {
		// Skip inactive instruments
		if instrument.Status != "TRADING" {
			continue
		}

		// Determine asset type based on symbol format
		// WooX symbols: SPOT symbols like "BTC_USDT", PERP symbols like "PERP_BTC_USDT"
		assetType := "spot"
		if strings.HasPrefix(instrument.Symbol, "PERP_") {
			assetType = "perpetual"
		}

		market := tt.Market{
			Label:     c.formatMarketLabel(instrument.Symbol, assetType),
			Symbol:    instrument.Symbol,
			Base:      instrument.BaseAsset,
			Quote:     instrument.QuoteAsset,
			AssetType: assetType,
			Status:    instrument.Status,

			// Precision & limits
			PriceTick:         instrument.QuoteTick,
			QuantityTick:      instrument.BaseTick,
			PricePrecision:    countPrecisionFromTickString(instrument.QuoteTick),
			QuantityPrecision: countPrecisionFromTickString(instrument.BaseTick),
			MinQuantity:       instrument.BaseMin,
			MaxQuantity:       instrument.BaseMax,
			MinNotional:       instrument.MinNotional,
			MaxNotional:       instrument.QuoteMax,

			// Funding
			FundingInterval: instrument.FundingIntervalHours,
			FundingCap:      instrument.FundingCap,
			FundingFloor:    instrument.FundingFloor,

			// Margin
			InitialMarginRate:     instrument.BaseIMR,
			MaintenanceMarginRate: instrument.BaseMMR,
		}

		markets = append(markets, market)
	}

	return markets, nil
}

func countPrecisionFromTickString(tick string) int {
	if tick == "" || tick == "0" {
		return 0
	}
	idx := strings.Index(tick, ".")
	if idx == -1 {
		return 0
	}
	dec := strings.TrimRight(tick[idx+1:], "0")
	if dec == "" {
		return 0
	}
	if len(dec) > 12 {
		return 12
	}
	return len(dec)
}

func (c *Client) formatMarketLabel(symbol, assetType string) string {
	parts := strings.Split(symbol, "_")
	if len(parts) != 3 {
		return symbol
	}

	if assetType == "perpetual" {
		return parts[1] + "-PERP"
	}

	if assetType == "spot" {
		return parts[1] + "/" + parts[2]
	}

	return symbol
}

// GetTimeframes returns the timeframes supported by WooX v3
func (c *Client) GetTimeframes() []tt.Timeframe {
	// WooX supported timeframes according to API docs: 1m/5m/15m/30m/1h/4h/12h/1d/1w/1mon/1y
	return []tt.Timeframe{
		{Value: 1, Unit: tt.Minutes},
		{Value: 5, Unit: tt.Minutes},
		{Value: 15, Unit: tt.Minutes},
		{Value: 30, Unit: tt.Minutes},
		{Value: 1, Unit: tt.Hours},
		{Value: 4, Unit: tt.Hours},
		{Value: 12, Unit: tt.Hours},
		{Value: 1, Unit: tt.Days},
		{Value: 1, Unit: tt.Weeks},
		{Value: 1, Unit: tt.Months},
		{Value: 1, Unit: tt.Years},
	}
}

// GetOHLCV fetches historical OHLCV data from WooX
func (c *Client) GetOHLCV(params exchange.GetOHLCVParams) ([]tt.OHLCVRecord, error) {
	// WooX has maximum time range limits per kline type (in milliseconds):
	// 1m: 604800000ms (7 days)
	// 5m: 2592000000ms (30 days)
	// 15m, 30m, 1h: 7776000000ms (90 days)
	// 4h, 12h, 1d: 31536000000ms (365 days)
	// If the requested range exceeds the limit, we cap it to the maximum allowed.
	// The calling application should detect incomplete results and request additional chunks.

	// Cap time range if both start and end are provided
	if params.StartTime != nil && params.EndTime != nil {
		var maxRangeMs int64
		switch params.Timeframe {
		case "1m":
			maxRangeMs = 604800000 // 7 days
		case "5m":
			maxRangeMs = 2592000000 // 30 days
		case "15m", "30m", "1h":
			maxRangeMs = 7776000000 // 90 days
		case "4h", "12h", "1d", "1w", "1mon", "1y":
			maxRangeMs = 31536000000 // 365 days
		default:
			maxRangeMs = 7776000000 // Default to 90 days
		}

		startMs := params.StartTime.UnixMilli()
		endMs := params.EndTime.UnixMilli()
		rangeMs := endMs - startMs

		if rangeMs > maxRangeMs {
			// Cap the end time to the maximum allowed range
			cappedEndMs := startMs + maxRangeMs
			cappedEnd := time.UnixMilli(cappedEndMs)
			params.EndTime = &cappedEnd

			c.log.WarnWithData("Time range exceeds WooX API limit, capping request", map[string]any{
				"requestedRangeMs": rangeMs,
				"maxRangeMs":       maxRangeMs,
				"timeframe":        params.Timeframe,
				"originalEnd":      endMs,
				"cappedEnd":        cappedEndMs,
			})
		}
	}

	// Build query parameters according to WooX API docs
	// For historical data: GET https://api-pub.woo.org/v1/hist/kline
	// For recent data: GET /v1/public/kline
	symbol := strings.TrimSpace(params.Market.Symbol)
	if symbol == "" {
		return nil, fmt.Errorf("market.symbol is required")
	}

	queryParams := fmt.Sprintf("symbol=%s&type=%s", symbol, params.Timeframe)

	// WooX uses start_time and end_time with 13-digit millisecond timestamps
	if params.StartTime != nil {
		// Convert from seconds to milliseconds
		queryParams += fmt.Sprintf("&start_time=%d", (*params.StartTime).UnixMilli())
	}

	if params.EndTime != nil {
		// Convert from seconds to milliseconds
		queryParams += fmt.Sprintf("&end_time=%d", (*params.EndTime).UnixMilli())
	}

	// Use 'size' parameter for limit (default 100, max 1000)
	if params.Limit > 0 {
		queryParams += fmt.Sprintf("&size=%d", params.Limit)
	} else {
		queryParams += "&size=100" // Default to 100
	}

	// Determine endpoint based on whether we need historical data
	var endpoint string
	useHistorical := params.StartTime != nil || params.EndTime != nil

	if useHistorical {
		// Use the historical endpoint on the pub domain
		endpoint = "https://api-pub.woox.io/v1/hist/kline?" + queryParams
	} else {
		// Use the recent data endpoint
		endpoint = c.baseURL + "/v1/public/kline?" + queryParams
	}

	c.log.InfoWithData("Fetching OHLCV from WooX", map[string]any{
		"endpoint":      endpoint,
		"symbol":        symbol,
		"timeframe":     params.Timeframe,
		"useHistorical": useHistorical,
	})

	req := &rt.Request{
		Method: "GET",
		URL:    endpoint,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	// Add authentication if available for enhanced rate limits
	c.addAuthHeaders(req, "")

	var response KlineResponse
	_, err := c.requester.Send(req, &response)
	if err != nil {
		c.log.ErrorWithData("Failed to fetch OHLCV data from WooX", map[string]any{
			"error":    err.Error(),
			"endpoint": endpoint,
			"symbol":   symbol,
		})
		return nil, fmt.Errorf("failed to fetch OHLCV data from WooX: %w", err)
	}

	if !response.Success {
		c.log.ErrorWithData("WooX API returned success=false", map[string]any{
			"endpoint":  endpoint,
			"symbol":    symbol,
			"timestamp": response.Timestamp,
		})
		return nil, fmt.Errorf("WooX API returned success=false for OHLCV data")
	}

	// Check if we got any data
	if len(response.Data.Rows) == 0 {
		c.log.WarnWithData("WooX returned no data", map[string]any{
			"endpoint": endpoint,
			"symbol":   symbol,
		})
		return []tt.OHLCVRecord{}, nil // Return empty slice for no data
	}

	var records []tt.OHLCVRecord
	for _, kline := range response.Data.Rows {
		// Convert float64 values to strings for arbitrary precision
		records = append(records, tt.OHLCVRecord{
			OpenTime: kline.StartTimestamp / 1000, // Convert from milliseconds to seconds
			Open:     fmt.Sprintf("%.8f", kline.Open),
			High:     fmt.Sprintf("%.8f", kline.High),
			Low:      fmt.Sprintf("%.8f", kline.Low),
			Close:    fmt.Sprintf("%.8f", kline.Close),
			Volume:   fmt.Sprintf("%.8f", kline.Volume),
		})
	}

	c.log.InfoWithData("Successfully fetched OHLCV data", map[string]any{
		"recordCount": len(records),
		"symbol":      symbol,
	})

	return records, nil
}

// PrepareStream prepares streaming connection setup
func (c *Client) PrepareStream(request plugin.StreamSetupRequest) (plugin.StreamSetupResponse, error) {
	c.log.InfoWithData("PrepareStream", map[string]any{
		"streamRequest": request,
	})

	// Caller-owned context (required and authoritative).
	streamContext, _ := request.Parameters["streamContext"].(map[string]any)
	if streamContext == nil {
		return plugin.StreamSetupResponse{Success: false, Error: "streamContext is required"}, nil
	}
	ctxSymbol, _ := streamContext["symbol"].(string)
	ctxTimeframe, _ := streamContext["timeframe"].(string)
	if strings.TrimSpace(ctxSymbol) == "" || strings.TrimSpace(ctxTimeframe) == "" {
		return plugin.StreamSetupResponse{Success: false, Error: "streamContext.symbol and streamContext.timeframe are required"}, nil
	}

	// Extract parameters
	// Strict contract: symbol/timeframe come from streamContext.
	symbol := strings.TrimSpace(ctxSymbol)
	timeframe := strings.TrimSpace(ctxTimeframe)
	usePrivate, _ := request.Parameters["private"].(bool)

	supportedTf := c.GetTimeframes()

	found := false
	for _, tf := range supportedTf {
		if tf.String() == timeframe {
			found = true
			break
		}
	}

	if !found {
		return plugin.StreamSetupResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported timeframe: %s", timeframe),
		}, nil
	}

	// Determine WebSocket URL based on environment and authentication
	var wsURL string
	var initialMessages []string
	var headers map[string]string

	if usePrivate && c.isAuthenticated() {
		// Private WebSocket connection with authentication
		if strings.Contains(c.baseURL, "staging") {
			wsURL = "wss://wss.staging.woox.io/v3/private"
		} else {
			wsURL = "wss://wss.woox.io/v3/private"
		}

		// Generate listen key for private connection
		listenKey, err := c.generateListenKey()
		if err != nil {
			return plugin.StreamSetupResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to generate listen key: %v", err),
			}, nil
		}

		// Add listen key as query parameter
		wsURL += "?listenKey=" + listenKey
	} else {
		// Public WebSocket connection - Use WebSocket API V2 with application_id
		// URL format: wss://wss.woox.io/ws/stream/{application_id}

		// Use the decrypted applicationID from the client struct
		if c.applicationID == "" {
			return plugin.StreamSetupResponse{
				Success: false,
				Error:   "WooX Application ID not configured. Please add your WooX credentials (Application ID, API Key, API Secret) in the data source settings.",
			}, nil
		}

		if strings.Contains(c.baseURL, "staging") {
			wsURL = fmt.Sprintf("wss://wss.staging.woox.io/ws/stream/%s", c.applicationID)
		} else {
			wsURL = fmt.Sprintf("wss://wss.woox.io/ws/stream/%s", c.applicationID)
		}
	}

	// Create subscription message for WebSocket API V2
	// Topic format: {symbol}@kline_{time}
	// Example: "SPOT_BTC_USDT@kline_1m"
	topic := fmt.Sprintf("%s@kline_%s", symbol, timeframe)
	subscribeMsg := WSSubscribeMessage{
		ID:    "sub_1",
		Event: "subscribe",
		Topic: topic,
	}

	msgBytes, err := json.Marshal(subscribeMsg)
	if err != nil {
		return plugin.StreamSetupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to marshal subscribe message: %v", err),
		}, nil
	}

	initialMessages = append(initialMessages, string(msgBytes))

	return plugin.StreamSetupResponse{
		Success:         true,
		WebSocketURL:    wsURL,
		Headers:         headers,
		Subprotocol:     "",
		InitialMessages: initialMessages,
		StreamContext:   streamContext,
	}, nil
}

// HandleStreamMessage processes incoming stream messages
func (c *Client) HandleStreamMessage(request plugin.StreamMessageRequest) (plugin.StreamMessageResponse, error) {
	// Try to parse as subscription response first (WebSocket V2 format)
	var wsResponse WSResponse
	if err := json.Unmarshal([]byte(request.Message), &wsResponse); err == nil {
		if wsResponse.Event == "subscribe" && wsResponse.Success {
			// Subscription successful - ignore
			return plugin.StreamMessageResponse{
				Success: true,
				Action:  "ignore",
			}, nil
		}
	}

	// Try to parse as kline update (WebSocket V2 format)
	var klineUpdate WSKlineUpdate
	if err := json.Unmarshal([]byte(request.Message), &klineUpdate); err == nil {
		// Topic format: {symbol}@kline_{time}, e.g., "SPOT_BTC_USDT@kline_1m"
		if strings.Contains(klineUpdate.Topic, "@kline_") {
			symbol, _ := request.StreamContext["symbol"].(string)
			timeframe, _ := request.StreamContext["timeframe"].(string)

			if symbol == "" || timeframe == "" {
				// Missing context - ignore message (host should persist StreamContext)
				return plugin.StreamMessageResponse{Success: true, Action: "ignore"}, nil
			}

			// Build expected topic for this stream
			expectedTopic := fmt.Sprintf("%s@kline_%s", symbol, timeframe)

			// Only process messages that match this stream's symbol and timeframe
			if klineUpdate.Topic != expectedTopic {
				// This message is for a different stream - ignore it
				return plugin.StreamMessageResponse{
					Success: true,
					Action:  "ignore",
				}, nil
			}

			// Convert to OHLCV record
			record, err := c.convertKlineToOHLCV(klineUpdate)
			if err != nil {
				return plugin.StreamMessageResponse{
					Success: true,
					Action:  "ignore",
				}, nil
			}

			return plugin.StreamMessageResponse{
				Success:  true,
				Action:   "data",
				DataType: "ohlcv",
				Data:     record,
			}, nil
		}
	}

	// Unknown message - ignore
	return plugin.StreamMessageResponse{
		Success: true,
		Action:  "ignore",
	}, nil
}

// HandleConnectionEvent handles stream connection events
func (c *Client) HandleConnectionEvent(event plugin.StreamConnectionEvent) (plugin.StreamConnectionResponse, error) {
	switch event.EventType {
	case "connecting":
		// Connection attempt in progress
		return plugin.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	case "connected":
		// Connection established successfully
		return plugin.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	case "disconnected":
		// Connection lost. Let the host decide reconnection strategy.
		return plugin.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	case "error":
		c.log.ErrorWithData("WebSocket error occurred", map[string]any{
			"error": event.Error,
		})
		// Error occurred - do NOT reconnect here, wait for disconnected event
		// This prevents double reconnection attempts
		return plugin.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	default:
		c.log.InfoWithData("Unknown connection event", map[string]any{
			"event_type": event.EventType,
		})
		return plugin.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	}
}

// convertKlineToOHLCV converts WooX kline data to OHLCV record
func (c *Client) convertKlineToOHLCV(update WSKlineUpdate) (tt.OHLCVRecord, error) {
	// WooX returns numeric values as float64, convert to strings for arbitrary precision
	return tt.OHLCVRecord{
		OpenTime: update.Data.StartTime / 1000, // Convert from milliseconds to seconds
		Open:     fmt.Sprintf("%.8f", update.Data.Open),
		High:     fmt.Sprintf("%.8f", update.Data.High),
		Low:      fmt.Sprintf("%.8f", update.Data.Low),
		Close:    fmt.Sprintf("%.8f", update.Data.Close),
		Volume:   fmt.Sprintf("%.8f", update.Data.Volume),
	}, nil
}

// generateWooXSignature creates HMAC SHA256 signature for WooX API authentication
func (c *Client) generateWooXSignature(timestamp string, method, path, body string) string {
	// Create the string to sign: timestamp + method + path + body
	message := timestamp + method + path + body

	h := hmac.New(sha256.New, []byte(c.apiSecret))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// addAuthHeaders adds WooX authentication headers to a request
func (c *Client) addAuthHeaders(req *rt.Request, body string) {
	if c.apiKey == "" || c.apiSecret == "" {
		return // No authentication configured
	}

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	// Extract path from URL for signature
	path := req.URL
	if strings.Contains(path, c.baseURL) {
		path = strings.TrimPrefix(path, c.baseURL)
	}

	signature := c.generateWooXSignature(timestamp, req.Method, path, body)

	if req.Headers == nil {
		req.Headers = make(map[string]string)
	}

	req.Headers["x-api-key"] = c.apiKey
	req.Headers["x-api-timestamp"] = timestamp
	req.Headers["x-api-signature"] = signature
	req.Headers["Content-Type"] = "application/json"
}

// isAuthenticated returns true if the client has authentication credentials
func (c *Client) isAuthenticated() bool {
	return c.apiKey != "" && c.apiSecret != ""
}

// generateListenKey generates a listen key for private WebSocket connections
func (c *Client) generateListenKey() (string, error) {
	if !c.isAuthenticated() {
		return "", fmt.Errorf("authentication required for listen key generation")
	}

	req := &rt.Request{
		Method: "POST",
		URL:    c.baseURL + "/v3/private/user/ws/listenKey",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	c.addAuthHeaders(req, "")

	var response ListenKeyResponse
	_, err := c.requester.Send(req, &response)
	if err != nil {
		return "", fmt.Errorf("failed to generate listen key: %w", err)
	}

	if !response.Success {
		return "", fmt.Errorf("WooX API returned success=false for listen key generation")
	}

	return response.Data.ListenKey, nil
}

// GetAccountInfo retrieves account information (requires authentication)
func (c *Client) GetAccountInfo() (*AccountInfo, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("authentication required for account info")
	}

	req := &rt.Request{
		Method: "GET",
		URL:    c.baseURL + "/v3/private/client/info",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	c.addAuthHeaders(req, "")

	var response AccountInfoResponse
	_, err := c.requester.Send(req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account info: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("WooX API returned success=false for account info")
	}

	if len(response.Data.Rows) == 0 {
		return nil, fmt.Errorf("no account info returned")
	}

	return &response.Data.Rows[0], nil
}

// GetBalances retrieves account balances (requires authentication)
func (c *Client) GetBalances() ([]Balance, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("authentication required for balance info")
	}

	req := &rt.Request{
		Method: "GET",
		URL:    c.baseURL + "/v3/private/client/holding",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	c.addAuthHeaders(req, "")

	var response BalanceResponse
	_, err := c.requester.Send(req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch balances: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("WooX API returned success=false for balances")
	}

	return response.Data.Holding, nil
}

// PlaceOrder places a new order (requires authentication)
func (c *Client) PlaceOrder(orderReq OrderRequest) (*Order, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("authentication required for placing orders")
	}

	body, err := json.Marshal(orderReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal order request: %w", err)
	}

	req := &rt.Request{
		Method: "POST",
		URL:    c.baseURL + "/v3/private/order",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: body,
	}

	c.addAuthHeaders(req, string(body))

	var response struct {
		Success   bool  `json:"success"`
		Timestamp int64 `json:"timestamp"`
		Data      Order `json:"data"`
	}

	_, err = c.requester.Send(req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to place order: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("WooX API returned success=false for order placement")
	}

	return &response.Data, nil
}

// GetOrders retrieves orders (requires authentication)
func (c *Client) GetOrders(symbol string, status string, limit int) ([]Order, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("authentication required for order history")
	}

	queryParams := ""
	if symbol != "" {
		queryParams += "symbol=" + symbol
	}
	if status != "" {
		if queryParams != "" {
			queryParams += "&"
		}
		queryParams += "status=" + status
	}
	if limit > 0 {
		if queryParams != "" {
			queryParams += "&"
		}
		queryParams += fmt.Sprintf("size=%d", limit)
	}

	url := c.baseURL + "/v3/private/orders"
	if queryParams != "" {
		url += "?" + queryParams
	}

	req := &rt.Request{
		Method: "GET",
		URL:    url,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	c.addAuthHeaders(req, "")

	var response OrderResponse
	_, err := c.requester.Send(req, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch orders: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("WooX API returned success=false for orders")
	}

	return response.Data.Rows, nil
}

// CancelOrder cancels an existing order (requires authentication)
func (c *Client) CancelOrder(orderID string, symbol string) error {
	if !c.isAuthenticated() {
		return fmt.Errorf("authentication required for order cancellation")
	}

	req := &rt.Request{
		Method: "DELETE",
		URL:    c.baseURL + "/v3/private/order/" + orderID,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	c.addAuthHeaders(req, "")

	var response struct {
		Success   bool  `json:"success"`
		Timestamp int64 `json:"timestamp"`
	}

	_, err := c.requester.Send(req, &response)
	if err != nil {
		return fmt.Errorf("failed to cancel order: %w", err)
	}

	if !response.Success {
		return fmt.Errorf("WooX API returned success=false for order cancellation")
	}

	return nil
}
