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

	"github.com/plusev-terminal/go-plugin-common/logging"

	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	rt "github.com/plusev-terminal/go-plugin-common/requester/types"
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

// Legacy V3 subscription (deprecated)
type WSSubscribeMessageV3 struct {
	ID     string   `json:"id"`
	Cmd    string   `json:"cmd"`
	Params []string `json:"params"`
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

func (c *Client) GetConfigFields() []dt.ConfigField {
	return []dt.ConfigField{
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
func (c *Client) GetMarkets() ([]dt.Market, error) {
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

	var markets []dt.Market
	for _, instrument := range response.Data.Rows {
		// Skip inactive instruments
		if instrument.Status != "TRADING" {
			continue
		}

		// Determine asset type based on symbol format
		// WooX symbols: SPOT symbols like "BTC_USDT", PERP symbols like "PERP_BTC_USDT"
		var assetType string
		if strings.HasPrefix(instrument.Symbol, "PERP_") {
			assetType = "futures"
		} else {
			assetType = "spot"
		}

		markets = append(markets, dt.Market{
			Symbol:    instrument.Symbol,
			Base:      instrument.BaseAsset,
			Quote:     instrument.QuoteAsset,
			AssetType: assetType,
		})
	}

	return markets, nil
}

// GetTimeframes returns the timeframes supported by WooX v3
func (c *Client) GetTimeframes() []dt.Timeframe {
	// WooX supported timeframes according to API docs: 1m/5m/15m/30m/1h/4h/12h/1d/1w/1mon/1y
	return []dt.Timeframe{
		{Label: "1 Minute", Value: "1m", Interval: 60},
		{Label: "5 Minutes", Value: "5m", Interval: 300},
		{Label: "15 Minutes", Value: "15m", Interval: 900},
		{Label: "30 Minutes", Value: "30m", Interval: 1800},
		{Label: "1 Hour", Value: "1h", Interval: 3600},
		{Label: "4 Hours", Value: "4h", Interval: 14400},
		{Label: "12 Hours", Value: "12h", Interval: 43200},
		{Label: "1 Day", Value: "1d", Interval: 86400},
		{Label: "1 Week", Value: "1w", Interval: 604800},
		{Label: "1 Month", Value: "1mon", Interval: 2592000}, // Approximate
		{Label: "1 Year", Value: "1y", Interval: 31536000},   // Approximate
	}
}

// GetOHLCV fetches historical OHLCV data from WooX
func (c *Client) GetOHLCV(params dt.OHLCVParams) ([]dt.OHLCVRecord, error) {
	// Build query parameters according to WooX API docs
	// For historical data: GET https://api-pub.woo.org/v1/hist/kline
	// For recent data: GET /v1/public/kline
	queryParams := fmt.Sprintf("symbol=%s&type=%s", params.Symbol, params.Timeframe)

	// WooX uses start_time and end_time with 13-digit millisecond timestamps
	if params.StartTime > 0 {
		// Convert from seconds to milliseconds
		queryParams += fmt.Sprintf("&start_time=%d", params.StartTime*1000)
	}

	if params.EndTime > 0 {
		// Convert from seconds to milliseconds
		queryParams += fmt.Sprintf("&end_time=%d", params.EndTime*1000)
	}

	// Use 'size' parameter for limit (default 100, max 1000)
	if params.Limit > 0 {
		queryParams += fmt.Sprintf("&size=%d", params.Limit)
	} else {
		queryParams += "&size=100" // Default to 100
	}

	// Determine endpoint based on whether we need historical data
	var endpoint string
	useHistorical := params.StartTime > 0 || params.EndTime > 0

	if useHistorical {
		// Use the historical endpoint on the pub domain
		endpoint = "https://api-pub.woox.io/v1/hist/kline?" + queryParams
	} else {
		// Use the recent data endpoint
		endpoint = c.baseURL + "/v1/public/kline?" + queryParams
	}

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
		return nil, fmt.Errorf("failed to fetch OHLCV data from WooX: %w", err)
	}

	if !response.Success {
		return nil, fmt.Errorf("WooX API returned success=false for OHLCV data")
	}

	var records []dt.OHLCVRecord
	for _, kline := range response.Data.Rows {
		// Convert float64 values to strings for arbitrary precision
		records = append(records, dt.OHLCVRecord{
			Timestamp: kline.StartTimestamp / 1000, // Convert from milliseconds to seconds
			Open:      fmt.Sprintf("%.8f", kline.Open),
			High:      fmt.Sprintf("%.8f", kline.High),
			Low:       fmt.Sprintf("%.8f", kline.Low),
			Close:     fmt.Sprintf("%.8f", kline.Close),
			Volume:    fmt.Sprintf("%.8f", kline.Volume),
		})
	}

	return records, nil
}

// PrepareStream prepares streaming connection setup
func (c *Client) PrepareStream(request dt.StreamSetupRequest) (dt.StreamSetupResponse, error) {
	// Extract parameters
	symbol, _ := request.Parameters["symbol"].(string)
	interval, _ := request.Parameters["interval"].(string)
	usePrivate, _ := request.Parameters["private"].(bool)

	if symbol == "" {
		return dt.StreamSetupResponse{
			Success: false,
			Error:   "symbol parameter is required",
		}, nil
	}

	// Convert interval (timeframe) to WooX kline format
	// According to WooX docs, valid values are: 1m/5m/15m/30m/1h/4h/12h/1d/1w/1mon/1y
	timeframe := "1m" // default
	if interval != "" {
		timeframe = interval
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
			return dt.StreamSetupResponse{
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
			return dt.StreamSetupResponse{
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
		return dt.StreamSetupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to marshal subscribe message: %v", err),
		}, nil
	}

	initialMessages = append(initialMessages, string(msgBytes))

	return dt.StreamSetupResponse{
		Success:         true,
		WebSocketURL:    wsURL,
		Headers:         headers,
		Subprotocol:     "",
		InitialMessages: initialMessages,
	}, nil
}

// HandleStreamMessage processes incoming stream messages
func (c *Client) HandleStreamMessage(request dt.StreamMessageRequest) (dt.StreamMessageResponse, error) {
	// Try to parse as subscription response first (WebSocket V2 format)
	var wsResponse WSResponse
	if err := json.Unmarshal([]byte(request.Message), &wsResponse); err == nil {
		// Handle ping messages - send pong response
		if wsResponse.Event == "ping" {
			// WooX expects a pong message in response to ping
			// Format: {"event":"pong","ts":<timestamp>}
			pongMsg := fmt.Sprintf(`{"event":"pong","ts":%d}`, wsResponse.Ts)
			return dt.StreamMessageResponse{
				Success:     true,
				Action:      "send",
				SendMessage: pongMsg,
			}, nil
		}

		if wsResponse.Event == "subscribe" && wsResponse.Success {
			// Subscription successful - ignore
			return dt.StreamMessageResponse{
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
			// Convert to OHLCV record
			record, err := c.convertKlineToOHLCV(klineUpdate)
			if err != nil {
				return dt.StreamMessageResponse{
					Success: true,
					Action:  "ignore",
				}, nil
			}

			return dt.StreamMessageResponse{
				Success:  true,
				Action:   "data",
				DataType: "ohlcv",
				Data:     record,
			}, nil
		}
	}

	// Unknown message - ignore
	return dt.StreamMessageResponse{
		Success: true,
		Action:  "ignore",
	}, nil
}

// HandleConnectionEvent handles stream connection events
func (c *Client) HandleConnectionEvent(event dt.StreamConnectionEvent) (dt.StreamConnectionResponse, error) {
	switch event.EventType {
	case "connecting":
		// Connection attempt in progress
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	case "connected":
		// Connection established successfully
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	case "disconnected":
		// Connection lost - request reconnection
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "reconnect",
		}, nil
	case "error":
		c.log.ErrorWithData("WebSocket error occurred", map[string]any{
			"error": event.Error,
		})
		// Error occurred - do NOT reconnect here, wait for disconnected event
		// This prevents double reconnection attempts
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	default:
		c.log.InfoWithData("Unknown connection event", map[string]any{
			"event_type": event.EventType,
		})
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	}
}

// convertKlineToOHLCV converts WooX kline data to OHLCV record
func (c *Client) convertKlineToOHLCV(update WSKlineUpdate) (dt.OHLCVRecord, error) {
	// WooX returns numeric values as float64, convert to strings for arbitrary precision
	return dt.OHLCVRecord{
		Timestamp: update.Data.StartTime / 1000, // Convert from milliseconds to seconds
		Open:      fmt.Sprintf("%.8f", update.Data.Open),
		High:      fmt.Sprintf("%.8f", update.Data.High),
		Low:       fmt.Sprintf("%.8f", update.Data.Low),
		Close:     fmt.Sprintf("%.8f", update.Data.Close),
		Volume:    fmt.Sprintf("%.8f", update.Data.Volume),
	}, nil
}

// mapIntervalToTimeframe converts interval seconds to WooX timeframe string
func (c *Client) mapIntervalToTimeframe(interval int64) string {
	switch interval {
	case 60:
		return "1m"
	case 180:
		return "3m"
	case 300:
		return "5m"
	case 900:
		return "15m"
	case 1800:
		return "30m"
	case 3600:
		return "1h"
	case 7200:
		return "2h"
	case 14400:
		return "4h"
	case 21600:
		return "6h"
	case 43200:
		return "12h"
	case 86400:
		return "1d"
	case 604800:
		return "1w"
	case 2592000:
		return "1mon"
	case 31536000:
		return "1y"
	default:
		return "1h" // Default to 1 hour
	}
}

// SupportsStreaming returns true as WebSocket streaming is now implemented
func (c *Client) SupportsStreaming() bool {
	return true
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
