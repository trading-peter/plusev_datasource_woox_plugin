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
	name      string
	baseURL   string
	requester rt.RequestDoer
	log       *logging.Logger
	apiKey    string
	apiSecret string
}

// NewClient creates a new WooX API client
func NewClient(req rt.RequestDoer, baseURL string) *Client {
	return &Client{
		name:      "WooX",
		baseURL:   baseURL,
		requester: req,
		log:       logging.NewLogger("WooX"),
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
	Symbol         string `json:"symbol"`
	Open           string `json:"open"`
	Close          string `json:"close"`
	High           string `json:"high"`
	Low            string `json:"low"`
	Volume         string `json:"volume"`
	Amount         string `json:"amount"`
	Type           string `json:"type"`
	StartTimestamp int64  `json:"startTimestamp"`
	EndTimestamp   int64  `json:"endTimestamp"`
}

type KlineResponse struct {
	Success   bool  `json:"success"`
	Timestamp int64 `json:"timestamp"`
	Data      struct {
		Rows []KlineData `json:"rows"`
	} `json:"data"`
}

// WooX WebSocket message structures
type WSSubscribeMessage struct {
	ID     string   `json:"id"`
	Cmd    string   `json:"cmd"`
	Params []string `json:"params"`
}

type WSResponse struct {
	ID      string   `json:"id"`
	Cmd     string   `json:"cmd"`
	Success bool     `json:"success"`
	Time    int64    `json:"time"`
	Data    []string `json:"data,omitempty"`
}

type WSKlineUpdate struct {
	Topic string      `json:"topic"`
	Ts    int64       `json:"ts"`
	Data  WSKlineData `json:"data"`
}

type WSKlineData struct {
	Symbol         string `json:"s"`   // symbol
	Type           string `json:"t"`   // kline type
	Open           string `json:"o"`   // open
	Close          string `json:"c"`   // close
	High           string `json:"h"`   // high
	Low            string `json:"l"`   // low
	Volume         string `json:"v"`   // volume in base token
	Amount         string `json:"a"`   // amount in USDT
	StartTimestamp int64  `json:"st"`  // kline start timestamp
	EndTimestamp   int64  `json:"et"`  // kline end timestamp
	Timestamp      int64  `json:"ts"`  // kline generation time
	TradeTimestamp int64  `json:"tts"` // last trade time
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
	c.apiKey = creds["apiKey"]
	c.apiSecret = creds["apiSecret"]
}

// GetName returns the name of the data source
func (c *Client) GetName() string {
	return c.name
}

func (c *Client) GetCredentialFields() ([]dt.CredentialField, error) {
	return []dt.CredentialField{
		{
			Name:      "api_key",
			Encrypt:   false,
			Mask:      true,
			OmitEmpty: true,
		},
		{
			Name:      "api_secret",
			Encrypt:   true,
			Mask:      true,
			OmitEmpty: true,
		},
	}, nil
}

// GetMarkets returns all available trading markets from WooX
func (c *Client) GetMarkets() ([]dt.MarketMeta, error) {
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

	var markets []dt.MarketMeta
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

		markets = append(markets, dt.MarketMeta{
			Name:      instrument.Symbol,
			Base:      instrument.BaseAsset,
			Quote:     instrument.QuoteAsset,
			AssetType: assetType,
		})
	}

	return markets, nil
}

// GetTimeframes returns the timeframes supported by WooX v3
func (c *Client) GetTimeframes() []dt.Timeframe {
	// WooX v3 supported timeframes: 1m/3m/5m/15m/30m/1h/2h/4h/6h/12h/1d/1w/1mon/1y
	return []dt.Timeframe{
		{Label: "1m", ApiValue: "1m", Interval: 60},
		{Label: "3m", ApiValue: "3m", Interval: 180},
		{Label: "5m", ApiValue: "5m", Interval: 300},
		{Label: "15m", ApiValue: "15m", Interval: 900},
		{Label: "30m", ApiValue: "30m", Interval: 1800},
		{Label: "1h", ApiValue: "1h", Interval: 3600},
		{Label: "2h", ApiValue: "2h", Interval: 7200},
		{Label: "4h", ApiValue: "4h", Interval: 14400},
		{Label: "6h", ApiValue: "6h", Interval: 21600},
		{Label: "12h", ApiValue: "12h", Interval: 43200},
		{Label: "1d", ApiValue: "1d", Interval: 86400},
		{Label: "1w", ApiValue: "1w", Interval: 604800},
		{Label: "1M", ApiValue: "1mon", Interval: 2592000}, // Approximate
		{Label: "1y", ApiValue: "1y", Interval: 31536000},  // Approximate
	}
}

// GetOHLCV fetches historical OHLCV data from WooX v3
func (c *Client) GetOHLCV(params dt.OHLCVParams) ([]dt.OHLCVRecord, error) {
	// Build query parameters for v3 API
	queryParams := fmt.Sprintf("symbol=%s&type=%s", params.Symbol, params.Timeframe)

	// Use before/after pagination instead of start_t/end_t
	if params.StartTime > 0 {
		// Convert to milliseconds for v3 API
		queryParams += fmt.Sprintf("&after=%d", params.StartTime*1000)
	}

	if params.EndTime > 0 {
		// Convert to milliseconds for v3 API
		queryParams += fmt.Sprintf("&before=%d", params.EndTime*1000)
	}

	if params.Limit > 0 {
		queryParams += fmt.Sprintf("&limit=%d", params.Limit)
	}

	req := &rt.Request{
		Method: "GET",
		URL:    c.baseURL + "/v3/public/klineHistory?" + queryParams,
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
		// Parse string values to float64
		open, err := strconv.ParseFloat(kline.Open, 64)
		if err != nil {
			continue // Skip invalid data
		}

		high, err := strconv.ParseFloat(kline.High, 64)
		if err != nil {
			continue
		}

		low, err := strconv.ParseFloat(kline.Low, 64)
		if err != nil {
			continue
		}

		close, err := strconv.ParseFloat(kline.Close, 64)
		if err != nil {
			continue
		}

		volume, err := strconv.ParseFloat(kline.Volume, 64)
		if err != nil {
			continue
		}

		records = append(records, dt.OHLCVRecord{
			Timestamp: kline.StartTimestamp / 1000, // Convert from milliseconds to seconds
			Open:      open,
			High:      high,
			Low:       low,
			Close:     close,
			Volume:    volume,
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

		c.log.InfoWithData(fmt.Sprintf("Preparing private stream for %s", symbol), map[string]any{
			"websocket_url": wsURL,
			"listen_key":    listenKey[:8] + "...", // Log only first 8 chars for security
		})
	} else {
		// Public WebSocket connection
		if strings.Contains(c.baseURL, "staging") {
			wsURL = "wss://wss.staging.woox.io/v3/public"
		} else {
			wsURL = "wss://wss.woox.io/v3/public"
		}

		c.log.InfoWithData(fmt.Sprintf("Preparing public stream for %s", symbol), map[string]any{
			"websocket_url": wsURL,
		})
	}

	// Convert interval (timeframe) to WooX kline format
	timeframe := "1m" // default
	if interval != "" {
		timeframe = interval
	}

	// Create subscription message
	topic := fmt.Sprintf("kline@%s@%s", symbol, timeframe)
	subscribeMsg := WSSubscribeMessage{
		ID:     "sub_1",
		Cmd:    "SUBSCRIBE",
		Params: []string{topic},
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
	c.log.InfoWithData(fmt.Sprintf("Processing message for stream %s", request.StreamID), map[string]any{
		"message": request.Message,
	})

	// Try to parse as subscription response first
	var wsResponse WSResponse
	if err := json.Unmarshal([]byte(request.Message), &wsResponse); err == nil {
		if wsResponse.Cmd == "SUBSCRIBE" && wsResponse.Success {
			// Subscription successful - ignore
			return dt.StreamMessageResponse{
				Success: true,
				Action:  "ignore",
			}, nil
		}
	}

	// Try to parse as kline update
	var klineUpdate WSKlineUpdate
	if err := json.Unmarshal([]byte(request.Message), &klineUpdate); err == nil {
		if strings.HasPrefix(klineUpdate.Topic, "kline@") {
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
		// Error occurred - attempt reconnection
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "reconnect",
		}, nil
	default:
		return dt.StreamConnectionResponse{
			Success: true,
			Action:  "ignore",
		}, nil
	}
}

// convertKlineToOHLCV converts WooX kline data to OHLCV record
func (c *Client) convertKlineToOHLCV(update WSKlineUpdate) (dt.OHLCVRecord, error) {
	// Parse string values to float64
	open, err := strconv.ParseFloat(update.Data.Open, 64)
	if err != nil {
		return dt.OHLCVRecord{}, fmt.Errorf("failed to parse open price: %w", err)
	}

	high, err := strconv.ParseFloat(update.Data.High, 64)
	if err != nil {
		return dt.OHLCVRecord{}, fmt.Errorf("failed to parse high price: %w", err)
	}

	low, err := strconv.ParseFloat(update.Data.Low, 64)
	if err != nil {
		return dt.OHLCVRecord{}, fmt.Errorf("failed to parse low price: %w", err)
	}

	close, err := strconv.ParseFloat(update.Data.Close, 64)
	if err != nil {
		return dt.OHLCVRecord{}, fmt.Errorf("failed to parse close price: %w", err)
	}

	volume, err := strconv.ParseFloat(update.Data.Volume, 64)
	if err != nil {
		return dt.OHLCVRecord{}, fmt.Errorf("failed to parse volume: %w", err)
	}

	return dt.OHLCVRecord{
		Timestamp: update.Data.StartTimestamp / 1000, // Convert from milliseconds to seconds
		Open:      open,
		High:      high,
		Low:       low,
		Close:     close,
		Volume:    volume,
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
