package woox

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	rt "github.com/plusev-terminal/go-plugin-common/requester/types"
)

// Client represents a client for the WooX v3 API
type Client struct {
	name      string
	baseURL   string
	requester rt.RequestDoer
}

// NewClient creates a new WooX API client
func NewClient(req rt.RequestDoer, baseURL string) *Client {
	return &Client{
		name:      "WooX",
		baseURL:   baseURL,
		requester: req,
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
	Symbol         string `json:"symbol"`
	Open           string `json:"open"`
	High           string `json:"high"`
	Low            string `json:"low"`
	Close          string `json:"close"`
	Volume         string `json:"volume"`
	Amount         string `json:"amount"`
	Type           string `json:"type"`
	StartTimestamp int64  `json:"startTimestamp"`
	EndTimestamp   int64  `json:"endTimestamp"`
}

// GetName returns the name of the data source
func (c *Client) GetName() string {
	return c.name
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
func (c *Client) PrepareStream(config dt.StreamConfig) (dt.StreamSetup, error) {
	// Determine WebSocket URL based on environment
	wsURL := "wss://wss.woox.io/v3/public"
	if strings.Contains(c.baseURL, "staging") {
		wsURL = "wss://wss.staging.woox.io/v3/public"
	}

	// Map interval to timeframe string
	timeframe := c.mapIntervalToTimeframe(config.Interval)

	// Create subscription message
	topic := fmt.Sprintf("kline_%s_%s", config.Symbol, timeframe)
	subscribeMsg := WSSubscribeMessage{
		ID:     "sub_1",
		Cmd:    "SUBSCRIBE",
		Params: []string{topic},
	}

	msgBytes, err := json.Marshal(subscribeMsg)
	if err != nil {
		return dt.StreamSetup{}, fmt.Errorf("failed to marshal subscribe message: %w", err)
	}

	return dt.StreamSetup{
		WebSocketURL:    wsURL,
		Headers:         nil,
		Subprotocol:     "",
		InitialMessages: []string{string(msgBytes)},
	}, nil
}

// HandleStreamMessage processes incoming stream messages
func (c *Client) HandleStreamMessage(message dt.StreamMessage) (dt.StreamResponse, error) {
	// Try to parse as subscription response first
	var wsResponse WSResponse
	if err := json.Unmarshal([]byte(message.Message), &wsResponse); err == nil {
		if wsResponse.Cmd == "SUBSCRIBE" && wsResponse.Success {
			// Subscription successful - ignore
			return dt.StreamResponse{Action: "ignore"}, nil
		}
	}

	// Try to parse as kline update
	var klineUpdate WSKlineUpdate
	if err := json.Unmarshal([]byte(message.Message), &klineUpdate); err == nil {
		if strings.HasPrefix(klineUpdate.Topic, "kline_") {
			// Convert to OHLCV record
			record, err := c.convertKlineToOHLCV(klineUpdate)
			if err != nil {
				return dt.StreamResponse{Action: "ignore"}, nil
			}

			return dt.StreamResponse{
				Action:      "ohlcv",
				OHLCVRecord: &record,
			}, nil
		}
	}

	// Unknown message - ignore
	return dt.StreamResponse{Action: "ignore"}, nil
}

// HandleConnectionEvent handles stream connection events
func (c *Client) HandleConnectionEvent(event dt.ConnectionEvent) (dt.ConnectionResponse, error) {
	switch event.EventType {
	case "connected":
		// Connection established successfully
		return dt.ConnectionResponse{Action: "ignore"}, nil
	case "disconnected":
		// Connection lost - request reconnection
		return dt.ConnectionResponse{Action: "reconnect"}, nil
	case "error":
		// Error occurred - attempt reconnection
		return dt.ConnectionResponse{Action: "reconnect"}, nil
	default:
		return dt.ConnectionResponse{Action: "ignore"}, nil
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
