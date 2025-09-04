package woox

import (
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

// StartStream starts streaming live data (not implemented yet)
func (c *Client) StartStream(config dt.StreamConfig) error {
	// WebSocket streaming will be implemented once the WebSocket host functions are available
	return fmt.Errorf("WebSocket streaming not yet implemented for WooX")
}

// SupportsStreaming returns false as WebSocket streaming is not yet implemented
func (c *Client) SupportsStreaming() bool {
	return false
}
