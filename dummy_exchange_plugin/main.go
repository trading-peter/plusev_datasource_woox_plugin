package main

import (
	"fmt"
	"time"

	ex "github.com/plusev-terminal/go-plugin-common/datasrc/exchange"
	m "github.com/plusev-terminal/go-plugin-common/meta"
	"github.com/plusev-terminal/go-plugin-common/plugin"
	tt "github.com/plusev-terminal/go-plugin-common/trading"
)

// ============================================================================
// Main - Register the plugin
// ============================================================================

func init() {
	p := &DummyExchangePlugin{}
	plugin.RegisterPlugin(p)
}

func main() {
	// Required for WASM, but can be empty
}

// ============================================================================
// Plugin Implementation
// ============================================================================

type DummyExchangePlugin struct {
	config *plugin.ConfigStore
	base   DummyExchange
}

func (p *DummyExchangePlugin) GetMeta() m.Meta {
	return m.Meta{
		PluginID:    "dummy-datasource",
		Name:        "Dummy Exchange",
		AppID:       "datasrc",
		Category:    "demo",
		Description: "Dummy data source plugin template (returns fake markets + OHLCV)",
		Author:      "your_name",
		Version:     "v0.1.0",
		Repository:  "https://example.com/your-repo",
		Tags:        []string{"dummy", "template", "datasource"},
		Resources: m.ResourceAccess{
			AllowedNetworkTargets: []m.NetworkTargetRule{
				// Keep empty if you do not call the network.
				// If you later add HTTP calls, you MUST whitelist hosts here.
			},
		},
		Features: []string{},
	}
}

func (p *DummyExchangePlugin) GetRateLimits() []plugin.RateLimit {
	return []plugin.RateLimit{
		{
			Command: ex.CMD_GET_MARKETS,
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeIP},
			RPS:     20,
			Burst:   20,
		},
		{
			Command: ex.CMD_GET_TIMEFRAMES,
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeIP},
			RPS:     50,
			Burst:   50,
		},
		{
			Command: ex.CMD_GET_OHLCV,
			Scope:   []plugin.RateLimitScope{plugin.RateLimitScopeIP},
			RPS:     10,
			Burst:   10,
		},
	}
}

func (p *DummyExchangePlugin) GetConfigFields() []plugin.ConfigField {
	// The terminal builds a settings UI from these.
	// Keys here should match what you read in OnInit().
	return []plugin.ConfigField{
		{
			Label:       "API Key",
			Name:        "key",
			Description: "Generate on your account dashboard.",
			Required:    true,
			Type:        "password",
			Encrypt:     true,
			Mask:        true,
		},
		{
			Label:    "API Secret",
			Name:     "secret",
			Required: true,
			Type:     "password",
			Encrypt:  true,
			Mask:     true,
		},
	}
}

func (p *DummyExchangePlugin) OnInit(config *plugin.ConfigStore) error {
	p.config = config

	// This is where you would build your real client.
	// For the dummy exchange, we just seed deterministic behavior.
	creds := DummyCredentials{
		APIKey:    config.GetString("key"),
		APISecret: config.GetString("secret"),
	}

	p.base = DummyExchange{
		Credentials: creds,
	}

	return nil
}

func (p *DummyExchangePlugin) OnShutdown() error {
	return nil
}

func (p *DummyExchangePlugin) RegisterCommands(router *plugin.CommandRouter) {
	router.Register(ex.CMD_GET_MARKETS, p.handleGetMarkets)
	router.Register(ex.CMD_GET_TIMEFRAMES, p.handleGetTimeframes)
	router.Register(ex.CMD_GET_OHLCV, p.handleGetOHLCV)
}

// ============================================================================
// Command Handlers
// ============================================================================

func (p *DummyExchangePlugin) handleGetMarkets(params map[string]any) plugin.Response {
	markets := []tt.Market{
		{
			Label:        "BTC/USD",
			Symbol:       "BTC-USD",
			Base:         "BTC",
			Quote:        "USD",
			AssetType:    "spot",
			PriceTick:    "0.1",
			QuantityTick: "0.0001",
			MinQuantity:  "0.0001",
			Status:       "TRADING",
		},
		{
			Label:        "ETH/USD",
			Symbol:       "ETH-USD",
			Base:         "ETH",
			Quote:        "USD",
			AssetType:    "spot",
			PriceTick:    "0.01",
			QuantityTick: "0.001",
			MinQuantity:  "0.001",
			Status:       "TRADING",
		},
		{
			Label:        "BTC Perp",
			Symbol:       "BTC-PERP",
			Base:         "BTC",
			Quote:        "USD",
			AssetType:    "perpetual",
			PriceTick:    "0.1",
			QuantityTick: "0.001",
			MinQuantity:  "0.001",
			MaxLeverage:  "50",
			Status:       "TRADING",
		},
	}

	// Cache for 12h: markets rarely change.
	return plugin.SuccessResponse(markets, 12*time.Hour)
}

func (p *DummyExchangePlugin) handleGetTimeframes(params map[string]any) plugin.Response {
	// The terminal expects valid timeframe identifiers it knows how to request.
	// Use the same set you plan to support in OHLCV.
	timeframes := []string{"1m", "5m", "15m", "1h", "4h", "1d"}
	return plugin.SuccessResponse(timeframes, 12*time.Hour)
}

func (p *DummyExchangePlugin) handleGetOHLCV(params map[string]any) plugin.Response {
	if p.config == nil {
		return plugin.ErrorResponseMsg("plugin not initialized")
	}

	ohlcvParams := ex.GetOHLCVParamsFromMap(params)
	if ohlcvParams.Market.Symbol == "" {
		return plugin.ErrorResponseMsg("market.symbol is required")
	}

	records, err := p.base.GetOHLCV(ohlcvParams)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	// Use requested cache duration if provided; otherwise no cache.
	if ohlcvParams.CacheForSeconds > 0 {
		return plugin.SuccessResponse(records, time.Duration(ohlcvParams.CacheForSeconds)*time.Second)
	}

	return plugin.SuccessResponse(records)
}

// ============================================================================
// Dummy Exchange Implementation
// ============================================================================

type DummyExchange struct {
	Credentials DummyCredentials
}

type DummyCredentials struct {
	APIKey    string
	APISecret string
}

func (d DummyExchange) GetOHLCV(p ex.GetOHLCVParams) ([]tt.OHLCVRecord, error) {
	// GetOHLCV is expected to return candles in this shape:
	// - Timestamp: OpenTime (ms)
	// - OHLCV values: strings
	// This dummy implementation returns constant candles so it's easy to grasp.
	step, err := timeframeToDuration(p.Timeframe)
	if err != nil {
		return nil, err
	}

	end := time.Now().UTC().Truncate(step)
	limit := p.Limit
	if limit <= 0 {
		limit = 200
	}
	start := end.Add(-time.Duration(limit) * step)
	if p.StartTime != nil {
		start = p.StartTime.UTC()
	}
	if p.EndTime != nil {
		end = p.EndTime.UTC()
	}
	if !end.After(start) {
		return []tt.OHLCVRecord{}, nil
	}

	start = start.Truncate(step)
	end = end.Truncate(step)

	var out []tt.OHLCVRecord
	for t := start; !t.After(end); t = t.Add(step) {
		out = append(out, tt.OHLCVRecord{
			OpenTime: t.UnixMilli(),
			Open:     "100",
			High:     "100",
			Low:      "100",
			Close:    "100",
			Volume:   "0",
		})
	}

	return out, nil
}

func timeframeToDuration(tf string) (time.Duration, error) {
	switch tf {
	case "1m":
		return time.Minute, nil
	case "5m":
		return 5 * time.Minute, nil
	case "15m":
		return 15 * time.Minute, nil
	case "1h":
		return time.Hour, nil
	case "4h":
		return 4 * time.Hour, nil
	case "1d":
		return 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported timeframe: %s", tf)
	}
}
