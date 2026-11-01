package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	ex "github.com/plusev-terminal/go-plugin-common/v2/datasrc/exchange"
	acct "github.com/plusev-terminal/go-plugin-common/v2/datasrc/exchange/account"
	"github.com/plusev-terminal/go-plugin-common/v2/logging"
	m "github.com/plusev-terminal/go-plugin-common/v2/meta"
	"github.com/plusev-terminal/go-plugin-common/v2/plugin"
	"github.com/plusev-terminal/go-plugin-common/v2/requester"
	commonstream "github.com/plusev-terminal/go-plugin-common/v2/stream"

	"github.com/trading-peter/plusev_datasource_woox_plugin/woox"
	"github.com/trading-peter/plusev_datasource_woox_plugin/wooxlimits"
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
		Author:      "trading_peter",
		Version:     "v1.1.0",
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
				// WOO X's published per-endpoint rate limits — the rule table
				// and its doc sources live in the wooxlimits package (pure
				// meta, natively testable). Public endpoints are limited per
				// IP, private endpoints per account (application ID); these
				// are the standard app-less tiers, overridable in the Rate
				// Limits UI.
				{
					Pattern: "https://api.woox.io/*",
					Limits:  wooxlimits.APIWooX(),
				},
				{
					Pattern: "https://api-pub.woox.io/*",
					Limits:  wooxlimits.APIPubWooX(),
				},
				// Staging (testnet) mirrors the production endpoints, but the
				// REST base URL is hardcoded to https://api.woox.io, so no REST
				// traffic ever reaches staging — nothing declared there.
				{Pattern: "https://api.staging.woox.io/*"},
				{Pattern: "wss://wss.woox.io/*"},
				{Pattern: "wss://wss.staging.woox.io/*"},
			},
		},
		// Features will be auto-populated with registered commands
		Features: []string{},
	}
}

// GetRateLimits returns an empty slice: WOO X's real per-endpoint budgets are
// declared as manifest limits on the network targets in GetMeta, and opting
// out of the legacy per-command limiter here keeps requests from being
// throttled by both layers.
func (p *WooXPlugin) GetRateLimits() []plugin.RateLimit {
	return []plugin.RateLimit{}
}

// GetOrderCapabilities deliberately declares nothing: this plugin registers
// no createOrders command (its order surface is read-only — getOrders plus
// trade/order/transfer history), so the honest capability set is empty. The
// host reads this declaration and rejects any order attempt against WooX
// with a clear error instead of dispatching it to a plugin that cannot place
// orders.
func (p *WooXPlugin) GetOrderCapabilities() ex.OrderCapabilities {
	return ex.OrderCapabilities{}
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
	router.Register(ex.CMD_GET_BALANCES, p.handleGetBalances)
	router.Register(ex.CMD_GET_POSITIONS, p.handleGetPositions)
	router.Register(ex.CMD_GET_ORDERS, p.handleGetOrders)
	router.Register(ex.CMD_GET_TRADE_HISTORY, p.handleGetTradeHistory)
	router.Register(ex.CMD_GET_ORDER_HISTORY, p.handleGetOrderHistory)
	router.Register(ex.CMD_GET_TRANSFER_HISTORY, p.handleGetTransferHistory)
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

func normalizeWooXSide(side string) acct.OrderSide {
	s := strings.ToUpper(strings.TrimSpace(side))
	switch s {
	case "BUY", "BID", "LONG":
		return acct.OrderSideBuy
	case "SELL", "ASK", "SHORT":
		return acct.OrderSideSell
	case "":
		return acct.OrderSideUnknown
	default:
		return acct.OrderSide(strings.ToLower(s))
	}
}

func normalizeWooXStatus(status string) acct.OrderStatus {
	s := strings.ToUpper(strings.TrimSpace(status))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	switch s {
	case "NEW":
		return acct.OrderStatusNew
	case "PARTIAL_FILLED", "PARTIALLY_FILLED":
		return acct.OrderStatusPartiallyFilled
	case "FILLED":
		return acct.OrderStatusFilled
	case "CANCELED", "CANCELLED":
		return acct.OrderStatusCanceled
	case "REJECTED":
		return acct.OrderStatusRejected
	case "EXPIRED":
		return acct.OrderStatusExpired
	case "INCOMPLETE":
		return acct.OrderStatusIncomplete
	case "COMPLETED":
		return acct.OrderStatusCompleted
	case "":
		return acct.OrderStatusUnknown
	default:
		return acct.OrderStatus(strings.ToLower(s))
	}
}

func normalizeWooXType(orderType string) (acct.OrderType, acct.TimeInForce, bool) {
	s := strings.ToUpper(strings.TrimSpace(orderType))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	switch s {
	case "LIMIT":
		return acct.OrderTypeLimit, acct.TimeInForceUnknown, false
	case "MARKET":
		return acct.OrderTypeMarket, acct.TimeInForceUnknown, false
	case "IOC":
		return acct.OrderTypeLimit, acct.TimeInForceIOC, false
	case "FOK":
		return acct.OrderTypeLimit, acct.TimeInForceFOK, false
	case "POST_ONLY":
		return acct.OrderTypeLimit, acct.TimeInForcePostOnly, true
	case "ASK", "BID":
		return acct.OrderTypeLimit, acct.TimeInForceUnknown, false
	case "STOP", "STOP_LOSS":
		return acct.OrderTypeStop, acct.TimeInForceUnknown, false
	case "STOP_LIMIT":
		return acct.OrderTypeStopLimit, acct.TimeInForceUnknown, false
	case "STOP_MARKET":
		return acct.OrderTypeStopMarket, acct.TimeInForceUnknown, false
	case "TAKE_PROFIT", "TP":
		return acct.OrderTypeTakeProfit, acct.TimeInForceUnknown, false
	case "TAKE_PROFIT_LIMIT":
		return acct.OrderTypeTakeProfitLimit, acct.TimeInForceUnknown, false
	case "TAKE_PROFIT_MARKET":
		return acct.OrderTypeTakeProfitMarket, acct.TimeInForceUnknown, false
	case "TRAILING_STOP":
		return acct.OrderTypeTrailingStop, acct.TimeInForceUnknown, false
	case "":
		return acct.OrderTypeUnknown, acct.TimeInForceUnknown, false
	default:
		return acct.OrderType(strings.ToLower(s)), acct.TimeInForceUnknown, false
	}
}

func (p *WooXPlugin) handleGetBalances(params map[string]any) plugin.Response {
	if p.client == nil {
		return plugin.ErrorResponseMsg("client not initialized")
	}
	_ = ex.GetBalancesParamsFromMap(params)

	balances, err := p.client.GetBalances()
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	resp := acct.BalancesResponse{
		FetchedAt: time.Now(),
		Scopes:    map[acct.ScopeType]acct.BalanceScope{},
		Extra:     map[string]any{},
	}

	scope := acct.BalanceScope{
		Balances: map[string]acct.AssetBalance{},
		Extra:    map[string]any{},
	}

	for _, b := range balances {
		asset := strings.ToUpper(strings.TrimSpace(b.Token))
		if asset == "" {
			continue
		}

		available := b.Holding
		if b.Holding != "" && b.Frozen != "" {
			if h, err := strconv.ParseFloat(b.Holding, 64); err == nil {
				if f, err := strconv.ParseFloat(b.Frozen, 64); err == nil {
					available = fmt.Sprintf("%.15g", h-f)
				}
			}
		}

		bal := acct.AssetBalance{
			Asset:            asset,
			Total:            b.Holding,
			AvailableToTrade: available,
			Components:       map[string]string{},
			Extra:            map[string]any{},
		}
		if b.Frozen != "" {
			bal.Components["frozen"] = b.Frozen
		}
		if b.Pending != "" {
			bal.Components["pending"] = b.Pending
		}
		if b.Interest != "" {
			bal.Components["interest"] = b.Interest
		}
		if b.Staked != "" {
			bal.Components["staked"] = b.Staked
		}

		scope.Balances[asset] = bal
	}

	resp.Scopes[acct.ScopeUnified] = scope

	return plugin.SuccessResponse(resp, time.Second*3)
}

func (p *WooXPlugin) handleGetPositions(params map[string]any) plugin.Response {
	if p.client == nil {
		return plugin.ErrorResponseMsg("client not initialized")
	}
	_ = ex.GetPositionsParamsFromMap(params)

	rows, err := p.client.GetPositions()
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	positions := make([]acct.Position, 0, len(rows))
	for _, row := range rows {
		qty := strings.TrimSpace(row.PositionSize)
		if qty == "" {
			qty = strings.TrimSpace(row.Size)
		}
		if qty == "" {
			qty = strings.TrimSpace(row.Quantity)
		}

		side := strings.TrimSpace(row.PositionSide)
		if side == "" {
			side = strings.TrimSpace(row.Side)
		}
		if qty != "" {
			if f, err := strconv.ParseFloat(qty, 64); err == nil {
				if f < 0 {
					qty = fmt.Sprintf("%.15g", -f)
					if side == "" {
						side = "SHORT"
					}
				} else if f > 0 && side == "" {
					side = "LONG"
				}
			}
		}

		entry := strings.TrimSpace(row.EntryPrice)
		if entry == "" {
			entry = strings.TrimSpace(row.AvgEntryPrice)
		}
		unrealized := strings.TrimSpace(row.UnrealizedPnL)
		if unrealized == "" {
			unrealized = strings.TrimSpace(row.PnL)
		}

		pos := acct.Position{
			Symbol:           row.Symbol,
			Side:             strings.ToLower(side),
			Quantity:         qty,
			EntryPrice:       entry,
			MarkPrice:        row.MarkPrice,
			UnrealizedPnL:    unrealized,
			LiquidationPrice: row.LiquidationPrice,
			Leverage:         row.Leverage,
			IsIsolated:       row.IsIsolated || strings.EqualFold(row.MarginType, "isolated"),
			Components: map[string]string{
				"position_value":  row.PositionValue,
				"margin_type":     row.MarginType,
				"isolated_margin": row.IsolatedMargin,
			},
			Extra: map[string]any{},
		}

		if pos.Symbol == "" || pos.Quantity == "" {
			continue
		}
		positions = append(positions, pos)
	}

	resp := acct.PositionsResponse{
		FetchedAt: time.Now(),
		Scopes: map[acct.ScopeType]acct.PositionScope{
			acct.ScopeFutures: {
				Positions: positions,
				Extra:     map[string]any{},
			},
		},
		Extra: map[string]any{},
	}

	return plugin.SuccessResponse(resp, time.Second*3)
}

func (p *WooXPlugin) handleGetOrders(params map[string]any) plugin.Response {
	if p.client == nil {
		return plugin.ErrorResponseMsg("client not initialized")
	}
	parsed := ex.GetOrdersParamsFromMap(params)

	status := ""
	if parsed.OpenOnly {
		status = "INCOMPLETE"
	}

	rows, err := p.client.GetOrders("", status, 0)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	orders := make([]acct.Order, 0, len(rows))
	for _, o := range rows {
		status := normalizeWooXStatus(o.OrderStatus)
		if parsed.OpenOnly && status != acct.OrderStatusNew && status != acct.OrderStatusPartiallyFilled {
			continue
		}

		orderType, tif, postOnly := normalizeWooXType(o.OrderType)
		remaining := ""
		if o.Quantity != "" && o.TotalExecutedQuantity != "" {
			if q, err := strconv.ParseFloat(o.Quantity, 64); err == nil {
				if exq, err := strconv.ParseFloat(o.TotalExecutedQuantity, 64); err == nil {
					remaining = fmt.Sprintf("%.15g", q-exq)
				}
			}
		}

		order := acct.Order{
			OrderID:       fmt.Sprintf("%d", o.OrderID),
			ClientOrderID: o.ClientID,
			Symbol:        o.Symbol,
			Side:          normalizeWooXSide(o.Side),
			Type:          orderType,
			Status:        status,

			// Venues fill unused price fields with zero placeholders; absent
			// prices are the empty string in the normalized shape.
			Price:             acct.OptionalPrice(o.Price),
			Quantity:          o.Quantity,
			ExecutedQuantity:  o.TotalExecutedQuantity,
			RemainingQuantity: remaining,
			TimeInForce:       tif,
			ReduceOnly:        o.ReduceOnly,
			PostOnly:          postOnly,
			TriggerPrice:      acct.OptionalPrice(o.TriggerPrice),

			Components: map[string]string{
				"amount":         o.Amount,
				"total_fee":      o.TotalFee,
				"total_rebate":   o.TotalRebate,
				"fee_asset":      o.FeeAsset,
				"rebate_asset":   o.RebateAsset,
				"order_tag":      o.OrderTag,
				"raw_order_type": o.OrderType,
			},
		}
		if o.CreatedTime > 0 {
			order.CreatedAt = time.UnixMilli(o.CreatedTime)
		}
		if o.UpdatedTime > 0 {
			order.UpdatedAt = time.UnixMilli(o.UpdatedTime)
		}
		orders = append(orders, order)
	}

	resp := acct.OrdersResponse{
		FetchedAt: time.Now(),
		Scopes: map[acct.ScopeType]acct.OrderScope{
			acct.ScopeUnified: {
				Orders: orders,
				Extra:  map[string]any{},
			},
		},
		Extra: map[string]any{},
	}

	return plugin.SuccessResponse(resp, time.Second*3)
}

// handleGetTradeHistory returns paginated trade fill history.
func (p *WooXPlugin) handleGetTradeHistory(params map[string]any) plugin.Response {
	if p.client == nil {
		return plugin.ErrorResponseMsg("client not initialized")
	}
	parsed := ex.GetTradeHistoryParamsFromMap(params)

	result, err := p.client.GetTradeHistory(parsed)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	return plugin.SuccessResponse(result)
}

// handleGetOrderHistory returns paginated completed order history.
func (p *WooXPlugin) handleGetOrderHistory(params map[string]any) plugin.Response {
	if p.client == nil {
		return plugin.ErrorResponseMsg("client not initialized")
	}
	parsed := ex.GetOrderHistoryParamsFromMap(params)

	result, err := p.client.GetOrderHistory(parsed)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	return plugin.SuccessResponse(result)
}

// handleGetTransferHistory returns paginated deposit/withdrawal history.
func (p *WooXPlugin) handleGetTransferHistory(params map[string]any) plugin.Response {
	if p.client == nil {
		return plugin.ErrorResponseMsg("client not initialized")
	}
	parsed := ex.GetTransferHistoryParamsFromMap(params)

	result, err := p.client.GetTransferHistory(parsed)
	if err != nil {
		return plugin.ErrorResponse(err)
	}

	return plugin.SuccessResponse(result)
}

// handleOHLCVStream sets up a WebSocket stream for OHLCV data
func (p *WooXPlugin) handleOHLCVStream(params map[string]any) plugin.Response {
	logging.NewLogger("woox-datasource").InfoWithData("handleOHLCVStream", params)

	// Extract validated parameters - validation already done by terminal
	streamParams := ex.OHLCVStreamParamsFromMap(params)
	if strings.TrimSpace(streamParams.Market.Symbol) == "" {
		return plugin.ErrorResponseMsg("market.symbol is required")
	}

	assetType := strings.TrimSpace(string(streamParams.Market.AssetType))

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
