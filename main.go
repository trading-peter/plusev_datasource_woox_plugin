package main

import (
	"github.com/plusev-terminal/go-plugin-common/datasrc"
	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	m "github.com/plusev-terminal/go-plugin-common/meta"
	"github.com/plusev-terminal/go-plugin-common/requester"

	"github.com/trading-peter/plusev_datasource_woox_plugin/woox"
)

func main() {}

// WooXExchange implements the DataSource interface for WooX exchange
type WooXExchange struct {
	client *woox.Client
}

// GetName returns the name of the data source
func (w *WooXExchange) GetName() string {
	return w.client.GetName()
}

// GetMarkets returns all available trading markets from WooX
func (w *WooXExchange) GetMarkets() ([]dt.MarketMeta, error) {
	return w.client.GetMarkets()
}

// GetTimeframes returns the timeframes supported by WooX v3
func (w *WooXExchange) GetTimeframes() []dt.Timeframe {
	return w.client.GetTimeframes()
}

// GetOHLCV fetches historical OHLCV data from WooX v3
func (w *WooXExchange) GetOHLCV(params dt.OHLCVParams) ([]dt.OHLCVRecord, error) {
	return w.client.GetOHLCV(params)
}

// StartStream starts streaming live data (not implemented yet)
func (w *WooXExchange) StartStream(config dt.StreamConfig) error {
	return w.client.StartStream(config)
}

// SupportsStreaming returns true as WebSocket streaming is now implemented
func (w *WooXExchange) SupportsStreaming() bool {
	return w.client.SupportsStreaming()
}

// StopStream stops the WebSocket streaming
func (w *WooXExchange) StopStream() error {
	return w.client.StopStream()
}

// Plugin configuration
var config = datasrc.DataSourceConfig{
	PluginID:    "woox-datasource",
	Name:        "WooX Exchange Data Source",
	Description: "Provides market data from WooX exchange via REST API",
	Author:      "PlusEV Team",
	Version:     "1.0.0",
	Repository:  "https://github.com/trading-peter/plusev_datasource_woox_plugin",
	Tags:        []string{"woox", "crypto", "exchange", "spot", "futures"},
	Contacts: []m.AuthorContact{
		{
			Kind:  "email",
			Value: "dev@plusev.com",
		},
	},
	NetworkTargets: []string{
		"https://api.woox.io/*",
		"https://api.staging.woox.io/*",
		"wss://wss.woox.io/*",
		"wss://wss.staging.woox.io/*",
	},
}

// Create data source instance using production requester
var dataSource = &WooXExchange{
	client: woox.NewClient(requester.NewRequester(), "https://api.woox.io"),
}

// Create plugin handler
var handler = datasrc.NewPluginHandler(config, dataSource)

// Export functions
//
//go:wasmexport meta
func meta() int32 {
	return handler.ExportMeta()
}

//go:wasmexport get_name
func getName() int32 {
	return handler.ExportGetName()
}

//go:wasmexport list_markets
func listMarkets() int32 {
	return handler.ExportListMarkets()
}

//go:wasmexport get_timeframes
func getTimeframes() int32 {
	return handler.ExportGetTimeframes()
}

//go:wasmexport get_ohlcv
func getOHLCV() int32 {
	return handler.ExportGetOHLCV()
}

//go:wasmexport stream_ohlcv
func streamOHLCV() int32 {
	return handler.ExportStreamOHLCV()
}
