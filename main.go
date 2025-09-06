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

func (w *WooXExchange) GetCredentialFields() ([]dt.CredentialField, error) {
	return w.client.GetCredentialFields()
}

func (w *WooXExchange) SetCredentials(creds map[string]string) error {
	w.client.SetCredentials(creds)
	return nil
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

// PrepareStream prepares streaming connection setup
func (w *WooXExchange) PrepareStream(request dt.StreamSetupRequest) (dt.StreamSetupResponse, error) {
	return w.client.PrepareStream(request)
}

// HandleStreamMessage processes incoming stream messages
func (w *WooXExchange) HandleStreamMessage(request dt.StreamMessageRequest) (dt.StreamMessageResponse, error) {
	return w.client.HandleStreamMessage(request)
}

// HandleConnectionEvent handles stream connection events
func (w *WooXExchange) HandleConnectionEvent(event dt.StreamConnectionEvent) (dt.StreamConnectionResponse, error) {
	return w.client.HandleConnectionEvent(event)
}

// SupportsStreaming returns true as WebSocket streaming is now implemented
func (w *WooXExchange) SupportsStreaming() bool {
	return w.client.SupportsStreaming()
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

//go:wasmexport get_credential_fields
func getCredentialFields() int32 {
	return handler.ExportGetCredentialFields()
}

//go:wasmexport set_credentials
func setCredentials() int32 {
	return handler.ExportSetCredentials()
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

//go:wasmexport prepare_stream
func prepareStream() int32 {
	return handler.ExportPrepareStream()
}

//go:wasmexport handle_stream_message
func handleStreamMessage() int32 {
	return handler.ExportHandleStreamMessage()
}

//go:wasmexport stream_connection_event
func streamConnectionEvent() int32 {
	return handler.ExportStreamConnectionEvent()
}
