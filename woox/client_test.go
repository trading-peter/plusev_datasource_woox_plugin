package woox

import (
	"testing"

	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	requestertesting "github.com/plusev-terminal/go-plugin-common/requester/testing"
)

func TestWooXExchange(t *testing.T) {
	t.Run("GetMarkets", func(t *testing.T) {
		// Create mock requester
		mockReq := requestertesting.NewMockRequester()

		// Create testable exchange
		client := NewClient(mockReq, "https://api.woox.io")

		// Test GetMarkets
		markets, err := client.GetMarkets()
		if err != nil {
			t.Fatalf("GetMarkets failed: %v", err)
		}

		// Verify results
		if len(markets) == 0 {
			t.Errorf("Expected more than 0 markets, got none")
		}

		// Check specific markets
		btcMarket := findMarket(markets, "SPOT_BTC_USDT")
		if btcMarket == nil {
			t.Error("SPOT_BTC_USDT market not found")
		} else {
			if btcMarket.AssetType != "spot" {
				t.Errorf("Expected SPOT_BTC_USDT to be spot, got %s", btcMarket.AssetType)
			}
			if btcMarket.Base != "BTC" || btcMarket.Quote != "USDT" {
				t.Errorf("Expected BTC/USDT, got %s/%s", btcMarket.Base, btcMarket.Quote)
			}
		}

		ethMarket := findMarket(markets, "PERP_ETH_USDT")
		if ethMarket == nil {
			t.Error("PERP_ETH_USDT market not found")
		} else {
			if ethMarket.AssetType != "futures" {
				t.Errorf("Expected PERP_ETH_USDT to be futures, got %s", ethMarket.AssetType)
			}
		}

		// Verify the API was called correctly
		calls := mockReq.GetCalls()
		if len(calls) != 1 {
			t.Errorf("Expected 1 API call, got %d", len(calls))
		}
		if len(calls) > 0 && calls[0] != "https://api.woox.io/v3/public/instruments" {
			t.Errorf("Expected call to instruments endpoint, got %s", calls[0])
		}
	})

	t.Run("GetOHLCV", func(t *testing.T) {
		mockReq := requestertesting.NewMockRequester()

		client := NewClient(mockReq, "https://api.woox.io")

		// Test GetOHLCV
		params := dt.OHLCVParams{
			Symbol:    "SPOT_BTC_USDT",
			Timeframe: "1h",
			Limit:     10,
		}

		records, err := client.GetOHLCV(params)
		if err != nil {
			t.Fatalf("GetOHLCV failed: %v", err)
		}

		// Verify results
		if len(records) != 10 {
			t.Errorf("Expected 10 records, got %d", len(records))
		}

		if len(records) > 0 {
			first := records[0]
			if first.Open == 0.0 {
				t.Errorf("Expected first open to be > 0, got %f", first.Open)
			}
			if first.Timestamp == 0 { // Converted from milliseconds
				t.Errorf("Expected timestamp > 0, got %d", first.Timestamp)
			}
		}

		// Verify API call
		calls := mockReq.GetCalls()
		if len(calls) != 1 {
			t.Errorf("Expected 1 API call, got %d", len(calls))
		}
	})

	t.Run("GetTimeframes", func(t *testing.T) {
		// This doesn't require network requests, so no mock needed
		mockReq := requestertesting.NewMockRequester()
		client := NewClient(mockReq, "https://api.woox.io")

		timeframes := client.GetTimeframes()

		if len(timeframes) == 0 {
			t.Error("Expected timeframes, got none")
		}

		// Check for some expected timeframes
		found1m := false
		found1h := false
		found1d := false

		for _, tf := range timeframes {
			switch tf.ApiValue {
			case "1m":
				found1m = true
				if tf.Interval != 60 {
					t.Errorf("Expected 1m interval to be 60, got %d", tf.Interval)
				}
			case "1h":
				found1h = true
				if tf.Interval != 3600 {
					t.Errorf("Expected 1h interval to be 3600, got %d", tf.Interval)
				}
			case "1d":
				found1d = true
				if tf.Interval != 86400 {
					t.Errorf("Expected 1d interval to be 86400, got %d", tf.Interval)
				}
			}
		}

		if !found1m || !found1h || !found1d {
			t.Error("Missing expected timeframes (1m, 1h, 1d)")
		}
	})
}

// Helper function to find a market by name
func findMarket(markets []dt.MarketMeta, name string) *dt.MarketMeta {
	for _, market := range markets {
		if market.Name == name {
			return &market
		}
	}
	return nil
}
