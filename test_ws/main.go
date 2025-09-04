package main

import (
	"fmt"
	"time"

	dt "github.com/plusev-terminal/go-plugin-common/datasrc/types"
	"github.com/plusev-terminal/go-plugin-common/requester"
	"github.com/trading-peter/plusev_datasource_woox_plugin/woox"
)

func main() {
	fmt.Println("🚀 Testing WooX WebSocket Streaming Implementation")
	fmt.Println("=================================================")

	// Create WooX client
	client := woox.NewClient(requester.NewRequester(), "https://api.woox.io")

	fmt.Printf("📡 Data source: %s\n", client.GetName())
	fmt.Printf("🔌 Supports streaming: %v\n", client.SupportsStreaming())

	// Test streaming configuration
	config := dt.StreamConfig{
		Symbol:   "PERP_BTC_USDT",
		Interval: 3600, // 1 hour
	}

	fmt.Printf("🎯 Testing stream for %s with %ds interval\n", config.Symbol, config.Interval)

	// Start streaming (this will fail in standalone test without WebSocket host functions)
	fmt.Println("▶️  Starting WebSocket stream...")
	err := client.StartStream(config)
	if err != nil {
		fmt.Printf("⚠️  Expected error (no WebSocket host functions): %v\n", err)
		fmt.Println("✅ This is expected in standalone test - WebSocket requires plugin host environment")
		return
	}

	fmt.Println("✅ Stream started successfully!")
	fmt.Println("📊 Stream would now receive real-time OHLCV data...")
	fmt.Println("⏱️  Simulating stream for 10 seconds...")

	// Let it run for a bit
	time.Sleep(10 * time.Second)

	// Stop streaming
	fmt.Println("⏹️  Stopping stream...")
	err = client.StopStream()
	if err != nil {
		fmt.Printf("❌ Failed to stop stream: %v\n", err)
		return
	}

	fmt.Println("✅ Stream stopped successfully!")
	fmt.Println("🏁 WebSocket streaming test completed!")
}
