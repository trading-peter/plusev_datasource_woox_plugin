package wooxlimits

import (
	"reflect"
	"testing"

	m "github.com/plusev-terminal/go-plugin-common/meta"
)

// TestWooXManifestRateLimits pins the manifest rate-limit declarations to the
// numbers published by WOO X (docs.woox.io + developer.woox.io, retrieved
// 2026-10-31) so they cannot silently drift. Sources are listed on the
// package in limits.go.
func TestWooXManifestRateLimits(t *testing.T) {
	wantAPI := []m.RateLimitRule{
		{ID: "public-instruments", Label: "Public instruments (per IP)", Limit: 10, WindowMs: 1000, Paths: []string{"/v3/public/instruments"}},
		{ID: "public-kline", Label: "Public klines (per IP)", Limit: 10, WindowMs: 1000, Paths: []string{"/v1/public/kline"}},
		{ID: "private-balances", Label: "Balances (per account)", Limit: 100, WindowMs: 60000, Burst: 60, Scope: m.RateLimitScopeCredential, Paths: []string{"/v3/balances"}},
		{ID: "private-positions", Label: "Positions (per account)", Limit: 30, WindowMs: 10000, Scope: m.RateLimitScopeCredential, Paths: []string{"/v3/positions"}},
		{ID: "private-account-info", Label: "Account info (per account)", Limit: 10, WindowMs: 60000, Scope: m.RateLimitScopeCredential, Paths: []string{"/v3/private/client/info"}},
		{ID: "private-listen-key", Label: "WS listen key (per account)", Limit: 5, WindowMs: 10000, Scope: m.RateLimitScopeCredential, Paths: []string{"/v3/private/user/ws/listenKey"}},
		{ID: "private-orders", Label: "Orders (per account)", Limit: 10, WindowMs: 1000, Scope: m.RateLimitScopeCredential, Paths: []string{"/v1/orders"}},
		{ID: "private-hist-trades", Label: "Trade history (per account)", Limit: 1, WindowMs: 1000, Scope: m.RateLimitScopeCredential, Paths: []string{"/v1/client/hist_trades"}},
		{ID: "private-asset-history", Label: "Transfer history (per account)", Limit: 10, WindowMs: 60000, Scope: m.RateLimitScopeCredential, Paths: []string{"/v1/asset/history"}},
	}
	if got := APIWooX(); !reflect.DeepEqual(got, wantAPI) {
		t.Errorf("api.woox.io limits changed:\n got: %#v\nwant: %#v", got, wantAPI)
	}

	wantPub := []m.RateLimitRule{
		{ID: "public-hist-kline", Label: "Historical klines (per IP)", Limit: 1, WindowMs: 1000, Paths: []string{"/v1/hist/kline"}},
	}
	if got := APIPubWooX(); !reflect.DeepEqual(got, wantPub) {
		t.Errorf("api-pub.woox.io limits changed:\n got: %#v\nwant: %#v", got, wantPub)
	}
}
