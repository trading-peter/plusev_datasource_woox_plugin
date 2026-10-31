// Package wooxlimits declares WOO X's published per-endpoint rate-limit
// budgets as manifest limits for the plugin's network targets. It depends
// only on the SDK meta package (no extism/wasm imports) so the pinning test
// runs natively — the rest of the plugin is wasm-only.
package wooxlimits

import (
	"time"

	m "github.com/plusev-terminal/go-plugin-common/meta"
)

// Sources (retrieved 2026-10-31):
//   - https://docs.woox.io/ ("Rate Limit" section + per-endpoint "Limit:" notes)
//   - https://developer.woox.io/api-reference/endpoint/public_data/instruments.md
//   - https://developer.woox.io/api-reference/endpoint/futures/get_positions.md
//   - https://developer.woox.io/api-reference/endpoint/account/listen_key.md
//   - https://developer.woox.io/api-reference/endpoint/account/get_account_info.md
//
// Scope rules (docs.woox.io, General Information): public endpoints are
// limited per IP address; private endpoints per account (application ID) —
// all API keys of one application share the budget. These are the standard
// app-less tiers; accounts with raised limits can override them in the
// Rate Limits UI.

// APIWooX returns the rate limits for https://api.woox.io (production REST).
func APIWooX() []m.RateLimitRule {
	return []m.RateLimitRule{
		// GET /v3/public/instruments — 10 req/s per IP
		m.NewRateLimitRule("public-instruments", 10, time.Second).
			WithLabel("Public instruments (per IP)").
			ForPaths("/v3/public/instruments"),
		// GET /v1/public/kline — 10 req/s per IP
		m.NewRateLimitRule("public-kline", 10, time.Second).
			WithLabel("Public klines (per IP)").
			ForPaths("/v1/public/kline"),
		// GET /v3/balances — 100 req/min per account (doc has no bucket
		// size; burst capped at 60 per numbers policy)
		m.NewRateLimitRule("private-balances", 100, time.Minute).
			WithLabel("Balances (per account)").
			WithBurst(60).
			PerCredential().
			ForPaths("/v3/balances"),
		// GET /v3/positions — 30 req/10s per user
		m.NewRateLimitRule("private-positions", 30, 10*time.Second).
			WithLabel("Positions (per account)").
			PerCredential().
			ForPaths("/v3/positions"),
		// GET /v3/private/client/info — 10 req/60s per account
		m.NewRateLimitRule("private-account-info", 10, time.Minute).
			WithLabel("Account info (per account)").
			PerCredential().
			ForPaths("/v3/private/client/info"),
		// POST /v3/private/user/ws/listenKey — 5 req/10s per account
		m.NewRateLimitRule("private-listen-key", 5, 10*time.Second).
			WithLabel("WS listen key (per account)").
			PerCredential().
			ForPaths("/v3/private/user/ws/listenKey"),
		// GET /v1/orders (open orders + order history) — 10 req/s per account
		m.NewRateLimitRule("private-orders", 10, time.Second).
			WithLabel("Orders (per account)").
			PerCredential().
			ForPaths("/v1/orders"),
		// GET /v1/client/hist_trades — 1 req/s per account
		m.NewRateLimitRule("private-hist-trades", 1, time.Second).
			WithLabel("Trade history (per account)").
			PerCredential().
			ForPaths("/v1/client/hist_trades"),
		// GET /v1/asset/history — 10 req/60s per account
		m.NewRateLimitRule("private-asset-history", 10, time.Minute).
			WithLabel("Transfer history (per account)").
			PerCredential().
			ForPaths("/v1/asset/history"),
	}
}

// APIPubWooX returns the rate limits for https://api-pub.woox.io (public
// historical-data host).
func APIPubWooX() []m.RateLimitRule {
	return []m.RateLimitRule{
		// GET /v1/hist/kline — 1 req/s per IP
		m.NewRateLimitRule("public-hist-kline", 1, time.Second).
			WithLabel("Historical klines (per IP)").
			ForPaths("/v1/hist/kline"),
	}
}
