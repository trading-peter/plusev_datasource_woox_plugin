package main

import (
	"testing"

	ex "github.com/plusev-terminal/go-plugin-common/v2/datasrc/exchange"
	acct "github.com/plusev-terminal/go-plugin-common/v2/datasrc/exchange/account"
	"github.com/plusev-terminal/go-plugin-common/v2/plugin"
	tt "github.com/plusev-terminal/go-plugin-common/v2/trading"
)

// TestOrderSurfaceMatchesCapabilityDeclaration pins the honest declaration:
// WooX registers no createOrders (its order surface is read-only), so the
// capability set stays empty and the host rejects any order attempt. Adding
// createOrders later requires declaring what its handler really sends — this
// test fails first, forcing that decision.
func TestOrderSurfaceMatchesCapabilityDeclaration(t *testing.T) {
	p := &WooXPlugin{}

	router := plugin.NewCommandRouter()
	p.RegisterCommands(router)

	creates := false
	for _, cmd := range router.GetRegisteredCommands() {
		if cmd == ex.CMD_CREATE_ORDERS {
			creates = true
		}
	}
	if creates {
		t.Fatal("createOrders is registered: update GetOrderCapabilities to declare what the handler sends, then update this test")
	}

	caps := p.GetOrderCapabilities()
	basic := ex.CreateOrderParams{
		Market:   tt.Market{Symbol: "PERP_BTC_USDT", AssetType: tt.AssetTypePerpetual},
		Side:     acct.OrderSideBuy,
		Type:     acct.OrderTypeLimit,
		Quantity: "1",
		Price:    "50000",
	}
	if err := caps.Check(basic); err == nil {
		t.Fatal("with no createOrders registration the declaration must stay empty so the host rejects every order")
	}
}
