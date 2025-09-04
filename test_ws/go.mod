module woox-websocket-test

go 1.21

require (
	github.com/plusev-terminal/go-plugin-common v0.0.0
	github.com/trading-peter/plusev_datasource_woox_plugin v0.0.0
)

replace github.com/plusev-terminal/go-plugin-common => ../../plusev/go-plugin-common
replace github.com/trading-peter/plusev_datasource_woox_plugin => ../
