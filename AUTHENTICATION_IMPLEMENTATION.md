# WooX Plugin Authentication Implementation

## ✅ **Implementation Complete**

I have successfully added comprehensive authentication support to the WooX datasource plugin for both REST API endpoints and WebSocket connections.

## 🔐 **Authentication Features Added**

### **1. Credential Management**
- **API Key**: Stored with masking for security (`api_key`)
- **API Secret**: Encrypted storage with full masking (`api_secret`)
- **Automatic credential validation**: Client checks for authentication before private operations

### **2. HMAC SHA256 Authentication**
- Follows WooX v3 API authentication specification
- **Signature format**: `timestamp + method + path + body`
- **Headers**:
  - `x-api-key`: API key for identification
  - `x-api-timestamp`: Unix timestamp in milliseconds
  - `x-api-signature`: HMAC SHA256 hex signature

### **3. REST API Authentication**
Enhanced all endpoints to support authentication when available:
- ✅ **Public endpoints**: Work without authentication
- ✅ **Private endpoints**: Require authentication
- ✅ **Enhanced rate limits**: Authentication provides better rate limits

#### **Supported Private Endpoints**
- `GET /v3/private/client/info` - Account information
- `GET /v3/private/client/holding` - Account balances
- `POST /v3/private/order` - Place orders
- `GET /v3/private/orders` - Order history
- `DELETE /v3/private/order/{orderId}` - Cancel orders
- `POST /v3/private/user/ws/listenKey` - Generate WebSocket listen key

### **4. WebSocket Authentication**
- **Public streams**: `wss://wss.woox.io/v3/public`
- **Private streams**: `wss://wss.woox.io/v3/private?listenKey={key}`
- **Listen key generation**: Automatic via REST API
- **Authentication flow**:
  1. Generate listen key using authenticated REST API
  2. Append listen key to private WebSocket URL
  3. Connect and subscribe to private channels

## 🏗️ **Architecture Implementation**

### **Client Structure Enhanced**
```go
type Client struct {
    name      string
    baseURL   string  
    requester rt.RequestDoer
    log       *logging.Logger
    apiKey    string    // NEW: API key for authentication
    apiSecret string    // NEW: API secret for HMAC signatures
}
```

### **Authentication Methods**
```go
// Create authenticated client
func NewClientWithAuth(req rt.RequestDoer, baseURL, apiKey, apiSecret string) *Client

// Generate HMAC signature for WooX API
func (c *Client) generateWooXSignature(timestamp, method, path, body string) string

// Add authentication headers to requests  
func (c *Client) addAuthHeaders(req *rt.Request, body string)

// Check if client has authentication credentials
func (c *Client) isAuthenticated() bool

// Generate listen key for private WebSocket
func (c *Client) generateListenKey() (string, error)
```

### **Trading Operations**
```go
// Account and balance information
func (c *Client) GetAccountInfo() (*AccountInfo, error)
func (c *Client) GetBalances() ([]Balance, error)

// Order management
func (c *Client) PlaceOrder(orderReq OrderRequest) (*Order, error)
func (c *Client) GetOrders(symbol, status string, limit int) ([]Order, error)
func (c *Client) CancelOrder(orderID, symbol string) error
```

### **Data Structures Added**
- `AccountInfo` - Account information and settings
- `Balance` - Token balances and holdings
- `OrderRequest` - Order placement parameters
- `Order` - Order details and status
- `ListenKeyResponse` - WebSocket authentication response

## 🌐 **Network Configuration**

Updated plugin manifest to include private endpoints:
```go
NetworkTargets: []string{
    "https://api.woox.io/*",           // Public & Private REST
    "https://api.staging.woox.io/*",   // Staging environment
    "wss://wss.woox.io/*",            // Public & Private WebSocket
    "wss://wss.staging.woox.io/*",    // Staging WebSocket
}
```

## 📡 **WebSocket Authentication Flow**

### **Public Streams** (No Authentication)
```
wss://wss.woox.io/v3/public
├─ Subscribe: {"cmd": "SUBSCRIBE", "params": ["kline@BTC_USDT@1m"]}
└─ Receive: Real-time kline updates
```

### **Private Streams** (Authentication Required)
```
1. Generate Listen Key: POST /v3/private/user/ws/listenKey
2. Connect: wss://wss.woox.io/v3/private?listenKey={key}
3. Subscribe: {"cmd": "SUBSCRIBE", "params": ["balance", "order"]}
4. Receive: Account updates, order fills, balance changes
```

## 🔄 **Usage Examples**

### **Basic Authentication Setup**
```go
// Create authenticated client
client := woox.NewClientWithAuth(
    requester.NewRequester(),
    "https://api.woox.io",
    "your-api-key",
    "your-api-secret",
)

// Check account info
accountInfo, err := client.GetAccountInfo()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Account: %s, Trade Enabled: %t\n", 
    accountInfo.Account, accountInfo.TradeEnabled)
```

### **Trading Operations**
```go
// Get balances
balances, err := client.GetBalances()
for _, balance := range balances {
    if balance.Holding != "0" {
        fmt.Printf("%s: %s\n", balance.Token, balance.Holding)
    }
}

// Place limit order
order, err := client.PlaceOrder(woox.OrderRequest{
    Symbol:    "BTC_USDT",
    Side:      "BUY",
    OrderType: "LIMIT", 
    Quantity:  "0.001",
    Price:     "30000",
})

// Cancel order
err = client.CancelOrder(fmt.Sprintf("%d", order.OrderID), order.Symbol)
```

### **Private WebSocket Streaming**
```go
// Setup private stream
response, err := client.PrepareStream(dt.StreamSetupRequest{
    Parameters: map[string]interface{}{
        "symbol":   "BTC_USDT",
        "interval": "1m",
        "private":  true,  // Enable private stream
    },
})

// WebSocket URL will be: wss://wss.woox.io/v3/private?listenKey=xxx
```

## 🔒 **Security Features**

### **Credential Protection**
- **API Secret**: Encrypted in database (`Encrypt: true`)
- **API Key**: Masked in logs and responses (`Mask: true`)
- **Optional fields**: Won't cause errors if empty (`OmitEmpty: true`)

### **Request Signing**
- **Timestamp protection**: Prevents replay attacks
- **HMAC verification**: Ensures request integrity
- **Path normalization**: Handles URL-encoded parameters correctly

### **Error Handling**
- **Authentication failures**: Clear error messages
- **Missing credentials**: Graceful fallback to public endpoints
- **Network errors**: Proper error propagation

## 🎯 **Production Readiness**

### **Environment Support**
- ✅ **Production**: `api.woox.io`, `wss.woox.io`
- ✅ **Staging**: `api.staging.woox.io`, `wss.staging.woox.io`
- ✅ **Automatic detection**: Based on base URL

### **Rate Limiting**
- **Public endpoints**: Standard rate limits
- **Authenticated endpoints**: Enhanced rate limits
- **WebSocket**: 24-hour connection limit handled

### **Error Recovery**
- **Listen key expiration**: Automatic regeneration
- **Connection drops**: Reconnection with new listen key
- **Authentication errors**: Clear error reporting

## 📋 **Integration with PlusEV Terminal**

### **Plugin Configuration**
```json
{
  "credentials": {
    "api_key": "your-woox-api-key",
    "api_secret": "your-woox-api-secret"
  }
}
```

### **Credential Fields Response**
```json
[
  {
    "name": "api_key",
    "encrypt": false,
    "mask": true,
    "omitEmpty": true
  },
  {
    "name": "api_secret", 
    "encrypt": true,
    "mask": true,
    "omitEmpty": true
  }
]
```

## 🚀 **Ready for Deployment**

The WooX datasource plugin now has complete authentication support for:
- ✅ **REST API**: All private endpoints with HMAC authentication
- ✅ **WebSocket**: Private streams with listen key authentication
- ✅ **Trading**: Order placement, cancellation, and history
- ✅ **Account management**: Balances, account info, and settings
- ✅ **Security**: Proper credential encryption and masking
- ✅ **Production**: Support for both staging and production environments

The plugin is ready for production use with the PlusEV Terminal authentication system.
