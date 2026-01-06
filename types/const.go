package types

// Environment variable key constants.
const (
	PRIVATE_KEY          = "PRIVATE_KEY"
	RPC_URL_ETHEREUM     = "RPC_URL_ETHEREUM"
	RPC_URL_BASE         = "RPC_URL_BASE"
	RPC_URL_SEPOLIA      = "RPC_URL_SEPOLIA"
	RPC_URL_BASE_SEPOLIA = "RPC_URL_BASE_SEPOLIA"
	STATIC_API_KEY       = "STATIC_API_KEY"
	DATABASE_URL         = "DATABASE_URL"
	DATABASE_QUERY       = "DATABASE_QUERY"
)

// ChainID supported network constants.
const (
	ChainIDEthereum    int64 = 1
	ChainIDBase        int64 = 8453
	ChainIDSepolia     int64 = 11155111
	ChainIDBaseSepolia int64 = 84532
)
