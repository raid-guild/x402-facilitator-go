package v1

// Scheme is the scheme enum.
type Scheme string

const (
	SchemeExact Scheme = "exact"
)

// Network is the network enum.
type Network string

const (
	NetworkEthereum    Network = "ethereum"
	NetworkBase        Network = "base"
	NetworkSepolia     Network = "sepolia"
	NetworkBaseSepolia Network = "base-sepolia"
)
