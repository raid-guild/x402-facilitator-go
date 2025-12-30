package v2

// Scheme is the scheme enum.
type Scheme string

const (
	SchemeExact Scheme = "exact"
)

// Network is the network enum.
type Network string

const (
	NetworkEthereum    Network = "eip155:1"
	NetworkBase        Network = "eip155:8453"
	NetworkSepolia     Network = "eip155:11155111"
	NetworkBaseSepolia Network = "eip155:84532"
)
