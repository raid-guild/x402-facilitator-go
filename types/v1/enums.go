package v1

// Scheme is the scheme enum.
type Scheme string

const (
	SchemeExact Scheme = "exact"
)

// Network is the network enum.
type Network string

const (
	// main networks
	NetworkEthereum Network = "ethereum"
	NetworkBase     Network = "base"

	// test networks
	NetworkSepolia     Network = "sepolia"
	NetworkBaseSepolia Network = "base-sepolia"
)
