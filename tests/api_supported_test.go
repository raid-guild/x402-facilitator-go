package tests

import (
	"net/http"
	"testing"

	"github.com/raid-guild/x402-facilitator-go/types"
)

func TestSupported(t *testing.T) {

	t.Run("all supported networks", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "rpc-url-sepolia")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "rpc-url-base-sepolia")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "sepolia"},
			{X402Version: 1, Scheme: "exact", Network: "base-sepolia"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:11155111"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:84532"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("only sepolia networks", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "rpc-url-sepolia")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "sepolia"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:11155111"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("only base sepolia networks", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "rpc-url-base-sepolia")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "base-sepolia"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:84532"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("no supported networks", func(t *testing.T) {
		t.Setenv("RPC_URL_SEPOLIA", "")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "")

		supported(t, http.StatusOK, expectSupportedKinds([]types.SupportedKind{}))
	})

}
