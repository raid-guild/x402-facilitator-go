package tests

//nolint:paralleltest // Tests use t.Setenv() which is not safe for parallel execution

import (
	"net/http"
	"testing"

	handler "github.com/raid-guild/x402-facilitator-go/api"
	"github.com/raid-guild/x402-facilitator-go/types"
)

func TestSupported(t *testing.T) {

	t.Run("all supported networks", func(t *testing.T) {
		handler.ResetSupportedResponseCache()

		t.Setenv("RPC_URL_ETHEREUM", "rpc-url-ethereum")
		t.Setenv("RPC_URL_BASE", "rpc-url-base")
		t.Setenv("RPC_URL_SEPOLIA", "rpc-url-sepolia")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "rpc-url-base-sepolia")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "ethereum"},
			{X402Version: 1, Scheme: "exact", Network: "base"},
			{X402Version: 1, Scheme: "exact", Network: "sepolia"},
			{X402Version: 1, Scheme: "exact", Network: "base-sepolia"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:1"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:8453"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:11155111"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:84532"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("only ethereum network", func(t *testing.T) {
		handler.ResetSupportedResponseCache()

		t.Setenv("RPC_URL_ETHEREUM", "rpc-url-ethereum")
		t.Setenv("RPC_URL_BASE", "")
		t.Setenv("RPC_URL_SEPOLIA", "")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "ethereum"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:1"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("only base network", func(t *testing.T) {
		handler.ResetSupportedResponseCache()

		t.Setenv("RPC_URL_ETHEREUM", "")
		t.Setenv("RPC_URL_BASE", "rpc-url-base")
		t.Setenv("RPC_URL_SEPOLIA", "")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "base"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:8453"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("only sepolia network", func(t *testing.T) {
		handler.ResetSupportedResponseCache()

		t.Setenv("RPC_URL_ETHEREUM", "")
		t.Setenv("RPC_URL_BASE", "")
		t.Setenv("RPC_URL_SEPOLIA", "rpc-url-sepolia")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "sepolia"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:11155111"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("only base sepolia network", func(t *testing.T) {
		handler.ResetSupportedResponseCache()

		t.Setenv("RPC_URL_ETHEREUM", "")
		t.Setenv("RPC_URL_BASE", "")
		t.Setenv("RPC_URL_SEPOLIA", "")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "rpc-url-base-sepolia")

		expectedKinds := []types.SupportedKind{
			{X402Version: 1, Scheme: "exact", Network: "base-sepolia"},
			{X402Version: 2, Scheme: "exact", Network: "eip155:84532"},
		}

		supported(t, http.StatusOK, expectSupportedKinds(expectedKinds))
	})

	t.Run("no supported networks", func(t *testing.T) {
		handler.ResetSupportedResponseCache()

		t.Setenv("RPC_URL_ETHEREUM", "")
		t.Setenv("RPC_URL_BASE", "")
		t.Setenv("RPC_URL_SEPOLIA", "")
		t.Setenv("RPC_URL_BASE_SEPOLIA", "")

		supported(t, http.StatusOK, expectSupportedKinds([]types.SupportedKind{}))
	})

}
