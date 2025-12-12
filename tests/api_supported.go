package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	handler "github.com/raid-guild/x402-facilitator-go/api"
	jsonfile "github.com/raid-guild/x402-facilitator-go/json"
)

func TestSupported(t *testing.T) {

	t.Run("returns the supported networks and schemes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/supported", nil)
		w := httptest.NewRecorder()

		handler.Supported(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Fatalf("expected content type %s, got %s", "application/json", contentType)
		}

		respBody := w.Body.String()

		var jsonData any
		if err := json.Unmarshal([]byte(respBody), &jsonData); err != nil {
			t.Errorf("response body is not valid JSON: %v", err)
		}

		expectedBytes := jsonfile.SupportedJSON

		if respBody != string(expectedBytes) {
			t.Errorf("expected body %s, got %s", string(expectedBytes), respBody)
		}
	})

}
