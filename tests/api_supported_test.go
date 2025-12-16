package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
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
		if contentType == "" || !strings.HasPrefix(contentType, "application/json") {
			t.Fatalf("expected content type application/json, got %q", contentType)
		}

		respBody := w.Body.String()

		expectedBytes := jsonfile.SupportedJSON

		var expected, actual any
		if err := json.Unmarshal(expectedBytes, &expected); err != nil {
			t.Fatalf("failed to unmarshal expected JSON: %v", err)
		}
		if err := json.Unmarshal([]byte(respBody), &actual); err != nil {
			t.Fatalf("failed to unmarshal actual JSON: %v", err)
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Errorf("expected body %s, got %s", string(expectedBytes), respBody)
		}
	})

}
