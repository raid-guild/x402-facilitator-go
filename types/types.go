package types

import "encoding/json"

// RequestBody is the request body for the settle and verify endpoints.
type RequestBody struct {
	X402Version         X402Version     `json:"x402Version"`
	PaymentPayload      json.RawMessage `json:"paymentPayload"`
	PaymentRequirements json.RawMessage `json:"paymentRequirements"`
}

// SettleResponse is the response of the settle endpoint.
type SettleResponse struct {
	Scheme      string      `json:"scheme,omitempty"`
	Network     string      `json:"network,omitempty"`
	Success     bool        `json:"success"`
	Transaction string      `json:"transaction,omitempty"`
	ErrorReason ErrorReason `json:"errorReason,omitempty"`
}

// VerifyResponse is the response of the verify endpoint.
type VerifyResponse struct {
	Scheme        string        `json:"scheme,omitempty"`
	Network       string        `json:"network,omitempty"`
	IsValid       bool          `json:"isValid"`
	Payer         string        `json:"payer,omitempty"`
	InvalidReason InvalidReason `json:"invalidReason,omitempty"`
}

// SupportedResponse is the response of the supported endpoint.
type SupportedResponse struct {
	Kinds []SupportedKind `json:"kinds"`
}

// SupportedKind is the supported kind.
type SupportedKind struct {
	X402Version int    `json:"x402Version"`
	Scheme      string `json:"scheme"`
	Network     string `json:"network"`
}
