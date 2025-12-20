package types

import "encoding/json"

// RequestBody is the request body.
type RequestBody struct {
	X402Version         X402Version     `json:"x402Version"`
	PaymentPayload      json.RawMessage `json:"paymentPayload"`
	PaymentRequirements json.RawMessage `json:"paymentRequirements"`
}

// PaymentPayload is the payment payload.
type PaymentPayload struct {
	Scheme  Scheme  `json:"scheme"`
	Network Network `json:"network"`
	Payload Payload `json:"payload"`
}

// Payload is the payload for the payment.
type Payload struct {
	Signature     string        `json:"signature"`
	Authorization Authorization `json:"authorization"`
}

// Authorization is the authorization for the payment.
type Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

// PaymentRequirements is the payment requirements.
type PaymentRequirements struct {
	Scheme            Scheme  `json:"scheme"`
	Network           Network `json:"network"`
	MaxAmountRequired string  `json:"maxAmountRequired"`
	MaxTimeoutSeconds int64   `json:"maxTimeoutSeconds"`
	Asset             string  `json:"asset"`
	PayTo             string  `json:"payTo"`
	Extra             Extra   `json:"extra"`
}

// Extra is the extra for the payment requirements.
type Extra struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	GasLimit uint64 `json:"gasLimit"`
}

// SettleResponse is the response of the settle operation.
type SettleResponse struct {
	Success     bool        `json:"success"`
	Transaction string      `json:"transaction,omitempty"`
	ErrorReason ErrorReason `json:"errorReason,omitempty"`
}

// VerifyResponse is the response of the verify operation.
type VerifyResponse struct {
	IsValid       bool          `json:"isValid"`
	Payer         string        `json:"payer,omitempty"`
	InvalidReason InvalidReason `json:"invalidReason,omitempty"`
}
