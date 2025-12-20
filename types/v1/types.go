package v1

// PaymentPayload is the payment payload.
type PaymentPayload struct {
	Scheme  Scheme  `json:"scheme"`
	Network Network `json:"network"`
	Payload Payload `json:"payload"`
}

// Payload is the payload of the payment payload.
type Payload struct {
	Signature     string        `json:"signature"`
	Authorization Authorization `json:"authorization"`
}

// Authorization is the authorization of the payload.
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
	Asset             string  `json:"asset"`
	PayTo             string  `json:"payTo"`
	MaxAmountRequired string  `json:"maxAmountRequired"`
	MaxTimeoutSeconds int64   `json:"maxTimeoutSeconds"`
	Extra             Extra   `json:"extra"`
}

// Extra is the extra of the payment requirements.
type Extra struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	GasLimit uint64 `json:"gasLimit"`
}
