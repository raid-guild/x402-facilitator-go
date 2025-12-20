package v2

// PaymentPayload is the payment payload.
type PaymentPayload struct {
	Payload  Payload  `json:"payload"`
	Accepted Accepted `json:"accepted"`
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

// Accepted is the accepted of the payment payload.
type Accepted struct {
	Scheme  Scheme  `json:"scheme"`
	Network Network `json:"network"`
}

// PaymentRequirements is the payment requirements.
type PaymentRequirements struct {
	Scheme            Scheme  `json:"scheme"`
	Network           Network `json:"network"`
	Asset             string  `json:"asset"`
	PayTo             string  `json:"payTo"`
	Amount            string  `json:"amount"`
	MaxTimeoutSeconds int64   `json:"maxTimeoutSeconds"`
	Extra             Extra   `json:"extra"`
}

// Extra is the extra of the payment requirements.
type Extra struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	GasLimit uint64 `json:"gasLimit"`
}
