package v2

// PaymentPayload is the payment payload.
type PaymentPayload struct {
	Accepted Accepted `json:"accepted"`
	Payload  Payload  `json:"payload"`
}

// Accepted is the accepted of the payment payload.
type Accepted struct {
	Scheme  Scheme  `json:"scheme"`
	Network Network `json:"network"`
}

// Payload is the payload of the payment payload.
type Payload struct {
	Authorization Authorization `json:"authorization"`
	Signature     string        `json:"signature"`
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
	Amount            string  `json:"amount"`
	MaxTimeoutSeconds int64   `json:"maxTimeoutSeconds"`
	Extra             Extra   `json:"extra"`
}

// Extra is the extra of the payment requirements.
type Extra struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
