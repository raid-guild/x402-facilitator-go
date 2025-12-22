package types

// X402Version is the x402 version enum.
type X402Version int

const (
	X402Version1 X402Version = 1
	X402Version2 X402Version = 2
)

// InvalidReason is the invalid reason enum.
type InvalidReason string

const (
	InvalidReasonInvalidX402Version                  InvalidReason = "invalid_x402_version"
	InvalidReasonInvalidPaymentPayload               InvalidReason = "invalid_payment_payload"
	InvalidReasonInvalidPaymentRequirements          InvalidReason = "invalid_payment_requirements"
	InvalidReasonInvalidScheme                       InvalidReason = "invalid_scheme"
	InvalidReasonInvalidNetwork                      InvalidReason = "invalid_network"
	InvalidReasonInvalidSchemeMismatch               InvalidReason = "invalid_scheme_mismatch"
	InvalidReasonInvalidNetworkMismatch              InvalidReason = "invalid_network_mismatch"
	InvalidReasonInvalidAuthorizationFrom            InvalidReason = "invalid_authorization_from"
	InvalidReasonInvalidAuthorizationTo              InvalidReason = "invalid_authorization_to"
	InvalidReasonInvalidAuthorizationToMismatch      InvalidReason = "invalid_authorization_to_mismatch"
	InvalidReasonInvalidAuthorizationValue           InvalidReason = "invalid_authorization_value"
	InvalidReasonInvalidAuthorizationValueNegative   InvalidReason = "invalid_authorization_value_negative"
	InvalidReasonInvalidAuthorizationValueMismatch   InvalidReason = "invalid_authorization_value_mismatch"
	InvalidReasonInvalidAuthorizationTimeWindow      InvalidReason = "invalid_authorization_time_window"
	InvalidReasonInvalidAuthorizationValidAfter      InvalidReason = "invalid_authorization_valid_after"
	InvalidReasonInvalidAuthorizationValidBefore     InvalidReason = "invalid_authorization_valid_before"
	InvalidReasonInvalidAuthorizationNonce           InvalidReason = "invalid_authorization_nonce"
	InvalidReasonInvalidAuthorizationNonceLength     InvalidReason = "invalid_authorization_nonce_length"
	InvalidReasonInvalidAuthorizationSignature       InvalidReason = "invalid_authorization_signature"
	InvalidReasonInvalidAuthorizationSignatureLength InvalidReason = "invalid_authorization_signature_length"
	InvalidReasonInvalidAuthorizationSignatureHash   InvalidReason = "invalid_authorization_signature_hash"
	InvalidReasonInvalidRequirementsAsset            InvalidReason = "invalid_requirements_asset"
	InvalidReasonInvalidRequirementsPayTo            InvalidReason = "invalid_requirements_pay_to"
	InvalidReasonInvalidRequirementsAmount           InvalidReason = "invalid_requirements_amount"
	InvalidReasonInvalidRequirementsMaxTimeout       InvalidReason = "invalid_requirements_max_timeout"
	InvalidReasonInvalidRequirementsExtraName        InvalidReason = "invalid_requirements_extra_name"
	InvalidReasonInvalidRequirementsExtraVersion     InvalidReason = "invalid_requirements_extra_version"
	InvalidReasonInvalidTypedDataDomain              InvalidReason = "invalid_typed_data_domain"
	InvalidReasonInvalidTypedDataMessage             InvalidReason = "invalid_typed_data_message"
	InvalidReasonInvalidAuthorizationPubkey          InvalidReason = "invalid_authorization_pubkey"
	InvalidReasonInvalidAuthorizationPubkeyLength    InvalidReason = "invalid_authorization_pubkey_length"
	InvalidReasonInvalidAuthorizationPubkeyMismatch  InvalidReason = "invalid_authorization_pubkey_mismatch"
	InvalidReasonInsufficientFunds                   InvalidReason = "insufficient_funds"
)

// ErrorReason is the error reason enum.
type ErrorReason string

const (
	ErrorReasonInvalidX402Version              ErrorReason = "invalid_x402_version"
	ErrorReasonInvalidScheme                   ErrorReason = "invalid_scheme"
	ErrorReasonInvalidNetwork                  ErrorReason = "invalid_network"
	ErrorReasonInvalidPaymentPayload           ErrorReason = "invalid_payment_payload"
	ErrorReasonInvalidPaymentRequirements      ErrorReason = "invalid_payment_requirements"
	ErrorReasonInvalidAuthorizationValue       ErrorReason = "invalid_authorization_value"
	ErrorReasonInvalidAuthorizationValidAfter  ErrorReason = "invalid_authorization_valid_after"
	ErrorReasonInvalidAuthorizationValidBefore ErrorReason = "invalid_authorization_valid_before"
	ErrorReasonInvalidAuthorizationNonce       ErrorReason = "invalid_authorization_nonce"
	ErrorReasonInvalidAuthorizationSignature   ErrorReason = "invalid_authorization_signature"
	ErrorReasonInvalidAuthorizationMessage     ErrorReason = "invalid_authorization_message"
	ErrorReasonInsufficientGasLimit            ErrorReason = "insufficient_gas_limit"
)
