package types

// X402Version is the x402 version enum.
type X402Version int

const (
	X402Version1 X402Version = 1
	X402Version2 X402Version = 2
)

// Scheme is the scheme enum.
type Scheme string

const (
	SchemeExact Scheme = "exact"
)

// Network is the network enum.
type Network string

const (
	NetworkSepolia     Network = "sepolia"
	NetworkBaseSepolia Network = "base-sepolia"

	// NOTE: Until we need different types to support different x402 versions, we use the
	// same network enum for both versions and add the V2 suffix to the V2 network name.
	NetworkSepoliaV2     Network = "eip155:11155111"
	NetworkBaseSepoliaV2 Network = "eip155:84532"
)

// InvalidReason is the invalid reason enum.
type InvalidReason string

const (
	InvalidReasonInvalidX402Version                    InvalidReason = "invalid_x402_version"
	InvalidReasonInvalidScheme                         InvalidReason = "invalid_scheme"
	InvalidReasonInvalidNetwork                        InvalidReason = "invalid_network"
	InvalidReasonInvalidPaymentPayload                 InvalidReason = "invalid_payment_payload"
	InvalidReasonInvalidPaymentRequirements            InvalidReason = "invalid_payment_requirements"
	InvalidReasonInvalidSchemeMismatch                 InvalidReason = "invalid_scheme_mismatch"
	InvalidReasonInvalidNetworkMismatch                InvalidReason = "invalid_network_mismatch"
	InvalidReasonInvalidAuthorizationTimeWindow        InvalidReason = "invalid_authorization_time_window"
	InvalidReasonInvalidAuthorizationValidAfter        InvalidReason = "invalid_authorization_valid_after"
	InvalidReasonInvalidAuthorizationValidBefore       InvalidReason = "invalid_authorization_valid_before"
	InvalidReasonInvalidAuthorizationValue             InvalidReason = "invalid_authorization_value"
	InvalidReasonInvalidAuthorizationValueNegative     InvalidReason = "invalid_authorization_value_negative"
	InvalidReasonInvalidAuthorizationValueExceeded     InvalidReason = "invalid_authorization_value_exceeded"
	InvalidReasonInvalidAuthorizationFromAddress       InvalidReason = "invalid_authorization_from_address"
	InvalidReasonInvalidAuthorizationToAddress         InvalidReason = "invalid_authorization_to_address"
	InvalidReasonInvalidAuthorizationToAddressMismatch InvalidReason = "invalid_authorization_to_address_mismatch"
	InvalidReasonInvalidAuthorizationNonce             InvalidReason = "invalid_authorization_nonce"
	InvalidReasonInvalidAuthorizationNonceLength       InvalidReason = "invalid_authorization_nonce_length"
	InvalidReasonInvalidRequirementsPayToAddress       InvalidReason = "invalid_requirements_pay_to_address"
	InvalidReasonInvalidRequirementsAsset              InvalidReason = "invalid_requirements_asset"
	InvalidReasonInvalidRequirementsMaxAmount          InvalidReason = "invalid_requirements_max_amount"
	InvalidReasonInvalidRequirementsMaxTimeout         InvalidReason = "invalid_requirements_max_timeout"
	InvalidReasonInvalidRequirementsExtraName          InvalidReason = "invalid_requirements_extra_name"
	InvalidReasonInvalidRequirementsExtraVersion       InvalidReason = "invalid_requirements_extra_version"
	InvalidReasonInvalidTypedDataDomain                InvalidReason = "invalid_typed_data_domain"
	InvalidReasonInvalidTypedDataMessage               InvalidReason = "invalid_typed_data_message"
	InvalidReasonInvalidAuthorizationSignature         InvalidReason = "invalid_authorization_signature"
	InvalidReasonInvalidAuthorizationSignatureLength   InvalidReason = "invalid_authorization_signature_length"
	InvalidReasonInvalidAuthorizationSignatureHash     InvalidReason = "invalid_authorization_signature_hash"
	InvalidReasonInvalidAuthorizationPubkey            InvalidReason = "invalid_authorization_pubkey"
	InvalidReasonInvalidAuthorizationPubkeyLength      InvalidReason = "invalid_authorization_pubkey_length"
	InvalidReasonInvalidAuthorizationSenderMismatch    InvalidReason = "invalid_authorization_sender_mismatch"
	InvalidReasonInsufficientFunds                     InvalidReason = "insufficient_funds"
)

// ErrorReason is the error reason enum.
type ErrorReason string

const (
	ErrorReasonInvalidX402Version                  ErrorReason = "invalid_x402_version"
	ErrorReasonInvalidScheme                       ErrorReason = "invalid_scheme"
	ErrorReasonInvalidNetwork                      ErrorReason = "invalid_network"
	ErrorReasonInvalidPaymentPayload               ErrorReason = "invalid_payment_payload"
	ErrorReasonInvalidPaymentRequirements          ErrorReason = "invalid_payment_requirements"
	ErrorReasonInvalidAuthorizationValue           ErrorReason = "invalid_authorization_value"
	ErrorReasonInvalidAuthorizationNonce           ErrorReason = "invalid_authorization_nonce"
	ErrorReasonInvalidAuthorizationNonceLength     ErrorReason = "invalid_authorization_nonce_length"
	ErrorReasonInvalidAuthorizationSignature       ErrorReason = "invalid_authorization_signature"
	ErrorReasonInvalidAuthorizationSignatureLength ErrorReason = "invalid_authorization_signature_length"
	ErrorReasonInvalidAuthorizationMessage         ErrorReason = "invalid_authorization_message"
	ErrorReasonInvalidRequirementsMaxTimeout       ErrorReason = "invalid_requirements_max_timeout"
	ErrorReasonInsufficientRequirementsGasLimit    ErrorReason = "insufficient_requirements_gas_limit"
)
