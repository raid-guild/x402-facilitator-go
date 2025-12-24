<div align="center">

# x402-facilitator-go

A one-click deploy x402 facilitator brought to you by [Raid Guild](https://www.raidguild.org/)

[![Deploy](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fraid-guild%2Fx402-facilitator-go)

</div>

## 🚀 Quick Start

1. **Deploy**: Click the "Deploy" button above to deploy to Vercel
2. **Configure**: Set environment variables in Vercel (see [Configuration](#%EF%B8%8F-configuration))
3. **Fund**: Ensure your facilitator account has funds for gas fees
4. **Test**: Go to the `/supported` endpoint to verify your setup
5. **Build**: Add the `/verify` and `/settle` endpoints to your backend

> **Note**: x402-facilitator-go is also compatible with [coinbase/x402](https://github.com/coinbase/x402). For the easiest building experience, use the coinbase/x402 library and configure the middleware to use your deployed facilitator.

## 📐 Why Vercel

This service is designed for deployments to [Vercel](https://vercel.com/home). Vercel provides several key advantages:

- **Easy Deployment**: Deploy in seconds with a single click or push
- **Low Maintenance**: No servers to provision, configure, or maintain
- **Cost-Effective**: Pay nothing with the free tier or pay only for what you use
- **Automatic Scaling**: Handles traffic spikes automatically without intervention
- **Built-in HTTPS**: SSL certificates are automatically provisioned and renewed
- **Edge Network**: Low-latency responses from Vercel's global edge network

> **Note**: Support for other hosting options can be implemented by extending the codebase.

## 💸 How x402 Works

The [x402](https://www.x402.org/) protocol is a payment protocol that enables micro-payments for API access and backend services. It allows developers to gate their backend calls behind on-chain payments using ERC-20 tokens.

1. **Authorization**: Users sign a transfer with authorization ([ERC-3009](https://eips.ethereum.org/EIPS/eip-3009)) message that grants permission to transfer a specific amount of tokens to a recipient account within a specified time window.

2. **Verification**: Before processing, the backend calls the facilitator's `/verify` endpoint to check:
   - The payment recipient matches the required recipient
   - The payment amount matches the required amount
   - The transfer authorization is within its valid time window
   - The payer has a sufficient token balance for the payment
   - The signature is valid and matches the payer's address

3. **Settlement**: After successful verification, the backend calls the facilitator's `/settle` endpoint to execute the payment on-chain. The facilitator submits a transaction to transfer the tokens from the payer account to the recipient account and then verifies the transfer was successful.

4. **Backend Access**: Once payment is verified and settled, the backend processes the user's request.

> **Note**: This pattern represents the `exact` payments scheme. [x402 v2](https://www.x402.org/writing/x402-v2-launch) is expanding the protocol beyond exact payments. This service currently only supports the `exact` payments scheme but it supports both v1 and v2 request formats. Support for other schemes can be added by extending the codebase.

## 🔧 The Facilitator

The facilitator is an integral component of the x402 protocol that serves as a trusted intermediary between users, backends, and blockchain networks. By handling the verification and settlement of x402 payments, the facilitator abstracts away the complexity of blockchain interactions.

### Key Responsibilities

- **Payment Verification**: Validates payment payloads by cryptographically verifying signatures, checking balances, and ensuring payment details meet all server requirements before settlement
- **On-Chain Settlement**: Submits validated payments to the blockchain network, monitors for transaction confirmations, and ensures funds are properly transferred to the recipient
- **Gas Management**: Handles gas estimation, tip and fee calculation, and limit enforcement, paying all gas costs on behalf of users to ensure reliable settlement even during network congestion
- **Network Abstraction**: Provides a unified API interface that works across multiple blockchain networks, abstracting network-specific implementation details
- **Error Handling**: Provides structured responses with reasons for invalid verification or failed settlement, helping developers quickly identify and resolve payment issues

### Key Advantages

- **User Experience**: Users sign payment authorizations instead of submitting transactions themselves, eliminating the need to hold native blockchain tokens or manage gas fees
- **Backend Simplicity**: Backend services focus on business logic without managing RPC connections, blockchain interactions, transaction monitoring, or network-specific implementations

## 🔌 API Endpoints

The facilitator exposes three endpoints:

### `/verify` (POST)

Verifies a payment authorization without executing it on-chain.

**Authentication**: May require API key (see [Configuration](#%EF%B8%8F-configuration))

**Request Body**:
```json
{
  "x402Version": 1,
  "paymentPayload": { ... },
  "paymentRequirements": { ... }
}
```

**Response** (`200 OK` - Valid):
```json
{
  "scheme": "exact",
  "network": "sepolia",
  "isValid": true,
  "payer": "0x..."
}
```

**Response** (`200 OK` - Invalid):
```json
{
  "scheme": "exact",
  "network": "sepolia",
  "isValid": false,
  "invalidReason": "invalid_authorization_signature"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid request body format
- `401 Unauthorized`: Missing or invalid API key (if authentication is configured)
- `500 Internal Server Error`: Server error during verification

### `/settle` (POST)

Settles a payment authorization by executing it on-chain.

**Authentication**: May require API key (see [Configuration](#%EF%B8%8F-configuration))

**Request Body**:
```json
{
  "x402Version": 1,
  "paymentPayload": { ... },
  "paymentRequirements": { ... }
}
```

**Response** (`200 OK` - Success):
```json
{
  "scheme": "exact",
  "network": "sepolia",
  "success": true,
  "transaction": "0x..."
}
```

**Response** (`200 OK` - Failed):
```json
{
  "scheme": "exact",
  "network": "sepolia",
  "success": false,
  "errorReason": "invalid_authorization_signature"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid request body format
- `401 Unauthorized`: Missing or invalid API key (if authentication is configured)
- `500 Internal Server Error`: Server error during settlement

### `/supported` (GET)

Returns a list of supported x402 versions, schemes, and networks based on the configuration.

**Authentication**: Not required

**Response** (`200 OK`):
```json
{
    "kinds": [
        {
            "x402Version": 1,
            "scheme": "exact",
            "network": "sepolia"
        },
        {
            "x402Version": 2,
            "scheme": "exact",
            "network": "eip155:11155111"
        }
    ]
}
```

## ⚙️ Configuration

After deploying to Vercel, configure the following environment variables in your Vercel project settings. The facilitator will not handle payments until at least `PRIVATE_KEY` and one RPC URL are configured.

### Required Environment Variables

#### Blockchain Configuration

- **`PRIVATE_KEY`** (required): The private key of the facilitator account (without `0x` prefix). This account will be used to submit settlement transactions and must have sufficient funds for gas fees.

- **`RPC_URL_SEPOLIA`** (optional): RPC URL for Ethereum Sepolia testnet.

- **`RPC_URL_BASE_SEPOLIA`** (optional): RPC URL for Base Sepolia testnet.

> **Note**: At least one RPC URL must be configured for the facilitator to handle payments. The `/supported` endpoint will only return networks for which RPC URLs are configured.

### Optional Environment Variables

#### API Authentication

You can secure your facilitator endpoints using one of two authentication methods:

**Option 1: Static API Key** (simpler, for single-user deployments)

- **`STATIC_API_KEY`**: A single API key that will be accepted for all requests. When set, all requests to `/verify` and `/settle` must include this key in the `X-API-Key` header.

**Option 2: Database API Keys** (for multi-user deployments)

- **`DATABASE_URL`**: A PostgreSQL connection string (using the standard `postgres://` format). When set, API keys are validated against a `users` table with an `api_key` column. All requests to `/verify` and `/settle` must include a valid key in the `X-API-Key` header.

> **Important**: You can only set **either** `STATIC_API_KEY` **or** `DATABASE_URL`, not both. If both are set, an error is returned. If neither is set, the endpoints will be publicly accessible.

### Setting Environment Variables in Vercel

1. Go to your project in the [Vercel Dashboard](https://vercel.com/dashboard)
2. Navigate to **Settings** > **Environment Variables**
3. Add each environment variable and its value
4. Select the environments where they should be available
5. Redeploy your application for the changes to take effect

## 🔒 Security Considerations

- **Private Key**: Never share your `PRIVATE_KEY`. Never commit your `PRIVATE_KEY` to version control. Use Vercel to manage your environment variables.
- **Facilitator Account**: Use a dedicated account for your facilitator. The account should never hold funds of significant value. Top off the account regularly based on your usage needs.
- **API Keys**: Use strong, randomly generated API keys.
- **Transport**: Use HTTPS (automatically provided by Vercel).

## 📚 Supported Schemes

Currently supported schemes:
- **Exact** - exact payments designed for pay-per-use

> **Note**: This facilitator currently supports exact payments only. Support for additional schemes can be added by extending the codebase.

## 📚 Supported Networks

Currently supported networks:
- **Sepolia** (Ethereum testnet) - Chain ID: `11155111`
- **Base Sepolia** (Base testnet) - Chain ID: `84532`

> **Note**: This facilitator currently supports two test networks only. Support for additional networks can be added by extending the codebase.

## 📝 License

See [LICENSE](LICENSE) for details.
