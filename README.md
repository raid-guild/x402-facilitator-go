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

> **Note**: x402-facilitator-go is also compatible with [coinbase/x402](https://github.com/coinbase/x402). For the easiest building experience, use the coinbase/x402 library and configure the middleware to use your deployed facilitator. For examples on how to use the coinbase/x402 library with your deployed facilitator, check out the [demo](https://github.com/raid-guild/x402-facilitator-go/tree/demo) branch.

## 📐 Why Vercel

This service is designed for deployments to [Vercel](https://vercel.com/home). Vercel provides several key advantages:

- **Easy Deployment**: Deploy in seconds with a single click or push
- **Low Maintenance**: No servers to provision, configure, or maintain
- **Cost-Effective**: Pay nothing with the free tier or pay only for what you use
- **Automatic Scaling**: Handles traffic spikes automatically without intervention
- **Built-in HTTPS**: SSL certificates are automatically provisioned and renewed
- **Edge Network**: Low-latency responses from Vercel's global edge network

> **Note**: Support for other server setups can be implemented by extending the codebase.

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
- **Network Abstraction**: Provides a unified API that works across multiple blockchain networks, abstracting network-specific implementation details
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
  "x402Version": 2,
  "paymentPayload": {
    "accepted": {
      "scheme": "exact",
      "network": "eip155:11155111"
    },
    "payload": {
      "authorization": {
        "from": "0x354b5cBeEaE7751f2055BfC2d9d78556aD2E1c61",
        "to": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
        "value": "1000",
        "validAfter": "1767140522",
        "validBefore": "1767141422",
        "nonce": "0x2454c8d9065ebdffd65226693448da75f3c1227fec5ed9c3d0043892cd593f84"
      },
      "signature": "0xdf3cac4be24a317e07b4374b5f1198fc9760c9849fe80f1383755c2d541c4e042b7b9f79aee3b67c236130127299609998a4b31be154963091dd1920a374b0201b"
    }
  },
  "paymentRequirements": {
    "scheme": "exact",
    "network": "eip155:11155111",
    "asset": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    "payTo": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
    "amount": "1000",
    "maxTimeoutSeconds": 300,
    "extra": {
      "name": "USDC",
      "version": "2"
    }
  }
}
```

**Response** (`200 OK` - Valid):
```json
{
  "scheme": "exact",
  "network": "eip155:11155111",
  "isValid": true,
  "payer": "0x354b5cBeEaE7751f2055BfC2d9d78556aD2E1c61"
}
```

**Response** (`200 OK` - Invalid):
```json
{
  "scheme": "exact",
  "network": "eip155:11155111",
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
  "x402Version": 2,
  "paymentPayload": {
    "accepted": {
      "scheme": "exact",
      "network": "eip155:11155111"
    },
    "payload": {
      "authorization": {
        "from": "0x354b5cBeEaE7751f2055BfC2d9d78556aD2E1c61",
        "to": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
        "value": "1000",
        "validAfter": "1767140522",
        "validBefore": "1767141422",
        "nonce": "0x2454c8d9065ebdffd65226693448da75f3c1227fec5ed9c3d0043892cd593f84"
      },
      "signature": "0xdf3cac4be24a317e07b4374b5f1198fc9760c9849fe80f1383755c2d541c4e042b7b9f79aee3b67c236130127299609998a4b31be154963091dd1920a374b0201b"
    }
  },
  "paymentRequirements": {
    "scheme": "exact",
    "network": "eip155:11155111",
    "asset": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    "payTo": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
    "amount": "1000",
    "maxTimeoutSeconds": 300,
    "extra": {
      "name": "USDC",
      "version": "2"
    }
  }
}
```

**Response** (`200 OK` - Success):
```json
{
  "scheme": "exact",
  "network": "eip155:11155111",
  "success": true,
  "transaction": "0xb6b3f3770f2a24ab064a0801922616886acd9058ace6a29be00bdf1d7b8289b6"
}
```

**Response** (`200 OK` - Failed):
```json
{
  "scheme": "exact",
  "network": "eip155:11155111",
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

### Blockchain Configuration

- **`PRIVATE_KEY`** (required): The private key of the facilitator account (without `0x` prefix). This account will be used to submit settlement transactions and must have sufficient funds for gas fees.
- **`RPC_URL_ETHEREUM`** (optional): RPC URL for Ethereum mainnet.
- **`RPC_URL_BASE`** (optional): RPC URL for Base mainnet.
- **`RPC_URL_SEPOLIA`** (optional): RPC URL for Ethereum Sepolia testnet.
- **`RPC_URL_BASE_SEPOLIA`** (optional): RPC URL for Base Sepolia testnet.

> **Important**: At least one of the RPC URLs must be configured for the facilitator to handle payments. The `/supported` endpoint will only return networks for which RPC URLs are configured.

### API Authentication (Optional)

You can secure your facilitator endpoints using one or both authentication methods:

**Option 1: Static API Key** (simpler, for single-user deployments)

- **`STATIC_API_KEY`**: A single API key that will be accepted for all requests. When set, all requests to `/verify` and `/settle` must include this key in the `X-API-Key` header.

**Option 2: Database API Keys** (for multi-user deployments)

- **`DATABASE_URL`**: A Postgres connection string (`postgres://`). When set, API keys are validated against a database using a SQL query (either the default query or a custom query specified by `DATABASE_QUERY`). All requests to `/verify` and `/settle` must include a valid key in the `X-API-Key` header.
- **`DATABASE_QUERY`**: (optional) A custom SQL query to validate API keys. The custom query must accept the provided API key as a parameter (`$1`) and return at least one row if the key is valid. The query is wrapped in `EXISTS()`, so it must be written as a subquery (e.g. `SELECT 1 FROM table WHERE column = $1`). If not set, the default query will be used (i.e. `SELECT 1 FROM users WHERE api_key = $1`).

**Option 3: Static API Key and Database API Keys**

You can also set both `STATIC_API_KEY` and `DATABASE_URL`. When both are set, the provided API key is checked against the static key. If it matches, authentication succeeds. If the static key doesn't match, the API key is then validated against the database. If it exists in the database, authentication succeeds. If neither check succeeds, authentication fails. This allows you to have a master static key for administrative access while also supporting multiple database-backed API keys for different users or services.

> **Important**: If neither `STATIC_API_KEY` nor `DATABASE_URL` is set, all endpoints will be publicly accessible.

> **Note**: If you are using `DATABASE_URL` with a database managed by [Supabase](https://supabase.com/), use the pooled connection string (includes `.pooler.supabase.com`) which is specifically designed for serverless environments.

### Setting Environment Variables in Vercel

1. Go to your project in the [Vercel Dashboard](https://vercel.com/dashboard)
2. Navigate to **Settings** > **Environment Variables**
3. Add each environment variable and its value
4. Select the environments where they should be available
5. Redeploy your application for the changes to take effect

## 🔒 Security Considerations

- **Private Key**: Never share your `PRIVATE_KEY`. Never commit your `PRIVATE_KEY` to version control. Use Vercel to manage your `PRIVATE_KEY` environment variable.
- **Facilitator Account**: Use a dedicated account for your facilitator. The account should never hold funds of significant value. Top off the account regularly based on your usage needs.
- **API Keys**: Use strong, randomly generated API keys.
- **Transport**: Use HTTPS (automatically provided by Vercel).

## 📚 Supported Schemes

Currently supported schemes:
- **Exact** - exact payments designed for pay-per-use

> **Note**: This facilitator currently supports exact payments only. Support for additional schemes can be added by extending the codebase.

## 📚 Supported Networks

Currently supported networks:
- **Ethereum** (Ethereum mainnet) - Chain ID: `1`
- **Base** (Base mainnet) - Chain ID: `8453`
- **Sepolia** (Ethereum testnet) - Chain ID: `11155111`
- **Base Sepolia** (Base testnet) - Chain ID: `84532`

> **Note**: This facilitator currently supports four networks only. Support for additional networks can be added by extending the codebase.

## 📝 License

See [LICENSE](LICENSE) for details.
