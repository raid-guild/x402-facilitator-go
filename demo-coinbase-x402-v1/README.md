# demo-coinbase-x402-v1

## Setup

Install dependencies:

```
bun install
```

Set environment variables:

```
cp .env-example .env
```

## Server Only

Start server:

```
bun server
```

Go to endpoint:

- http://localhost:4021/sepolia

Known issues (sepolia):

- coinbase/x402 v1 does not support `sepolia`

Go to endpoint:

- http://localhost:4021/base-sepolia

Common issues (base-sepolia):

- `Error: Failed to verify payment: Internal Server Error`
  - This error is expected if the facilitator is not configured correctly

## Server and Client Without Pay

Start server:

```
bun server
```

Run client without pay:

```
bun client-without-pay
```

## Server and Client With Pay

Start server:

```
bun server
```

Run client with pay:

```
bun client-with-pay
```

Known issues (sepolia):

- coinbase/x402 v1 does not support `sepolia`

Common issues (base-sepolia):

- `Error: Failed to verify payment: Internal Server Error`
  - This error is expected if the facilitator is not configured correctly

## Example Request Body

```
{
  "x402Version": 1,
  "paymentPayload": {
    "x402Version": 1,
    "scheme": "exact",
    "network": "base-sepolia",
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
    "network": "base-sepolia",
    "maxAmountRequired": "1000",
    "resource": "http://localhost:4021/base-sepolia",
    "description": "",
    "mimeType": "",
    "payTo": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
    "maxTimeoutSeconds": 60,
    "asset": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    "outputSchema": {
      "input": {
        "type": "http",
        "method": "GET",
        "discoverable": true
      }
    },
    "extra": {
      "name": "USDC",
      "version": "2"
    }
  }
}
```
