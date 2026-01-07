# demo-coinbase-x402-v2

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

http://localhost:4022/sepolia

Go to endpoint:

http://localhost:4022/base-sepolia

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

Common issues (sepolia):

- `402` response with an empty response body (same as without pay)
  - `Internal Server Error` is expected if the facilator is not configured correctly

Common issues (base-sepolia):

- `402` response with an empty response body (same as without pay)
  - `Internal Server Error` is expected if the facilator is not configured correctly

## Example Request Body

```
{
  "x402Version": 2,
  "paymentPayload": {
    "x402Version": 2,
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
    },
    "resource":{
      "url": "http://localhost:4022/sepolia",
      "description": "",
      "mimeType": ""
    },
    "accepted": {
      "scheme": "exact",
      "network": "eip155:11155111",
      "amount": "1000",
      "asset": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
      "payTo": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
      "maxTimeoutSeconds": 300,
      "extra": {
        "name": "USDC",
        "version": "2"
      }
    }
  },
  "paymentRequirements": {
    "scheme": "exact",
    "network": "eip155:11155111",
    "amount": "1000",
    "asset": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    "payTo": "0x9a4e1A0BC77639Fdce69df88E1DF1D589e454811",
    "maxTimeoutSeconds": 300,
    "extra": {
      "name": "USDC",
      "version": "2"
    }
  }
}
```
