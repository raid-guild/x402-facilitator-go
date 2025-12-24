# test-coinbase-x402-v1

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

Current issues (sepolia):

- coinbase/x402 v1 does not support `sepolia`

Go to endpoint:

- http://localhost:4021/base-sepolia

Current issues (base-sepolia):

- Using `https://x402-facilitator-go.vercel.app`
  - `Error: Failed to verify payment: Internal Server Error`
  - This error is expected if the environment variables are not set
- Using `https://x402-facilitator-ryanchristo.vercel.app`
  - No issues, verified and settled payment using configured facilitator

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

Current issues (sepolia):

- coinbase/x402 v1 does not support `sepolia`

Current issues (base-sepolia):

- Using `https://x402-facilitator-go.vercel.app`
  - `Error: Failed to verify payment: Internal Server Error`
  - This error is expected if the environment variables are not set
- Using `https://x402-facilitator-ryanchristo.vercel.app`
  - No issues, verified and settled payment using configured facilitator

## Example Request Body

```
{
  "x402Version":1,
  "paymentPayload":{
    "x402Version":1,
    "scheme":"exact",
    "network":"base-sepolia",
    "payload":{
      "signature":"0x...",
      "authorization":{
        "from":"0x...",
        "to":"0x...",
        "value":"1000",
        "validAfter":"1766196645",
        "validBefore":"1766197305",
        "nonce":"0x..."
      }
    }
  },
  "paymentRequirements":{
    "scheme":"exact",
    "network":"base-sepolia",
    "maxAmountRequired":"1000",
    "resource":"http://localhost:4021/base-sepolia",
    "description":"",
    "mimeType":"",
    "payTo":"0x...",
    "maxTimeoutSeconds":60,
    "asset":"0x...",
    "outputSchema":{
      "input":{
        "type":"http",
        "method":"GET",
        "discoverable":true
      }
    },
    "extra":{
      "name":"USDC",
      "version":"2"
    }
  }
}
```
