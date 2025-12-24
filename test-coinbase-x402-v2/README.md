# test-coinbase-x402-v2

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

Current issues (sepolia):

- `Note: Install @x402/paywall for full wallet connection and payment UI.`
- I did not test with server only, see the example below for any current issues

Go to endpoint:

http://localhost:4022/base-sepolia

Current issues (base-sepolia):

- `Note: Install @x402/paywall for full wallet connection and payment UI.`
- I did not test with server only, see the example below for any current issues

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

- Using `https://x402-facilitator-go.vercel.app`
  - Example code returns `402` response with an empty response body (same as without pay)
  - Not visible but `Internal Server Error` is expected if the environment variables are not set
- Using `https://x402-facilitator-ryanchristo.vercel.app`
  - No issues, verified and settled payment using configured facilitator

Current issues (base-sepolia):

- Using `https://x402-facilitator-go.vercel.app`
  - Example code returns `402` response with an empty response body (same as without pay)
  - Not visible but `Internal Server Error` is expected if the environment variables are not set
- Using `https://x402-facilitator-ryanchristo.vercel.app`
  - No issues, verified and settled payment using configured facilitator

## Example Request Body

```
{
  "x402Version":2,
  "paymentPayload":{
    "x402Version":2,
    "payload":{
      "authorization":{
        "from":"0x...",
        "to":"0x...",
        "value":"1000",
        "validAfter":"1766200595",
        "validBefore":"1766201495",
        "nonce":"0x..."
      },
      "signature":"0x..."
    },
    "resource":{
      "url":"http://localhost:4022/sepolia",
      "description":"",
      "mimeType":""
    },
    "accepted":{
      "scheme":"exact",
      "network":"eip155:11155111",
      "amount":"1000",
      "asset":"0x...",
      "payTo":"0x...",
      "maxTimeoutSeconds":300,
      "extra":{
        "name":"USDC",
        "version":"2"
      }
    }
  },
  "paymentRequirements":{
    "scheme":"exact",
    "network":"eip155:11155111",
    "amount":"1000",
    "asset":"0x...",
    "payTo":"0x...",
    "maxTimeoutSeconds":300,
    "extra":{
      "name":"USDC",
      "version":"2"
    }
  }
}
```
