import { config } from "dotenv";
import express from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { HTTPFacilitatorClient } from "@x402/core/server";

config();

const facilitatorUrl = process.env.FACILITATOR_URL as string;
const facilitatorApiKey = process.env.FACILITATOR_API_KEY as string;
const payToAddress = process.env.PAY_TO_ADDRESS as `0x${string}`;

if (!facilitatorUrl || !facilitatorApiKey || !payToAddress) {
  console.error("missing required environment variables");
  process.exit(1);
}

const createAuthHeaders = async () => ({
  verify: { "X-API-Key": facilitatorApiKey },
  settle: { "X-API-Key": facilitatorApiKey },
  supported: {},
});

const facilitatorClient = new HTTPFacilitatorClient({
  url: facilitatorUrl,
  createAuthHeaders,
});

const app = express();

app.use(
  paymentMiddleware(
    {
      "GET /sepolia": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.001",
            network: "eip155:11155111",
            payTo: payToAddress,
          },
        ],
      },
      "GET /base-sepolia": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.001",
            network: "eip155:84532",
            payTo: payToAddress,
          },
        ],
      },
    },
    new x402ResourceServer(facilitatorClient)
      .register("eip155:11155111", new ExactEvmScheme())
      .register("eip155:84532", new ExactEvmScheme()),
  ),
);

app.get("/sepolia", (req: any, res: any) => {
  res.send({
    report: {
      message: "payment successful",
    },
  });
});

app.get("/base-sepolia", (req: any, res: any) => {
  res.send({
    report: {
      message: "payment successful",
    },
  });
});

app.listen(4022, () => {
  console.log(`Server listening at http://localhost:4022`);
});
