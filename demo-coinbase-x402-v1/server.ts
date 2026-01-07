import { config } from "dotenv";
import express from "express";
import { paymentMiddleware, Resource } from "x402-express";

config();

const facilitatorUrl = process.env.FACILITATOR_URL as Resource;
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

const app = express();

app.use(
  paymentMiddleware(
    payToAddress,
    {
      // "GET /sepolia": {
      //   price: "$0.001",
      //   network: "sepolia",
      // },
      "GET /base-sepolia": {
        price: "$0.001",
        network: "base-sepolia",
      },
    },
    {
      url: facilitatorUrl,
      createAuthHeaders: createAuthHeaders,
    },
  ),
);

// app.get("/sepolia", (req: any, res: any) => {
//   res.send({
//     message: "payment successful",
//   });
// });

app.get("/base-sepolia", (req: any, res: any) => {
  res.send({
    message: "payment successful",
  });
});

app.listen(4021, () => {
  console.log(`server listening at http://localhost:4021`);
});
