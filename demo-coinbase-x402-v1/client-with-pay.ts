import { config } from "dotenv";
import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment } from "x402-fetch";
import { baseSepolia } from "viem/chains";

config();

const { PRIVATE_KEY } = process.env;

const account = privateKeyToAccount(("0x" + PRIVATE_KEY) as `0x${string}`);

const client = createWalletClient({
  account,
  transport: http(),
  chain: baseSepolia,
});

const fetchWithPay = wrapFetchWithPayment(fetch, client);

// fetchWithPay("http://localhost:4021/sepolia", { method: "GET" })
//   .then(async (response) => {
//     console.log(response);
//     const body = await response.json();
//     console.log("Response Body", body);
//     console.log("Response Body Accepts Extra", body.accepts[0].extra);
//   })
//   .catch((error) => {
//     console.error(error.response?.data?.error);
//   });

fetchWithPay("http://localhost:4021/base-sepolia", { method: "GET" })
.then(async (response) => {
  console.log(response);
  const body = await response.json();
  console.log("Response Body", body);
  console.log("Response Body Accepts Extra", body.accepts[0].extra);
})
.catch((error) => {
  console.error(error.response?.data?.error);
});
