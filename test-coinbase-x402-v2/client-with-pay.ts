import { config } from "dotenv";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

config();

const { PRIVATE_KEY } = process.env;

const account = privateKeyToAccount(("0x" + PRIVATE_KEY) as `0x${string}`);

const client = new x402Client();

registerExactEvmScheme(client, { signer: account });

const fetchWithPay = wrapFetchWithPayment(fetch, client);

async function main(): Promise<void> {

  await fetchWithPay("http://localhost:4022/sepolia", { method: "GET" })
    .then(async (response) => {
      console.log(response);
      const body = await response.json();
      console.log("Response Body", body);
    })
    .catch((error) => {
      console.error(error.response?.data?.error);
    });


  await fetchWithPay("http://localhost:4022/base-sepolia", { method: "GET" })
    .then(async (response) => {
      console.log(response);
      const body = await response.json();
      console.log("Response Body", body);
    })
    .catch((error) => {
      console.error(error.response?.data?.error);
    });

}

main().catch(error => {
  console.error(error?.response?.data?.error ?? error);
  process.exit(1);
});
