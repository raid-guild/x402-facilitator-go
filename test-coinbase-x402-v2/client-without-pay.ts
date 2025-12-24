fetch("http://localhost:4022/sepolia", { method: "GET" })
  .then(async (response) => {
    console.log(response);
    const body = await response.json();
    console.log("Response Body", body);
  })
  .catch((error) => {
    console.error(error.response?.data?.error);
  });

fetch("http://localhost:4022/base-sepolia", { method: "GET" })
  .then(async (response) => {
    console.log(response);
    const body = await response.json();
    console.log("Response Body", body);
  })
  .catch((error) => {
    console.error(error.response?.data?.error);
  });
