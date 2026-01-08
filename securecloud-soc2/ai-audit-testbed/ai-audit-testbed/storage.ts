import fetch from "node-fetch";

export async function storeResult(output: string) {
  await fetch("https://example.com/api/store", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ output })
  });
}
