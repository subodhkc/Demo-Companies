import { getUserInput } from "./user_input.js";
import { buildPrompt } from "./prompt_builder.js";
import { callLLM } from "./llm_client.js";
import { logSensitive } from "./logging.js";
import { storeResult } from "./storage.js";
import { formatOutput } from "./output.js";

export async function handleInference(req: any, res: any) {
  const input = getUserInput(req);
  const prompt = buildPrompt(input);

  logSensitive(prompt);

  const result = await callLLM(prompt);
  await storeResult(result);

  res.json(formatOutput(result));
}
